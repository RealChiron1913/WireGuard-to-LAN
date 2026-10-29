import copy
import json
from pathlib import Path

import pytest
from lupa.lua51 import LuaRuntime

from conftest import ROOT, lua_to_py, to_lua

CONFIG = dict(enabled="1", virtual_ip="10.66.66.6", target_ip="192.168.31.39",
              lan_interface="br-lan", wireguard_interface="vpn", protocol="both")


@pytest.fixture
def engine():
    lua = LuaRuntime(unpack_returned_tuples=True)
    e = lua.execute((ROOT / "root/usr/lib/wgnat6/engine.lua").read_text(encoding="utf-8"))
    env = to_lua(lua, dict(local_ips=["192.168.31.10", "10.66.66.1"], peer_ips=["10.66.66.2/32"], route_device="br-lan"))
    env.lan, env.wg = e.subnet("192.168.31.10", 24), e.subnet("10.66.66.1", 24)
    return lua, e, env


@pytest.mark.parametrize("ip", ["", "1.2.3", "1.2.3.256", "1.2.3.-1", "1.2.3.4/32", " 1.2.3.4",
    "1.2.3.4\n", "01.2.3.4", "1.2.3.4;reboot", "$(reboot)", "1.2.3.4'", "1.2.3.4\x00", "::1",
    "127.0.0.1", "0.1.2.3", "169.254.1.1", "224.0.0.1", "255.255.255.255"])
def test_reject_bad_addresses(engine, ip):
    _, e, _ = engine
    with pytest.raises(Exception):
        e.ip(ip)


@pytest.mark.parametrize("field,value", [("target_ip", "192.168.31.10"), ("virtual_ip", "10.66.66.1"),
    ("virtual_ip", "10.66.66.2"), ("virtual_ip", "10.66.66.0"), ("virtual_ip", "10.66.66.255"),
    ("target_ip", "192.168.31.0"), ("target_ip", "192.168.31.255"), ("target_ip", "192.168.32.1"),
    ("virtual_ip", "192.168.31.50"), ("protocol", "tcp;reboot"), ("enabled", "yes"),
    ("lan_interface", 'br-lan" accept'), ("lan_interface", "br-lan\n"), ("wireguard_interface", "br-lan")])
def test_reject_conflicts(engine, field, value):
    lua, e, env = engine
    c = CONFIG | {field: value}
    with pytest.raises(Exception):
        e.validate(to_lua(lua, c), env)


@pytest.mark.parametrize("peer", ["10.66.66.6/32", "10.66.66.6"])
def test_explicit_peer_host_conflicts(engine, peer):
    lua, e, env = engine
    env.peer_ips = to_lua(lua, [peer])
    with pytest.raises(Exception):
        e.validate(to_lua(lua, CONFIG), env)


def test_route_and_nat_conflicts(engine):
    lua, e, env = engine
    for field, value in [("route_device", "wan"), ("route_gateway", "192.168.31.1"), ("conflict", True)]:
        bad = to_lua(lua, lua_to_py(env) | {field: value})
        with pytest.raises(Exception):
            e.validate(to_lua(lua, CONFIG), bad)


def test_source_and_port_scope(engine):
    lua, e, env = engine
    g = e.generate(to_lua(lua, CONFIG), env)
    for stage in ("dnat", "snat", "forward"):
        rules = lua_to_py(g.rules[stage])
        assert len(rules) == 4
        assert all('ip saddr ' in r["text"] for r in rules)
        assert all('meta l4proto ' in r["text"] for r in rules)
        assert all('dport' not in r["text"] and 'sport' not in r["text"] for r in rules)
        assert sum('iifname "vpn"' in r["text"] for r in rules) == 2
        assert sum('iifname "br-lan"' in r["text"] for r in rules) == 2
        if stage != "dnat":
            assert all('oifname "br-lan" ip daddr 192.168.31.39 ct original ip daddr 10.66.66.6' in r["text"] for r in rules)
            assert all('ct status dnat ct state != invalid' in r["text"] for r in rules)
    batch = e.batch(g)
    assert batch.count("flush chain inet fw4 wgnat6_") == 3
    assert "flush table" not in batch and "flush ruleset" not in batch and "delete" not in batch


@pytest.mark.parametrize("protocol,count", [("both", 4), ("tcp", 2), ("udp", 2)])
def test_protocol_selection(engine, protocol, count):
    lua, e, env = engine
    g = e.generate(to_lua(lua, CONFIG | {"protocol": protocol}), env)
    assert len(g.rules.dnat) == count
    if protocol != "both":
        assert all(f"l4proto {protocol}" in r["text"] for r in lua_to_py(g.rules.dnat))


def test_disable_without_live_interfaces(engine):
    lua, e, _ = engine
    g = e.generate(to_lua(lua, CONFIG | {"enabled": "0"}), to_lua(lua, {}))
    assert len(g.rules.dnat) == len(g.rules.snat) == len(g.rules.forward) == 0
    assert e.batch(g).count("flush chain") == 3


def test_generator_is_deterministic_and_single_target(engine):
    lua, e, env = engine
    a = e.generate(to_lua(lua, CONFIG), env)
    b = e.generate(to_lua(lua, CONFIG), env)
    assert e.batch(a) == e.batch(b)
    changed = e.generate(to_lua(lua, CONFIG | {"target_ip": "192.168.31.50"}), env)
    assert "192.168.31.39" not in e.batch(changed)
    assert e.batch(changed).count("192.168.31.50") == 12


def kernel_document(e, lua, g, stage):
    items = [{"chain": {"family": "inet", "table": "fw4", "name": "wgnat6_" + stage}}]
    for r in lua_to_py(g.rules[stage]):
        expressions = copy.deepcopy(r["expr"])
        for expression in expressions:
            if expression.get("counter"):
                expression["counter"] = {"packets": 100, "bytes": 10240}
            if expression.get("dnat"):
                expression["dnat"] = {"family": "ip", "addr": expression["dnat"]}
        items.append({"rule": {"family": "inet", "table": "fw4", "chain": "wgnat6_" + stage,
                               "comment": r["comment"], "expr": expressions}})
    return {"nftables": items}


def test_verify_rejects_missing_extra_or_modified_rules(engine):
    lua, e, env = engine
    g = e.generate(to_lua(lua, CONFIG), env)
    for stage in ("dnat", "snat", "forward"):
        good = kernel_document(e, lua, g, stage)
        e.verify_chain(to_lua(lua, good), stage, g)
        mutations = []
        bad = copy.deepcopy(good); bad["nftables"].pop(); mutations.append(bad)
        bad = copy.deepcopy(good); bad["nftables"].append(bad["nftables"][-1]); mutations.append(bad)
        bad = copy.deepcopy(good); bad["nftables"][1]["rule"]["expr"][0]["match"]["right"] = "wan"; mutations.append(bad)
        bad = copy.deepcopy(good); bad["nftables"][1]["rule"]["expr"].pop(1); mutations.append(bad)
        for bad in mutations:
            with pytest.raises(Exception):
                e.verify_chain(to_lua(lua, bad), stage, g)


@pytest.mark.parametrize('fixture', ['legacy', 'generated'])
def test_real_nft_111_original_destination_without_family(engine, fixture):
    lua, e, env = engine
    g = e.generate(to_lua(lua, CONFIG), env)
    # Captured from the user's active legacy rule; its preceding IPv4 payload
    # match establishes the packet family. It is not generated from g.
    captured = json.loads((ROOT / f'tests/fixtures/istoreos-24.10.7-nft-1.1.1-{fixture}-ct.json').read_text())
    for stage in ('snat', 'forward'):
        good = kernel_document(e, lua, g, stage)
        good['nftables'][1]['rule']['expr'][5] = copy.deepcopy(captured)
        e.verify_chain(to_lua(lua, good), stage, g)
        for path, value in [(['left', 'ct', 'dir'], 'reply'), (['left', 'ct', 'key'], 'saddr'),
                            (['left', 'ct', 'key'], 'ip6 daddr'),
                            (['left', 'ct', 'family'], 'ip6'), (['right'], '10.66.66.7'),
                            (['op'], '!=')]:
            bad = copy.deepcopy(good)
            node = bad['nftables'][1]['rule']['expr'][5]['match']
            for part in path[:-1]: node = node[part]
            node[path[-1]] = value
            with pytest.raises(Exception): e.verify_chain(to_lua(lua, bad), stage, g)
    wanted = lua_to_py(g.rules.snat[1].expr[6])
    assert not e.expression_equal(to_lua(lua, captured), to_lua(lua, wanted), False)


def test_all_lua_sources_compile_as_51(engine):
    lua, _, _ = engine
    compile_source = lua.eval("function(s) return assert(loadstring(s)) end")
    for path in (ROOT / "root").rglob("*.lua"):
        compile_source(path.read_text(encoding="utf-8"))
