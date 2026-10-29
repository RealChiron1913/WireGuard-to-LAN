"""Fault-injection tests for the real Lua transaction code, with an in-memory OS.

The harness replaces only process execution and platform libraries. It does not
pretend to test nft syntax or packet forwarding; tests/linux_network.py does that.
"""
import copy
import json
import re

import pytest
from lupa.lua51 import LuaRuntime

from conftest import ROOT, lua_to_py, to_lua
from test_engine import CONFIG, kernel_document

BASE = "/etc/wgnat6/luci"


class Exit(Exception):
    pass


class Platform:
    def __init__(self):
        self.files = {
            "/etc/config/wgnat6": "config mapping 'main'\n" + "".join(f"\toption {k} '{v}'\n" for k,v in CONFIG.items()),
            "/etc/config/firewall": "# existing unrelated firewall\n",
            "/proc/sys/kernel/random/boot_id": "boot-one\n", "/proc/uptime": "100.0 90.0\n",
            "/sbin/fw4": "LOCK=/var/run/fw4.lock\nflock -x 1000\n",
            "/usr/share/ucode/fw4.uc": "table-pre chain-pre",
            "/etc/init.d/firewall": "START=19\n",
            "/www/luci-static/resources/form.js": "JSONMap",
            "/usr/share/wgnat6/version": "1.5.14\n",
        }
        self.dirs = {"/", "/etc", "/etc/config", "/var", "/var/run"}
        self.links = {}
        self.sections = {"unrelated": {".type": "rule", ".name": "unrelated", "name": "Keep me"}}
        self.kernel = {}
        self.calls, self.output, self.logs = [], [], []
        self.nonce = 0
        self.fail_check = False
        self.fail_verify_once = False
        self.tampered_id = None
        self.watchdog = True
        self.clock = 1000
        self.peer = "10.66.66.2/32"
        self.wg_device = 'vpn'
        self.interfaces = [
            {"ifname": "br-lan", "addr_info": [{"family": "inet", "local": "192.168.31.10", "prefixlen": 24}]},
            {"ifname": "vpn", "addr_info": [{"family": "inet", "local": "10.66.66.1", "prefixlen": 24}]},
        ]
        self.route_dev = "br-lan"
        self.route_gateway = None
        self.ping = False
        self.foreign_dnat = False

    def resolve(self, path):
        for link, target in self.links.items():
            if path == link or path.startswith(link + "/"):
                return target + path[len(link):]
        return path

    def lstat(self, path):
        kind = "lnk" if path in self.links else "dir" if path in self.dirs else "reg" if path in self.files else None
        return {"type": kind} if kind else None

    def mkdir(self, path):
        while path:
            self.dirs.add(path)
            path = path.rpartition("/")[0]
        return True

    def unlink(self, path):
        self.files.pop(path, None)
        self.links.pop(path, None)
        return True

    def rename(self, src, dst):
        if src in self.links:
            self.links[dst] = self.links.pop(src)
        else:
            self.files[dst] = self.files.pop(src)
        return True

    def symlink(self, src, dst):
        self.links[dst] = src
        return True

    def directories(self, path):
        return sorted(p[len(path) + 1:] for p in self.dirs if p.startswith(path + "/") and "/" not in p[len(path) + 1:])

    def random(self):
        self.nonce += 1
        return f"{self.nonce:016d}"

    def get_config(self):
        # UCI can omit empty string options: model that behavior instead of retaining ''.
        rows=self.get_configurations()
        main=next((row for row in rows if row['.name']=='main'),rows[0] if rows else {})
        return {k:v for k,v in main.items() if not k.startswith('.')}

    def get_configurations(self):
        rows=[]
        text=self.files.get('/etc/config/wgnat6','')
        for match in re.finditer(r"config\s+(\w+)\s+'([^']+)'([^\x00]*?)(?=\nconfig\s|\Z)",text):
            row={'.type':match[1],'.name':match[2]}
            row.update({k:v for k,v in re.findall(r"option\s+(\w+)\s+'([^']*)'",match[3]) if v!=''})
            rows.append(row)
        return rows

    def current_id(self):
        return self.links.get(BASE + "/current", "").rpartition("/")[2]

    def generation(self, id=None):
        return json.loads(self.files[BASE + "/gens/" + (id or self.current_id()) + "/generation.json"])

    def document(self, g, stage):
        # Create the kernel's JSON representation, including actual null verdicts.
        rules = []
        for r in g["rules"][stage] if isinstance(g["rules"][stage], list) else []:
            expr = copy.deepcopy(r["expr"])
            for e in expr:
                if "counter" in e:
                    e["counter"] = {"packets": 0, "bytes": 0}
                if "dnat" in e:
                    e["dnat"] = {"addr": e["dnat"], "family": "ip"}
                if "accept" in e: e["accept"] = None
                if "masquerade" in e: e["masquerade"] = None
            rules.append({"rule": {"family": "inet", "table": "fw4", "chain": "wgnat6_" + stage,
                                   "comment": r["comment"], "expr": expr}})
        return {"nftables": [{"chain": {"family": "inet", "table": "fw4", "name": "wgnat6_" + stage}}] + rules}

    def load_kernel(self, id):
        g = self.generation(id)
        self.kernel = {"wgnat6_" + s: self.document(g, s) for s in ("dnat", "snat", "forward")}
        for s, parent in [("dnat", "dstnat"), ("snat", "srcnat"), ("forward", "forward")]:
            self.kernel[parent] = {"nftables": [{"chain": {"name": parent}}, {"rule": {
                "handle": 100 + len(self.kernel), "comment": "wgnat6:anchor:" + s, "expr": [{"jump": {"target": "wgnat6_" + s}}]}}]}

    def run(self, path, args):
        a = lua_to_py(args) or []
        self.calls.append((path, a))
        if path == "/sbin/ip":
            if 'link' in a:
                data=getattr(self,'device_links',None) or [{'ifname':device['ifname'],'flags':['UP'],'operstate':'UP'} for device in self.interfaces]
            elif "address" in a:
                data = self.interfaces
            else:
                data = [{"dev": self.route_dev} | ({"gateway": self.route_gateway} if self.route_gateway else {})]
            return True, json.dumps(data), ""
        if path == "/usr/bin/wg":
            if a==['show','interfaces']: return True,getattr(self,'wg_interfaces',self.wg_device),''
            return True, self.wg_device + " public-peer " + self.peer, ""
        if path == "/bin/ubus":
            return True, json.dumps({"wgnat6": {"instances": {"main": {"running": self.watchdog}}}}), ""
        if path == "/bin/ping": return self.ping, "", ""
        if path == "/sbin/uci": return True, "", ""
        if path == "/sbin/fw4":
            if a == ["print"]:
                paths = re.findall(r'"path":\s*"([^"]+)"', json.dumps(self.sections))
                return True, "\n".join('include "' + p + '"' for p in paths), ""
            if a == ["reload"]:
                if "wgnat6_dnat" in self.sections and self.sections["wgnat6_dnat"].get("path", "").startswith(BASE):
                    self.load_kernel(self.current_id())
                else:
                    if getattr(self, 'retain_empty_chains', False):
                        self.kernel = {name: {'nftables': [copy.deepcopy(doc['nftables'][0])]} for name, doc in self.kernel.items() if name.startswith('wgnat6_')}
                    else: self.kernel = {}
            return True, "", ""
        if path == "/usr/sbin/nft":
            if a == ["--version"]: return True, "nftables v1.1.1", ""
            if a == ["-j", "list", "tables"]: return True, '{"nftables":[]}', ""
            if a == ["-j", "list", "ruleset"]:
                rules = [{"rule": {"family": "inet", "table": "other", "chain": "dnat", "expr": [
                    {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "10.66.66.6"}}, {"dnat": {"addr": "192.168.31.77"}}]}}] if self.foreign_dnat else []
                for document in self.kernel.values(): rules.extend(copy.deepcopy(document['nftables']))
                return True, json.dumps({"nftables": rules}), ""
            if "chain" in a:
                chain = a[-1]
                if chain not in self.kernel: return False, "", "No such chain"
                d = copy.deepcopy(self.kernel[chain])
                if self.tampered_id == self.current_id() and chain == "wgnat6_dnat": d["nftables"].pop()
                if getattr(self, 'bad_snat_expression', False) and chain == 'wgnat6_snat':
                    d['nftables'][1]['rule']['expr'][5]['match']['right'] = '10.66.66.99'
                return True, json.dumps(d), ""
            if "-c" in a:
                if getattr(self, 'fail_anchor_check', False) and a[-1].endswith('anchor-repair.nft'):
                    return False, '', 'injected anchor syntax failure'
                if self.fail_check and a[-1].endswith("batch.nft"):
                    return False, "", "injected invalid nft candidate"
                return True, "", ""
            if a == ['-f', '/var/run/wgnat6/anchor-repair.nft']:
                for line in self.files[a[-1]].splitlines():
                    parts = line.split()
                    parent = parts[4]
                    if parts[0] == 'insert':
                        stage = parts[6].removeprefix('wgnat6_')
                        self.kernel[parent]['nftables'].insert(1, {'rule': {'handle': 1000 + len(self.calls),
                            'comment': 'wgnat6:anchor:' + stage, 'expr': [{'jump': {'target': parts[6]}}]}})
                    elif parts[0] == 'delete':
                        handle = int(parts[-1])
                        self.kernel[parent]['nftables'] = [item for item in self.kernel[parent]['nftables']
                            if item.get('rule', {}).get('handle') != handle]
                return True, '', ''
            if "-f" in a and a[-1].endswith("batch.nft"):
                id = a[-1].split("/")[-2]
                self.load_kernel(id)
                if self.fail_verify_once:
                    self.tampered_id = id
                    self.fail_verify_once = False
                return True, "", ""
        raise AssertionError((path, a))

    def invoke(self, action, data=None, cli=False, extra=None):
        lua = LuaRuntime(unpack_returned_tuples=True)
        def dumps(v): return json.dumps(lua_to_py(v), ensure_ascii=False)
        def loads(v): return to_lua(lua, json.loads(v))
        h = lua.table_from({
            "read": lambda p: self.files.get(self.resolve(p)), "write": lambda p, d: self.files.__setitem__(p, d) or len(d),
            "lstat": lambda p: to_lua(lua, self.lstat(p)), "mkdir": self.mkdir, "unlink": self.unlink,
            "rename": self.rename, "symlink": self.symlink, "readlink": lambda p: self.links.get(p),
            "dir": lambda p: to_lua(lua, self.directories(p)), "rmdir": lambda p: self.dirs.discard(p) or True,
            "json_dump": dumps, "json_parse": loads, "output": self.output.append,
            "run": self.run, "random": self.random, "log": self.logs.append,
            "clock": lambda: self.clock, "config": lambda: to_lua(lua, self.get_config()),
            "configurations": lambda: to_lua(lua,self.get_configurations()),
            "sections": to_lua(lua, copy.deepcopy(self.sections)),
            "networks": to_lua(lua,copy.deepcopy(getattr(self,'networks',[]))),
            "commit": lambda sections: setattr(self, "sections", lua_to_py(sections)) or True,
            "request": json.dumps(data or {}),
        })
        lua.globals().H = h
        lua.execute("""
            package.preload['luci.jsonc']=function() return {parse=H.json_parse, stringify=H.json_dump} end
            package.preload['nixio.fs']=function() return {
                readfile=H.read, lstat=H.lstat, mkdirr=H.mkdir,
                chmod=function(_,mode) assert(mode=='rwx------'); return true end,
                rename=H.rename, unlink=H.unlink, symlink=H.symlink, readlink=H.readlink,
                dir=function(p) local list=H.dir(p); local i=0; return function() i=i+1; return list[i] end end,
                rmdir=H.rmdir, access=function() return true end
            } end
            package.preload['nixio']=function() return {
                open=function(path,mode,permissions)
                    if mode=='w' then assert(permissions=='rw-------'); H.write(path,'') end
                    local value=''
                    return {write=function(_,s) value=value..s; H.write(path,value); return #s end,
                            sync=function() return true end, close=function() end}
                end,
                openlog=function(ident,flag,extra) assert(ident=='wgnat6' and flag=='pid' and extra==nil) end,
                syslog=function(_,s) H.log(s) end, closelog=function() end
            } end
            package.preload['uci']=function()
                local isolated={}
                local function copy(value)
                    if type(value)~='table' then return value end
                    local out={}; for k,v in pairs(value) do out[k]=copy(v) end; return out
                end
                return {cursor=function(confdir)
                local probe=confdir~='/etc/config'
                if probe then isolated[confdir]=isolated[confdir] or {} end
                local sections=probe and isolated[confdir] or H.sections
                return {
                    foreach=function(_,file,kind,cb)
                        if file=='wgnat6' then for _,c in ipairs(H.configurations()) do cb(c) end
                        elseif file=='network' then for _,s in ipairs(H.networks) do cb(s) end
                        elseif file=='firewall' then for k,s in pairs(H.sections) do if not kind or s['.type']==kind then cb(s) end end end
                    end,
                    get_all=function(_,file,name) return copy(sections[name]) end,
                    get=function(_,file,name,key)
                        local s=sections[name]; if not s then return nil end
                        if key then return copy(s[key]) end
                        return s['.type']
                    end,
                    delete=function(_,file,name,key)
                        if not sections[name] then return false end
                        if key then sections[name][key]=nil else sections[name]=nil end
                        return true
                    end,
                    -- Native libuci-lua has no section() helper. Three-argument
                    -- set creates/retypes a named section; four arguments set an option.
                    set=function(_,file,name,key,value)
                        if value==nil then
                            sections[name]=sections[name] or {['.name']=name}
                            sections[name]['.type']=key
                            return true
                        end
                        if not sections[name] then return false,'Entry not found' end
                        sections[name][key]=copy(value); return true
                    end,
                    save=function() return true end,
                    commit=function() if not probe then H.commit(sections) end; return true end,
                    close=function() end
                }
            end} end
            io.read=function() return H.request end
            io.write=function(s) H.output(s) end
            io.open=function() return {read=function() return H.random() end, close=function() end} end
            os.time=function() return H.clock() end
        """)
        engine = lua.execute((ROOT / "root/usr/lib/wgnat6/engine.lua").read_text(encoding="utf-8"))
        lua.globals().package.loaded.engine = engine
        lua.globals().package.loaded.legacy = lua.execute((ROOT / 'root/usr/lib/wgnat6/legacy.lua').read_text(encoding='utf-8'))
        lua.globals().arg = to_lua(lua, [action] + (extra or []) if cli else ["rpc", action])
        # Test-only source instrumentation: substitute process runner at its boundary.
        source = (ROOT / "root/usr/lib/wgnat6/main.lua").read_text(encoding="utf-8")
        source = source.replace("local function run(path, args)\n", "local function run(path, args)\n    if true then return H.run(path,args) end\n", 1)
        source = source.replace("os.exit(1)", "error('test CLI failure')")
        if hasattr(self,'source_transform'): source=self.source_transform(source)
        self.output.clear()
        try:
            lua.execute(source)
        except Exception:
            if not self.output:
                raise
        return json.loads(self.output[-1])

    def setup(self, legacy=False):
        if legacy:
            for stage in ("dnat", "snat", "forward"):
                name = "wgnat6_" + stage
                self.sections[name] = {".type": "include", ".name": name, "type": "nftables", "path": "/etc/wgnat6/" + stage + ".nft"}
                self.files["/etc/wgnat6/" + stage + ".nft"] = "# legacy " + stage
            return self.invoke("setup", cli=True, extra=["--migrate"])
        return self.invoke("setup", cli=True)


@pytest.fixture
def platform():
    p = Platform()
    result = p.setup()
    assert result["ok"], result
    return p


def test_apply_then_confirm_is_only_commit_point(platform):
    p = platform
    previous = p.current_id()
    applied = p.invoke("apply", CONFIG | {"target_ip": "192.168.31.50"})
    assert applied["ok"] and applied["pending"]
    assert p.current_id() != previous
    assert p.get_config()["target_ip"] == "192.168.31.39"
    assert p.invoke("verify")["ok"]
    assert not p.invoke("confirm", {"token": "wrong"})["ok"]
    assert p.invoke("confirm", {"token": applied["token"]})["ok"]
    assert p.get_config()["target_ip"] == "192.168.31.50"
    assert BASE + "/pending.json" not in p.files
    assert p.files[BASE + "/previous"] == previous


def test_invalid_candidate_leaves_last_good_untouched(platform):
    p = platform
    before = (copy.deepcopy(p.files), copy.deepcopy(p.kernel), p.current_id())
    result = p.invoke("apply", CONFIG | {"target_ip": "192.168.31.50;reboot"})
    assert not result["ok"]
    assert (p.files, p.kernel, p.current_id()) == before


def test_syntax_failure_before_live_update(platform):
    p = platform; previous = p.current_id(); kernel = copy.deepcopy(p.kernel)
    p.fail_check = True
    assert not p.invoke("apply", CONFIG | {"target_ip": "192.168.31.50"})["ok"]
    assert p.current_id() == previous and p.kernel == kernel
    assert BASE + "/pending.json" not in p.files


def test_kernel_verification_failure_restores_previous(platform):
    p = platform; previous = p.current_id(); kernel = copy.deepcopy(p.kernel)
    p.fail_verify_once = True
    result = p.invoke("apply", CONFIG | {"target_ip": "192.168.31.50"})
    assert not result["ok"] and "已恢复" in result["error"]
    assert p.current_id() == previous and p.kernel == kernel
    assert p.get_config()["target_ip"] == "192.168.31.39"
    assert BASE + "/pending.json" not in p.files


def test_verification_records_only_mismatch_before_rollback(platform):
    p = platform
    p.bad_snat_expression = True
    result = p.invoke('verify')
    assert not result['ok']
    detail = json.loads(p.files['/var/run/wgnat6/verify-error.json'])
    assert (detail['stage'], detail['rule'], detail['expression']) == ('snat', 1, 6)
    assert detail['actual']['match']['right'] == '10.66.66.99'
    assert detail['expected']['match']['right'] == '10.66.66.6'
    for stage in ('dnat', 'snat', 'forward'):
        captured = json.loads(p.files['/var/run/wgnat6/verify-chain-' + stage + '.json'])
        assert captured['nftables'][0]['chain']['name'] == 'wgnat6_' + stage


def test_maintain_moves_only_our_anchor_ahead_of_late_openclash_rules(platform):
    p = platform
    foreign = {'dstnat': {'handle': 401, 'comment': 'OpenClash DNS Hijack', 'expr': [{'redirect': {'port': 53}}]},
               'forward': {'handle': 402, 'comment': 'OpenClash QUIC REJECT', 'expr': [{'reject': {}}]}}
    for parent, rule in foreign.items(): p.kernel[parent]['nftables'].insert(1, {'rule': copy.deepcopy(rule)})
    assert not p.invoke('verify')['ok']
    result = p.invoke('maintain', cli=True)
    assert result['ok'] and result['changed']
    assert p.invoke('verify')['ok']
    for parent, rule in foreign.items():
        assert p.kernel[parent]['nftables'][2]['rule'] == rule
    batch = p.files['/var/run/wgnat6/anchor-repair.nft']
    assert batch.count('insert rule') == 2 and batch.count('delete rule') == 2
    assert 'flush' not in batch and 'OpenClash' not in batch
    assert not p.invoke('maintain', cli=True)['changed']


def test_maintain_refuses_to_move_unknown_or_modified_application_rules(platform):
    p = platform
    p.kernel['dstnat']['nftables'].insert(1, {'rule': {'handle': 999, 'expr': [{'accept': None}]}})
    p.kernel['wgnat6_snat']['nftables'][1]['rule']['expr'][0]['match']['right'] = 'wan'
    before = copy.deepcopy(p.kernel)
    assert not p.invoke('maintain', cli=True)['ok']
    assert p.kernel == before


def test_maintain_check_failure_leaves_all_rules_unchanged(platform):
    p = platform
    p.kernel['dstnat']['nftables'].insert(1, {'rule': {'handle': 999, 'expr': [{'accept': None}]}})
    p.fail_anchor_check = True
    before = copy.deepcopy(p.kernel)
    assert not p.invoke('maintain', cli=True)['ok']
    assert p.kernel == before


def test_confirm_restores_anchor_order_after_late_foreign_insert(platform):
    p = platform
    candidate = p.invoke('apply', CONFIG | {'target_ip': '192.168.31.50'})
    assert candidate['ok']
    foreign = {'handle': 803, 'comment': 'OpenClash DNS Hijack', 'expr': [{'redirect': {'port': 53}}]}
    p.kernel['dstnat']['nftables'].insert(1, {'rule': copy.deepcopy(foreign)})
    assert p.invoke('confirm', {'token': candidate['token']})['ok']
    assert p.kernel['dstnat']['nftables'][2]['rule'] == foreign
    assert p.get_config()['target_ip'] == '192.168.31.50'


def test_monotonic_timeout_despite_clock_adjustment(platform):
    p = platform; previous = p.current_id()
    assert p.invoke("apply", CONFIG | {"target_ip": "192.168.31.50"})["ok"]
    p.clock -= 10000  # NTP moved wall time backwards; monotonic expiry still wins.
    p.files["/proc/uptime"] = "191.0 90.0"
    assert p.invoke("recover", cli=True)["ok"]
    assert p.current_id() == previous and BASE + "/pending.json" not in p.files


def test_reboot_rolls_back_without_live_firewall_commands(platform):
    p = platform; previous = p.current_id()
    assert p.invoke("apply", CONFIG | {"target_ip": "192.168.31.50"})["ok"]
    p.calls.clear()
    p.files["/proc/sys/kernel/random/boot_id"] = "boot-two"
    assert p.invoke("boot", cli=True)["ok"]
    assert p.current_id() == previous
    assert not p.calls


def test_disable_reenable_and_repeat_do_not_grow_rules(platform):
    p = platform
    for enabled in ("0", "1", "1", "1"):
        r = p.invoke("apply", CONFIG | {"enabled": enabled})
        assert r["ok"], r
        assert p.invoke("confirm", {"token": r["token"]})["ok"]
        for chain in ("wgnat6_dnat", "wgnat6_snat", "wgnat6_forward"):
            assert len(p.kernel[chain]["nftables"]) == (5 if enabled == "1" else 1)
    assert len([d for d in p.dirs if re.match(BASE + r"/gens/[0-9a-f]{32}$", d)]) == 2


def test_no_runtime_apply_without_watchdog(platform):
    p = platform; previous = p.current_id(); p.watchdog = False
    assert not p.invoke("apply", CONFIG)["ok"]
    assert p.current_id() == previous


def test_existing_mapping_or_bad_route_blocks_apply(platform):
    p = platform; previous = p.current_id()
    p.foreign_dnat = True
    assert not p.invoke("apply", CONFIG)["ok"]
    p.foreign_dnat = False; p.route_dev = "wan"
    assert not p.invoke("apply", CONFIG)["ok"]
    assert p.current_id() == previous


def test_unreachable_target_is_warning_not_false_failure(platform):
    r = platform.invoke("apply", CONFIG)
    assert r["ok"] and "未回应 ICMP" in r["warning"]


def test_manual_rollback_and_previous_version(platform):
    p = platform
    r = p.invoke("apply", CONFIG | {"target_ip": "192.168.31.50"})
    assert p.invoke("rollback")["ok"]
    assert p.get_config()["target_ip"] == "192.168.31.39"
    r = p.invoke("apply", CONFIG | {"target_ip": "192.168.31.50"})
    p.invoke("confirm", {"token": r["token"]})
    r = p.invoke("rollback")
    assert r["ok"] and r["pending"]
    p.invoke("confirm", {"token": r["token"]})
    assert p.get_config()["target_ip"] == "192.168.31.39"


def test_detach_preserves_unrelated_uci_and_files(platform):
    p = platform
    untouched = copy.deepcopy(p.sections["unrelated"])
    p.files["/etc/wgnat6/dnat.nft"] = "legacy file untouched"
    assert p.invoke("detach", cli=True)["ok"]
    assert p.sections == {"unrelated": untouched}
    assert p.files["/etc/wgnat6/dnat.nft"] == "legacy file untouched"
    assert not p.kernel and BASE + "/owned.json" not in p.files


def test_detach_accepts_proven_empty_unreferenced_chains(platform):
    p = platform
    p.files[BASE + '/package-id'] = 'luci-app-wgnat6-state-v1\n'
    p.retain_empty_chains = True
    result = p.invoke('detach', cli=True)
    assert result['ok'], result
    assert BASE + '/owned.json' not in p.files
    assert set(p.kernel) == {'wgnat6_dnat', 'wgnat6_snat', 'wgnat6_forward'}
    assert all(len(chain['nftables']) == 1 for chain in p.kernel.values())


def test_detach_refuses_chain_referenced_after_reload(platform):
    p = platform
    p.files[BASE + '/package-id'] = 'luci-app-wgnat6-state-v1\n'
    p.retain_empty_chains = True
    original_run = p.run
    def inject_reference(path, args):
        out = original_run(path, args)
        if path == '/sbin/fw4' and list(args.values()) == ['reload'] and 'wgnat6_dnat' in p.kernel and 'dstnat' not in p.kernel:
            p.kernel['foreign'] = {'nftables': [{'rule': {'chain': 'other', 'expr': [{'jump': {'target': 'wgnat6_dnat'}}]}}]}
        return out
    p.run = inject_reference
    result = p.invoke('detach', cli=True)
    assert not result['ok'] and '已恢复' in result['error']
    assert BASE + '/owned.json' in p.files
    assert p.sections['wgnat6_dnat']['path'].startswith(BASE)


def test_unknown_existing_include_is_not_overwritten():
    p = Platform()
    p.sections["wgnat6_dnat"] = {".type": "include", "path": "/etc/someone-else.nft"}
    before = copy.deepcopy(p.sections)
    assert not p.setup()["ok"]
    assert p.sections == before


def stranded_chains():
    p = Platform()
    assert p.invoke('boot', cli=True)['ok']
    p.retain_empty_chains = True
    p.bad_snat_expression = True
    assert not p.setup(legacy=True)['ok']
    p.bad_snat_expression = False
    assert set(p.kernel) == {'wgnat6_dnat', 'wgnat6_snat', 'wgnat6_forward'}
    assert all(len(doc['nftables']) == 1 for doc in p.kernel.values())
    return p


def test_retry_after_failed_migration_reuses_proven_empty_chains():
    p = stranded_chains()
    result = p.setup(legacy=True)
    assert result['ok'], result
    assert p.invoke('verify')['ok']


@pytest.mark.parametrize('alteration', ['missing_identity', 'tampered_snippet', 'rule', 'reference', 'hook'])
def test_stranded_chains_are_never_reused_without_proof_or_when_used(alteration):
    p = stranded_chains()
    if alteration == 'missing_identity': p.files.pop(BASE + '/package-id')
    elif alteration == 'tampered_snippet': p.files[BASE + '/gens/' + p.current_id() + '/snat.nft'] += '# changed\n'
    elif alteration == 'rule': p.kernel['wgnat6_snat']['nftables'].append({'rule': {'chain': 'wgnat6_snat'}})
    elif alteration == 'reference': p.kernel['foreign'] = {'nftables': [{'rule': {'chain': 'other', 'expr': [{'jump': {'target': 'wgnat6_snat'}}]}}]}
    else: p.kernel['wgnat6_snat']['nftables'][0]['chain']['hook'] = 'postrouting'
    before = copy.deepcopy(p.kernel)
    assert not p.setup(legacy=True)['ok']
    assert p.kernel == before


def test_explicit_migration_backs_up_and_restores_legacy():
    p = Platform()
    assert p.setup(legacy=True)["ok"]
    owned = json.loads(p.files[BASE + "/owned.json"])
    for stage in ("dnat", "snat", "forward"):
        assert p.files[BASE + "/backups/" + owned["backup"] + "/" + stage + ".nft"] == "# legacy " + stage
        assert p.files["/etc/wgnat6/" + stage + ".nft"] == "# legacy " + stage
    assert p.invoke("detach", cli=True)["ok"]
    for stage in ("dnat", "snat", "forward"):
        assert p.sections["wgnat6_" + stage]["path"] == "/etc/wgnat6/" + stage + ".nft"


def test_boot_restores_uci_modified_outside_transaction(platform):
    p = platform
    p.files["/etc/config/wgnat6"] = p.files["/etc/config/wgnat6"].replace("192.168.31.39", "192.168.31.88")
    assert p.invoke("boot", cli=True)["ok"]
    assert p.get_config()["target_ip"] == "192.168.31.39"
