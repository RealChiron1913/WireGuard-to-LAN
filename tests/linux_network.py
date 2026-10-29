#!/usr/bin/env python3
"""Opt-in root integration test: all nft writes are inside NEW network namespaces.

Run on Linux with iproute2, nft, sysctl and lupa installed:
    sudo .venv/bin/python tests/linux_network.py
Never runs the router backend, edits /etc/config, or changes host firewall rules.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from conftest import ROOT, lua_to_py, to_lua
from lupa.lua51 import LuaRuntime

SERVER = r'''
import socket, threading, time, json, sys
def tcp(ip):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((ip,3389)); s.listen()
    while True:
        c,_=s.accept(); c.sendall(ip.encode()); c.close()
def udp(ip):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind((ip,51888))
    while True:
        _,a=s.recvfrom(1024); s.sendto(ip.encode(),a)
for ip in json.loads(sys.argv[1]):
    for fn in [tcp,udp]: threading.Thread(target=fn,args=(ip,),daemon=True).start()
while True: time.sleep(1)
'''
CLIENT = r'''
import socket,sys
proto,dst,src=sys.argv[1:]
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if proto=='tcp' else socket.SOCK_DGRAM)
s.settimeout(1)
if src!='-': s.bind((src,0))
try:
    if proto=='tcp': s.connect((dst,3389)); data=s.recv(1024)
    else: s.sendto(b'test',(dst,51888)); data=s.recv(1024)
    print(data.decode())
except (OSError,TimeoutError): sys.exit(2)
finally: s.close()
'''


def run(*argv, check=True):
    result = subprocess.run(list(argv), check=False, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {list(argv)!r}\nstdout: {result.stdout}\nstderr: {result.stderr}")
    return result


def main():
    profiles=json.loads((ROOT/'tests/network_profiles.json').read_text(encoding='utf-8'))
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',choices=sorted(profiles),default='home')
    options=parser.parse_args()
    profile=profiles[options.profile]
    config=profile['config']
    second_vip=str(ipaddress.IPv4Address(config['virtual_ip'])+1)
    lan_device,wg_device=config['lan_interface'],config['wireguard_interface']
    assert sys.platform.startswith("linux") and os.geteuid() == 0, "Requires Linux root with network namespace support"
    prefix = f"wn6-{os.getpid()}-"
    ns = {k: prefix + k for k in ("r", "wg", "lan", "t")}
    created, server = [], None
    lua = LuaRuntime(unpack_returned_tuples=True)
    e = lua.execute((ROOT / "root/usr/lib/wgnat6/engine.lua").read_text(encoding='utf-8'))
    env = to_lua(lua, dict(local_ips=[profile['lan_router'],profile['wg_router']],peer_ips=[profile['wg_client']+'/32'],route_device=lan_device))
    env.lan=e.subnet(profile['lan_router'],profile['lan_bits'])
    env.wg=e.parse_subnet(config['wireguard_subnet']) if config.get('wireguard_subnet') else e.subnet(profile['wg_router'],profile['wg_bits'])

    def ip(k, *args): return run("ip", "-n", ns[k], *args)
    def inside(k, *args, **kw): return run("ip", "netns", "exec", ns[k], *args, **kw)
    def nft(*args, **kw): return inside("r", "nft", *args, **kw)
    def get_chain(stage):
        data = json.loads(nft("-j", "list", "chain", "inet", "fw4", "wgnat6_" + stage).stdout)
        for item in data["nftables"]:
            for expr in item.get("rule", {}).get("expr", []):
                for verdict in ("accept", "masquerade"):
                    if verdict in expr and expr[verdict] is None: expr[verdict] = True
        return data
    def verify(g):
        for stage in ("dnat", "snat", "forward"):
            e.verify_chain(to_lua(lua, get_chain(stage)), stage, g)
    def client(k, protocol, expected, dst=None, source="-"):
        dst=dst or config['virtual_ip']
        result = inside(k, sys.executable, "-c", CLIENT, protocol, dst, source, check=False)
        if expected is None:
            assert result.returncode == 2, (k, protocol, result)
        else:
            assert result.returncode == 0 and result.stdout.strip() == expected, (k, protocol, result)
    def stable_ruleset():
        data = json.loads(nft("-j", "list", "table", "inet", "unrelated").stdout)
        for item in data["nftables"]:
            for expr in item.get("rule", {}).get("expr", []):
                if isinstance(expr.get("counter"),dict): expr["counter"] = {}
        return data

    with tempfile.TemporaryDirectory(prefix="wgnat6-fixture-") as directory:
        directory = Path(directory)
        def install(g, first=False):
            file = directory / "rules.nft"
            if first:
                text = "table inet fw4 {\n"
                for stage in ("dnat", "snat", "forward"): text += e.snippet(g,stage)
                text += '''chain dstnat { type nat hook prerouting priority dstnat; policy accept;
jump wgnat6_dnat comment "wgnat6:anchor:dnat"
}
chain srcnat { type nat hook postrouting priority srcnat; policy accept;
jump wgnat6_snat comment "wgnat6:anchor:snat"
}
chain forward { type filter hook forward priority filter; policy drop;
jump wgnat6_forward comment "wgnat6:anchor:forward"
ct state established,related accept
}
}
'''
            else: text = e.batch(g)
            file.write_text(text, encoding='utf-8')
            nft("-c", "-f", str(file)); nft("-f", str(file)); verify(g)
        try:
            for name in ns.values():
                run("ip", "netns", "add", name); created.append(name)
            for k in ns: ip(k, "link", "set", "lo", "up")
            ip("r", "link", "add", wg_device, "type", "veth", "peer", "name", "wgc", "netns", ns["wg"])
            ip("r", "link", "add", "rl", "type", "veth", "peer", "name", "lc", "netns", ns["lan"])
            ip("r", "link", "add", "rt", "type", "veth", "peer", "name", "tc", "netns", ns["t"])
            ip("r", "link", "add", lan_device, "type", "bridge")
            for port in ("rl", "rt"): ip("r", "link", "set", port, "master", lan_device)
            for k, dev, addr in [("r",wg_device,f"{profile['wg_router']}/{profile['wg_bits']}"),
                    ("r",lan_device,f"{profile['lan_router']}/{profile['lan_bits']}"),
                    ("wg","wgc",f"{profile['wg_client']}/{int(env.wg.bits)}"),
                    ("lan","lc",f"{profile['lan_client']}/{profile['lan_bits']}"),
                    ("t","tc",f"{config['target_ip']}/{profile['lan_bits']}")]:
                ip(k,"addr","add",addr,"dev",dev); ip(k,"link","set",dev,"up")
            for port in ("rl", "rt"): ip("r","link","set",port,"up")
            for addr in (profile['target_next'],profile['other_target']): ip("t","addr","add",f"{addr}/{profile['lan_bits']}","dev","tc")
            ip("wg","addr","add","192.0.2.2/32","dev","wgc")
            if profile['wg_bits']==32: ip('r','route','add',profile['wg_client']+'/32','dev',wg_device)
            ip("wg","route","add",config['virtual_ip']+'/32',"via",profile['wg_router'])
            ip("wg","route","add",env.lan.cidr,"via",profile['wg_router'])
            ip("lan","route","add",config['virtual_ip']+'/32',"via",profile['lan_router'])
            ip('wg','route','add',second_vip+'/32','via',profile['wg_router'])
            ip('lan','route','add',second_vip+'/32','via',profile['lan_router'])
            inside("r","sysctl","-qw","net.ipv4.ip_forward=1")
            g = e.generate(to_lua(lua,config),env); install(g,True)
            unrelated = directory / "unrelated.nft"
            unrelated.write_text('''table inet unrelated {
    chain sentinel {
        type filter hook forward priority -20; policy accept;
        counter comment "unrelated"
    }
}
''', encoding='utf-8')
            nft("-f",str(unrelated)); sentinel = stable_ruleset()
            server = subprocess.Popen(["ip","netns","exec",ns["t"],sys.executable,"-u","-c",SERVER,json.dumps([config['target_ip'],profile['target_next'],profile['other_target']])], stdout=subprocess.DEVNULL)
            time.sleep(0.4)
            for k in ("wg","lan"):
                for protocol in ("tcp","udp"): client(k,protocol,config['target_ip'])
            client("wg","tcp",None,dst=profile['other_target'])
            client("wg","tcp",None,source="192.0.2.2")
            print("PASS: WG ingress, LAN hairpin, TCP/UDP, unchanged destination ports, unrelated LAN denied")
            group_rows=[{'id':'main','config':config},{'id':'device2','config':config | {'virtual_ip':second_vip,'target_ip':profile['target_next']}}]
            group_env=to_lua(lua,{'main':lua_to_py(env),'device2':lua_to_py(env)})
            multiple=e.generate_mappings(to_lua(lua,group_rows),group_env); install(multiple)
            for k in ('wg','lan'):
                for protocol in ('tcp','udp'):
                    client(k,protocol,config['target_ip'])
                    client(k,protocol,profile['target_next'],dst=second_vip)
            group_rows[0]['config']=config | {'enabled':'0'}
            partial=e.generate_mappings(to_lua(lua,group_rows),group_env); install(partial)
            client('wg','tcp',None)
            client('wg','tcp',profile['target_next'],dst=second_vip)
            install(g)
            print('PASS: two simultaneous virtual IPs select different target IPs; disabling one preserves the other')
            changed=e.generate(to_lua(lua,config | {"target_ip":profile['target_next']}),env)
            for _ in range(3): install(changed)
            for k in ("wg","lan"):
                for protocol in ("tcp","udp"): client(k,protocol,profile['target_next'])
            print("PASS: target change and idempotent scoped chain replacement")
            bad=directory/"bad.nft"
            bad.write_text(e.batch(g)+'add rule inet fw4 nonexistent_chain accept\n', encoding='utf-8')
            assert nft("-c","-f",str(bad),check=False).returncode != 0
            assert nft("-f",str(bad),check=False).returncode != 0
            verify(changed)
            print("PASS: rejected nft transaction leaves active generation intact")
            disabled=e.generate(to_lua(lua,config | {"enabled":"0"}),to_lua(lua,{})); install(disabled)
            client("wg","tcp",None); client("lan","tcp",None)
            install(g); client("wg","tcp",config['target_ip'])
            assert stable_ruleset()==sentinel
            print("PASS: disable, re-enable, rollback and unrelated table preservation")
        finally:
            if server:
                server.terminate()
                try: server.wait(timeout=3)
                except subprocess.TimeoutExpired: server.kill(); server.wait()
            for name in reversed(created): run("ip","netns","del",name,check=False)


if __name__ == "__main__": main()
