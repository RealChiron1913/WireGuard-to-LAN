import copy
import json
from conftest import ROOT
from test_backend import Platform


def test_inventory_uses_live_devices_and_separates_wireguard():
    p=Platform()
    p.device_links=[
        {'ifname':'lo','flags':['UP','LOOPBACK']},
        {'ifname':'vpn','flags':['UP'],'operstate':'UNKNOWN'},
        {'ifname':'br-lan','flags':['UP'],'operstate':'UP'},
        {'ifname':'eth1.40','flags':[],'operstate':'DOWN'},
        {'ifname':'wg-extra','flags':[]},
    ]
    p.wg_interfaces='vpn wg-extra\n'
    original=copy.deepcopy(p.files)
    r=p.invoke('interfaces')
    assert r['ok'],r
    assert [d['name'] for d in r['lan']]==['br-lan','eth1.40']
    assert [d['name'] for d in r['wireguard']]==['vpn','wg-extra']
    assert r['lan'][0]['ipv4']==['192.168.31.10/24']
    assert r['wireguard'][0]['up'] and not r['wireguard'][1]['up']
    assert p.files==original and not p.kernel
    assert ('/usr/bin/wg',['show','interfaces']) in p.calls
    assert all('private-key' not in args and 'dump' not in args for _,args in p.calls)


def test_discovery_lists_addressless_interfaces_and_deduplicates_names():
    p=Platform()
    p.interfaces=[]
    p.device_links=[{'ifname':'wg0'},{'ifname':'br-office'},{'ifname':'br-office'}]
    p.wg_interfaces='wg0'
    r=p.invoke('interfaces')
    assert r['ok'] and len(r['lan'])==len(r['wireguard'])==1
    assert len(r['wireguard'][0]['ipv4'])==0


def test_only_wireguard_names_present_in_the_kernel_link_inventory_are_offered():
    p=Platform()
    p.device_links=[{'ifname':'br-lan'},{'ifname':'vpn'}]
    p.wg_interfaces='vpn removed-wg'
    r=p.invoke('interfaces')
    assert [d['name'] for d in r['wireguard']]==['vpn']


def test_discovery_failure_is_reported_without_mutating_saved_state():
    p=Platform(); before=copy.deepcopy(p.files)
    original=p.run
    def fail(path,args):
        if path=='/usr/bin/wg': return False,'','wireguard tool unavailable'
        return original(path,args)
    p.run=fail
    r=p.invoke('interfaces')
    assert not r['ok'] and 'unavailable' in r['error']
    assert p.files==before


def test_interface_rpc_has_only_application_read_scope():
    acl=json.loads((ROOT/'root/usr/share/rpcd/acl.d/luci-app-wgnat6.json').read_text(encoding='utf-8'))['luci-app-wgnat6']
    assert 'interfaces' in acl['read']['ubus']['wgnat6']
    assert 'file' not in acl['read']['ubus'] and 'network' not in acl['read']


def test_interface_discovery_never_applies_firewall_recovery():
    from test_engine import CONFIG
    p=Platform(); assert p.setup()['ok']
    assert p.invoke('apply',CONFIG)['ok']
    p.files['/proc/uptime']='191.0 90.0'
    before=copy.deepcopy(p.files); p.calls.clear()
    assert p.invoke('interfaces')['ok']
    assert p.files==before
    assert all(path not in ('/usr/sbin/nft','/sbin/fw4') for path,_ in p.calls)
