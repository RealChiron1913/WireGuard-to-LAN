import re

import pytest
from conftest import ROOT, lua_to_py, to_lua
from test_engine import CONFIG, engine
from test_backend import Platform


@pytest.mark.parametrize('lan,lanbits,router,target,wg,wgbits,wgrouter,vip,ldev,wdev', [
    ('192.168.1.0',24,'192.168.1.1','192.168.1.100','10.8.0.0',24,'10.8.0.1','10.8.0.99','br-lan','wg0'),
    ('10.20.0.0',16,'10.20.0.1','10.20.8.39','172.27.0.0',20,'172.27.0.1','172.27.1.6','br-office','wg-office'),
    ('172.30.40.0',28,'172.30.40.1','172.30.40.9','10.200.40.0',24,'10.200.40.1','10.200.40.6','eth1.40','tun-wg'),
    ('100.64.0.0',10,'100.64.0.1','100.65.0.9','192.168.250.0',24,'192.168.250.1','192.168.250.6','br-cgnat','vpn2'),
])
def test_arbitrary_networks_and_device_names(engine,lan,lanbits,router,target,wg,wgbits,wgrouter,vip,ldev,wdev):
    lua,e,_=engine
    c=CONFIG | dict(virtual_ip=vip,target_ip=target,lan_interface=ldev,wireguard_interface=wdev)
    env=to_lua(lua,dict(local_ips=[router,wgrouter],peer_ips=[],route_device=ldev))
    env.lan,env.wg=e.subnet(lan,lanbits),e.subnet(wg,wgbits)
    g=e.generate(to_lua(lua,c),env)
    batch=e.batch(g)
    assert f'dnat ip to {target}' in batch and f'ct original ip daddr {vip}' in batch
    assert f'iifname "{wdev}" ip saddr {wg}/{wgbits}' in batch
    assert f'iifname "{ldev}" ip saddr {lan}/{lanbits}' in batch
    for original in ['10.66.66.6','192.168.31.39','"vpn"','"br-lan"' if ldev!='br-lan' else '__absent__']:
        assert original not in batch


def test_safe_unconfigured_defaults(engine):
    lua,e,_=engine
    text=(ROOT/'root/etc/config/wgnat6').read_text()
    c=dict(re.findall(r"option\s+(\w+)\s+'([^']*)'",text))
    assert c['enabled']=='0' and c['target_ip']==c['virtual_ip']==c['wireguard_interface']==''
    assert len(e.generate(to_lua(lua,c),to_lua(lua,{})).rules.dnat)==0
    c['enabled']='1'
    with pytest.raises(Exception): e.validate(to_lua(lua,c))


@pytest.mark.parametrize('value',['10.1.2.3/24','10.1.2.0/0','10.1.2.0/33','10.1.2.0/024','10.1.2.0/24\n','10.1.2.0/24;reboot'])
def test_strict_network_cidr(engine,value):
    _,e,_=engine
    with pytest.raises(Exception): e.parse_subnet(value)


def test_multi_address_lan_uses_most_specific_scope(engine):
    lua,e,_=engine
    addresses=to_lua(lua,[lua_to_py(e.subnet('10.0.0.1',8)),lua_to_py(e.subnet('10.20.1.1',24)),lua_to_py(e.subnet('192.168.1.1',24))])
    assert e.select_subnet(addresses,'','10.20.1.39','lan').cidr=='10.20.1.0/24'
    assert e.select_subnet(addresses,'10.20.1.32/27','10.20.1.39','lan').cidr=='10.20.1.32/27'
    with pytest.raises(Exception): e.select_subnet(addresses,'10.20.2.0/24','10.20.1.39','lan')


def test_wireguard_32_requires_explicit_source_prefix(engine):
    lua,e,_=engine
    addresses=to_lua(lua,[lua_to_py(e.subnet('10.99.0.1',32))])
    with pytest.raises(Exception): e.select_subnet(addresses,'','10.99.0.6','wg')
    assert e.select_subnet(addresses,'10.99.0.0/24','10.99.0.6','wg').cidr=='10.99.0.0/24'
    assert e.select_subnet(to_lua(lua,[]),'10.99.0.0/24','172.22.15.6','wg').cidr=='10.99.0.0/24'


def test_separate_virtual_network_and_single_peer_source(engine):
    lua,e,_=engine
    c=CONFIG | dict(virtual_ip='172.22.15.6',wireguard_subnet='10.99.0.2/32')
    env=to_lua(lua,dict(local_ips=['192.168.31.10','10.99.0.1'],peer_ips=['10.99.0.2/32'],route_device='br-lan'))
    env.lan,env.wg=e.subnet('192.168.31.10',24),e.subnet('10.99.0.2',32)
    g=e.generate(to_lua(lua,c),env)
    assert 'ip saddr 10.99.0.2/32' in e.batch(g)
    assert g.rules.dnat[1].expr[2].match.right=='10.99.0.2'


def test_virtual_must_not_overlap_another_lan_prefix(engine):
    lua,e,env=engine
    env.lan_subnets=to_lua(lua,[lua_to_py(e.subnet('10.66.66.1',24))])
    with pytest.raises(Exception): e.validate(to_lua(lua,CONFIG),env)


def test_rfc3021_hosts_on_31_lan(engine):
    lua,e,_=engine
    c=CONFIG | dict(target_ip='192.0.2.11')
    env=to_lua(lua,dict(local_ips=['192.0.2.10','10.66.66.1'],peer_ips=['10.66.66.2/32'],route_device='br-lan'))
    env.lan,env.wg=e.subnet('192.0.2.10',31),e.subnet('10.66.66.1',24)
    assert e.generate(to_lua(lua,c),env).config.target_ip=='192.0.2.11'


def test_backend_custom_interfaces_multi_address_and_32_wireguard():
    p=Platform()
    c=CONFIG | dict(target_ip='10.20.8.39',virtual_ip='172.22.15.6',lan_interface='br-office',wireguard_interface='wg0',wireguard_subnet='10.99.0.0/24')
    p.files['/etc/config/wgnat6']="config mapping 'main'\n"+''.join(f"\toption {k} '{v}'\n" for k,v in c.items())
    p.interfaces=[
        dict(ifname='br-office',addr_info=[dict(family='inet',local='10.20.0.1',prefixlen=16),dict(family='inet',local='192.168.1.1',prefixlen=24)]),
        dict(ifname='wg0',addr_info=[dict(family='inet',local='10.99.0.1',prefixlen=32)]),
    ]
    p.wg_device='wg0'; p.peer='10.99.0.2/32'; p.route_dev='br-office'
    assert p.setup()['ok']
    assert p.generation()['environment']['lan']['cidr']=='10.20.0.0/16'
    r=p.invoke('apply',c | dict(target_ip='10.20.8.50'))
    assert r['ok'],r
    assert p.invoke('confirm',dict(token=r['token']))['ok']
    assert p.get_config()['target_ip']=='10.20.8.50'


def test_preflight_is_capability_based():
    p=Platform()
    p.files['/etc/openwrt_release']="DISTRIB_ID='CommunityFirmware'\nDISTRIB_ARCH='aarch64_generic'\n"
    r=p.invoke('preflight',cli=True)
    assert r['ok'] and r['architecture_independent'] and 'CommunityFirmware' in r['release']
    p.files['/www/luci-static/resources/form.js']='legacy form'
    assert not p.invoke('preflight',cli=True)['ok']


def test_legacy_six_field_snapshot_survives_upgrade_boot():
    p=Platform(); assert p.setup()['ok']
    g=p.generation(); g['config'].pop('lan_subnet',None); g['config'].pop('wireguard_subnet',None)
    import json
    p.files[f'{"/etc/wgnat6/luci"}/gens/{p.current_id()}/generation.json']=json.dumps(g)
    assert p.invoke('boot',cli=True)['ok']
    assert not any('未通过应用事务' in message for message in p.logs)


def test_unconfigured_install_then_web_apply():
    p=Platform()
    p.files['/etc/config/wgnat6']=(ROOT/'root/etc/config/wgnat6').read_text()
    assert p.setup()['ok']
    assert p.generation()['config']['enabled']=='0'
    r=p.invoke('apply',CONFIG)
    assert r['ok'],r
    assert p.get_config()['enabled']=='0'
    assert p.invoke('confirm',dict(token=r['token']))['ok']
    assert p.get_config()['enabled']=='1'


def test_explicit_wireguard_source_without_device_ipv4():
    p=Platform()
    p.interfaces[1]['addr_info']=[]
    c=CONFIG | dict(wireguard_subnet='10.66.66.0/24')
    p.files['/etc/config/wgnat6']="config mapping 'main'\n"+''.join(f"\toption {k} '{v}'\n" for k,v in c.items())
    assert p.setup()['ok']


def test_other_wireguard_default_route_is_not_a_peer_conflict():
    p=Platform()
    p.peer='10.66.66.2/32\nwg-exit public-peer 0.0.0.0/0'
    assert p.setup()['ok']


@pytest.mark.parametrize('key',['lan_subnet','wireguard_subnet'])
def test_optional_cidr_cannot_be_boolean(engine,key):
    lua,e,_=engine
    with pytest.raises(Exception): e.validate(to_lua(lua,CONFIG | {key:False}))
