import copy
import json
import pytest
from conftest import ROOT,to_lua,lua_to_py
from test_engine import engine,CONFIG
from test_backend import Platform,BASE

FILES={
 'dnat':'iifname { "vpn", "br-lan" } ip daddr 10.66.66.6 meta l4proto { tcp, udp } counter dnat ip to 192.168.31.39 comment "wgnat6-dnat"\n',
 'snat':'oifname "br-lan" ip saddr { 10.66.66.0/24, 192.168.31.0/24 } ip daddr 192.168.31.39 ct original daddr 10.66.66.6 meta l4proto { tcp, udp } counter masquerade comment "wgnat6-snat"\n',
 'forward':'iifname { "vpn", "br-lan" } oifname "br-lan" ip saddr { 10.66.66.0/24, 192.168.31.0/24 } ip daddr 192.168.31.39 ct status dnat meta l4proto { tcp, udp } counter accept comment "wgnat6-forward"\n'
}

def parser(engine):
    lua,e,_=engine; lua.globals().package.loaded.engine=e
    return lua,lua.execute((ROOT/'root/usr/lib/wgnat6/legacy.lua').read_text(encoding='utf-8'))

def old_mapping(p):
    for stage in ('dnat','snat','forward'):
        name='wgnat6_'+stage
        p.sections[name]={'.name':name,'.type':'include','type':'nftables','path':f'/etc/wgnat6/{stage}.nft','position':'chain-pre','chain':{'dnat':'dstnat','snat':'srcnat','forward':'forward'}[stage]}
        p.files[f'/etc/wgnat6/{stage}.nft']=FILES[stage]

def test_recognizes_the_users_exact_three_snippets(engine):
    lua,l=parser(engine); c=lua_to_py(l.parse(to_lua(lua,FILES)))
    assert all(c[k]==v for k,v in CONFIG.items())
    assert c['lan_subnet']=='192.168.31.0/24' and c['wireguard_subnet']=='10.66.66.0/24'

@pytest.mark.parametrize('prefix,replace',[('tcp','tcp'),('udp','udp')])
def test_protocol_selection_is_preserved(engine,prefix,replace):
    lua,l=parser(engine)
    files={k:v.replace('{ tcp, udp }',replace) for k,v in FILES.items()}
    assert l.parse(to_lua(lua,files)).protocol==prefix

def test_different_addresses_and_device_names(engine):
    lua,l=parser(engine)
    files={k:v.replace('10.66.66.','172.27.1.').replace('192.168.31.','10.20.8.').replace('vpn','wg-office').replace('br-lan','br-office') for k,v in FILES.items()}
    c=l.parse(to_lua(lua,files))
    assert c.virtual_ip=='172.27.1.6' and c.target_ip=='10.20.8.39'
    assert c.wireguard_interface=='wg-office' and c.lan_interface=='br-office'

@pytest.mark.parametrize('change',[
 lambda f:f.update(snat=f['snat'].replace('192.168.31.39','192.168.31.50')),
 lambda f:f.update(dnat=f['dnat'].replace('192.168.31.39','192.168.31.39:3389')),
 lambda f:f.update(dnat=f['dnat'].replace('counter','tcp dport 3389 counter')),
 lambda f:f.update(dnat=f['dnat']+f['dnat'].replace('192.168.31.39','192.168.31.50')),
 lambda f:f.update(dnat='include "/etc/config/network"\n'),
 lambda f:f.update(forward=f['forward'].replace('"vpn",','"vpn", "wg-other",')),
])
def test_ambiguous_or_restricted_rules_are_not_silently_expanded(engine,change):
    lua,l=parser(engine); files=FILES.copy(); change(files)
    with pytest.raises(Exception): l.parse(to_lua(lua,files))

def test_comments_do_not_create_false_dnat_matches(engine):
    lua,l=parser(engine)
    files={k:'# dnat ip to 192.168.1.2\n'+v for k,v in FILES.items()}
    files['dnat']=files['dnat'].replace('"wgnat6-dnat"','"dnat ip to 192.168.1.3 # comment"')
    assert l.parse(to_lua(lua,files)).target_ip=='192.168.31.39'

def test_status_prefills_legacy_without_persisting_or_claiming_kernel_success():
    p=Platform(); p.files['/etc/config/wgnat6']=(ROOT/'root/etc/config/wgnat6').read_text(); old_mapping(p)
    before=copy.deepcopy(p.files); sections=copy.deepcopy(p.sections)
    r=p.invoke('status')
    assert r['ok'] and r['legacy']['recognized'] and r['needs_migration']
    assert r['form_config']['target_ip']=='192.168.31.39' and r['form_config']['wireguard_interface']=='vpn'
    assert r['form_source']=='legacy_nft_files' and r['config']['virtual_ip']==''
    assert not r['runtime_ok'] and not r['initialized']
    assert p.files==before and p.sections==sections and not p.kernel

def test_explicit_app_uci_always_wins_over_legacy_files():
    p=Platform(); old_mapping(p)
    p.files['/etc/config/wgnat6']=p.files['/etc/config/wgnat6'].replace('192.168.31.39','192.168.31.50')
    r=p.invoke('status')
    assert r['form_source']=='uci' and r['form_config']['target_ip']=='192.168.31.50'
    assert r['legacy']['config']['target_ip']=='192.168.31.39'

def test_boot_creates_persistent_identity_and_reinstall_keeps_saved_config():
    p=Platform(); assert p.setup()['ok']; assert p.invoke('boot',cli=True)['ok']
    assert p.files[BASE+'/package-id']=='luci-app-wgnat6-state-v1\n'
    assert p.invoke('detach',cli=True)['ok']
    preserved=p.files['/etc/config/wgnat6']
    assert p.invoke('boot',cli=True)['ok']
    assert p.files['/etc/config/wgnat6']==preserved
    r=p.invoke('status'); assert r['form_config']['target_ip']=='192.168.31.39' and not r['initialized']

def test_missing_uci_after_reinstall_recovers_only_confirmed_snapshot():
    p=Platform(); assert p.setup()['ok']; p.invoke('boot',cli=True); p.invoke('detach',cli=True)
    p.files['/etc/config/wgnat6']=(ROOT/'root/etc/config/wgnat6').read_text()
    p.calls.clear(); assert p.invoke('boot',cli=True)['ok']
    assert p.get_config()['target_ip']=='192.168.31.39' and not p.calls
    assert BASE+'/owned.json' not in p.files

def test_reinstall_does_not_restore_an_unconfirmed_candidate():
    p=Platform(); assert p.setup()['ok']; p.invoke('boot',cli=True); p.invoke('detach',cli=True)
    p.files[BASE+'/last-success.json']=json.dumps({'generation':'0'*32})
    p.files['/etc/config/wgnat6']=(ROOT/'root/etc/config/wgnat6').read_text()
    assert p.invoke('boot',cli=True)['ok']
    assert 'target_ip' not in p.get_config()

def test_bad_state_identity_is_not_silently_adopted():
    p=Platform(); p.files[BASE+'/package-id']='different application'
    before=copy.deepcopy(p.files)
    assert not p.invoke('boot',cli=True)['ok']
    assert p.files==before

def test_reinstall_cancels_stale_queued_initialization():
    p=Platform()
    p.files['/var/run/wgnat6/initialize.json']=json.dumps({'id':'old','state':'queued','config':CONFIG})
    assert p.invoke('boot',cli=True)['ok']
    assert json.loads(p.files['/var/run/wgnat6/initialize.json'])['state']=='cancelled'
    assert BASE+'/owned.json' not in p.files
