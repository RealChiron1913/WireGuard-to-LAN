import copy
import json
import pytest
from conftest import lua_to_py,to_lua
from test_engine import CONFIG,engine
from test_backend import Platform


@pytest.mark.parametrize('prefix',['10.66.66.0/24','10.0.0.0/8','0.0.0.0/0'])
def test_aggregate_routes_are_not_host_occupancy(engine,prefix):
    lua,e,env=engine
    env.peer_ips=to_lua(lua,[prefix,'10.66.66.2/32','10.66.66.4/32','10.66.66.5/32'])
    assert e.validate(to_lua(lua,CONFIG),env).virtual_ip=='10.66.66.6'
    overlaps=e.peer_overlaps(env.peer_ips,'10.66.66.6')
    assert len(overlaps.exact)==0 and lua_to_py(overlaps.covering)==[prefix]


@pytest.mark.parametrize('prefix',['10.66.66.6/32','10.66.66.6'])
def test_explicit_peer_host_remains_a_hard_conflict(engine,prefix):
    lua,e,env=engine; env.peer_ips=to_lua(lua,[prefix,'10.66.66.0/24'])
    with pytest.raises(Exception,match='10.66.66.6/32'): e.validate(to_lua(lua,CONFIG),env)


def user_peers(p):
    # Exact runtime data provided by the user, with only dummy public identifiers.
    p.peer='10.66.66.2/32\nvpn peer-b 10.66.66.0/24\nvpn peer-c 10.66.66.4/32\nvpn peer-d 10.66.66.5/32'


def test_interface_subnet_is_not_reported_as_aggregate_warning():
    p=Platform(); p.setup(); user_peers(p)
    before_network=copy.deepcopy(getattr(p,'networks',[]))
    result=p.invoke('apply',CONFIG)
    assert result['ok'] and result['pending'],result
    assert '10.66.66.0/24' not in result['warning']
    assert not p.invoke('status')['warnings']
    assert p.invoke('confirm',{'token':result['token']})['ok']
    assert not p.invoke('verify')['warnings']
    assert getattr(p,'networks',[])==before_network
    assert all(not (path=='/usr/bin/wg' and args[0] in ('set','setconf','syncconf')) for path,args in p.calls)


def test_same_network_with_host_bits_is_suppressed_in_uci_and_runtime():
    p=Platform(); p.setup(); user_peers(p)
    p.networks=[{'.type':'wireguard_vpn','allowed_ips':['10.66.66.3/24','10.66.66.0/24']}]
    result=p.invoke('apply',CONFIG)
    assert result['ok'] and not result['warnings']


def test_other_aggregate_still_warns_and_uses_old_snapshot_fallback():
    p=Platform(); p.setup(); p.peer='10.66.66.0/24\nvpn peer-b 10.0.0.0/8'
    result=p.invoke('apply',CONFIG)
    assert result['ok'] and '10.0.0.0/8' in result['warnings'][0]
    assert '10.66.66.0/24' not in result['warnings'][0]
    generation=p.generation(); generation['environment'].pop('wg_subnets')
    p.files['/etc/wgnat6/luci/gens/' + p.current_id() + '/generation.json'] = json.dumps(generation)
    assert '10.0.0.0/8' in p.invoke('status')['warnings'][0]


def test_saved_explicit_host_reports_the_saved_source_and_preserves_all_rules():
    p=Platform(); p.setup(); user_peers(p)
    p.networks=[{'.type':'wireguard_vpn','allowed_ips':'10.66.66.2/32, 10.66.66.6/32'}]
    before=p.current_id(); kernel=copy.deepcopy(p.kernel)
    result=p.invoke('apply',CONFIG)
    assert not result['ok'] and '10.66.66.6/32' in result['error'] and 'UCI' in result['error']
    assert p.current_id()==before and p.kernel==kernel


def test_real_runtime_host_does_not_get_bypassed_by_a_covering_route():
    p=Platform(); p.setup(); p.peer='10.66.66.6/32\nvpn peer-b 10.66.66.0/24'
    before=p.current_id()
    result=p.invoke('apply',CONFIG)
    assert not result['ok'] and '运行配置' in result['error'] and p.current_id()==before


def test_aggregate_routes_work_for_two_distinct_virtual_addresses():
    p=Platform(); p.setup(); user_peers(p)
    rows=[{'id':'main','config':CONFIG},{'id':'second','config':CONFIG|{'virtual_ip':'10.66.66.7','target_ip':'192.168.31.50'}}]
    result=p.invoke('apply_all',{'mappings_json':json.dumps(rows)})
    assert result['ok'] and not result['warnings'],result


def test_users_legacy_mapping_initializes_without_changing_any_peer():
    from test_legacy import old_mapping
    from conftest import ROOT
    p=Platform(); p.files['/etc/config/wgnat6']=(ROOT/'root/etc/config/wgnat6').read_text()
    old_mapping(p); user_peers(p)
    detected=p.invoke('status')['form_config']
    result=p.invoke('initialize_all',{'mappings_json':json.dumps([{'id':'main','config':detected}]),'migrate':'1'})
    assert result['queued'],result
    assert p.invoke('initialize-worker',cli=True)['ok']
    status=p.invoke('status')
    assert status['pending'] and status['runtime_ok'],status
    assert status['initialization']['state']=='await_confirm'
    assert not status['warnings']
    assert p.invoke('confirm',{'token':status['pending']['token']})['ok']
    assert p.get_config()['virtual_ip']=='10.66.66.6'
    assert all(not(path=='/usr/bin/wg' and args[0] in ('set','setconf','syncconf')) for path,args in p.calls)
