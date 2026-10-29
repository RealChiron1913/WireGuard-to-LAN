import copy
import json
import pytest
from conftest import to_lua,lua_to_py,ROOT
from test_engine import engine,CONFIG
from test_backend import Platform,BASE
from test_legacy import old_mapping


def rows():
    return [{'id':'main','config':CONFIG.copy()},
            {'id':'device2','config':CONFIG | {'virtual_ip':'10.66.66.7','target_ip':'192.168.31.50'}}]


def test_multiple_mappings_generate_distinct_scoped_rules(engine):
    lua,e,env=engine
    group=e.generate_mappings(to_lua(lua,rows()),to_lua(lua,{'main':lua_to_py(env),'device2':lua_to_py(env)}))
    assert len(group.rules.dnat)==len(group.rules.snat)==len(group.rules.forward)==8
    batch=e.batch(group)
    assert batch.count('flush chain')==3
    assert 'ip daddr 10.66.66.6 counter dnat ip to 192.168.31.39' in batch
    assert 'ip daddr 10.66.66.7 counter dnat ip to 192.168.31.50' in batch
    assert len(set(rule['comment'] for stage in ('dnat','snat','forward') for rule in lua_to_py(group.rules[stage])))==24
    text=e.config_text_mappings(to_lua(lua,rows()))
    assert "config mapping 'main'" in text and "config mapping 'device2'" in text


def test_duplicate_enabled_virtual_ip_rejected_before_changes(engine):
    lua,e,_=engine
    values=rows(); values[1]['config']['virtual_ip']='10.66.66.6'
    with pytest.raises(Exception,match='虚拟 IP'): e.validate_mappings(to_lua(lua,values))
    values[1]['config']['enabled']='0'
    assert len(e.validate_mappings(to_lua(lua,values)))==2


def test_group_apply_commit_reload_and_rollback_are_atomic():
    p=Platform(); assert p.setup()['ok']
    original=p.current_id()
    result=p.invoke('apply_all',{'mappings_json':json.dumps(rows())})
    assert result['ok'],result
    assert len(p.get_configurations())==1
    assert len(p.kernel['wgnat6_dnat']['nftables'])==9
    assert p.invoke('confirm',{'token':result['token']})['ok']
    assert len(p.get_configurations())==2
    assert p.invoke('verify')['ok']
    assert p.invoke('boot',cli=True)['ok']
    assert len(p.get_configurations())==2
    rollback=p.invoke('rollback'); assert rollback['pending']
    assert p.invoke('confirm',{'token':rollback['token']})['ok']
    assert len(p.get_configurations())==1
    assert p.files[BASE+'/previous']!=original


def test_disabling_and_removing_one_mapping_keeps_the_other():
    p=Platform(); p.setup()
    result=p.invoke('apply_all',{'mappings_json':json.dumps(rows())}); p.invoke('confirm',{'token':result['token']})
    changed=rows(); changed[1]['config']['enabled']='0'
    result=p.invoke('apply_all',{'mappings_json':json.dumps(changed)})
    assert result['ok'] and len(p.kernel['wgnat6_dnat']['nftables'])==5
    p.invoke('confirm',{'token':result['token']})
    result=p.invoke('apply_all',{'mappings_json':json.dumps([rows()[1]])})
    assert result['ok']; p.invoke('confirm',{'token':result['token']})
    assert p.get_configurations()[0]['.name']=='device2'
    assert p.get_config()['virtual_ip']=='10.66.66.7'


def test_any_invalid_row_keeps_the_entire_last_good_group():
    p=Platform(); p.setup(); saved=p.current_id(); kernel=copy.deepcopy(p.kernel)
    values=rows(); values[1]['config']['target_ip']='192.168.31.10'
    result=p.invoke('apply_all',{'mappings_json':json.dumps(values)})
    assert not result['ok'] and p.current_id()==saved and p.kernel==kernel
    assert BASE+'/pending.json' not in p.files


def test_first_multimapping_migration_and_confirmation():
    p=Platform(); p.files['/etc/config/wgnat6']=(ROOT/'root/etc/config/wgnat6').read_text(); old_mapping(p)
    refused=p.invoke('initialize_all',{'mappings_json':json.dumps(rows()),'migrate':'0'})
    assert not refused['ok'] and '勾选' in refused['error'] and '未知' not in refused['error']
    result=p.invoke('initialize_all',{'mappings_json':json.dumps(rows()),'migrate':'1'})
    assert result['queued']; p.invoke('initialize-worker',cli=True)
    status=p.invoke('status'); assert status['pending'] and len(status['active_mappings'])==2
    assert p.invoke('confirm',{'token':status['pending']['token']})['ok']
    assert len(p.get_configurations())==2


def test_multimapping_timeout_and_reinstall_restore_whole_group():
    p=Platform(); p.setup(); p.invoke('boot',cli=True)
    result=p.invoke('apply_all',{'mappings_json':json.dumps(rows())}); p.invoke('confirm',{'token':result['token']})
    result=p.invoke('apply_all',{'mappings_json':json.dumps([rows()[1]])})
    assert result['pending']; p.files['/proc/uptime']='191.0 90.0'; assert p.invoke('recover',cli=True)['ok']
    assert len(p.get_configurations())==2
    p.invoke('detach',cli=True); p.files['/etc/config/wgnat6']=(ROOT/'root/etc/config/wgnat6').read_text()
    assert p.invoke('boot',cli=True)['ok']
    assert len(p.get_configurations())==2


@pytest.mark.parametrize('values',[[],[{'id':'bad;name','config':CONFIG}],rows()+[rows()[1]]])
def test_malformed_group_rejected(engine,values):
    lua,e,_=engine
    with pytest.raises(Exception): e.validate_mappings(to_lua(lua,values))


@pytest.mark.parametrize('name',['settings','__proto__','constructor','hasOwnProperty'])
def test_reserved_frontend_section_names_are_rejected(engine,name):
    lua,e,_=engine
    with pytest.raises(Exception): e.validate_mappings(to_lua(lua,[{'id':name,'config':CONFIG}]))


def test_multi_apply_reads_shared_network_state_once():
    p=Platform(); p.setup(); p.calls.clear()
    result=p.invoke('apply_all',{'mappings_json':json.dumps(rows())})
    assert result['ok'],result
    assert p.calls.count(('/sbin/ip',['-j','-4','address','show']))==1
    assert p.calls.count(('/usr/sbin/nft',['-j','list','ruleset']))==1


def test_known_forward_without_migration_flag_gets_a_specific_prompt():
    p=Platform(); old_mapping(p)
    result=p.invoke('initialize',CONFIG | {'migrate':'0'})
    assert not result['ok'] and '勾选' in result['error'] and '未知' not in result['error']
    assert '/var/run/wgnat6/initialize.json' not in p.files


def test_true_unknown_section_is_still_preserved():
    p=Platform(); old_mapping(p)
    p.sections['wgnat6_forward']['path']='/etc/somebody-else.nft'
    original=copy.deepcopy(p.sections)
    result=p.invoke('initialize',CONFIG | {'migrate':'1'})
    assert not result['ok'] and '类型或路径' in result['error']
    assert p.sections==original
