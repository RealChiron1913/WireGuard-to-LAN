import copy
import json
import pytest

from conftest import ROOT
from test_backend import Platform, BASE
from test_engine import CONFIG, engine


def fresh():
    p=Platform()
    p.files['/etc/config/wgnat6']=(ROOT/'root/etc/config/wgnat6').read_text()
    return p


def test_real_uci_omits_empty_values_but_status_is_editable():
    p=fresh()
    assert 'virtual_ip' not in p.get_config()
    before=copy.deepcopy(p.files)
    result=p.invoke('status')
    assert result['ok'],result
    assert not result['initialized']
    assert result['config']['virtual_ip']==result['config']['target_ip']==''
    assert p.files==before  # merely opening the page never overwrites UCI


def test_invalid_enabled_config_does_not_block_the_form():
    p=fresh()
    p.files['/etc/config/wgnat6']="config mapping 'main'\n option enabled '1'\n"
    result=p.invoke('status')
    assert result['ok'] and result['config_error'] and result['config']['virtual_ip']==''


def test_missing_main_section_gets_disabled_editable_defaults():
    p=fresh(); p.files['/etc/config/wgnat6']=''
    r=p.invoke('status')
    assert r['ok'] and r['config']['enabled']=='0'


def queue(p,config=None,migrate='0'):
    r=p.invoke('initialize',(config or CONFIG) | {'migrate':migrate})
    assert r['ok'] and r['queued'],r
    return r


def run_worker(p):
    r=p.invoke('initialize-worker',cli=True)
    assert r['ok'],r
    return p.invoke('status')


def test_web_first_apply_then_explicit_confirm():
    p=fresh(); original=p.files['/etc/config/wgnat6']
    queue(p)
    assert not p.kernel and p.files['/etc/config/wgnat6']==original
    r=run_worker(p)
    assert r['ok'] and r['initialized'] and r['pending']
    assert r['active_config']['target_ip']=='192.168.31.39'
    assert p.files['/etc/config/wgnat6']==original
    assert not p.invoke('confirm',{})['ok']
    assert p.invoke('confirm',{'token':r['pending']['token']})['ok']
    assert p.get_config()['virtual_ip']=='10.66.66.6'
    assert BASE+'/setup-journal.json' not in p.files
    assert p.invoke('status')['initialization']['state']=='done'
    # Future changes use only the existing three-chain transaction.
    p.calls.clear()
    changed=p.invoke('apply',CONFIG | {'target_ip':'192.168.31.50'})
    assert changed['ok'] and changed['pending']
    assert not any(path=='/sbin/fw4' and args==['reload'] for path,args in p.calls)


def test_detach_rejects_unconfirmed_initialization():
    p=fresh()
    queue(p); assert run_worker(p)['pending']
    assert not p.invoke('detach',cli=True)['ok']
    assert BASE+'/setup-journal.json' in p.files


@pytest.mark.parametrize('action',['timeout','rollback','boot'])
def test_initialization_can_restore_the_original_rules_and_config(action):
    p=fresh(); original=p.files['/etc/config/wgnat6']; sections=copy.deepcopy(p.sections)
    queue(p); assert run_worker(p)['pending']
    if action=='boot':
        p.calls.clear(); assert p.invoke('boot',cli=True)['ok']
        assert not p.calls
    else:
        if action=='timeout': p.files['/proc/uptime']='191.0 90.0'
        else: assert p.invoke('rollback')['queued']
        run_worker(p)
        assert not p.kernel
    assert p.files['/etc/config/wgnat6']==original
    assert p.sections==sections and BASE+'/owned.json' not in p.files


def test_initial_migration_is_a_web_checkbox_and_rolls_back_legacy():
    p=fresh()
    for stage in ('dnat','snat','forward'):
        name='wgnat6_'+stage
        p.sections[name]={'.type':'include','.name':name,'type':'nftables','path':f'/etc/wgnat6/{stage}.nft'}
        p.files[f'/etc/wgnat6/{stage}.nft']='legacy '+stage
    original=copy.deepcopy(p.sections)
    assert p.invoke('status')['needs_migration']
    refused=p.invoke('initialize',CONFIG | {'migrate':'0'})
    assert not refused['ok'] and '勾选' in refused['error'] and '未知' not in refused['error']
    assert p.sections==original
    queue(p,migrate='1'); r=run_worker(p)
    assert r['pending']
    assert p.invoke('rollback')['queued']; run_worker(p)
    assert p.sections==original
    assert all(p.files[f'/etc/wgnat6/{stage}.nft']=='legacy '+stage for stage in ('dnat','snat','forward'))


def test_web_candidate_validation_failure_does_not_replace_saved_config():
    p=fresh(); original=p.files['/etc/config/wgnat6']
    assert not p.invoke('initialize',CONFIG | {'virtual_ip':'bad;reboot'})['ok']
    assert p.files['/etc/config/wgnat6']==original and not p.kernel
    queue(p,CONFIG | {'target_ip':'192.168.31.10'})
    assert run_worker(p)['initialization']['state']=='error'
    assert p.files['/etc/config/wgnat6']==original and not p.kernel


def test_async_setup_kernel_verification_failure_restores_original():
    p=fresh(); original=p.files['/etc/config/wgnat6']; sections=copy.deepcopy(p.sections)
    # This fake nft response corrupts the first read after fw4 reload.
    run=p.run
    def fail(path,args):
        values=list(args.values())
        result=run(path,args)
        if path=='/sbin/fw4' and values==['reload'] and p.kernel.get('wgnat6_dnat'):
            p.kernel['wgnat6_dnat']['nftables'].pop()
        return result
    p.run=fail
    queue(p)
    run_worker(p)
    assert p.invoke('status')['initialization']['state']=='error'
    assert p.sections==sections and p.files['/etc/config/wgnat6']==original


def test_no_second_initialize_or_apply_during_pending_initialization():
    p=fresh(); queue(p); run_worker(p)
    assert not p.invoke('initialize',CONFIG)['ok']
    assert not p.invoke('apply',CONFIG)['ok']


def test_empty_disabled_config_can_be_saved_after_setup(engine):
    lua,e,_=engine
    c=e.validate(lua.table_from({'enabled':'0'}))
    assert c.virtual_ip==c.target_ip=='' and c.protocol=='both'
    with pytest.raises(Exception): e.validate(lua.table_from({'enabled':'1'}))


def test_initialize_rpc_is_narrowly_scoped():
    acl=json.loads((ROOT/'root/usr/share/rpcd/acl.d/luci-app-wgnat6.json').read_text(encoding='utf-8'))['luci-app-wgnat6']
    assert 'initialize' in acl['write']['ubus']['wgnat6']
    assert 'initialize' not in acl['read']['ubus']['wgnat6']
    assert 'file' not in acl['write']['ubus']


def test_worker_recovers_interruption_after_firewall_apply():
    p=fresh(); original=p.files['/etc/config/wgnat6']; queue(p); run_worker(p)
    job=json.loads(p.files['/var/run/wgnat6/initialize.json']); job['state']='running'
    p.files['/var/run/wgnat6/initialize.json']=json.dumps(job)
    r=run_worker(p)
    assert r['initialization']['state']=='rolled_back' and not r['initialized']
    assert p.files['/etc/config/wgnat6']==original


def test_confirmed_initialization_not_undone_after_job_status_interruption():
    p=fresh(); queue(p); r=run_worker(p)
    job=p.files['/var/run/wgnat6/initialize.json']
    assert p.invoke('confirm',{'token':r['pending']['token']})['ok']
    p.files['/var/run/wgnat6/initialize.json']=job
    r=run_worker(p)
    assert r['initialization']['state']=='done' and r['initialized']
    assert p.get_config()['virtual_ip']=='10.66.66.6'
