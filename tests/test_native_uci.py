import copy
import json
import re
from conftest import ROOT
from test_backend import Platform,BASE
from test_engine import CONFIG
from test_legacy import old_mapping
from test_peer_prefixes import user_peers


def test_backend_only_uses_exported_native_uci_methods():
    # Contract is the exports in openwrt/uci lua/uci.c, not luci.model.uci helpers.
    exported={'cursor','foreach','get','get_all','set','delete','save','commit','close','revert','reorder'}
    source=(ROOT/'root/usr/lib/wgnat6/main.lua').read_text(encoding='utf-8')
    methods=set(re.findall(r'\b(?:u|fresh|reloaded):([a-z_]+)\(',source))
    assert methods<=exported
    assert ':section(' not in source


def test_preflight_roundtrips_native_uci_only_in_an_isolated_directory():
    p=Platform(); original=copy.deepcopy(p.files); sections=copy.deepcopy(p.sections)
    result=p.invoke('preflight',cli=True)
    assert result['ok'] and result['native_uci_checked'],result
    assert p.files==original and p.sections==sections
    assert not any('/uci-api-' in filename for filename in p.files)
    assert not any(path=='/sbin/fw4' or path=='/usr/sbin/nft' and '-f' in args for path,args in p.calls)


def test_upgrade_recovers_the_actual_missing_section_method_failure():
    p=Platform(); old_mapping(p); user_peers(p)
    p.files['/etc/config/wgnat6']=(ROOT/'root/etc/config/wgnat6').read_text()
    original_sections=copy.deepcopy(p.sections); original_config=p.files['/etc/config/wgnat6']
    request={'mappings_json':json.dumps([{'id':'main','config':CONFIG}]),'migrate':'1'}
    assert p.invoke('initialize_all',request)['queued']
    # Reproduce the old production fault with a native cursor that has NO section().
    p.source_transform=lambda code:code.replace(
        "assert(u:set('firewall',name,s['.type'] or 'include'),",
        "assert(u:section('firewall',s['.type'] or 'include',name,{}),")
    p.invoke('initialize-worker',cli=True)
    job=json.loads(p.files['/var/run/wgnat6/initialize.json'])
    assert job['state']=='recovering' and 'section' in job['error']
    assert BASE+'/setup-journal.json' in p.files
    del p.source_transform
    p.calls.clear()
    assert p.invoke('boot',cli=True)['ok']
    assert p.sections==original_sections and p.files['/etc/config/wgnat6']==original_config
    assert BASE+'/setup-journal.json' not in p.files and BASE+'/owned.json' not in p.files
    assert not p.calls  # boot recovery restores files; it never reloads the live firewall
    assert p.invoke('initialize-worker',cli=True)['ok']
    # The user can now retry the same mapping; no manual deletion or peer edits.
    assert p.invoke('initialize_all',request)['queued']
    assert p.invoke('initialize-worker',cli=True)['ok']
    result=p.invoke('status'); assert result['pending'] and result['runtime_ok'],result
    assert p.invoke('confirm',{'token':result['pending']['token']})['ok']


def test_native_set_replaces_obsolete_options_and_restores_all_original_values():
    p=Platform(); old_mapping(p)
    p.sections['wgnat6_dnat'].update(reload='1',family='ipv4')
    original=copy.deepcopy(p.sections)
    assert p.invoke('setup',cli=True,extra=['--migrate'])['ok']
    s=p.sections['wgnat6_dnat']
    assert s['.type']=='include' and s['type']=='nftables'
    assert 'chain' not in s and 'reload' not in s and 'family' not in s
    assert p.sections['unrelated']==original['unrelated']
    assert p.invoke('detach',cli=True)['ok']
    assert p.sections==original
