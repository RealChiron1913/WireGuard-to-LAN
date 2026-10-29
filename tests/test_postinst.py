"""Execute the real postinst using isolated fake init services, never host procd."""
import os
from pathlib import Path
import re
import subprocess
from conftest import ROOT
from test_preinst import shell


def posix(path):
    value=path.as_posix()
    return '/'+value[0].lower()+value[2:] if os.name=='nt' else value


def invoke(tmp_path,*,running=False,fail='',offline=False):
    init=tmp_path/'etc/init.d'; init.mkdir(parents=True)
    calls=tmp_path/'calls'; calls.write_text('')
    state=tmp_path/'running'
    if running: state.write_text('yes')
    service=init/'wgnat6'
    service.write_text('''#!/bin/sh
echo "$1" >> "$TEST_CALLS"
case "$1" in
  enable) [ "$TEST_FAIL" != enable ] ;;
  running) [ -f "$TEST_RUNNING" ] ;;
  start|restart)
    if [ "$1" = restart ] && [ ! -f "$TEST_RUNNING" ]; then
      echo 'Command failed: ubus call service delete { "name": "wgnat6" } (Not found)' >&2
    fi
    if [ "$TEST_FAIL" = "$1" ]; then echo 'real start failure' >&2; exit 1; fi
    # rc.common may return success with an empty/unstarted procd service.
    [ "$TEST_FAIL" = inactive ] || echo yes > "$TEST_RUNNING"
    exit 0
    ;;
esac
''',encoding='utf-8',newline='\n')
    rpc=init/'rpcd'
    rpc.write_text('''#!/bin/sh
echo "rpc-$1" >> "$TEST_CALLS"
[ "$TEST_FAIL" != rpc ]
''',encoding='utf-8',newline='\n')
    service.chmod(0o755); rpc.chmod(0o755)
    body=re.search(r'^define Package/luci-app-wgnat6/postinst\n(.*?)\nendef$',(ROOT/'Makefile').read_text(),re.M|re.S)[1].replace('$$','$')
    prefix=posix(tmp_path)
    assert not any(c.isspace() for c in prefix)
    body=body.replace('/etc/init.d/',prefix+'/etc/init.d/')
    # Replace only sleep in the test harness; bounded retries still get counted.
    body='sleep() { echo sleep >> "$TEST_CALLS"; }\n'+body
    script=tmp_path/'postinst'; script.write_text(body,encoding='utf-8',newline='\n')
    env=os.environ.copy(); env.pop('IPKG_INSTROOT',None)
    env.update(TEST_CALLS=posix(calls),TEST_RUNNING=posix(state),TEST_FAIL=fail)
    if offline: env['IPKG_INSTROOT']='/offline/image'
    result=subprocess.run([shell(),posix(script),'configure'],env=env,text=True,capture_output=True,timeout=10)
    return result,calls.read_text().splitlines()


def test_first_install_starts_without_deleting_missing_service(tmp_path):
    result,calls=invoke(tmp_path)
    assert result.returncode==0 and result.stderr=='',result.stderr
    assert 'start' in calls and 'restart' not in calls
    assert calls[-1]=='rpc-reload'


def test_live_upgrade_restarts_existing_worker(tmp_path):
    result,calls=invoke(tmp_path,running=True)
    assert result.returncode==0,result.stderr
    assert 'restart' in calls and 'start' not in calls


def test_real_start_failure_is_not_suppressed(tmp_path):
    result,calls=invoke(tmp_path,fail='start')
    assert result.returncode==1 and 'real start failure' in result.stderr
    assert 'rpc-reload' not in calls


def test_empty_service_is_not_reported_as_running(tmp_path):
    result,calls=invoke(tmp_path,fail='inactive')
    assert result.returncode==1 and 'worker did not start' in result.stderr
    assert calls.count('sleep')==4 and 'rpc-reload' not in calls


def test_enable_failure_stops_install_configuration(tmp_path):
    result,calls=invoke(tmp_path,fail='enable')
    assert result.returncode==1 and calls==['enable']


def test_rpc_reload_failure_is_visible(tmp_path):
    result,calls=invoke(tmp_path,fail='rpc')
    assert result.returncode==1 and calls[-1]=='rpc-reload'
    assert 'installed.' not in result.stdout


def test_offline_build_never_starts_live_services(tmp_path):
    result,calls=invoke(tmp_path,offline=True)
    assert result.returncode==0 and calls==[]
