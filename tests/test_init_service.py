"""Exercise the real init start_service with only a private fake boot command."""
import os
import subprocess
from conftest import ROOT
from test_preinst import shell
from test_postinst import posix


def invoke(tmp_path,codes):
    boot=tmp_path/'wgnat6'; log=tmp_path/'calls'; state=tmp_path/'remaining'
    state.write_text('\n'.join(str(code) for code in codes)+'\n')
    boot.write_text('''#!/bin/sh
echo "boot $1" >> "$TEST_CALLS"
code=$(head -n 1 "$TEST_CODES")
sed '1d' "$TEST_CODES" > "$TEST_CODES.next"
mv "$TEST_CODES.next" "$TEST_CODES"
exit "${code:-0}"
''',encoding='utf-8',newline='\n'); boot.chmod(0o755)
    source=(ROOT/'root/etc/init.d/wgnat6').read_text().replace('/usr/sbin/wgnat6',posix(boot))
    harness='''
sleep() { echo sleep >> "$TEST_CALLS"; }
procd_open_instance() { echo open >> "$TEST_CALLS"; }
procd_set_param() { :; }
procd_close_instance() { echo close >> "$TEST_CALLS"; }
'''+source+'\nstart_service\n'
    script=tmp_path/'start'; script.write_text(harness,encoding='utf-8',newline='\n')
    env=os.environ.copy(); env.update(TEST_CALLS=posix(log),TEST_CODES=posix(state))
    result=subprocess.run([shell(),posix(script)],env=env,text=True,capture_output=True,timeout=10)
    return result,log.read_text().splitlines()


def test_transient_old_worker_lock_is_retried_before_registration(tmp_path):
    result,log=invoke(tmp_path,[75,0])
    assert result.returncode==0 and log.count('boot boot')==2 and log.count('sleep')==1
    assert log[-2:]==['open','close']


def test_actual_boot_error_does_not_register_an_empty_worker(tmp_path):
    result,log=invoke(tmp_path,[1])
    assert result.returncode==1 and log==['boot boot']


def test_lock_wait_is_bounded(tmp_path):
    result,log=invoke(tmp_path,[75]*5)
    assert result.returncode==75 and log.count('boot boot')==5 and log.count('sleep')==4
    assert 'open' not in log
