"""Execute the actual Makefile preinst against a private temporary filesystem.

Paths in the extracted script are rewritten by the test harness only. Nothing
in production accepts a test root or skips ownership checks using user input.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest
from conftest import ROOT


def shell():
    candidate=shutil.which('sh')
    if candidate: return candidate
    candidate=Path('C:/Program Files/Git/bin/bash.exe')
    if candidate.exists(): return str(candidate)
    pytest.skip('A POSIX shell is required for preinst execution tests')


def invoke(tmp_path,files=None,directories=(),args=('install',),env=None,symlinks=None):
    fs_root=tmp_path/'root'
    fs_root.mkdir()
    for name in directories: (fs_root/name.lstrip('/')).mkdir(parents=True,exist_ok=True)
    for name,data in (files or {}).items():
        path=fs_root/name.lstrip('/'); path.parent.mkdir(parents=True,exist_ok=True); path.write_text(data,encoding='utf-8')
    for name,target in (symlinks or {}).items():
        path=fs_root/name.lstrip('/'); path.parent.mkdir(parents=True,exist_ok=True)
        try: path.symlink_to(target)
        except OSError: pytest.skip('Creating symbolic links is unavailable on this test host')
    body=re.search(r'^define Package/luci-app-wgnat6/preinst\n(.*?)\nendef$',(ROOT/'Makefile').read_text(),re.M|re.S)[1].replace('$$','$')
    prefix=fs_root.as_posix()
    if os.name=='nt': prefix='/'+prefix[0].lower()+prefix[2:]
    # Rewrite every hard-coded system path, including patterns used by the guard.
    # Fake roots used here contain no spaces; no router/host path is left live.
    assert not any(c.isspace() for c in prefix)
    body=re.sub(r'/(?:etc|usr|www|lib)/',lambda match:prefix+match[0],body)
    assert not re.search(r'(?<![\w:/])/(?:etc|usr|www|lib)/',body)
    script=tmp_path/'preinst'; script.write_text(body+'\n',encoding='utf-8',newline='\n')
    script_arg=script.as_posix()
    if os.name=='nt': script_arg='/'+script_arg[0].lower()+script_arg[2:]
    process_env=os.environ.copy()
    for key in ('IPKG_INSTROOT','PKG_UPGRADE'): process_env.pop(key,None)
    process_env.update(env or {})
    return subprocess.run([shell(),script_arg,*args],text=True,capture_output=True,env=process_env,timeout=10),fs_root


@pytest.mark.parametrize('directories',[
    (),('/usr/lib/wgnat6',),('/usr/lib/wgnat6','/usr/libexec/wgnat6','/usr/share/wgnat6','/etc/wgnat6/luci'),
    ('/usr/lib/wgnat6','/etc/wgnat6/luci/gens','/etc/wgnat6/luci/backups/old-empty'),
])
def test_first_install_allows_existing_empty_directories(tmp_path,directories):
    result,_=invoke(tmp_path,directories=directories)
    assert result.returncode==0,result.stderr


def test_unrelated_noncolliding_directory_contents_are_preserved(tmp_path):
    files={'/usr/lib/wgnat6/notes.txt':'not part of this application'}
    result,root=invoke(tmp_path,files=files)
    assert result.returncode==0,result.stderr
    assert (root/'usr/lib/wgnat6/notes.txt').read_text()=='not part of this application'


@pytest.mark.parametrize('args,env',[(('upgrade','1.1.1-1'),{}),(('install',),{'PKG_UPGRADE':'1'})])
def test_upgrade_does_not_require_old_control_or_marker(tmp_path,args,env):
    result,_=invoke(tmp_path,files={'/usr/lib/wgnat6/engine.lua':'old installed code'},args=args,env=env)
    assert result.returncode==0,result.stderr


@pytest.mark.parametrize('marker',[
    {'/usr/lib/opkg/info/luci-app-wgnat6.control':'Package: luci-app-wgnat6\n'},
    {'/usr/share/wgnat6/package-id':'luci-app-wgnat6\n'},
    {'/etc/wgnat6/luci/package-id':'luci-app-wgnat6-state-v1\n'},
])
def test_registered_reinstall_recognizes_existing_application(tmp_path,marker):
    result,_=invoke(tmp_path,files=marker|{'/usr/lib/wgnat6/engine.lua':'installed code'})
    assert result.returncode==0,result.stderr


@pytest.mark.parametrize('name',[
    '/usr/lib/wgnat6/engine.lua','/usr/lib/wgnat6/main.lua','/etc/config/wgnat6',
    '/usr/libexec/wgnat6/watchdog','/usr/share/wgnat6/version','/etc/wgnat6/luci/owned.json',
])
def test_unowned_colliding_files_remain_protected(tmp_path,name):
    result,root=invoke(tmp_path,files={name:'unrelated existing data'})
    assert result.returncode==1 and 'Refusing to overwrite unowned path' in result.stderr
    assert (root/name.lstrip('/')).read_text()=='unrelated existing data'


def test_unknown_symlink_is_not_followed(tmp_path):
    result,_=invoke(tmp_path,symlinks={'/usr/lib/wgnat6':'/missing-target'})
    assert result.returncode==1


def test_offline_image_install_does_not_touch_live_paths(tmp_path):
    result,_=invoke(tmp_path,files={'/usr/lib/wgnat6/engine.lua':'image content'},env={'IPKG_INSTROOT':'/offline/image'})
    assert result.returncode==0


@pytest.mark.parametrize('name',['/etc/wgnat6/luci/gens/generation/config','/etc/wgnat6/luci/.pending'])
def test_nested_or_hidden_unowned_state_is_preserved(tmp_path,name):
    result,root=invoke(tmp_path,files={name:'existing state'})
    assert result.returncode==1
    assert (root/name.lstrip('/')).read_text()=='existing state'


def test_existing_legacy_nft_files_are_not_installation_collisions(tmp_path):
    files={f'/etc/wgnat6/{name}.nft':'legacy rules' for name in ('dnat','snat','forward')}
    result,root=invoke(tmp_path,files=files,directories=('/usr/lib/wgnat6',))
    assert result.returncode==0,result.stderr
    assert all((root/path.lstrip('/')).read_text()=='legacy rules' for path in files)


def test_preinst_checks_every_shipped_file(tmp_path):
    body=(ROOT/'Makefile').read_text()
    guard=re.search(r'^define Package/luci-app-wgnat6/preinst\n(.*?)\nendef$',body,re.M|re.S)[1]
    paths=['/'+p.relative_to(ROOT/'root').as_posix() for p in (ROOT/'root').rglob('*') if p.is_file()]
    paths.append('/www/luci-static/resources/view/wgnat6.js')
    assert all(path in guard for path in paths)
