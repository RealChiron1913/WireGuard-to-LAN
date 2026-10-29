import gzip
import hashlib
import importlib.util
import io
import re
import shutil
import subprocess
from pathlib import Path
import tarfile
import pytest

from conftest import ROOT


def verifier():
    spec=importlib.util.spec_from_file_location('verify_ipk',ROOT/'tools/verify_ipk.py')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.verify


def members(data):
    # OpenWrt's opkg-lede reads gzip -> tar -> control.tar.gz, not Debian ar.
    # See scripts/ipkg-build in OpenWrt 24.10 and libbb/unarchive.c deb_extract().
    assert data[:2] == b'\x1f\x8b', 'OpenWrt IPK outer archive must be gzip/tar, not ar'
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as outer:
        assert outer.getnames()==['./debian-binary','./data.tar.gz','./control.tar.gz']
        return {entry.name.removeprefix('./'):outer.extractfile(entry).read() for entry in outer.getmembers()}


def test_deterministic_ipk_metadata_permissions_and_scripts(tmp_path):
    spec = importlib.util.spec_from_file_location("build_ipk", ROOT / "tools/build_ipk.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    a = module.build(tmp_path / "a", 1780570342)
    b = module.build(tmp_path / "b", 1780570342)
    assert a.read_bytes() == b.read_bytes()
    version=re.search(r'^PKG_VERSION:=(.+)$',(ROOT/'Makefile').read_text(),re.M)[1]
    assert (a.parent / f"luci-app-wgnat6-{version}-source.tar.gz").read_bytes() == (b.parent / f"luci-app-wgnat6-{version}-source.tar.gz").read_bytes()
    with tarfile.open(a.parent / f"luci-app-wgnat6-{version}-source.tar.gz") as source:
        names=set(source.getnames())
        for path in ['LICENSE','CONTRIBUTING.md','SECURITY.md','CHANGELOG.md','docs/COMPATIBILITY.md','docs/RELEASING.md',
                     'examples/home.uci','examples/office.uci','examples/routed-wireguard32.uci','.github/workflows/release.yml']:
            assert f'./luci-app-wgnat6-{version}/{path}' in names
        assert not any('.vscode' in p or '.test-deps' in p or '\\' in p for p in names)
    ipk = members(a.read_bytes())
    result=verifier()(a)
    assert result['version']==version+'-1' and result['architecture']=='all'
    assert ipk["debian-binary"] == b"2.0\n"
    with tarfile.open(fileobj=io.BytesIO(ipk["control.tar.gz"])) as control:
        metadata = control.extractfile("./control").read().decode()
        assert "Architecture: all\n" in metadata
        installed_size=int(re.search(r'^Installed-Size: (\d+)$',metadata,re.M)[1])
        assert installed_size==len(gzip.decompress(ipk['data.tar.gz']))
        assert "coreutils-timeout" in metadata and "nftables-json" in metadata
        assert control.extractfile("./conffiles").read() == b"/etc/config/wgnat6\n"
        for script in ("preinst", "postinst", "prerm"):
            text = control.extractfile("./" + script).read()
            assert text.startswith(b"#!/bin/sh\n") and b"$$" not in text and b"\r" not in text
            if shutil.which('sh'):
                subprocess.run(['sh','-n'],input=text,check=True)
    with tarfile.open(fileobj=io.BytesIO(ipk["data.tar.gz"])) as data:
        for path in module.EXECUTABLES:
            assert data.getmember("./" + path).mode == 0o755
        assert data.getmember("./etc/config/wgnat6").mode == 0o644
        assert data.extractfile('./usr/share/wgnat6/version').read().decode().strip()==version
        assert not any("private" in f.name for f in data.getmembers())


@pytest.mark.parametrize('raw', [b'!<arch>\n' + b'old Debian container', b'<html>not a package</html>', b'', b'2.0\n'])
def test_reject_incompatible_or_wrong_download(tmp_path,raw):
    package=tmp_path/'upload.ipk'; package.write_bytes(raw)
    with pytest.raises(ValueError,match='gzip/tar'): verifier()(package)


def test_reject_renamed_source_tarball(tmp_path):
    raw=io.BytesIO()
    with tarfile.open(fileobj=raw,mode='w:gz') as archive:
        info=tarfile.TarInfo('README.md'); info.size=4
        archive.addfile(info,io.BytesIO(b'test'))
    package=tmp_path/'source.ipk'; package.write_bytes(raw.getvalue())
    with pytest.raises(ValueError,match='exactly'): verifier()(package)
