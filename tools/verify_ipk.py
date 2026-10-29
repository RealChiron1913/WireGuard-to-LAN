#!/usr/bin/env python3
"""Read-only OpenWrt IPK verification; never executes maintainer scripts.

Independent of build_ipk.py. Checks the gzip/tar container consumed by
OpenWrt opkg-lede, nested control/data archives, metadata, size and paths.
"""
import argparse
import gzip
import hashlib
import io
from pathlib import Path, PurePosixPath
import re
import tarfile


def verify(path):
    package=Path(path)
    raw=package.read_bytes()
    if raw[:2]!=b'\x1f\x8b':
        raise ValueError('OpenWrt IPK must use outer gzip/tar; Debian ar or a renamed source archive is not supported')
    expected={'debian-binary','control.tar.gz','data.tar.gz'}
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as outer:
        entries=outer.getmembers()
        normalized=[e.name.removeprefix('./') for e in entries]
        if len(entries)!=3 or set(normalized)!=expected or any(not e.isfile() for e in entries):
            raise ValueError('Expected exactly debian-binary, control.tar.gz and data.tar.gz regular files')
        files={e.name.removeprefix('./'):outer.extractfile(e).read() for e in entries}
    if files['debian-binary']!=b'2.0\n':
        raise ValueError('Invalid debian-binary version marker')
    with tarfile.open(fileobj=io.BytesIO(files['control.tar.gz']),mode='r:gz') as control:
        matches=[e for e in control.getmembers() if e.name.removeprefix('./')=='control' and e.isfile()]
        if len(matches)!=1:
            raise ValueError('Missing or duplicate control metadata')
        metadata=control.extractfile(matches[0]).read().decode('utf-8')
    fields={}
    for line in metadata.splitlines():
        if not line or line[0].isspace(): continue
        if ':' not in line: raise ValueError('Malformed control field')
        key,value=line.split(':',1)
        if key in fields: raise ValueError('Duplicate control field: '+key)
        fields[key]=value.strip()
    for key in ('Package','Version','Architecture','Description','Installed-Size'):
        if not fields.get(key): raise ValueError('Missing control field: '+key)
    if not re.fullmatch(r'[A-Za-z0-9_.+-]+',fields['Package']):
        raise ValueError('Invalid package name')
    data_raw=gzip.decompress(files['data.tar.gz'])
    if int(fields['Installed-Size'])!=len(data_raw):
        raise ValueError('Installed-Size must equal uncompressed data tar size, as in OpenWrt ipkg-build')
    with tarfile.open(fileobj=io.BytesIO(data_raw),mode='r:') as data:
        members=data.getmembers()
        names=set()
        for member in members:
            name=member.name.removeprefix('./')
            if PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts:
                raise ValueError('Unsafe archive path: '+member.name)
            if name in names: raise ValueError('Duplicate data member: '+name)
            names.add(name)
            if member.isfile(): data.extractfile(member).read()
    return {
        'package':fields['Package'],'version':fields['Version'],'architecture':fields['Architecture'],
        'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'data_members':len(members),
    }


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package',type=Path)
    args=parser.parse_args()
    try: result=verify(args.package)
    except (ValueError,OSError,tarfile.TarError,EOFError) as exc: parser.exit(1,f'Invalid IPK: {exc}\n')
    print(f"OpenWrt IPK OK: {result['package']} {result['version']} ({result['architecture']})")
    print(f"Bytes: {result['size']}\nSHA256: {result['sha256']}")
