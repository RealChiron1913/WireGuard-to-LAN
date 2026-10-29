#!/usr/bin/env python3
"""Build this architecture-independent interpreted package without an SDK.

No third-party dependencies or network access. SOURCE_DATE_EPOCH controls all
archive timestamps. Maintainer scripts and metadata come from Makefile.
"""
import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import tarfile

ROOT = Path(__file__).resolve().parents[1]
NAME = "luci-app-wgnat6"
EXECUTABLES = {
    "etc/init.d/wgnat6", "usr/sbin/wgnat6", "usr/libexec/rpcd/wgnat6",
    "usr/libexec/wgnat6/watchdog",
}


def gz_tar(files, epoch, *, sort_files=True, root_entry=False):
    stream = io.BytesIO()
    with gzip.GzipFile(fileobj=stream, mode="wb", filename="", mtime=epoch, compresslevel=9) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tar:
            if root_entry:
                item=tarfile.TarInfo('./')
                item.type=tarfile.DIRTYPE
                item.mode,item.mtime=0o755,epoch
                item.uid=item.gid=0
                tar.addfile(item)
            directories = set()
            for name in files:
                directories.update(p.as_posix() for p in PurePosixPath(name).parents if p.as_posix() != ".")
            for name in sorted(directories):
                item = tarfile.TarInfo("./" + name)
                item.type = tarfile.DIRTYPE
                item.mode, item.mtime = 0o755, epoch
                item.uid = item.gid = 0
                tar.addfile(item)
            for name, (data, mode) in (sorted(files.items()) if sort_files else files.items()):
                item = tarfile.TarInfo("./" + name)
                item.size, item.mode, item.mtime = len(data), mode, epoch
                item.uid = item.gid = 0
                tar.addfile(item, io.BytesIO(data))
    return stream.getvalue()


def build(output, epoch):
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    version = re.search(r"^PKG_VERSION:=(.+)$", makefile, re.M)[1]
    release = re.search(r"^PKG_RELEASE:=(.+)$", makefile, re.M)[1]
    dependencies = re.search(r"^  DEPENDS:=(.+)$", makefile, re.M)[1].split()
    dependencies = ", ".join(item.removeprefix("+") for item in dependencies)
    files = {}
    for path in sorted((ROOT / "root").rglob("*")):
        if path.is_file():
            relative = path.relative_to(ROOT / "root").as_posix()
            data = path.read_bytes().replace(b"\r\n", b"\n")
            files[relative] = (data, 0o755 if relative in EXECUTABLES else 0o644)
    frontend = "www/luci-static/resources/view/wgnat6.js"
    files[frontend] = ((ROOT / "htdocs/luci-static/resources/view/wgnat6.js").read_bytes().replace(b"\r\n", b"\n"), 0o644)
    data_archive=gz_tar(files,epoch,root_entry=True)
    # Match OpenWrt scripts/ipkg-build: Installed-Size is the uncompressed tar size.
    size=len(gzip.decompress(data_archive))
    control = (
        f"Package: {NAME}\nVersion: {version}-{release}\nArchitecture: all\n"
        f"Maintainer: WireGuard NAT contributors\nSection: luci\nPriority: optional\n"
        f"License: MIT\nDepends: {dependencies}\nInstalled-Size: {size}\n"
        "Description: Chinese LuCI manager for scoped WireGuard TCP/UDP NAT\n"
    )
    controls = {"control": (control.encode(), 0o644), "conffiles": (b"/etc/config/wgnat6\n", 0o644)}
    for script in ("preinst", "postinst", "prerm"):
        match = re.search(rf"^define Package/{NAME}/{script}\n(.*?)\nendef$", makefile, re.M | re.S)
        assert match, script
        controls[script] = ((match[1].replace("$$", "$") + "\n").encode(), 0o755)
    output.mkdir(parents=True, exist_ok=True)
    package = output / f"{NAME}_{version}-{release}_all.ipk"
    # OpenWrt opkg-lede expects an outer gzip-compressed tar, not Debian ar.
    # Keep the same member order and GNU tar format as scripts/ipkg-build.
    package.write_bytes(gz_tar({
        'debian-binary':(b'2.0\n',0o644),
        'data.tar.gz':(data_archive,0o644),
        'control.tar.gz':(gz_tar(controls,epoch,root_entry=True),0o644),
    },epoch,sort_files=False))
    source_files = {}
    for folder in ("root", "htdocs", "tools", "tests", "docs", "examples", ".github"):
        for path in sorted((ROOT / folder).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                name = f"{NAME}-{version}/" + path.relative_to(ROOT).as_posix()
                source_files[name] = (path.read_bytes().replace(b"\r\n", b"\n"), 0o644)
    for name in ("Makefile", "LICENSE", "README.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", ".gitignore", ".gitattributes"):
        if (ROOT / name).exists():
            source_files[f"{NAME}-{version}/{name}"] = ((ROOT / name).read_bytes().replace(b"\r\n", b"\n"), 0o644)
    source = output / f"{NAME}-{version}-source.tar.gz"
    source.write_bytes(gz_tar(source_files, epoch))
    sums = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in (package, source))
    (output / "SHA256SUMS").write_bytes(sums.encode("ascii"))
    print(sums, end="")
    return package


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--epoch", type=int, default=int(os.environ.get("SOURCE_DATE_EPOCH", "1780570342")))
    args = parser.parse_args()
    build(args.output, args.epoch)
