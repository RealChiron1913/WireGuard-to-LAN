# 可重复构建

## 无 SDK 打包（opkg 系统）

本应用没有需编译的二进制模块，目标为 opkg `.ipk`、`Architecture: all`。所有代码在目标固件的 LuCI/Lua 环境运行。打包器只使用 Python 标准库，依赖列表、版本、安装脚本以根目录 Makefile 为准。

```sh
python3 tools/build_ipk.py --epoch 1780570342
```

Windows 使用 `python` 或 `py`。产物：

```text
dist/luci-app-wgnat6_1.5.14-1_all.ipk
dist/luci-app-wgnat6-1.5.14-source.tar.gz
dist/SHA256SUMS
```

时间戳默认固定为 `1780570342`；可用 `SOURCE_DATE_EPOCH` 或 `--epoch` 指定。目录/文件排序、uid/gid、权限、GNU tar 格式及 gzip 时间戳均固定。相同源码与 epoch 产生相同的归档；跨 Python/zlib 版本若压缩实现不同，应以同一构建环境复验哈希。Windows 源文件 CRLF 会归一化成 LF，目录名统一为 POSIX 分隔符。

`.ipk` 是**外层 gzip 压缩的 tar**，依次包含 `./debian-binary`、`./data.tar.gz`、`./control.tar.gz`；后两项分别是内层 gzip/tar。该格式依据 [OpenWrt 24.10 ipkg-build](https://github.com/openwrt/openwrt/blob/openwrt-24.10/scripts/ipkg-build) 和 [opkg-lede 的 deb_extract](https://github.com/openwrt/opkg-lede/blob/38eccbb1fd694d4798ac1baf88f9ba83d1eac616/libbb/unarchive.c)。Installed-Size 使用 data tar 解压后的字节数。1.0.0-1/1.1.0-1 的 Python 构建包误用了 ar，已由 1.1.1 修复。

```sh
python3 tools/verify_ipk.py dist/luci-app-wgnat6_1.5.14-1_all.ipk
tar -tzf dist/luci-app-wgnat6_1.5.14-1_all.ipk
```

验证器只读取归档，不运行维护脚本或修改系统；它不代替目标路由器的实际 opkg 安装测试。该包没有附加签名，安装前应与可信交付的 SHA256SUMS 核对。使用固件原有 opkg 源安装依赖；不要换成其他发行版的软件源。

```sh
sha256sum -c dist/SHA256SUMS
```

## 使用 iStoreOS/OpenWrt SDK

根 Makefile 可加入 OpenWrt/iStoreOS/兼容衍生固件的 feed。使用与**目标固件版本、包管理器、架构及 ABI 对应**且已完成 feed 配置的 SDK，记录 SDK 地址、SHA256 和 feed commit；不限于 iStoreOS/x86。当前工作区没有 SDK，不虚构可下载的版本路径。

以下操作在 Linux SDK 根目录执行，`WG_SOURCE` 指向本项目的完整源码目录：

```sh
export WG_SOURCE=/absolute/path/to/WireGuard-to-LAN
mkdir -p package/luci-app-wgnat6
cp -a "$WG_SOURCE/Makefile" "$WG_SOURCE/root" "$WG_SOURCE/htdocs" package/luci-app-wgnat6/
./scripts/feeds update -a
./scripts/feeds install -a
make defconfig
./scripts/config -m PACKAGE_luci-app-wgnat6
make defconfig
make package/luci-app-wgnat6/compile V=s
find bin/packages -name 'luci-app-wgnat6*.ipk' -o -name 'luci-app-wgnat6*.apk'
```

首次 feed update 后，将 `feeds.conf.default` 中每个 feed 固定为已记录的 commit，再构建交付版本。SDK 构建产物不承诺与 Python 打包器字节一致；二者安装同一源文件、依赖与 maintainer scripts。OpenWrt 软件包构建约定见 [官方开发文档](https://openwrt.org/docs/guide-developer/packages)。

### APK 系统

相同 Makefile 由使用 APK 的 OpenWrt SDK 原生生成 `.apk`；不要设置 `CONFIG_USE_APK` 去改变一个本来不对应目标系统的 SDK。安装、升级识别使用包身份文件，不依赖 opkg 数据库；已有 1.0.x 的 opkg 升级路径继续识别旧登记文件。上游根据包管理器包装 maintainer scripts 和升级环境，见 [package-pack.mk](https://github.com/openwrt/openwrt/blob/master/include/package-pack.mk)。

在匹配目标并受信任签名的包准备好后：

```sh
apk update
apk add /tmp/luci-app-wgnat6-1.5.14-r1.apk
wgnat6 preflight
```

安装后在 LuCI 页面填写并保存；网页会执行首次初始化。CLI preflight 是可选诊断，不要求用户先写 UCI 或运行 setup。

实际文件名以 SDK 输出为准。公开 feed 应用 SDK 的签名流程及可信公钥，不默认关闭签名校验。该路径尚未进行 SDK 构建和设备安装验收。APK 本身不能为缺少 OpenWrt 运行环境的系统提供兼容性。

## 开发验证

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r tests/requirements.txt
python -m pytest tests -q
node --check htdocs/luci-static/resources/view/wgnat6.js
node --test tests/test_frontend.cjs
sh tools/check_shell.sh
```

Windows 中的 pytest 临时目录若受限制，可指定一个**新的、空的、项目内**绝对路径：

```powershell
python -m pytest tests -q --basetemp="D:\path\to\WireGuard-to-LAN\.test-tmp-new"
```

pytest 会管理该临时目录，不要把已有工作文件目录传给 `--basetemp`。

Lua 测试通过 `lupa.lua51` 直接运行项目的 Lua 5.1 源码。事务测试替换 OS 库和外部命令边界，覆盖配置提交、回滚、迁移等行为；它们不模拟为已完成真实内核转发验证。

1.5.3 移除了替身中错误提供的 section()，按原生 libuci-lua 的 set(package, section, type) 与 set(package, section, option, value) 契约执行测试。运行时还会在应用私有运行目录内实际创建并往返读写测试 UCI 包，原生自检通过后才改写 firewall UCI；自检不使用真实 firewall/network 配置文件。[原生 API 源码](https://github.com/openwrt/uci/blob/master/lua/uci.c)

1.5.0 的多映射使用多个命名 UCI mapping section。旧单条配置和旧快照继续有效；页面通过限定的 `apply_all`/`initialize_all` RPC 提交 `{id, config}` 列表 JSON，后端限制条数、标识、字段与虚拟地址唯一性，始终提交整个规则事务。单条旧 RPC 保留兼容入口，更新首条/主记录时不会删除其他记录。

真实 nftables 与数据面测试在 Linux 上单独运行：

```sh
sudo apt-get install nftables iproute2
sudo .venv/bin/python tests/linux_network.py --profile home
sudo .venv/bin/python tests/linux_network.py --profile office
sudo .venv/bin/python tests/linux_network.py --profile routed
```

该测试创建四个以 `wn6-进程号-` 命名的新 network namespace，所有 nft 写入仅发生在测试路由 namespace 内；最后清理自己创建的 namespace。它不使用宿主机防火墙，也不修改 `/etc/config`。WireGuard 入接口以 veth 模拟，用于验证 NAT/转发数据面；它不测试 WireGuard 加密握手。真实 firmware 的 fw4/rpcd/LuCI 与加密链路仍按 [TESTING.md](TESTING.md) 验收。

`.github/workflows/test.yml` 在 Linux/Windows 上执行单元及包测试，并在 Linux 上为三个 profile 分别执行网络测试。源码被放入 GitHub 并触发工作流后才运行；本次没有执行远程 CI。`.github/workflows/release.yml` 仅手动触发发布，使用方法见 [RELEASING.md](RELEASING.md)。
