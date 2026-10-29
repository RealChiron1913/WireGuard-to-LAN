# LuCI WireGuard NAT

用于 **OpenWrt 兼容系统**的中文 LuCI 应用，支持多条独立的 1:1 映射：每个虚拟 IPv4 的全部所选 TCP/UDP 目的端口映射到一台 LAN 设备。目标设备不需要安装 WireGuard。修改目标后，客户端继续使用原来的虚拟 IP 和端口。

项目采用 [MIT 许可证](LICENSE)，提供完整源码、OpenWrt SDK Makefile、可重复构建工具、测试和 GitHub 工作流。发布步骤见 [发布指南](docs/RELEASING.md)。

## 功能与兼容范围

- 启用/停用、虚拟 IPv4、目标 IPv4、协议均可配置；LAN/WireGuard 从现有设备下拉选择，没有内置的运行网段。
- 自动识别不同掩码的直连子网，支持多地址 LAN；可显式设置 LAN/WireGuard 源 CIDR。
- 显式 WG 源 CIDR 支持 /32 设备地址、无设备 IPv4 地址和独立虚拟 IP 网段。
- 支持 WireGuard 客户端与经过本路由器的 LAN 客户端，TCP/UDP 保留原目的端口。
- root 专用候选版本、nft 语法检查、内核表达式核对、90 秒人工确认、超时和重启回滚。
- 日常更改仅原子更新三个应用链，不刷新整个 table/ruleset，不清空 conntrack。
- 安全检测和备份旧 `wgnat6_*` include，不覆盖未知同名配置。

运行条件为 UCI/procd/rpcd、JavaScript LuCI、Lua 5.1 与所需库、firewall4 和支持 JSON 的 nftables。符合条件的 OpenWrt、iStoreOS、ImmortalWrt 等系统使用同一源码；不绑定固件品牌、CPU 架构或特定私有地址。

**兼容依据是系统能力和实测结果。** `Architecture: all` 表示应用不含架构相关二进制，依赖仍须匹配固件 ABI。fw3/iptables、仅旧 Lua CBI 的界面、普通 Linux/Windows/macOS 不能直接运行该 LuCI 包。详细条件和未验证范围见 [兼容性说明](docs/COMPATIBILITY.md)。当前支持 1–32 条 IPv4 映射；包名中的 `6` 沿用历史命名，不表示 IPv6。

## 快速安装

新安装默认**停用**，虚拟 IP、目标 IP、WireGuard 设备名留空，避免把某个示例网络直接应用到其他设备。空选项被 UCI 省略时，页面仍可打开和编辑。已有用户升级时保留 UCI 和已确认规则。

### opkg 系统

在项目目录使用 Python 3.9+ 构建；Windows 可将 `python3` 改为 `python` 或 `py`：

```sh
python3 tools/build_ipk.py
```

输出：

```text
dist/luci-app-wgnat6_1.5.14-1_all.ipk
dist/luci-app-wgnat6-1.5.14-source.tar.gz
dist/SHA256SUMS
```

把 `.ipk` 上传到路由器 `/tmp/`，使用该固件原有软件源安装依赖：

```sh
opkg update
opkg install /tmp/luci-app-wgnat6_1.5.14-1_all.ipk
```

安装完成后重新登录并强制刷新 LuCI，打开 **网络 → WireGuard NAT**：

1. 在“映射列表”新增/编辑记录，分别填写虚拟 IP、目标 LAN IP及协议；通过编辑选择该条 LAN/WireGuard 接口、源 CIDR。
2. 如检测到旧规则，点击“迁移已有规则”，核对旧规则和当前表单后确认迁移；没有旧规则时，点击“保存并应用”。
3. 页面自动提交后台初始化任务并显示进度；无需 SSH 写参数或先运行 setup。
4. 规则通过验证后，从客户端测试，再在 90 秒内点击“确认保留配置”。首次初始化也有确认窗口；超时、回滚或未确认重启会恢复原 include 和配置。

后续改目标使用相同的保存/确认流程。初始化涉及完整 fw4 reload，由守护进程异步执行以免受 HTTP/RPC 超时影响；日常目标修改仍只替换应用链。安装脚本在首次安装时启动服务，在已有 worker 运行时重启，并确认 worker 正常运行后 reload rpcd，以加载新 RPC 方法。

1.5.3 修复了原生 libuci-lua 没有 section() 的初始化/恢复缺陷。若旧版卡在恢复状态，保留 journal 和备份直接升级；服务启动会先恢复日志对应的原配置，再允许页面重试。改写 firewall UCI 前还会在应用私有运行目录做命名创建、提交重读和删除的原生 API 自检，避免依赖不存在的封装方法。[原生 libuci-lua 接口](https://github.com/openwrt/uci/blob/master/lua/uci.c)

1.5.4 兼容用户提供的 nftables 1.1.1 原始目的地址 JSON 省略 `family` 的格式。失败时记录表达式差异，详见[诊断与恢复](docs/RECOVERY.md)；实际应用链和 TCP/UDP 流量仍需在目标设备验收。

1.5.5 可在归属和空闲状态均核验通过后复用先前失败迁移遗留的空链；无法确认归属或存在引用时拒绝接管。

1.5.6 根据目标路由器生成的规则 JSON 兼容 `ip daddr` 键，并在核对失败时保留应用链快照供排查。

1.5.7 定期检查并在必要时原子恢复本应用锚点顺序，以便与会动态插入规则的 OpenClash 等服务共存。发往映射虚拟 IP 的 TCP/UDP，包括 DNS 53 和 UDP 443，优先进入映射；其他流量仍受原规则处理。检查间隔为约 3 秒，第三方插入规则后的短暂窗口仍需注意并实测。

1.5.8 可直接在映射列表中勾选或取消“启用映射”；点击“保存并应用”后，按页面提示测试并确认。

1.5.9 将两个可选来源网段移至映射编辑窗口的“高级设置”；留空时继续自动识别。

页面路径为 `/cgi-bin/luci/admin/network/wgnat6`，在自己的现有路由器管理地址下访问。路由器 LAN 管理 IP 不需要在本应用中另行硬编码。

### APK 系统与 SDK

使用对应固件/目标的 OpenWrt SDK 和根 Makefile 原生构建 `.apk`，依赖和签名由该系统的工具链处理。Python 打包器只生成 opkg `.ipk`，不能将其改扩展名用于 APK。

原生构建方法、所需依赖、SDK/feed 固定版本和验证命令见 [BUILD.md](docs/BUILD.md)。APK 路线已按上游构建接口准备，尚未执行 SDK 构建或设备安装验证。

## 配置自己的地址

唯一持久化用户配置为 `/etc/config/wgnat6`，支持六个基本字段和两个可选 CIDR。以下是一个办公室网络的**示例**：

```uci
config mapping 'main'
    option enabled '1'
    option virtual_ip '172.27.1.6'
    option target_ip '10.20.8.39'
    option lan_interface 'br-office'
    option wireguard_interface 'wg-office'
    option protocol 'both'
    option lan_subnet ''
    option wireguard_subnet ''
```

多设备场景每条记录使用一个独立 section，例如 [multiple-devices.uci](examples/multiple-devices.uci)：`10.66.66.6 → 192.168.31.39` 与 `10.66.66.7 → 192.168.31.50` 可以同时启用。每条单独设置协议、接口和源范围；启用的虚拟 IP 必须互不重复，且不能分配给 WireGuard peer 或本机。至少保留一条记录，不使用时可以停用。

保存、确认和回滚作用于整组。任何一条输入、路由或地址占用检查失败，均不会替换当前整组规则。停用/删除一条不会删除其他记录的映射；已有连接仍遵循 conntrack 原绑定。客户端 AllowedIPs/路由须覆盖全部使用的虚拟 IP。

接口字段为 Linux 设备名，不是任意 UCI zone 名。协议为 `tcp`、`udp` 或 `both`。虚拟 IP 和目标 IP 为主机 IPv4，不包含 `/掩码`。

页面从系统实时读取现有链路和 IPv4 地址，WireGuard 列表只包含 `wg show interfaces` 识别的现有设备；LAN 列表包含非 WireGuard、非 loopback 的现有设备，具体目标直连范围仍由后端检查。选项显示地址和启用状态。没有 WireGuard 设备时，先在网络设置创建/启用后刷新本页；已保存但消失的设备会标注“当前不可用”，不能用于启用映射，但允许停用。

| 配置方式 | LAN | WireGuard | 处理方式 |
|---|---|---|---|
| [家庭示例](examples/home.uci) | 192.168.31.0/24 | 10.66.66.0/24 | 自动识别 |
| [办公室示例](examples/office.uci) | 10.20.0.0/16 | 172.27.0.0/20 | 不同掩码和设备名，自动识别 |
| [WG /32 示例](examples/routed-wireguard32.uci) | 172.30.40.0/28 | 设备 10.99.0.1/32，客户端 10.99.0.0/24 | 显式 WG CIDR，VIP 使用独立网段 |

自动 LAN 模式选择包含目标的最具体直连前缀；同一设备的其他地址不会自动扩大客户端范围。`lan_subnet` 可指定包含目标且在实际直连范围内的更小 CIDR，同时作为 LAN 客户端源范围。虚拟 IP 不得与该设备任何直连 LAN 子网重叠。

自动 WireGuard 模式按虚拟 IP 选择设备上的匹配前缀。设备地址为 /32、没有 IPv4 地址或使用独立 VIP 网段时，应填写实际客户端源范围，例如 `wireguard_subnet '10.99.0.0/24'`；不擅自推断 /24。显式单主机 `/32` 源范围同样可用。

CIDR 必须填写规范网络地址，例如 `10.20.0.0/16`，不能写成 `10.20.8.39/16`。支持有效的 /31 点到点主机语义；禁止默认放开全部 IPv4 的源 `/0`。目标必须实际直连到指定 LAN 设备，不能经另一个网关转发。

## 迁移已有三段规则

如果已有 `/etc/wgnat6/dnat.nft`、`snat.nft`、`forward.nft`，在页面填入要保留的映射，点击“迁移已有规则”，核对当前表单和识别出的旧规则，再确认迁移。页面会明确显示是否发现已有 include，迁移不会静默发生。**不要使用空的停用配置替代仍要保留的工作映射。**

1.4.0 在尚未接管时读取这三段旧文件中的直接字面量规则，识别地址、接口、TCP/UDP 协议和源范围。应用 UCI 为空时自动预填；已有完整应用配置则优先显示 UCI，同时单独展示旧规则。可用“载入已识别的旧配置”按钮只更新表单，保存并确认后才迁移。接管完成后以应用 UCI 和待确认版本为准，不再反复读取已备份的旧文件。多个目标、端口限制或需要展开变量/include 的规则不会被猜测为全部端口映射。文件识别和内核运行验证分别展示。

高级维护仍可使用 `wgnat6 preflight/setup/verify` 等 CLI；它们不再是网页首次配置的前置条件。CLI `setup [--migrate]` 采用立即提交的维护流程，网页初始化则采用异步任务和 90 秒确认流程。

原三个命名 section 必须为 `include`，明确使用 `type nftables`，且路径为约定的三个旧文件。遇到未知 section、额外 wgnat6 include 或已存在的同名专用链会拒绝接管。原 section 完整选项、firewall 文件、应用配置和旧文件保存在 `/etc/wgnat6/luci/backups/<标识>/`；原三个文件不覆盖。

未经确认迁移时，页面不会提交初始化；后端也要求显式迁移参数，不会把已知旧规则误报成未知 section。类型或路径确实不匹配时才拒绝接管。不要为了绕过检查删除现有 section。

安装前已有未归属本包的配置/程序文件也会阻止覆盖。应先审查和备份冲突文件，再合并到新配置，不能跳过检查直接覆盖。

普通目录和卸载后残留的空目录树不会被判定为文件冲突；目录中的非本包文件也不会因安装而删除。升级优先使用包管理器提供的 upgrade 标志识别，不要求特定路径的旧 control 文件必须存在。没有登记且确实会被覆盖的文件、实际事务数据或未知符号链接仍会阻止安装。

**首次 setup 和 detach 会执行一次经过检查的 `fw4 reload`**，用于撤除旧 inline 规则或恢复旧 include。它可能触发其他组件的防火墙集成逻辑，须保留 SSH/备用 LAN 入口，并避免同时修改防火墙。正常网页改目标仅更新应用链。[firewall4 reload 实现](https://github.com/openwrt/firewall4/blob/18fc0ead/root/sbin/fw4)

## 规则与生命周期

应用在 `inet fw4` 内定义 `wgnat6_dnat`、`wgnat6_snat`、`wgnat6_forward` 三个普通链，以六个专属 UCI include 持久加载：

| include | position | chain | 内容 |
|---|---|---|---|
| wgnat6_dnat / snat / forward | table-pre | 无 | 各自的普通链定义 |
| wgnat6_dnat_jump | chain-pre | dstnat | 单一 DNAT jump |
| wgnat6_snat_jump | chain-pre | srcnat | 单一 SNAT jump |
| wgnat6_forward_jump | chain-pre | forward | 单一转发 jump |

文件位于 `/etc/wgnat6/luci/current/`；`current` 是指向不可变候选版本的原子切换链接。生成快照不是第二个用户配置入口。include 类型为 `nftables`；不依赖已废弃的 `reload` 选项。[firewall4 include 解析](https://github.com/openwrt/firewall4/blob/18fc0ead/root/usr/share/ucode/fw4.uc)

DNAT 同时限制入接口、源范围、协议和虚拟目的 IP；FORWARD 及 masquerade 进一步匹配实际 LAN 出接口、转换后的目标、conntrack 原始目的 IP、原方向和 DNAT 状态。未匹配流量返回 fw4 原流程，不新增整个 WireGuard 到 LAN 的转发授权。目标通常看到路由器 LAN 地址作为源，确保回包经同一路由器。[Netfilter NAT/conntrack 语义](https://netfilter.org/projects/nftables/manpage.html)

保存时先验证输入、设备、源 CIDR、本机/peer 地址占用、显式 DNAT 冲突与目标路由，然后暂存并执行 `nft -c -f`。持久化 journal 后切换版本，检查 fw4 确实包含全部 include，对完整渲染结果只做 dry run；真正更新时用一个 nft batch 刷新三个专用链。之后读取内核 JSON，逐条核对表达式、数量、顺序、NAT 目标及唯一锚点。只看到 include 文本不会算成功。

确认前 UCI 保留最近确认版本，页面显示候选与已提交配置的区别。90 秒窗口使用单调 uptime，不受 NTP 校时影响。未确认重启会先恢复文件，再让 firewall 启动。成功确认后提交 UCI 并记录 UTC 时间；失败恢复上版，仍失败则保留 journal 重试。互斥使用与 fw4 相同的 flock，忙时拒绝并发修改。

ACL 仅允许本应用的 status/interfaces/verify/initialize_all/apply_all/confirm/rollback RPC，并保留旧单条接口兼容入口，不授予任意 `file.exec` 或 firewall/network 写权限。interfaces 仅读取设备名、接口 IPv4 和启用状态，不读取密钥或 peer。initialize_all 只接受受限映射列表 JSON 及迁移开关，提交给已有守护进程；浏览器不能选择命令、脚本或路径。后端固定格式生成规则，以 argv 执行固定程序，没有用户 shell 插值。参见 [rpcd executable plugin](https://openwrt.org/docs/techref/rpcd)。

## 客户端路由和测试

客户端连接本路由器的 WireGuard peer 的 `AllowedIPs` 必须覆盖虚拟 IP；服务器给远端 peer 分配的地址则必须预留这个虚拟 IP。不要把 VIP 配成本机地址。独立 VIP 网段同样需要客户端路由/AllowedIPs 覆盖。[WireGuard cryptokey routing](https://www.wireguard.com/#cryptokey-routing)

AllowedIPs 描述路由/源地址授权范围，本身不等于主机地址分配。同址 `/32` 或裸主机条目视为明确保留而阻止使用；与所选 WireGuard 接口网段相同的聚合前缀不再提示，其他覆盖范围仍提示且不会被当成主机占用。无提示也不能证明虚拟 IP 空闲，仍需管理员核对远端实际地址。检查过程不自动删除、缩小或改写任何 peer。[官方概念说明](https://www.wireguard.com/#cryptokey-routing)

旁路由场景中，LAN 客户端或主网关须把 VIP `/32` 路由到本路由器的实际 LAN 管理地址。下面仅为家庭示例的 Windows 管理员命令：

```powershell
route -p ADD 10.66.66.6 MASK 255.255.255.255 192.168.31.10
Test-NetConnection 10.66.66.6 -Port 3389
```

按自己的 VIP、下一跳和真实监听端口替换。目标服务和自身防火墙必须允许访问；目标不回应 ping 只作为探测提示。只映射 TCP/UDP 时，ping VIP 可以失败。UDP 需应用请求/响应，详见 [TESTING.md](docs/TESTING.md)。

更换目标影响新建连接；已有 conntrack/offload 流仍可能到旧目标，停用也不强制切断现有流。测试时创建新连接，不全局清空 conntrack。[Netfilter NAT 的连接绑定行为](https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT))

OpenClash、Docker、Tailscale、miniupnpd 和既有 fw4 策略不由本应用修改；它们的提前截获、独立 drop/mark/route 和动态映射仍可能影响流量，需在具体系统上验收。复杂动态 set/map 和外部设备地址占用无法仅凭静态本机检查完全证明无冲突。

## 升级、回滚和卸载

升级前确认或回滚待定事务，并备份 `/etc/config/wgnat6`、`/etc/wgnat6/luci/` 以及旧安装包。通过系统包管理器安装更新；保留 conffile 和状态目录，不重复 setup。1.0.x 六字段配置兼容 1.1.x 的可选字段默认值。原始包与 `.apk` 应分别沿对应包管理器路径升级。

1.5.0 会将旧单条配置作为原记录继续使用，不需重建。旧版程序不支持多段 mapping；回退程序版本时应恢复升级前的 UCI 和状态备份，不能只用旧程序直接读取多条新配置。

从 1.4.0 起，应用启动会创建 `/etc/wgnat6/luci/package-id` 作为持久化归属标记，正常卸载程序后保留。重装识别该标记并沿用应用状态，不再将其当作未知残留；原 UCI 优先保留。若 UCI 丢失，只从与最近成功提交记录对应的快照恢复，并且不自动重新接管防火墙。不要删除状态目录来执行普通重装；删除它表示放弃这些恢复记录。旧版已经被手动卸载且没有标记的未知非空残留仍需核对，不能仅凭同名目录判定归属。

```sh
wgnat6 status
wgnat6 verify
wgnat6 rollback
# 没有待定事务时，上述命令将上一确认版本作为候选；实测后确认：
wgnat6 confirm
```

有待定事务时 rollback 直接恢复最近确认版本。绕过事务编辑 UCI 的内容在服务启动时会恢复成已确认快照；SSH 修改也应运行 `wgnat6 apply` 并确认。sysupgrade 的 keep.d 会保留应用配置和状态目录，固件升级后仍须安装本应用及匹配依赖。

卸载必须先解除集成：

```sh
if [ -f /etc/wgnat6/luci/pending.json ]; then wgnat6 rollback; fi
wgnat6 detach
# opkg 系统：
opkg remove luci-app-wgnat6
# APK 系统改为 apk del luci-app-wgnat6
/etc/init.d/rpcd reload
```

detach 只移除六个应用 section，并恢复迁移前曾备份的旧 include；因此旧 NAT 可能重新启用。没有旧 include 的新装环境则完全解除本应用映射。旧文件和备份不会自动删除，勿删除整个 `/etc/wgnat6`。恢复和程序版本回退命令见 [RECOVERY.md](docs/RECOVERY.md)。

## 源码和开发

```text
Makefile / LICENSE / CHANGELOG.md
README.md / CONTRIBUTING.md / SECURITY.md
root/etc/config/wgnat6                    默认停用配置
root/etc/init.d/wgnat6                    早期恢复和 procd
root/usr/lib/wgnat6/{engine,legacy,main}.lua  生成、旧规则识别、验证和事务
root/usr/sbin/wgnat6                      互斥入口
root/usr/libexec/{rpcd/wgnat6,wgnat6/watchdog}
root/usr/share/{luci/menu.d,rpcd/acl.d}/luci-app-wgnat6.json
root/usr/share/wgnat6/{package-id,version}
root/lib/upgrade/keep.d/wgnat6
htdocs/luci-static/resources/view/wgnat6.js
examples/                                不同网络的 UCI 配置
tools/build_ipk.py                        确定性构建器
tests/                                   Lua 5.1、事务、包和多网段数据面测试
docs/                                    构建、兼容、验收、恢复与发布
.github/                                 测试、手动发版和协作模板
```

开发与社区协作见 [CONTRIBUTING.md](CONTRIBUTING.md)。当前版本的实际本地检查、尚未执行的设备/SDK/网络测试见 [VALIDATION.md](docs/VALIDATION.md)，不要把“预期兼容”写成“已在所有系统验证”。
