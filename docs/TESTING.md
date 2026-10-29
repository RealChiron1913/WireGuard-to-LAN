# 设备验收和交互测试

适用于通过 [兼容性检查](COMPATIBILITY.md) 的系统。本文件命令中的 `vpn`、`br-lan` 和 IP 是家庭 profile 示例；其他设备替换为自己的实际值。必须为每个报告记录固件/架构/依赖版本。先保留 SSH/备用 LAN 管理入口，并记录测试前其他网络服务的连通性。

## 建立基线

```sh
cat /etc/openwrt_release
opkg list-installed | grep -E '^(luci-base|firewall4|nftables|rpcd|lua|libuci-lua|luci-lib-nixio|luci-lib-jsonc|ip-full|wireguard-tools|flock|coreutils-timeout)'
ip -4 address show dev vpn
ip -4 address show dev br-lan
ip -4 route get 192.168.31.39
wg show vpn allowed-ips
uci show firewall.wgnat6_dnat
uci show firewall.wgnat6_snat
uci show firewall.wgnat6_forward
```

APK 系统用 `apk list --installed` 记录对应包版本。新装默认停用且地址留空；直接打开页面填写并保存，首次初始化自动执行。已有旧映射时，点击迁移按钮，核对预览后确认。CLI 是高级维护入口，不是网页配置的前置步骤。

不要共享 `wg showconf`、`uci show network` 或完整网络备份，里面可能包含 WireGuard 私钥。上述 `wg show ... allowed-ips` 不读取私钥。

目标设备必须有实际监听并放行的 TCP 服务。Windows 目标以管理员 PowerShell 核实 RDP 服务，例如：

```powershell
Get-NetTCPConnection -LocalPort 3389 -State Listen
```

这条命令只检查监听，不会启用 RDP。目标通常看到来自 `192.168.31.10` 的连接，请使目标自身防火墙允许相应服务。不要为了测试永久关闭目标防火墙。

## 验收清单

| 场景 | 操作 | 必须满足的结果 |
|---|---|---|
| 初装 | 安装 ipk，直接打开空配置页面，填写并保存 | 空字段不阻止打开；初始化自动排队；确认前 UCI 保持原值 |
| 迁移 | 点击“迁移已有规则”，核对预览并确认 | 只接管约定的三个 include；备份和旧文件存在；超时可恢复旧 include |
| 空字段省略 | UCI 不包含 virtual_ip/target_ip 选项 | 页面提供空输入框，启用保存时再提示缺失字段，不抛出 Lua 源码错误 |
| 初始配置无效 | enabled=1 但缺失地址 | 页面能编辑并显示校验提示，修正后可继续初始化 |
| 多设备同时映射 | 新增 .6→.39 与 .7→.50，两侧客户端分别访问 | 两条 TCP/UDP 映射同时生效，目的端口保持不变 |
| 单条停用/删除 | 停用或删除 .6 记录，保留 .7 | 新连接仅按剩余启用记录映射，其他记录保留 |
| 重复虚拟 IP | 两条启用记录配置同一 VIP | 保存失败并保留整组旧规则；停用记录可保留为草稿 |
| 整组原子性 | 第二条输入错误或应用后核对失败 | 第一条也不提交；失败、超时及人工回滚恢复整组 |
| 迁移未经确认 | 旧 include 已存在，直接保存或取消预览 | 页面提示使用迁移按钮，不排队改规则；后端拒绝未经授权的迁移 |
| 旧失败记录 | 带已有 error 初始化记录打开页面并轮询 | 显示历史结果，不重复弹作本次错误；新任务失败仍通知一次 |
| 条件块隐藏 | 无接口错误/无旧配置/已初始化的页面 | 不生成字面量 null/undefined；协议显示中文，长说明留在编辑弹窗 |
| 原三段配置识别 | 使用已有三段字面量 nft 规则及 chain-pre include | 识别 VIP、目标、接口、协议和源范围；不修改 UCI 或声称已验证运行 |
| UCI 与旧规则并存 | 应用 UCI 目标与旧 nft 目标不同 | UCI 优先显示，两者分别呈现；载入按钮不提交配置 |
| 普通重装 | 先运行 1.4.0，按要求 detach/remove 后重装 | 持久归属标记、UCI 与恢复记录保留；不自动接管防火墙 |
| 重装时 UCI 丢失 | 保留有效确认快照和归属标记 | 只恢复最近成功记录对应参数，未确认版本不被采用 |
| 初始确认超时 | 首次保存后不确认 | 守护进程恢复初始化前的 include 和 UCI，支持重新填写重试 |
| 初始化进程中断 | 在隔离测试中中断 worker | journal 保留，后续 worker/启动恢复；不把未确认候选提交到 UCI |
| 原生 UCI 契约 | 执行 preflight/初始化中的隔离自检 | 实际完成命名 section 与字符串/列表提交重读删除，不依赖 LuCI section 封装 |
| 旧版 section 卡死 | 在测试替身中复现缺失方法后升级恢复 | 保留 journal，恢复原 include 与参数，结束恢复状态并可重新初始化 |
| 同名未知文件/section | 在测试设备构造未知占用 | 拒绝覆盖，原配置保留 |
| 不同网络/掩码 | 使用 home/office/routed 三个 profile | /24、/16、/20、/28 及自定义设备名均生成正确源范围 |
| 多地址 LAN | 一个设备配置多个实际前缀 | 按目标选择最具体直连前缀，VIP 不得与其他 LAN 前缀重叠 |
| WG /32 / 独立 VIP | 显式填写实际 WG 客户端源 CIDR | 不猜测 /24；客户端路由覆盖 VIP 后 TCP/UDP 可达 |
| 单源 /32 / LAN /31 | 在隔离设备验证精确源主机和点到点地址 | 源范围不扩大，/31 两端按主机处理 |
| 新装默认值 | 空地址并停用 | 无活动映射；启用但缺字段时拒绝申请 |
| 接口下拉 | 打开页面并检查 LAN/WireGuard 选项 | 仅出现对应现有设备；显示 IPv4/启用状态；WireGuard 不混入普通网口 |
| 无 WireGuard 设备 | 在隔离环境移除 WG 设备并刷新页面 | 显示空选择及说明，不编造 vpn/wg0 选项 |
| 已保存设备消失 | 停止/删除所选设备后刷新 | 显示当前不可用，启用校验拒绝，停用仍可保存 |
| 接口读取失败 | 模拟 discovery RPC 失败 | 页面仍显示并给出错误，不能将任意文本当作新接口提交 |
| 旧版升级 | 从 1.0.x 六字段配置与快照升级 | 原配置保留，无需重复 setup，不因可选新字段而误回滚 |
| 改目标 | `.39` 改为 `.50`，保存应用 | 页面运行目标变为 .50；提交目标暂仍为 .39；新连接到 .50 |
| 确认 | 测试后点击确认保留 | UCI 目标变为 .50，待定状态消失，成功时间更新 |
| 无效输入 | 超出 255、CIDR、换行、分号、引号、前导零 | 前后端拒绝；规则、指针、已提交 UCI 保持原值 |
| 地址冲突 | 路由器 .10、WG 本机 .1、peer 已占地址、网络/广播地址 | 启用申请被拒绝；解释错误原因 |
| peer 明确主机冲突 | 配置同址 /32 或裸 IPv4 主机条目 | 保留原规则，拒绝应用；显示匹配前缀和运行/UCI 来源 |
| peer 聚合路由 | 仅 /24、/8、0.0.0.0/0 覆盖 VIP | 显示核对提示，可继续验证/确认；不修改任何 peer |
| 错误路由 | 目标指向其他设备或经网关到达 | 拒绝启用，原映射保留 |
| 目标不可达 | 停止目标或禁用 ICMP | 保存可完成但提示探测失败；内核验证成功不等于服务可达 |
| 停用/再启用 | 分别保存、确认 | 停用时三链为空、锚点仍唯一；再启用恢复规则 |
| 重复应用 | 同一配置应用并确认 5 次 | 默认每链始终四条；每条锚点始终一条；不重复累加 |
| 人工回滚 | 应用 .50 但不确认，点击回滚 | 立即恢复 .39 的 UCI/规则/指针 |
| 超时回滚 | 不确认，等待 90–93 秒 | 自动恢复最近确认配置；日志记录恢复 |
| 页面关闭/断线 | 应用后关闭浏览器 | 守护进程独立回滚，不依赖网页在线 |
| 待确认重启 | 候选生效后重启 | 在 firewall 启动前恢复上版文件/配置；重启后规则是上版 |
| 已确认重启 | 确认配置后重启 | 同一目标和规则恢复，页面可读，守护进程运行 |
| firewall reload | `fw4 check` 后 `fw4 reload` | 同一版本三链及锚点重新加载，新连接成功 |
| LAN hairpin | LAN Windows 添加 VIP 路由后连接 | 经 .10 到目标；目标收到来自 .10 的流量 |
| 远端 WireGuard | 正常 peer 建隧道并访问 VIP | TCP 和 UDP 应用请求/响应成功 |
| 未相关目标 | WG 客户端直接访问其他 LAN 主机 | 本应用计数器不匹配；没有新增整个 LAN 的放行 |
| 单协议 | 分别选择 TCP / UDP | 只生成所选协议，每链两条；其他协议无本应用的 DNAT |
| 非 TCP/UDP | 对 VIP ping | 可以失败；不作为 TCP/UDP NAT 失败证据 |
| 候选语法无效 | 自动故障注入测试/隔离环境的无效 batch | `nft -c` 失败，未替换活跃规则 |
| 应用后规则异常 | mock 故障注入/隔离设备篡改候选 | 表达式核对失败、恢复上版；不是只检查注释 |
| fw4 正在更新 | 持锁时发起保存 | 锁冲突返回失败，无并发写入，稍后重试 |
| 复杂服务共存 | 开启现有 OpenClash/Docker/Tailscale/miniupnpd 等再测试 | 见下文；不假定所有组合天然兼容 |
| 卸载 | 无待定事务时 detach，再 remove | 专用链移除；非本应用 section/文件保留；旧 include 按备份恢复 |

默认协议 `both` 时三链各四条；停用后为零；单协议时各两条。不把现有 zone 中本来就允许的访问误认为由本应用新开放。

### TCP 测试

从真实 LAN 客户端和远端 WireGuard 客户端分别执行：

```powershell
Test-NetConnection 10.66.66.6 -Port 3389
```

`TcpTestSucceeded: True` 仅证明该 TCP 握手可达。接着建立实际 RDP/HTTP/其他服务连接，确认目标身份。每次更换目标后创建新连接；旧连接仍受旧 conntrack 绑定影响。

### UDP 测试

在可控测试目标上临时运行 UDP echo 服务，例如 Python：

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 51888))
while True:
    data, peer = s.recvfrom(2048)
    s.sendto(data, peer)
```

只放行测试所需的 UDP 51888，测试后停止服务并撤销该临时放行。客户端 PowerShell：

```powershell
$udp = [Net.Sockets.UdpClient]::new()
$udp.Client.ReceiveTimeout = 3000
$payload = [Text.Encoding]::UTF8.GetBytes('wgnat6-test')
[void]$udp.Send($payload, $payload.Length, '10.66.66.6', 51888)
$peer = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
[Text.Encoding]::UTF8.GetString($udp.Receive([ref]$peer))
$udp.Dispose()
```

收到 `wgnat6-test` 才是完整的 UDP 双向验证。仅发送一次无响应 UDP 数据不能说明连通。

## 规则和计数器

```sh
wgnat6 status
wgnat6 verify
uci show wgnat6
fw4 print
nft -a list chain inet fw4 dstnat
nft -a list chain inet fw4 srcnat
nft -a list chain inet fw4 forward
nft -a list chain inet fw4 wgnat6_dnat
nft -a list chain inet fw4 wgnat6_snat
nft -a list chain inet fw4 wgnat6_forward
logread -e wgnat6
ubus call service list '{"name":"wgnat6"}'
```

验收时可以保存 `nft -j list ruleset` 到本地私有文件以比较非应用链，分享前检查里面的公网地址和业务信息。计数器和动态集合内容可能因正常流量变化；比较结构与策略，不机械要求所有字节相同。

## 共存服务检查

先记录现有服务的基线，再分别在“目标变更”“确认”“外部 fw4 reload”“重启”后检查：

- WireGuard 握手、到路由器 LAN 管理地址的 SSH/LuCI 及现有隧道业务仍可用。
- OpenClash 的既有代理/DNS/直连路径仍符合其策略；确认它没有在更早的 NAT/TPROXY/策略路由阶段接管 VIP 流量。
- Docker 原有发布端口、容器出站和内部网络仍可用；不因 Docker 服务名相同就假定它使用 fw4 表。
- Tailscale 原有子网路由/exit node 策略仍可用，其独立 drop/mark/route 规则可能影响转发。
- miniupnpd 的既有动态映射仍可用；确认它没有占用 VIP 或被首次 fw4 reload 的自身集成逻辑丢失。

正常 Save & Apply 的 `nft` batch 只能包含三个 `flush chain inet fw4 wgnat6_*` 和对应 `add rule`，不能出现 table/ruleset flush。首次 setup/detach 与管理员主动执行的 `fw4 reload` 则按 firewall4 自身行为处理其他集成。

## 故障注入与隔离测试

开发机运行 `python -m pytest tests -q`，覆盖语法检查失败、应用后内核验证失败、错误确认令牌、超时、重启、备份迁移、未知占用、停用/启用和事务外 UCI 修改。

Linux root 分别运行 `python tests/linux_network.py --profile home`、`--profile office`、`--profile routed` 时，测试仅在新建 namespace 内写入 nft，验证 TCP/UDP、目标变更、hairpin、源范围、未相关目标拒绝、无效 nft 事务的原子性、重复替换及非应用表保留。WireGuard 入接口使用 veth 模拟，不代替加密链路实测。**不要为了故障注入在远程生产路由器上破坏正在工作的 include 或专用链。**
