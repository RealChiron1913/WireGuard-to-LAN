# 兼容性约定

本项目支持**具备下列能力的 OpenWrt 兼容系统**，不按固件品牌、版本号或 CPU 型号做白名单判断。“all” 指包内代码不含架构相关的二进制，不代表不需要依赖或已测试所有硬件。

| 能力 | 必须满足的条件 |
|---|---|
| 防火墙 | firewall4，`inet fw4` 中的 dstnat/srcnat/forward 链；支持 table-pre/chain-pre include |
| 更新互斥 | fw4 使用 `/var/run/fw4.lock` 和 flock；恢复服务早于 firewall 启动 |
| nftables | inet IPv4 NAT、conntrack 表达式、JSON 输出和 `nft -c -f` 检查 |
| 网页 | JavaScript LuCI form.JSONMap、rpc、menu.d；不需要修改 LuCI core |
| 系统服务 | UCI、procd、ubus、rpcd executable plugin/ACL、Linux procfs |
| Lua | Lua 5.1 及匹配系统 ABI 的 libuci-lua、luci-lib-nixio、luci-lib-jsonc |
| 工具 | ip-full 的 JSON 输出、wireguard-tools、flock、coreutils-timeout |
| 拓扑 | 1–32 条独立 IPv4 虚拟地址到 LAN 直连目标的映射，TCP/UDP 保留目的端口，客户端流量经过路由器 |

在系统上安装匹配该固件的软件包，再运行 `wgnat6 preflight`。检查版本输出用于诊断；通过依赖/能力检查及设备验收后才认定该安装环境兼容。OpenWrt 22.03/23.05/24.10 及使用相同接口的后续版本、iStoreOS/ImmortalWrt 等衍生系统属于适配候选，逐台以实际能力为准。发行版名称本身不是通过条件。

上游支持 include 的实现见 [firewall4 解析](https://github.com/openwrt/firewall4/blob/master/root/usr/share/ucode/fw4.uc)；包管理器选择由 [OpenWrt SDK 的 package-pack.mk](https://github.com/openwrt/openwrt/blob/master/include/package-pack.mk) 控制。

## 地址与接口

- 支持不同合法 IPv4 网络、掩码和 Linux 设备名；不内置 LAN/WireGuard 的固定地址。出厂配置留空并停用，`examples/` 中的地址只是配置示例。
- LAN 自动选择包含目标的最长直连前缀；多地址接口无需把全部地址合并成一个大网段。`lan_subnet` 可指定包含目标的更小网段，必须处于同一设备实际直连范围内。该网段同时作为 LAN 客户端源范围。
- WireGuard 自动模式按虚拟 IP 选择设备上的匹配前缀。若设备使用 /32、没有 IPv4 地址、或 VIP 不属于设备的地址网段，填写 `wireguard_subnet` 指定实际客户端源范围，不猜测成 /24。
- 显式 WG 源网段可以是单主机 /32。虚拟 IP 可以使用独立网段，但必须由客户端 AllowedIPs/路由送到本路由器，且不能分配给任意 peer 或路由器本身。它也不能与 LAN 任一直连子网重叠。
- 同址 peer `/32` 或裸主机条目仍硬性拒绝；聚合 AllowedIPs 的覆盖仅提示核对，不直接等同主机占用。管理员仍须确认 VIP 未被远端真实设备使用，因为仅凭路由前缀无法证明地址空闲。
- 支持 /31 点到点 IPv4 主机语义。自动模式在 /31 上仍需有可预留的虚拟地址；通常使用显式 WG 源 CIDR 和独立 VIP。
- 停用时允许地址留空或接口离线，启用时再执行完整检查。默认不接受源范围 /0，以免无意放开全部 IPv4 来源。

## 包管理器和 CPU

| 环境 | 安装路径 | 当前验证状态 |
|---|---|---|
| opkg | Python 打包的 `Architecture: all` ipk，或匹配固件的 SDK | 已完成本地确定性打包测试；路由器安装待验收 |
| OpenWrt SDK 使用 APK 的系统 | 同一 Makefile，由该 SDK 原生生成/签名 apk | 已核对上游生成流程；未执行 SDK 构建或设备安装 |
| x86、ARM、ARM64、MIPS、MIPS64、RISC-V 等 | 安装对应架构/ABI 的依赖；应用源文件相同 | 无架构专用代码；未做跨设备实测 |

不要把 `.ipk` 改扩展名当作 `.apk`，也不要在 Alpine Linux 上安装本包来替代 OpenWrt 的运行环境。APK 系统的依赖名若与本 Makefile 不同，应使用发行版对应的 feed/SDK 适配并验收。

## 明确边界

fw3/iptables 固件、仅有旧 Lua CBI 的 LuCI、原生 Windows/macOS、缺少 UCI/procd/rpcd 的普通 Linux 不符合运行条件。IPv6 NAT、跨路由下一跳目标和完整端口重映射不属于当前实现；这些不是“不同 LAN/WireGuard IPv4”适配的前提。每条映射仍为 1:1，启用记录的虚拟 IP 不得重复；可分别选择不同接口/源范围。

复杂 DNAT 动态 set/map、策略路由、不同网络服务提前截获流量及硬件 offload 需要设备验收。通过 preflight 不能替代真实业务测试。当前没有已完成的路由器实测条目，环境版本来源及测试记录见 [VALIDATION.md](VALIDATION.md)。
