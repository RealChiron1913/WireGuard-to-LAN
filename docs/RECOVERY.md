# 诊断与恢复

1.5.7 的 watchdog 检查父链顺序；当其他服务在应用锚点前插入规则时，仅在应用专用链内容及锚点本身验证通过后，原子移动应用锚点。其他规则及其相对顺序保留。映射目标的 DNS 和 QUIC 流量将优先进入映射；检查周期内可能存在短暂的顺序变化，应在目标设备与 OpenClash 同时运行时实测。

如果初始化失败后出现“内核已有同名专用链”，1.5.5 会检查应用历史生成记录，并仅复用完全空闲、无引用的匹配链。记录缺失、链中有规则、存在引用或未知属性时仍会拒绝；不要手动清空其他组件的链或整个防火墙。

内核表达式核对失败后，1.5.4 可读取最近一次差异：

```sh
cat /var/run/wgnat6/verify-error.json
```

该文件仅包含失败表达式和期望表达式，不包含 WireGuard 密钥；可能包含 IP 地址，分享前按需脱敏。它保存在运行目录，重启后会消失，且后续成功验证不会删除，因此必须结合错误发生时间判断。错误仍会触发回滚；不要删除旧规则或整个防火墙配置。

从 1.5.6 起，失败时也会尽力记录三条应用候选链，便于检查后续表达式：

```sh
cat /var/run/wgnat6/verify-chain-dnat.json
cat /var/run/wgnat6/verify-chain-snat.json
cat /var/run/wgnat6/verify-chain-forward.json
```

快照仅来自应用专用链，包含映射 IP 和接口名，不包含 WireGuard 密钥。文件在运行目录中，会在重启后消失；再次失败时被覆盖，成功后不自动清除。

本文件中的 `vpn`、`br-lan` 和 IP 是家庭示例，按实际配置替换；APK 系统的包管理命令使用对应 `apk` 操作，fw4/UCI/应用命令相同。

## 先判断是哪一层失败

```sh
wgnat6 status
uci show wgnat6
logread -e wgnat6
ubus -v list wgnat6
ubus call service list '{"name":"wgnat6"}'
ip -4 address show dev vpn
ip -4 address show dev br-lan
ip -4 route get 192.168.31.39
wg show vpn allowed-ips
```

页面内“运行中目标”可能是待确认候选；“已提交目标”来自 UCI。`runtime_ok` 表示已核对内核规则，不表示目标应用在线。

## 初始化或恢复提示 section 方法不存在

`attempt to call method 'section' (a nil value)` 是 1.5.2 及更早版本混用了 LuCI 封装方法和原生 libuci-lua 的缺陷。初始化和恢复使用同一个错误方法，因此可能一直显示“正在恢复”，按钮被禁用；等待不会自行解决。

保留 `/etc/wgnat6/luci/` 内的 journal、备份及旧 nft 文件，直接升级到 1.5.3。服务重新启动时会先用修复后的原生 set 接口按日志恢复 include 和应用配置，再启动 worker。该启动恢复只写配置文件，不执行全局防火墙 reload。完成后刷新 LuCI，核对旧映射，再勾选迁移重试。

新代码在改写 firewall UCI 之前自动使用独立目录做真实 libuci-lua 自检；不需要用户在 shell 中补写映射。若自检仍失败，应保留完整错误和备份再诊断，不删除 journal 或重置整个 firewall。[原生 set 契约和方法导出](https://github.com/openwrt/uci/blob/master/lua/uci.c)

## 提示虚拟 IP 已被 WireGuard peer 的 AllowedIPs 占用

先只读查看 `wg show vpn allowed-ips`，接口按自己的配置替换，不共享私钥。若匹配的是 `10.66.66.6/32` 这类同址主机条目，需核对实际地址分配，应用不会自动更改 peer。1.5.2 的错误会同时说明前缀及运行/UCI 来源；运行输出没有同址条目但错误注明 UCI 时，还需检查保存但未生效的 peer 配置。

若只有 `10.66.66.0/24` 覆盖 `.6`，属于旧检查的误报。AllowedIPs 是路由和源授权范围，不能仅据此断言 `.6` 已被某台设备使用。升级 1.5.2 并刷新页面后会改为核对提示，可继续迁移、测试并确认；不要为通过检查删除整个 `/24`。这不免除远端主机地址是否实际空闲的核对。

用户已提供的示例为 `.2/32`、`10.66.66.0/24`、`.4/32`、`.5/32`，没有 `.6/32`；该组合已加入初始化与多映射测试。

## 已有未知同名 section，拒绝覆盖

1.4.0 的检查把“已知旧配置但未允许迁移”和“真正未知配置”合并成同一错误。对已确认的 canonical 路径 `/etc/wgnat6/{dnat,snat,forward}.nft`，应在页面勾选“备份并迁移已有规则”。1.5.0 在保存前和后端排队前分别明确提示，已知旧 section 不再被误报为未知。

若 1.5.0 提示“类型或路径不是已知旧配置”，请核对该 section 的实际 type/path；不要删除现有 section 来绕过检查。原 section 和文件在安全迁移前保留不动。

若页面已经显示多映射列表和已识别旧配置，但顶部仍出现旧措辞，可能是进入页面前留下的失败任务被重新通知。1.5.1 会将这种结果放入“历史失败记录”，不再当作新错误反复弹出；新失败仍会明确提示。截图中的“备份并迁移已有规则”如未勾选，应先勾选再保存，识别参数不等于已经接管。页面出现字面量 null 的空节点渲染问题也已修复。

## 已有参数没有显示或重装后配置为空

升级到 1.4.0 后重新登录并刷新 LuCI。页面同时识别专用应用 UCI 和约定三段旧 nft 文件：完整 UCI 优先，UCI 为空则以已识别的旧文件预填；按钮“载入已识别的旧配置”只改表单，不写 UCI、不 reload 防火墙。旧文件包含多目标、端口限制、动态变量/include 等歧义时会显示原因，不能把识别当作内核运行验证。

普通重装应保留 `/etc/config/wgnat6` 和 `/etc/wgnat6/luci/`。1.4.0 在状态目录建立持久归属标记，重装可继续使用；若 UCI 丢失，会从最近确认记录对应的版本恢复参数，不恢复失败/未确认候选，也不自动接管防火墙。没有归属标记的旧版未知残留应先核对内容，不盲目删除。原三段 nft 文件始终独立保留。

## 页面提示缺少 virtual_ip / target_ip

1.1.x 在空 UCI 选项被省略后可能抛出“缺少字符串配置字段”。升级到 1.2.0 后重新登录并强制刷新 LuCI，直接在 **网络 → WireGuard NAT** 填写全部参数并保存，不需要 SSH 补写 UCI。即使配置中 enabled=1 且地址缺失，页面仍能打开修正；只有应用启用配置时才要求完整有效地址。

首次保存显示后台初始化进度，完成后需在 90 秒内确认。存在旧规则时勾选迁移选项；未确认会恢复原规则及配置。安装脚本重启本应用 worker 并 reload rpcd，以加载新初始化方法。

## 安装时提示 Malformed package file

先确认安装的是 `.ipk`，没有误传源码 `.tar.gz`、HTML 下载页或改名的文件。1.0.0-1/1.1.0-1 由本项目 Python 工具生成的 ipk 使用了错误的 ar 容器，请重新下载当前 1.2.0-1 或更新版本。不要通过 `--force-*` 绕过格式错误。

```sh
sha256sum /tmp/luci-app-wgnat6_1.5.14-1_all.ipk
tar -tzf /tmp/luci-app-wgnat6_1.5.14-1_all.ipk
```

将 SHA256 与交付文件核对。tar 必须列出 `./debian-binary`、`./data.tar.gz`、`./control.tar.gz`。三项格式正确后再 `opkg install /tmp/luci-app-wgnat6_1.5.14-1_all.ipk`；若仍有错误，保留完整输出和实际 SHA256 继续排查。

## 安装时提示 Refusing to overwrite unowned path

1.2.0 及更早的安装检查会误拒绝 `/usr/lib/wgnat6` 等普通空目录。若 `ls -la /usr/lib/wgnat6` 只显示 `.` 和 `..`，且 `opkg status luci-app-wgnat6` 为空，属于已复现的空目录残留场景；直接上传 1.2.1 或更新包重新安装即可，不需要删除该目录。

1.2.1 同时允许服务留下的空 `gens/backups` 目录树，正常升级通过包管理器标志识别。检查针对实际被安装的文件；未知真实文件、未登记事务状态和符号链接仍会被保留并拒绝覆盖。若错误具体指向 `engine.lua`、`owned.json` 等实际文件，应先检查包归属和内容，再决定如何备份/迁移，不把未知数据直接当作旧版应用。

## 候选配置失败或网页断开

先保留现有管理连接并等待约 93 秒，独立守护进程将恢复最近确认配置。仍可 SSH 时：

```sh
wgnat6 status
wgnat6 rollback
wgnat6 verify
```

有待定事务时上述 rollback 立即恢复已确认版本。没有待定事务时会把上一个已确认版本作为候选，请在确实要回退时执行，测试后再 `wgnat6 confirm`。

**不要在应用返回超时后盲目反复保存。** 先刷新状态；RPC 请求超时不等于事务已取消。守护进程需要运行，`begin` 会拒绝在没有运行中守护实例时应用候选。

## 锁冲突

`wgnat6` 与 fw4 使用非阻塞锁；防火墙 reload 正在进行时命令可能以状态码 75 返回，RPC 可能只显示无有效响应。等待系统现有操作结束再重试。不删除锁文件来“解锁”，因为删除文件不能安全解除另一个进程持有的 flock。

## fw4 reload 后规则缺失

先查看 include 及生成文件：

```sh
uci show firewall.wgnat6_dnat
uci show firewall.wgnat6_snat
uci show firewall.wgnat6_forward
uci show firewall.wgnat6_dnat_jump
uci show firewall.wgnat6_snat_jump
uci show firewall.wgnat6_forward_jump
readlink /etc/wgnat6/luci/current
cat /etc/wgnat6/luci/current/dnat.nft
cat /etc/wgnat6/luci/current/snat.nft
cat /etc/wgnat6/luci/current/forward.nft
fw4 print
fw4 check
```

确认检查成功，并确保有备用管理入口后再：

```sh
fw4 reload
wgnat6 recover
wgnat6 verify
```

fw4 reload 按系统规则集重建 fw4 表，可能运行其他 include 脚本。它是管理员的恢复操作，日常网页改目标不执行它。若 fw4 check 失败，先修复错误来源，不执行 reload、restart 或 flush 来碰运气。

回滚若遇到专用链已经被外部操作移除，会保留 journal 并重试。它已将 `current` 指回最近确认版本；完整 fw4 reload 重建链后，`recover` 可以完成剩余验证并清理 journal。

## 安装输出 service delete ... (Not found)

旧版安装脚本无条件执行 restart；OpenWrt restart 会先尝试停止/删除旧实例，再启动服务，首次不存在旧实例时可能输出该提示。它不一定表示安装或启动失败。可只读检查：

```sh
/etc/init.d/wgnat6 status
ubus call service list '{"name":"wgnat6"}'
```

若状态为 `running`，实例 `running` 为 `true` 且 command 为本应用 watchdog，可直接继续 LuCI 配置，无需因该提示重装。若未运行，查看 `logread -e wgnat6`。1.2.2 的安装脚本已区分首次启动和已有实例重启，并检查实际运行状态。[OpenWrt rc.common restart 实现](https://github.com/openwrt/openwrt/blob/openwrt-24.10/package/base-files/files/etc/rc.common)

## LuCI 页面不存在或 RPC 不可用

```sh
opkg status luci-app-wgnat6
ubus -v list wgnat6
/etc/init.d/rpcd reload
```

重新登录 LuCI，并对浏览器强制刷新。检查软件包的菜单文件、ACL 文件和 view 文件存在。不要修改 LuCI core 或开放任意 `file.exec` 权限来绕过 ACL。若 rpcd reload 在该固件上不能注册新对象，可从仍有效的 SSH 执行 `/etc/init.d/rpcd restart`，然后重新登录；restart 会失效现有 LuCI 登录会话。

## 整个管理页面无法访问

尝试通过 `192.168.31.10` 的 LAN 地址和已保留的 SSH 会话管理，不要通过正在更改的虚拟 IP 管理路由器。完全失联时用物理 LAN、串口或该固件支持的 failsafe 进入系统；恢复方式取决于设备启动环境。[OpenWrt failsafe 官方说明](https://openwrt.org/docs/guide-user/troubleshooting/failsafe_and_factory_reset)

取得 shell 后，若需要强制恢复尚未确认的文件状态：

```sh
/etc/init.d/wgnat6 stop
wgnat6 boot
fw4 check
# 仅在上一条成功后运行：
fw4 reload
/etc/init.d/wgnat6 start
wgnat6 verify
```

`boot` 的作用是恢复未完成的事务文件；它自身不执行 nft/fw4。服务正常启动也会调用它。不要在仍有其他应用事务写入时直接调用 boot；先停止该服务并确认没有正在执行的保存操作。

## 恢复到安装前的旧 include

正常路径：

```sh
wgnat6 detach
```

它只调整六个属于本应用的 section，恢复曾备份的原 section，并在检查及 reload 后核实专用链已消失，或剩余链已确认归属且为空、没有引用。原 `/etc/wgnat6/*.nft` 始终保留。未知同名 include 或选项被人为改动时 detach 会拒绝覆盖，请先根据 `owned.json` 和备份审查差异。

如果程序文件损坏导致 detach 无法运行，优先重新安装相同版本包恢复工具，再执行 detach：

```sh
opkg install --force-reinstall /tmp/luci-app-wgnat6_1.5.14-1_all.ipk
wgnat6 detach
```

手工恢复时应只恢复原有三个 section 并删除本应用三个 `*_jump` section。不要直接用旧的整个 firewall 备份覆盖当前配置，因为安装之后可能已有其他合法修改；完整备份用于对照和最后的人工恢复。

恢复到兼容旧程序版本可使用 `opkg install --force-downgrade /tmp/旧版本.ipk`；APK 使用与系统匹配的已签名旧包及其降级方式。包含新显式源 CIDR 的 1.1.x 配置不应直接交给 1.0.x；先在 1.1.x 中回退到旧的六字段兼容配置并完成验收，再更换程序，或恢复升级前的配置及状态备份。

## conntrack 与 offload

已有 NAT 连接不会因修改规则自动迁往新目标。测试时使用新建连接和新源端口，尤其注意 UDP 可能在一段时间内复用旧五元组。正常回滚也不迁移已经建立到候选目标的流。

确实需要立即切断此 VIP 的旧映射时，可在维护时安装/使用 conntrack 工具，只删除相关协议、原始目的 IP 的条目：

```sh
conntrack -L -f ipv4 -p tcp --orig-dst 10.66.66.6
conntrack -L -f ipv4 -p udp --orig-dst 10.66.66.6
# 审核上面的条目后，按需要分别执行：
conntrack -D -f ipv4 -p tcp --orig-dst 10.66.66.6
conntrack -D -f ipv4 -p udp --orig-dst 10.66.66.6
```

这些命令会中断访问该 VIP 的现有会话；不要用 `conntrack -F`。硬件 offload 的清退行为依赖具体驱动，必要时在维护时处理系统 offload；本应用不自动更改全局 offload 设置。[conntrack 官方命令手册](https://netfilter.org/projects/conntrack-tools/conntrack-manpage.html)
