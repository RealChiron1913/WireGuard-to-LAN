# 手动发布到 GitHub

本指南说明如何手动创建 GitHub 仓库、推送源码和发布版本。

## 首次发布

在 GitHub 创建一个空的 **Public** 仓库，例如 `luci-app-wgnat6`。本地目录尚未是 Git 仓库时执行：

```sh
git init -b main
git add .
git status --short
git commit -m "Release portable LuCI WireGuard NAT 1.5.14"
git remote add origin https://github.com/YOUR_ACCOUNT/luci-app-wgnat6.git
git push -u origin main
```

`YOUR_ACCOUNT` 必须换成自己的账号/组织。已有 Git 仓库则保留现有历史和 remote，按自己的分支流程提交。本项目 `.gitignore` 排除测试依赖、虚拟环境、IDE 配置、构建包和常见密钥文件；发布前仍需人工审核 staged 文件，不要把路由器备份或真实配置复制进仓库。

MIT LICENSE 已包含在源码。仓库主页建议设置 Topics：`openwrt`、`luci`、`wireguard`、`nftables`、`istoreos`；启用 Issues、Actions、Private vulnerability reporting，保护默认分支并要求测试通过。GitHub 具体选项以仓库当前设置为准。

## 生成 1.5.14 Release

首先等待 `validate-package` 工作流的两个平台测试和三个 namespace profile 全部通过。它们不能代替目标固件实测；Release notes 应写明已测试的系统及尚未测试的范围。

```sh
python tools/build_ipk.py
python tools/verify_ipk.py dist/luci-app-wgnat6_1.5.14-1_all.ipk
git tag -a v1.5.14 -m "WireGuard NAT 1.5.14"
git push origin v1.5.14
```

在 GitHub Releases 页面手动选择 `v1.5.14`，填写 CHANGELOG 中相应版本说明，上传：

- `dist/luci-app-wgnat6_1.5.14-1_all.ipk`
- `dist/luci-app-wgnat6-1.5.14-source.tar.gz`
- `dist/SHA256SUMS`

也可在 Actions 页面手动运行 `manual-release` 工作流并输入已存在的 tag。该工作流会检出 tag、验证版本、重新测试和打包，再使用仓库令牌创建 Release；不会因普通 push 自动发布。首次公开发布需要仓库所有者审查并允许此工作流的 contents:write 权限。

APK 资产需用对应系统的 SDK 原生构建、签名并单独命名，说明 SDK/架构/ABI 与签名公钥来源。Python 打包器只产生 ipk，不伪造 apk。不要把未执行的 SDK 构建写入 Release 的已验证列表。

发布 1.5.14 时移除/撤回旧 1.0.0-1 和 1.1.0-1 的 Python 构建 ipk；它们的外层格式有误，不能继续作为安装资产提供。旧源码可作为历史保留，但应指向修复记录。

后续发版需同步 Makefile 的 PKG_VERSION、`root/usr/share/wgnat6/version` 和 CHANGELOG；包测试会核对前两者一致。兼容性和状态结构变更要附升级/回退说明，不能只提升版本号。
