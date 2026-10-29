# 贡献指南

本项目以 MIT 许可证接受代码、文档、兼容性报告和翻译贡献。保持源码和安装包可审核、可重复构建，不提交私钥、访问令牌、真实设备配置或未脱敏日志。提交的贡献适用仓库 MIT 许可证。

开始修改前阅读 [架构与安装](README.md)、[兼容性约定](docs/COMPATIBILITY.md) 和 [测试计划](docs/TESTING.md)。新增系统适配应检查能力，而不是维护发行版名称或 CPU 型号白名单。

```sh
python -m pip install -r tests/requirements.txt
python -m pytest tests -q
node --check htdocs/luci-static/resources/view/wgnat6.js
node --test tests/test_frontend.cjs
python tools/build_ipk.py
```

涉及规则、子网选择、持久化或回滚的修改必须提供相应测试。Linux 上还应运行三个 namespace profile：

```sh
sudo .venv/bin/python tests/linux_network.py --profile home
sudo .venv/bin/python tests/linux_network.py --profile office
sudo .venv/bin/python tests/linux_network.py --profile routed
```

Pull Request 说明具体触发场景、修改后的行为和实际验证结果。只有经过目标设备实测的版本/架构才能列入“实机验证”；模拟平台测试与 namespace 数据面测试分别记录。设备实测报告应提供固件版本、包管理器、CPU 架构、依赖版本和脱敏的网段/掩码，不能提交完整 network UCI 或 WireGuard 私钥。

兼容性问题可提交公开 Issue；安全漏洞按 [SECURITY.md](SECURITY.md) 私下报告。维护者不应要求贡献者上传账户凭据或路由器管理密钥。
