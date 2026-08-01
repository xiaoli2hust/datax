# GitHub-hosted Windows 安装器预检（非发布，E1）

[`windows-hosted-preflight.yml`](../../.github/workflows/windows-hosted-preflight.yml) 是一个刻意
受限的开发预检。它会在 GitHub-hosted `windows-2025`（Windows Server x64）上，用真实 Windows
原生工具链执行 Launcher 单元测试/构建，并用固定 NSIS 3.11 压缩包编译一次临时安装器。

它的价值是尽早发现以下回归：

- Windows 原生 Rust/MSVC 编译失败；
- Launcher 的纯单元测试失败；
- NSIS 语法、宏、资源打包路径或 Unicode 插件引用失败。

该 hosted-only 静态检查显式使用 `Python 3.12.10`：这是 `windows-2025` 当前可用的精确
3.12 patch 版本，用来运行 hash-locked 的检查依赖，并不改变产品 API/Worker 镜像固定的
Python 3.12.13，也不构成产品 Runtime 的供应链证明。

该工作流若在线成功，最高证据等级也只能是 **E1**。当前仅完成 workflow 源码和本地静态约束
测试，尚无 GitHub-hosted 实际运行记录。它不创建、上传或保留任何候选安装包；临时
`nonrelease-installer-preflight.exe`、其非发布资源、NSIS 和 Cargo 输出都只存在于
GitHub-hosted runner 的临时目录，并在作业结束前删除。

## 硬边界

该 workflow 只能由 `pull_request`、`main`/`agent/**` 的普通 push 或手动 dispatch 触发；
没有 tag trigger，手动选择 tag 时 job 也会跳过。顶层和 job 权限都固定为 `contents: read`，没有 GitHub Environment、
secrets、OIDC `id-token`、attestation、发布、签名、Docker/WSL2 调用或 artifact upload。

NSIS 只从官方 SourceForge 下载固定的 `nsis-3.11.zip`，并要求 SHA-256
`c7d27f780ddb6cffb4730138cd1591e841f4b7edb155856901cdf5f214394fa1`；下载、哈希、解压或
`makensis.exe` 定位失败即失败，不回退到 PATH、Chocolatey 或任意预装 NSIS。
这只限制开发工具输入，不能证明最终发布工具链、工具目录 ACL、TOCTOU、签名私钥或候选二进制的
来源可信。NSIS 在本预检中只是构建时工具，不随产品分发；其官方许可证为 zlib/libpng。
替代路径是正式 self-hosted 签名 runner 上由受控发布环境显式提供的 `MAKENSIS_PATH`，不能把
该路径或任意 PATH/Chocolatey 回退混入 hosted 预检。

构建 Launcher 前显式移除 `DES_RELEASE_MANIFEST_SHA256` 及 Cargo/Rust 常见编译覆盖。
用于 NSIS 的镜像锁与 release manifest 是刻意无效的临时占位输入；工作流不执行
`Setup.exe` 或 `launcher.exe`，也不尝试产生可安装制品。

`scripts/acceptance/test_windows_hosted_preflight.py` 会静态拒绝把该工作流扩展成 tag/
`pull_request_target`/schedule 触发、Environment/secrets/OIDC、签名、发布、Docker/WSL 或
artifact 上传通道。

## 它不能证明的事项

GitHub-hosted `windows-2025` 是 Windows Server，不是 V1 认证目标 Windows 11 x64 Client；
它也不提供真实 Docker Desktop + WSL2、本机用户配置、代码签名证书、可信时间戳、受控签名
runner、真实 MySQL/PostgreSQL 或 DataX Runtime。因此它不能证明：

- `Setup.exe`/`launcher.exe` 的 Authenticode 签名、时间戳、安装、升级、卸载或可交付性；
- Docker Desktop/WSL2 前置检查、Compose、loopback/LAN、睡眠/重启、备份恢复；
- 任意真实 DataX E3，或 `E2E-WIN-001` / `E2E-WIN-002` 的 Windows E4；
- ADR-0010 的受保护 signing Environment、self-hosted Windows E4 harness、候选根或 hosted
  provenance。

正式发布仍只能经 `.github/workflows/release.yml` 的专用 self-hosted Windows 签名路径和
ADR-0010/ADR-0011 要求的真实证据完成。当前签名 Environment、受限 Windows runner 和完整
Windows E4 仍为 `BLOCKED`；本预检的成功绝不能改变该状态。
