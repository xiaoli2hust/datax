# Windows 安装器

`DataXEnterpriseStudio.nsi` 生成 Windows 11 x64 的每用户 `Setup.exe`：

- 默认安装到 `%LOCALAPPDATA%\Programs\DataXEnterpriseStudio`；
- 安装签名 `launcher.exe`、固定 `compose.yaml`、发布镜像锁、受控 ACL helper 和
  带 SHA-256 的发布清单；
- 写入程序目录前，先在 NSIS 临时目录运行签名 Launcher：校验自身信任链、发布清单
  绑定、发布证书 DER SHA-256 允许集，并要求当前 `Setup.exe` 与 Launcher 由同一张
  允许证书签名；缺失、无效、证书不匹配或资源被替换时不写入程序目录；
- 创建桌面启动快捷方式、开始菜单启动/安全停止/卸载快捷方式；
- 安装前拒绝 Windows Server、Windows on Arm、Windows 10、安装卷空间不足和降级覆盖；
- 当前自动升级前备份/迁移尚未完成，因此旧版本覆盖升级会 fail closed，同版本修复也必须
  先安全停止；
- 不包含、不下载、不安装 Docker Desktop 或 WSL2，也不代替用户接受第三方条款；
- 卸载前调用 Launcher 的安全停止路径；活动 Attempt 时默认取消。若 Docker/Launcher
  缺失、离线或资源损坏导致无法验证停止，用户经过默认“否”的二次警告后仍可只卸载程序，
  页面明确提示容器可能继续运行；
- 卸载仅删除程序文件和快捷方式，保留
  `%LOCALAPPDATA%\DataXEnterpriseStudio` 及 Docker named volumes。

这是每用户安装模型：当前登录用户本身不属于该用户会话内的安全隔离边界。Launcher 每次
运行仍校验自身 Authenticode、编译期绑定的发布清单和发布资源摘要；本机密钥放在独立
`%LOCALAPPDATA%\DataXEnterpriseStudio\secrets` 受限目录，不放入程序目录。
安装器内校验是正式制品的纵深防御，不会把一个已经被替换、且主动删除核验逻辑的恶意
Setup 变成可信程序；用户/组织在首次执行前仍必须通过 Windows 签名界面或发布验证工具
核对固定发布证书 SHA-256 和发布页文件 SHA-256。当前用户或管理员完全控制宿主仍是
明确剩余风险。

正式候选由 `.github/workflows/release.yml` 在受保护的
`windows-candidate-signing` environment 中生成。除固定 digest 镜像锁、PFX 和 SHA-1
签名选择器外，必须配置
`WINDOWS_SIGNING_CERTIFICATE_SHA256_ALLOWLIST_JSON`。其格式固定为：

```json
{"schema_version":"1.0","allowed_authenticode_signer_certificate_sha256":["<64 lowercase hex>"]}
```

流水线先核验实际 PFX 证书 DER SHA-256 属于该受保护、严格排序去重的允许集，再由
`scripts/release/finalize_windows_publisher_binding.ps1` 生成清单 1.1、重建并用同一证书
签名 Launcher/Setup。Linux 阶段还必须先以全新空 `DOCKER_CONFIG`、不继承 registry
凭据的方式匿名拉取五个固定 digest，并生成与镜像锁一致的
`anonymous-image-pulls.json`；任一镜像只能登录后读取时不进入 Windows 签名阶段。最后由
`scripts/release/verify_windows_publisher_binding.ps1` 和 Launcher 独立复核。直接运行
`scripts/windows/build-installer.ps1` 只会生成清单 1.0 的中间制品；新版 Launcher 会
fail closed，该路径不能作为正式或可安装发布物，也不存在 unsigned 发布路径。

输出名固定为 `DataX-Enterprise-Studio-Setup-<version>-x64.exe`。Launcher 已接入
一次性 Admin helper/Windows 原生引导对话框，但尚无真实 Windows 验收。由于仓库所有者
尚未选择原创代码许可证、固定发布镜像仍未生成、兼容升级闭环未交付，当前目录只是
fail-closed 安装器骨架，不是可发布安装包。即使构建成功，仍需在干净 Windows 11 x64
机器完成签名/时间戳、安装、启动、首次引导、实际端口、安全停止、数据保留、睡眠/恢复、
卸载及真实 DataX 验收。
