# Windows 安装器

`DataXEnterpriseStudio.nsi` 生成 Windows 11 x64 的每用户 `Setup.exe`：

- 固定安装到 `%LOCALAPPDATA%\Programs\DataXEnterpriseStudio`；`.onInit` 拒绝 NSIS
  默认 `/D=<path>` 覆盖，`CRCCheck force` 拒绝 `/NCRC` 跳过自身损坏校验（CRC 不是
  Authenticode 信任证明）；
- 安装签名 `launcher.exe`、固定 `compose.yaml`、发布镜像锁、受控 ACL helper 和
  带 SHA-256 的发布清单；
- 写入程序目录前，先在 NSIS 临时目录运行签名 Launcher：校验自身信任链、发布清单
  绑定、发布证书 DER SHA-256 允许集，并要求当前 `Setup.exe` 与 Launcher 由同一张
  允许证书签名；缺失、无效、证书不匹配或资源被替换时不写入程序目录；
- 创建桌面启动快捷方式、开始菜单启动/安全停止/卸载快捷方式；
- 安装前拒绝 Windows Server、Windows on Arm、Windows 10、安装卷空间不足和降级覆盖；
- 当前自动升级前备份/迁移尚未完成，因此旧版本覆盖升级会 fail closed；同版本修复先在
  临时目录完成候选 Setup/Launcher/资源核验，才安全停止旧服务，并用 no-skip、显式解除
  受控资源只读属性的方式修复，任一步失败都中止；
- 不包含、不下载、不安装 Docker Desktop 或 WSL2，也不代替用户接受第三方条款；
- 卸载前调用 Launcher 的安全停止路径；活动 Attempt 时默认取消。若 Docker/Launcher
  缺失、离线或资源损坏导致无法验证停止，用户经过默认“否”的二次警告后仍可只卸载程序，
  页面明确提示容器可能继续运行；
- 卸载从当前用户注册表记录重新绑定固定安装根（避免临时 self-copy 指向错误路径），仅删除
  程序文件和快捷方式，保留
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

签名 job 还必须只使用 `datax-release-signing` runner group 中带精确 Windows 标签的机器，
并显式提供本机固定盘、非重解析的 `CARGO_PATH`、`RUSTC_PATH`、`MAKENSIS_PATH` 与
`SIGNTOOL_PATH`。导入 PFX 前会拒绝 dirty/untracked checkout、Cargo wrapper/flags/target/home
环境覆盖；Cargo 进程把 `RUSTC` 固定为 `RUSTC_PATH`。这只是 PATH 和常见环境注入的 E1
失败关闭：拒绝环境 `CARGO_HOME` 仍会回落到 runner profile 的默认 Cargo home，工具字节/
目录 ACL、链接器、TOCTOU 和私钥不可导出性必须由受控 runner provisioning 与 Windows E3/E4
证据单独证明。

流水线先核验实际 PFX 证书 DER SHA-256 属于该受保护、严格排序去重的允许集；
`scripts/windows/build-installer.ps1` 必须显式接收同一份 `-AllowedSignerFile`，并只会生成
包含该 allowlist 的清单 `1.1`、由同一证书签名的 Launcher/Setup。随后
`scripts/release/finalize_windows_publisher_binding.ps1` 再次校验该 allowlist，并重建、重签
最终发布绑定。Linux 阶段还必须先以全新空 `DOCKER_CONFIG`、不继承 registry 凭据的方式
匿名拉取五个固定 digest，并生成与镜像锁一致的 `anonymous-image-pulls.json`；任一镜像只能
登录后读取时不进入 Windows 签名阶段。最后由
`scripts/release/verify_windows_publisher_binding.ps1` 和 Launcher 独立复核。直接运行构建器
缺少/非法 allowlist 或不在 allowlist 内的签名证书均失败关闭；即使得到已签名候选，也没有
unsigned 发布路径，且候选本身不等于已完成 Windows E4 或可正式交付的发布物。

输出名固定为 `DataX-Enterprise-Studio-Setup-<version>-x64.exe`。`/D`、`/NCRC`、候选先验签、
只读 repair 与卸载根绑定目前由 `scripts/acceptance/test_windows_installer_source.py` 静态检查，
仅为 E1；未在 Windows 上用 NSIS 编译或执行签名 Setup，不能称为安装验收。Launcher 已接入
一次性 Admin helper/Windows 原生引导对话框，但尚无真实 Windows 验收。由于仓库所有者
尚未选择原创代码许可证、固定发布镜像仍未生成、兼容升级闭环未交付，当前目录只是
fail-closed 安装器骨架，不是可发布安装包。即使构建成功，仍需在干净 Windows 11 x64
机器完成签名/时间戳、安装、启动、首次引导、实际端口、安全停止、数据保留、睡眠/恢复、
卸载及真实 DataX 验收。
