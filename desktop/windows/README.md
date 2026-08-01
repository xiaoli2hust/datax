# Windows Launcher

`launcher.exe` 是 Windows 11 x64 本地生命周期控制器，不承载业务状态，也不
直接运行 DataX。

默认行为：

1. 取得 Windows named mutex，阻止并发 Launcher。
2. 通过 Win32 原生架构和 ProductType 校验 Windows 11 客户端 AMD64，明确拒绝
   Windows Server 与 Windows on Arm 仿真；同时检查硬件虚拟化、SLAT、内存和 40 GiB
   可用磁盘水位。
3. 从 HKLM Docker Desktop 安装记录和受信 Program Files 根定位 `docker.exe`，逐级拒绝
   reparse point/当前用户可写目录，并校验 Authenticode 信任链与 Docker 发布者；不使用
   PATH/当前目录命中。Compose 也直接调用同一安装根中的已签名固定插件，不走用户插件
   搜索路径。
4. 校验 WSL2、Docker Desktop 本机 Linux/amd64 Engine、named-pipe context 和 Compose v2。
5. Launcher 自身必须有有效 Authenticode；其编译期摘要绑定
   `resources/release-manifest.json`。清单 `schema_version=1.1` 除锁定
   `compose.yaml`、`images.release.env` 和 `secure-acl.ps1` 外，还包含 1–8 个严格排序、
   去重的小写发布证书 DER SHA-256。Launcher 要求恰好一个主 Authenticode 签名者，
   同时验证 Windows 信任链和证书 SHA-256 允许集；仅由任意其他受信证书签名仍会拒绝。
   安装器内部使用 `verify-release --installer <Setup.exe>`，要求 Setup 与 Launcher 的
   实际证书 SHA-256 完全相同。五个镜像只能使用固定允许仓库的
   `repository@sha256:<64 lowercase hex>`。
6. 首次初始化先以 `create_new` 写入 ACL 受控的
   `%LOCALAPPDATA%\DataXEnterpriseStudio\initialization-incomplete`，其中保存本次
   32-byte OS CSPRNG 安装实例标识；在服务或 PostgreSQL 启动前，先完整生成并验证全部
   secret，再以同一标识创建并核验 `des-postgres-data`、`des-log-data`、
   `des-workspace-data` 三个卷，最后提交 `installation-id` 并清除初始化日志。中途崩溃
   只在日志仍有效、当前没有任何产品/数据卷容器、已存在卷标签与日志一致，而且卷一旦
   出现时全部 secret 已完整的条件下补齐；只存在未提交 secret 且零卷时可整组重新生成。
   任何矛盾都 fail closed，绝不自动删除卷、容器或可能已有数据。正常启动时三个卷必须
   同时存在并与当前安装实例/各自 volume-role 匹配；Docker 被重置、卷部分丢失、标签
   不符或已有卷却缺失实例标识时不会自动创建空库覆盖旧状态。
   Launcher 在 `%LOCALAPPDATA%\DataXEnterpriseStudio\secrets` 中以 `create_new`
   创建彼此独立的强随机 PostgreSQL 管理密码、出口守卫只读数据库密码、API 数据库
   角色密码与 Worker 数据库角色密码、
   Ed25519 PKCS#8/SPKI JWT 密钥对、32-byte
   refresh-token HMAC key、独立的 32-byte idempotency HMAC key，以及独立的 32-byte
   数据源凭据 KEK。三把对称密钥使用各自的 OS CSPRNG 取样和文件，不能复用。DACL
   会被重建并回读验证，只允许当前用户和 `SYSTEM`，拒绝 UNC/reparse point；已有数据卷
   缺失密钥、部分密钥束、公私钥不匹配、对称密钥相同或异常长度均 fail closed，不生成
   替代密钥。
7. 以固定 image env、project name 和参数数组执行 Compose；渲染配置、Docker 实际绑定
   和 Windows `netstat` IPv4/IPv6 监听都必须证明只有 Web 映射
   `127.0.0.1:17860`；渲染配置还必须逐项匹配每个 service 的 secret `source/target`，
   PEM target 不能退化成短语法。Launcher 还拒绝
   `DES_EGRESS_ENFORCEMENT_VERIFIED` 这类可伪造布尔值，要求只有 `egress-guard`
   获得 `NET_ADMIN`，API/Worker 均 `cap_drop=ALL` 并精确使用
   `network_mode: service:egress-guard`；启动后读取三者实际 `/proc/self/ns/net`，不一致
   立即停止。API live 后会在容器内只检查自己的数据库密码、JWT/HMAC 与 KEK 固定
   target，Worker 只检查自己的数据库密码与凭据 KEK，守卫只检查独立只读数据库密码；
   都只核验普通文件类型和长度，
   不读取或输出 secret 内容。`0.0.0.0`、`::`、`::1` 或其他地址会触发停止并失败。所有外部命令输出
   都有界读取；读失败或超过上限时整体失败关闭，不允许用部分输出完成端口、签名、
   Compose 或依赖安全判定。
8. 先等待 live，再调用容器内固定 lifecycle `resume`，最后等待 ready=200。`UP` 表示
   可运行任务；`DEGRADED` 只开放管理页面和诊断，执行仍由后端失败关闭；持续
   `503/DOWN` 才阻断打开页面。
9. ready 后调用固定 `datax-studio-bootstrap-admin --status --json`。仅空用户库显示
   Windows 原生首次 Admin 对话框；邮箱和显示名使用参数数组，密码只经受控子进程标准
   输入单行传递，内存缓冲在使用后清零。创建成功还会再次执行只读状态复核。
10. 只有首次引导已完成或本就不适用时才打开 `http://127.0.0.1:17860`；取消引导、
    矛盾 helper 状态或持续 503 都不会打开浏览器或伪装成功。

受控 secret 文件契约：

| 文件 | 格式 | Compose 挂载 |
|---|---|---|
| `postgres_password.txt` | 32-byte 随机数的小写 hex，共 64 bytes、无换行 | `/run/secrets/postgres_password` |
| `egress_guard_database_password.txt` | 与 PostgreSQL 管理密码独立的 32-byte 随机数小写 hex，共 64 bytes、无换行 | `/run/secrets/egress_guard_database_password`（仅迁移与守卫） |
| `api_database_password.txt` | 与其他数据库角色独立的 32-byte 随机数小写 hex，共 64 bytes、无换行 | API `/run/secrets/database_password`；迁移容器读取固定原名 |
| `worker_database_password.txt` | 与其他数据库角色独立的 32-byte 随机数小写 hex，共 64 bytes、无换行 | Worker `/run/secrets/database_password`；迁移容器读取固定原名 |
| `jwt_private_key.pem` | Ed25519 PKCS#8 PEM | `/run/secrets/jwt_private_key.pem` |
| `jwt_public_key.pem` | 对应 Ed25519 SPKI PEM | `/run/secrets/jwt_public_key.pem` |
| `refresh_token_hmac_key` | 独立 32-byte 随机原始二进制 | `/run/secrets/refresh_token_hmac_key` |
| `idempotency_hmac_key` | 另一把独立 32-byte 随机原始二进制 | `/run/secrets/idempotency_hmac_key` |
| `credential-kek-v1.key` | 与两把 HMAC key 独立的 32-byte 随机原始二进制 | `/run/secrets/credential-kek-v1.key`（API 与 Worker） |

停止：

- `launcher.exe stop`：先调用
  `python -m datax_studio.lifecycle preflight-stop --json`；存在活动 Execution/
  RecoveryProbe 时 fail closed。停止路径不执行启动专用的 40 GiB、内存、虚拟化、WSL2
  或 secret 生成门禁；固定 project 不存在时幂等成功。
- `launcher.exe stop --force`：显示不可跳过的风险确认，再执行不带
  `--volumes` 的 `compose down`。下次启动由 reconciler 处理 `LOST` 与恢复门禁。

系统备份导出：

```text
launcher.exe backup ^
  --data-output C:\DataXBackup\data ^
  --secrets-output D:\DataXBackup\secrets ^
  --data-key C:\OfflineKeys\data.key ^
  --secrets-key D:\OfflineKeys\secrets.key
```

- 两个输出目录必须是父目录已存在、但自身尚不存在的新叶子目录；Launcher 创建后才重建
  DACL，因此不会改写已有目录权限。输出目录和两个 key 文件必须位于本地盘、无
  reparse point、彼此不重叠；两个 key 必须是不同的 64-byte 小写 hex 且无换行。
  Launcher 只允许当前用户与 `SYSTEM` 访问新目录及 key 文件，并拒绝 key 路径位于安装/
  应用数据/运行 secret 目录，或 key 值复用数据库密码、JWT、HMAC、KEK 及其十六进制编码。
- Launcher 先进入 draining 并确认没有活动 Execution/RecoveryProbe，停止应用写入，
  用固定 PostgreSQL 容器生成
  `pg_dump --format=custom --compress=0 --serializable-deferrable`，再停止 PostgreSQL。
  Worker helper 以 `network=none`、只读根文件系统和 `cap_drop=ALL` 运行。
- `.dxdata` 只含一致性逻辑 dump、`des-log-data` 脱敏日志和三个固定发布元数据；
  `des-workspace-data`、任何 `job.json` 与物理 PostgreSQL volume 永不挂载到 helper。
  helper 会用全部私密运行 secret 做精确泄露扫描，并对日志做结构化二次脱敏检查。
- `.dxkeys` 单独保存九个固定运行 secret 与受支持 KEK，并通过
  `related_data_backup_id` 绑定 DATA 包。任一分包失败会失败关闭；临时明文 dump 位于
  受控随机 staging，成功或失败后均必须清理，否则返回高优先级阻断错误。
- 内部 helper 已能对双包做完整认证、配对与版本/发布摘要校验，使用双恢复秘密认证的
  journal 解包到全新空 staging，并在成功 staging 后返回
  `RESTORE_STAGED_COMMIT_BLOCKED`。这不是 PostgreSQL 恢复，也不会触碰运行卷。
- `launcher.exe restore --data-input ... --secrets-input ... --data-key ... --secrets-key ...`
  仅作为稳定失败关闭入口，固定返回
  `RESTORE_ATOMIC_VOLUME_COMMIT_UNAVAILABLE`，不读取 key、不停止服务、不创建 staging。
  新空 named volume、隔离 `pg_restore`、证据重算、原子提交及干净 Windows 11 x64
  异机演练完成前，Launcher 恢复和覆盖升级继续关闭。
  详细契约见
  [`../../docs/contracts/system-backup.v1.md`](../../docs/contracts/system-backup.v1.md)。

当前依赖均锁定在 `Cargo.lock`：

| 依赖 | 用途 | 许可证 | 不采用的替代 |
|---|---|---|---|
| `getrandom` | OS CSPRNG | MIT / Apache-2.0 | 不使用时间戳、伪随机或 PowerShell 拼 secret |
| `ed25519-dalek` | 生成、编码并核验 Ed25519 PKCS#8/SPKI 密钥 | BSD-3-Clause | 不依赖宿主 OpenSSL/临时命令 |
| `serde` / `serde_json` | 严格读取发布清单和 lifecycle JSON | MIT / Apache-2.0 | 不手写宽松 JSON 解析 |
| `sha2` | 校验发布资源和 Authenticode 签名证书 DER SHA-256 | MIT / Apache-2.0 | 不只检查文件存在或发布者显示名 |
| `wait-timeout` | 给固定外部进程设置有界等待 | MIT / Apache-2.0 | 不允许 Docker/WSL 命令无限挂起 |
| `zeroize` | 清理密码、私钥和 HMAC 临时缓冲 | MIT / Apache-2.0 | 不依赖普通 drop 后内存立即覆盖 |

macOS 只能执行静态检查和单元测试：

```text
cargo check --manifest-path desktop/windows/Cargo.toml --all-targets
cargo test --manifest-path desktop/windows/Cargo.toml
cargo check --manifest-path desktop/windows/Cargo.toml \
  --target x86_64-pc-windows-msvc --all-targets
cargo clippy --locked --manifest-path desktop/windows/Cargo.toml \
  --target x86_64-pc-windows-msvc --all-targets -- -D warnings
```

当前明确未完成：

- 无本次真实固定发布镜像 digest、受保护发布证书允许集、实际代码签名和干净
  Windows 11 x64 验收证据；
- Windows Runtime/FFI（包括首次 Admin 原生对话框）、Docker/WSL2、安装/卸载、
  nftables/selected-IP 租约 15 秒失效、睡眠/恢复、系统备份导出和真实 DataX 链路尚未
  实机验证；
- 兼容升级的数据迁移/回退流程与仓库原创代码许可证仍未由所有者闭合。

因此这些检查不等于 Windows 发布验收。
