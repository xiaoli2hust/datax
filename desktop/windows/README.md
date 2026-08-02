# Windows Launcher

`launcher.exe` 是 Windows 11 x64 本地生命周期控制器，不承载业务状态，也不
直接运行 DataX。

默认行为：

1. 取得 Windows named mutex，阻止并发 Launcher。
2. 通过 Win32 原生架构和 ProductType 校验 Windows 11 客户端 AMD64，明确拒绝
   Windows Server 与 Windows on Arm 仿真；同时检查硬件虚拟化、SLAT、内存和 40 GiB
   本地 Launcher 配置/备份目录的可用磁盘水位。该 40 GiB 不是 Docker Desktop 数据盘
   或 named volume 容量的证明。
3. 从 HKLM Docker Desktop 安装记录和受信 Program Files 根定位 `docker.exe`，逐级拒绝
   reparse point/当前用户可写目录，并校验 Authenticode 信任链与 Docker 发布者；不使用
   PATH/当前目录命中。Compose 也直接调用同一安装根中的已签名固定插件，不走用户插件
   搜索路径。
4. 校验 WSL2、Docker Desktop 本机 Linux/amd64 Engine、named-pipe context 和 Compose v2。
   受控 Docker/Compose 子进程不继承用户 `DOCKER_CONFIG`、context、TLS/认证、
   `DOCKER_DEFAULT_PLATFORM`、BuildKit、上/小写 proxy 或 Compose
   env-file/project/profile/行为/输出覆盖；只接收 Launcher 派生的值、匿名 CLI config 和
   已验证 local pipe。Docker Desktop daemon 的组织代理属于独立前置。此项目前是 E1 代码
   契约，尚未由 Windows Docker Desktop 实测。
5. Launcher 自身必须有有效 Authenticode；其编译期摘要绑定
   `resources/release-manifest.json`。清单 `schema_version=1.1` 除锁定
   `compose.yaml`、`images.release.env` 和 `secure-acl.ps1` 外，还包含 1–8 个严格排序、
   去重的小写发布证书 DER SHA-256。Launcher 要求恰好一个主 Authenticode 签名者，
   同时验证 Windows 信任链和证书 SHA-256 允许集；仅由任意其他受信证书签名仍会拒绝。
   安装器内部使用 `verify-release --installer <Setup.exe>`，要求 Setup 与 Launcher 的
   实际证书 SHA-256 完全相同。五个镜像只能使用固定允许仓库的
   `repository@sha256:<64 lowercase hex>`。
6. 首次初始化先以 `create_new` 写入 ACL 受控的
   `%LOCALAPPDATA%\DataXEnterpriseStudio\initialization-incomplete` FRESH journal。journal
   固定一个随机 `RuntimeGeneration`：generation id、installation identity、
   `generations/<generation-id>/secrets` 和三个随机 `des-*-<generation-id>` 卷名。
   服务或 PostgreSQL 启动前，Launcher 只从此 journal 派生并完整生成/验证全部 secret，
   再以同一 identity 创建、核验三个随机卷；最后以不覆盖、write-through rename 提交
   `runtime-generation.json`，再清除 journal。FRESH 不读写 root `installation-id`、root
   `secrets/` 或固定 LEGACY 卷；活动 pointer 是启动、Compose 和后续运行时唯一的当前来源。
   断电/崩溃只可继续相同 journal：只有三个该 generation 卷都不存在时才可生成零 secret 集；
   任一卷已存在则必须已有完整同代际 secret，绝不替换 identity/secret/卷名。半套 secret、卷标签
   不符、pointer 不一致或旧式残留都 fail closed，绝不自动删除卷、容器或可能已有数据。journal
   仅为 Launcher 内部状态，未新增公开 API/JSON Schema；活动 pointer 仍由
   `runtime-generation.v1.schema.json` 约束。
   在选择 FRESH/LEGACY 前，以及读取 FRESH journal 或活动 pointer 后，Launcher 都同时枚举全部
   Docker volume 名和带 `com.xiaoli.datax.volume-role` 标签的 volume：全新 FRESH 不允许任何此类
   旧对象；一次性 LEGACY 迁移只允许三条固定 LEGACY 卷；已有 journal/pointer 只允许其精确绑定的
   三条卷。额外的随机产品卷、固定卷或任意带该角色标签的未绑定卷均以
   `FRESH_INITIALIZATION_TARGET_NOT_CLEAN` 阻断，发生在 secret 或 volume 写入之前。journal、活动
   pointer 与 pending pointer 的存在性只以 `symlink_metadata` 判定：只有明确 `NotFound` 才是不存在；
   目录、链接/reparse point、悬空链接或元数据 I/O 异常均在 ACL 修改或 `create_new` 前失败关闭。
   活动 FRESH/RESTORE pointer 还必须通过无副作用的 root/generation exact-set 检查：root
   `installation-id`/`secrets/` 均不存在，`generations/` 只含当前 generation，generation 只含
   `secrets/`，后者只含十个固定 secret；任一 root LEGACY 对象、未知 sibling、未知 secret 或
   reparse/枚举异常均失败关闭。pending FRESH 仅可保留自身 generation 的空/部分已知 secret，且在
   写齐十项 secret、创建任一卷前再次复核。`ensure_runtime_secrets` 的 LEGACY 分支在 root marker、
   十个 secret 和三固定卷都已只读认证前，不会创建或修改运行 app-root 的 DACL，更不会创建 root
   `secrets/` 或修改其 ACL；认证通过后才可调整 root DACL，且调整后会再次认证同一集合。独立的
   `docker-cli-config`/`system-restore` 门禁不被误判为 generation sibling；前者是 Docker 子进程
   的独立受控配置，不能被表述为 LEGACY 运行对象预检已经涵盖了整个 Launcher 的所有文件副作用。
   已有候选安装只有在 root `installation-id`、root `secrets/` 和固定三卷全部通过身份检查时，
   才能一次性迁移成 `LEGACY` pointer；不会复制、移动或重命名旧对象。
   Launcher 在 FRESH 的 generation secret 目录（LEGACY 迁移时才为 root `secrets/`）中以
   `create_new` 创建彼此独立的强随机 PostgreSQL 管理密码、出口守卫只读数据库密码、API 数据库
   角色密码与 Worker 数据库角色密码、
   Ed25519 PKCS#8/SPKI JWT 密钥对、32-byte
   refresh-token HMAC key、独立的 32-byte idempotency HMAC key，以及独立的 32-byte
   数据源凭据 KEK；还生成与四个数据库角色密码值域分离的 32-byte 出口租约创建能力，
   其文件内容为 64 个小写十六进制字符。三把对称密钥使用各自的 OS CSPRNG 取样和文件，
   不能复用。DACL
   会被重建并回读验证，只允许当前用户和 `SYSTEM`，拒绝 UNC/reparse point；已有数据卷
   缺失密钥、部分密钥束、公私钥不匹配、对称密钥相同或异常长度均 fail closed，不生成
   替代密钥。
   `start` 与 `backup` 先确认五个锁定 Linux/amd64 镜像已缓存；仅缺失镜像通过匿名空
   Docker config 按 immutable digest 拉取，已缓存不访问 registry。预取完成后所有产品 `docker run`
   helper 与 `compose up` 都显式 `--pull=never`；缓存被并发 Docker 操作删除时必须失败关闭，
   不会在容量 admission 后重新下载。`start` 在上述活动代际
   和三卷 installation-id/role 以及 **local、无 options** driver 都已认证后、Compose `up`
   前，`backup` 在创建 staging 前，以固定、带 opaque name/双标签的 `docker run` 参数检查三个
   当前 generation named volume 的实际 `statvfs` 可用空间。探针只读挂载固定 `/probe/*`、
   `network=none`、无 secret、只读根、`0:0`、`cap_drop=ALL` 后仅加
   `DAC_READ_SEARCH` 以穿越 PostgreSQL `0700` 卷根、`no-new-privileges`、16 PID、64 MiB 与
   0.25 CPU，并以 `--pull=never` 运行固定 Python 脚本；任一 Docker/协议失败或任一卷不足
   200 GiB 均阻断。Linux 下该 capability 也可绕过普通文件读取和目录搜索权限，所以“脚本只执行
   `statvfs`”不等于卷内容被内核隔离；无写入/网络/secret 与固定 Worker digest/脚本共同限制受信
   probe 的行为。错误、超时或无效输出时仅按重新认证的 immutable ID 清理同名 probe 容器，不把
   安装目录余量当作 Docker 容量。容量失败时受控初始化或镜像缓存可能已经存在，但 Compose/业务
   数据库尚未启动。该控制当前只有 E1 单元/源码证据，尚未完成 Windows E4 的异盘、临界、耗尽、
   `0700` 权限、超时、残留与 cleanup 竞争验证。
7. 以固定 image env、project name 和参数数组执行 Compose；对任何已有同 project label
   容器，Launcher 在 `up`、`exec`、`stop`、`down` 或 cleanup 前均逐 ID 复核 project/service
   标签、仅允许且不重复的预期 service、精确锁定的 `Config.Image`，以及由已认证活动
   `RuntimeGeneration` 导出的 named-volume source/target 和 volume
   installation-id/role 标签。未知、重复、镜像/卷/代际不匹配或无法 inspect 时返回
   `COMPOSE_PROJECT_OWNERSHIP_UNVERIFIED`，不触碰现有容器；`down` 不使用
   `--remove-orphans`，启动失败 cleanup 也必须先重新认证。`exec` 与启动后的安全核验必须
   另外见到完整的预期 service 集；受认证的部分集合只允许 `up`/`down` 用于失败恢复。
   渲染配置、Docker 实际绑定
   和 Windows `netstat` IPv4/IPv6 监听都必须证明只有 Web 映射
   `127.0.0.1:17860`；渲染配置还必须逐项匹配每个 service 的 secret `source/target`，
   PEM target 不能退化成短语法。Launcher 还拒绝
   `DES_EGRESS_ENFORCEMENT_VERIFIED` 这类可伪造布尔值，要求只有 `egress-guard`
   获得 `NET_ADMIN`，API/Worker 均 `cap_drop=ALL` 并精确使用
   `network_mode: service:egress-guard`；启动后读取三者实际 `/proc/self/ns/net`，不一致
   立即停止。API live 后会在容器内只检查自己的数据库密码、JWT/HMAC 与 KEK 固定
   target，Worker 只检查自己的数据库密码、idempotency HMAC 与凭据 KEK，守卫只检查独立只读数据库密码；
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
| `egress_lease_creation_capability` | 与四个数据库角色密码独立的 32-byte 随机数小写 hex，共 64 bytes、无换行；不是租约 bearer token | guard、API、Worker 的 `/run/secrets/egress_lease_creation_capability`；只用于 guard `POST /v1/leases` 的创建者认证，绝不传给 DataX |
| `api_database_password.txt` | 与其他数据库角色独立的 32-byte 随机数小写 hex，共 64 bytes、无换行 | API `/run/secrets/database_password`；迁移容器读取固定原名 |
| `worker_database_password.txt` | 与其他数据库角色独立的 32-byte 随机数小写 hex，共 64 bytes、无换行 | Worker `/run/secrets/database_password`；迁移容器读取固定原名 |
| `jwt_private_key.pem` | Ed25519 PKCS#8 PEM | `/run/secrets/jwt_private_key.pem` |
| `jwt_public_key.pem` | 对应 Ed25519 SPKI PEM | `/run/secrets/jwt_public_key.pem` |
| `refresh_token_hmac_key` | 独立 32-byte 随机原始二进制 | `/run/secrets/refresh_token_hmac_key` |
| `idempotency_hmac_key` | 另一把独立 32-byte 随机原始二进制 | API 与 Worker `/run/secrets/idempotency_hmac_key`；Worker 仅用于控制面完整性，不获得 JWT 或 refresh-token key |
| `credential-kek-v1.key` | 与两把 HMAC key 独立的 32-byte 随机原始二进制 | `/run/secrets/credential-kek-v1.key`（API 与 Worker） |

停止：

- `launcher.exe stop`：先调用
  `python -m datax_studio.lifecycle preflight-stop --json`；存在活动 Execution/
  RecoveryProbe 时 fail closed。停止路径不执行启动专用的 40 GiB、内存、虚拟化、WSL2
  或 secret 生成门禁；不存在任何同 project 容器时幂等成功，但只要检测到标签容器就必须先
  通过上述归属认证，不能把未知容器当作“固定 project 已存在”后停止。
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
  Worker helper 以 `network=none`、只读根文件系统和 `cap_drop=ALL` 运行。每个 helper 有
  角色/不透明 ID 标签与不泄露安装身份的确定性名称；timeout、CLI/capture 或 helper 结果
  错误后，只能验证 immutable container ID 和双标签后强制删除该 ID。清理不能证明、标签
  不匹配或名称重用时返回 `HELPER_CLEANUP_FAILED`，不删未知容器或 named volume；当前仅 E1。
- `.dxdata` 只含一致性逻辑 dump、`des-log-data` 脱敏日志和三个固定发布元数据；
  `des-workspace-data`、任何 `job.json` 与物理 PostgreSQL volume 永不挂载到 helper。
  helper 会用全部私密运行 secret 做精确泄露扫描，并对日志做结构化二次脱敏检查。
- `.dxkeys` 单独保存九个固定非 KEK secret（含出口租约创建能力）与至少一个受支持 KEK；
  默认新安装因此有十个运行 secret 文件。它通过 `related_data_backup_id` 绑定 DATA 包。
  任一分包失败会失败关闭；临时明文 dump 位于
  受控随机 staging，成功或失败后均必须清理，否则返回高优先级阻断错误。
- 内部 helper 已能对双包做完整认证、配对与版本/发布摘要校验，使用双恢复秘密认证的
  journal 解包到全新空 staging，并在成功 staging 后返回
  `RESTORE_STAGED_COMMIT_BLOCKED`。这不是 PostgreSQL 恢复，也不会触碰运行卷。
- `launcher.exe restore --data-input ... --secrets-input ... --data-key ... --secrets-key ...`
  先证明目标没有旧身份、代际、运行 secret、产品容器或产品卷，再用固定 Worker 镜像在
  `network=none` 中认证/配对双包；两把 key 只通过恰好两行标准输入传递。成功只写受 ACL
  保护的 journal/staging 并返回 `RESTORE_STAGED_COMMIT_BLOCKED`，不创建运行卷。
  只要固定应用数据根下仍有 `system-restore`，后续普通 `start` 和 `backup` 都会在生成
  secret、installation-id、卷或读取备份源前返回 `RESTORE_IN_PROGRESS`；无法证明该根
  不存在时返回 `RESTORE_STATE_CHECK_FAILED`，不得回退成空白安装。
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
