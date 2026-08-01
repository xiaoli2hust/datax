# Windows 本地系统备份 V1 内部契约

本契约只描述签名 Windows Launcher 通过固定 Worker 镜像调用的系统级备份 helper。它不
进入产品 OpenAPI，也不允许浏览器直接读取宿主密钥或 Docker volume。业务执行的
RecoveryGate 与这里的系统灾难恢复不是同一概念。

## 1. 当前证据边界

仓库已有 DATA/SECRETS 分包、加密包格式、归档 allowlist、二次秘密扫描和单元测试。
内部 helper 现在还能把经过认证且严格配对的双包解到一个全新的空 staging，并创建由
两把恢复秘密共同认证的 restore journal；该能力只达到 E1
`IMPLEMENTED_STAGING_ONLY`。新空 PostgreSQL named volume、`pg_restore`、数据库/审计链
证据重算、日志与 secrets 的原子提交、签名安装包集成、实际 Docker named volume 演练、
异机 Windows 11 x64 恢复与 RPO/RTO 仍为 `NOT_RUN/BLOCKED`。

因此普通单包 `restore_package` 固定返回 `RESTORE_PAIR_REQUIRED`。内部
`stage-restore-pair` 成功完成认证与解包后也必须返回非成功状态
`RESTORE_STAGED_COMMIT_BLOCKED`；Launcher 接受完整 restore 参数只用于返回稳定的
`RESTORE_ATOMIC_VOLUME_COMMIT_UNAVAILABLE`，不得启动 staging、覆盖卷或开放升级。代码、
journal 或 staging 文件存在都不能表述为“Windows 可恢复门禁已通过”。

## 2. 停写与一致性边界

- Launcher 先调用固定 lifecycle helper 进入 draining，证明没有活动 Execution 或
  RecoveryProbe，再停止 `web/api/worker/egress-guard`；PostgreSQL 只在生成逻辑备份时
  保持运行。
- 数据库必须由固定 PostgreSQL 容器执行参数数组形式的
  `pg_dump --format=custom --compress=0 --serializable-deferrable` 并取得单一一致性
  快照；禁用 dump 压缩是为了让导出前的部署 secret 精确 byte 扫描可执行。helper 只接受
  以 `PGDMP` 开头的普通文件，不接受物理
  `des-postgres-data` volume 归档。
- 逻辑 dump 的宿主 staging 文件必须位于 Launcher 创建的受限 ACL 随机目录；分包完成或
  失败后都必须清理。该短暂明文 staging 是尚待真实 Windows 验收的残余风险，不得伪装为
  “从不落明文”。
- DATA/SECRETS 输出路径必须是父目录已存在但自身尚不存在的新叶子目录，由 Launcher
  创建后收紧 ACL；不得为备份改写用户已有目录的权限。
- helper 只能来自发布锁定的 Worker `repository@sha256:<64 hex>` 镜像，使用参数数组，
  `network=none`、只读根文件系统、`cap_drop=ALL`、`no-new-privileges`。
- 密码只经标准输入传给一次性 helper，不得进入参数、环境、日志、JSON 结果或 Git。
- DATA/SECRETS 两把恢复 key 必须与安装目录、应用数据目录和运行 secret 目录路径分离，
  并与全部数据库密码、JWT、HMAC、KEK 及 32-byte secret 的十六进制编码做值域分离。

## 3. DATA 固定 allowlist

DATA 包只允许以下归档项：

| 归档路径 | 来源 | 约束 |
|---|---|---|
| `database/postgres.dump` | 一致性 `pg_dump` custom-format 文件 | 普通文件、`PGDMP` magic、长度和 SHA-256 与清单一致 |
| `logs/` | 只读 `des-log-data` | 只允许 `<execution UUID>/<attempt UUID>.log` |
| `metadata/compose.yaml` | 发布制品 | 固定文件、大小和 SHA-256 与清单一致 |
| `metadata/images.release.env` | 发布制品 | 固定文件、大小和 SHA-256 与清单一致 |
| `metadata/release-manifest.json` | 发布制品 | 固定文件、大小和 SHA-256 与清单一致 |

下列对象绝不进入 DATA 包：

- `des-workspace-data`、任何运行时工作目录或 `job.json`；
- `des-postgres-data` 物理卷、数据库数据目录、WAL 或 Docker volume tar；
- Launcher keyring、数据库密码、JWT 私钥、HMAC、KEK、数据源明文凭据；
- 未知元数据文件、链接、设备、FIFO、socket 或未声明归档路径。

导出 DATA 前，helper 必须读取并校验固定 secret 集合但不得将其归档，用于：

1. 在 dump、日志和发布元数据中搜索当前部署秘密的精确 byte 值；
2. 对日志再次运行与 Worker 相同的结构化脱敏器；
3. 拒绝私钥标记、DataX `job/reader/writer` 组合和任何 `job.json` 路径。

发现疑似泄露时返回 `BACKUP_SECRET_LEAK_DETECTED` 或
`BACKUP_DATA_ALLOWLIST_REJECTED`，且不得发布 `.dxdata`。

## 4. DATA/SECRETS 分包

一次受控备份固定产生两类包：

| 包 | 后缀 | 内容 | 保管要求 |
|---|---|---|---|
| 数据包 | `.dxdata` | PostgreSQL 逻辑 dump、脱敏日志、固定发布/迁移元数据 | 可放入受控备份介质 |
| 密钥包 | `.dxkeys` | PostgreSQL 管理密码、egress-guard/API/Worker 独立数据库角色密码、JWT 密钥、HMAC、全部受支持 KEK | 与数据包分开保管 |

两包必须使用不同的高熵恢复秘密。密钥包通过
`related_data_backup_id` 精确绑定数据包；检查时还要比较 `installation_id`、产品版本和
迁移版本。缺包、错包、错密码、密钥集合不完整、公私钥不匹配、四类数据库角色密码/
HMAC/KEK 任意重用或未知密钥对象一律失败关闭。`installation_id` 位于加密清单内，不以
明文文件名泄露。

## 5. 加密与归档完整性

- 外层固定为 `ARGON2ID-1.3`（64 MiB、3 次、并行度 1）派生的
  `AES-256-GCM-CHUNKED`；salt 16 bytes、nonce prefix 8 bytes，每块最大 1 MiB。
- nonce 为 `prefix || uint32_be(counter)`；AAD 为
  `SHA-256(完整包头) || counter || plaintext_length`。零长度加密块是唯一结束标记。
- 缺少结束标记、截断、重排、重复、篡改、超长块或结束后附加数据均拒绝。
- 内层是流式 PAX tar。第一项必须是 `manifest.json`；拒绝绝对路径、`..`、反斜杠、
  重复路径、符号/硬链接、设备、FIFO 和 socket。
- 脱敏日志树保存规范路径、mode、长度和文件 SHA-256 形成的 `tree_sha256`；数据库 dump
  单独保存 format、长度和 SHA-256。清单结构符合
  [`system-backup-manifest.v1.schema.json`](./system-backup-manifest.v1.schema.json)。
- 包先写随机 `.partial`，`fsync` 后以不覆盖已有目标的方式发布。任何错误不得返回
  `BACKUP_CREATED`。

## 6. 恢复与升级门禁

恢复实现必须同时具备：

1. 受 ACL 保护、可恢复的 restore journal；
2. 全包认证、版本/包对检查和恢复前空间检查；
3. 新建且为空、带当前安装 role 标签的目标 named volumes；
4. 在空 PostgreSQL 目标上执行 `pg_restore`，重算数据库、审计链、日志与密钥证据；
5. staging secrets、installation-id 和目标 volumes 的原子提交；
6. 中断后只允许使用同一包对和秘密继续，或只清理由 journal 记录的 staging 对象。

以上门禁及干净 Windows 11 x64 异机演练完成前，恢复和覆盖升级必须保持失败关闭。普通
`start` 不得把部分恢复当作全新安装，也不得生成替代 KEK。

### 6.1 当前已实现的内部 staging 边界

内部 Worker 镜像提供：

```text
datax-studio-system-backup stage-restore-pair \
  --data-input /restore/input/data.dxdata \
  --secrets-input /restore/input/secrets.dxkeys \
  --staging-root /restore/staging \
  --journal /restore/journal/restore.json \
  --expected-product-version <exact-version> \
  --expected-migration-revision <exact-revision> \
  --expected-release-manifest-sha256 <launcher-bound-sha256>
```

- DATA 与 SECRETS 的恢复秘密按该顺序作为恰好两行标准输入传入；不得进入参数、环境、
  journal 或结果。两把秘密必须不同，且在 SECRETS 解包后再次证明没有复用任一数据库
  密码、JWT、HMAC、KEK 或 32-byte secret 的十六进制编码。
- helper 先完整认证两包，核对 `related_data_backup_id`、`installation_id`、产品版本、
  迁移版本，并把 DATA 中 `release-manifest.json` 的 SHA-256 与已签名 Launcher 内置绑定值
  比较。该比较只证明包内发布元数据属于当前已签名制品；helper 自身不能替代 Launcher 的
  Authenticode 校验。
- staging 根必须是已存在、非链接且为空的目录；包、journal 与 staging 路径必须分离。
  helper 只以 `O_EXCL/O_NOFOLLOW` 新建 `0600` 文件和受限目录，重新验证 tar allowlist、
  每个文件长度/摘要、PGDMP magic、日志布局和完整 secrets 集。
- journal 固定使用 `HMAC-SHA256`；先分别用每个包头已经认证的 Argon2id 参数/salt 派生
  DATA/SECRETS key，再以 `DXES-RESTORE-JOURNAL-HMAC-v1` 域派生 journal key，不能用快速
  哈希直接把 journal 变成恢复秘密的低成本离线验证器。journal 记录两包 SHA-256/长度/
  backup ID/KDF salt、
  预期版本、installation-id、staging 绝对路径和单调事件。已有 journal 只有在认证通过且
  上述身份完全一致时才能清理由该 journal 限定的 `data/`、`secrets/` staging 后重新开始；
  未知对象、链接或特殊文件一律阻断清理。
- `cleanup-restore-staging` 同样要求两行恢复秘密并认证 journal，只删除其 staging 根下
  固定 `data/`、`secrets/`；不删除 journal、包、运行 secret 或 Docker volume。
- 完成双包 staging 后 journal 状态为 `STAGED_COMMIT_BLOCKED`。结果明确要求下一门禁
  `PG_RESTORE_NEW_EMPTY_VOLUME_AND_ATOMIC_COMMIT`，helper 不返回“恢复成功”。

### 6.2 尚未实现且继续阻断的提交边界

当前 Compose 把三个运行卷固定命名为
`des-postgres-data/des-log-data/des-workspace-data`，也没有一个经 journal 认证、可原子
切换的 active-volume pointer。Docker named volume 本身不提供安全 rename/compare-and-swap。
在没有先设计并验收该提交协议前，Launcher 不能把 staging 数据复制进固定活跃卷，也不能
删除、改名或重建这些卷。

此外，现有首次 `start` 流程会生成新 installation-id、运行 secrets 和固定卷；异机恢复
必须新增一个在首次初始化提交前执行、且不会生成替代 KEK/密码或固定卷的 clean-restore
模式。当前失败关闭的 `restore` 分支特意位于 secrets/volume 初始化之前，但尚未拥有下面
的 staging-volume 提交能力。

后续实现至少必须在产品服务和出站网络完全停止的隔离阶段：

1. 以随机名创建带 installation-id、role 和 restore-journal-id 标签的新空 PostgreSQL、
   日志与 workspace 卷，并证明没有产品容器引用；
2. 在 `network=none` 或只含临时 PostgreSQL 的专用隔离网络中初始化空数据库，以参数数组
   执行 `pg_restore --exit-on-error --single-transaction --no-owner --no-privileges`；
3. 在 staging 数据库上执行迁移版本、约束、行数、审计链、JobVersion/Execution、日志、
   Envelope/KEK 解密探针和发布制品证据重算；
4. 以崩溃可恢复的单一提交点切换 installation-id、secret 目录和三个 active volume
   引用；提交前任何失败只清理 journal 记录的新对象，提交后失败可明确回滚到完整旧集合；
5. 在干净 Windows 11 x64 上覆盖掉电、Docker/WSL2 中断、错包/错密码/错版本、空间不足、
   `pg_restore` 失败、证据失败、提交中断和旧卷保留的 E4 演练。

上述协议未完成前，`launcher.exe restore ...` 必须稳定返回
`RESTORE_ATOMIC_VOLUME_COMMIT_UNAVAILABLE` 且不读取恢复 key、不停止服务、不创建 staging
对象、不修改运行卷。
