# Windows 本地系统备份 V1 内部契约

本契约只描述签名 Windows Launcher 通过固定 Worker 镜像调用的系统级备份 helper。它不
进入产品 OpenAPI，也不允许浏览器直接读取宿主密钥或 Docker volume。业务执行的
RecoveryGate 与这里的系统灾难恢复不是同一概念。

## 1. 当前证据边界

仓库已有 DATA/SECRETS 分包、加密包格式、归档 allowlist、二次秘密扫描和单元测试。
内部 helper 现在还能把经过认证且严格配对的双包解到一个全新的空 staging，并创建由
两把恢复秘密共同认证的 restore journal；该能力只达到 E1
`IMPLEMENTED_STAGING_ONLY`。ADR-0008、运行代际机器契约、严格 Rust 解析/摘要/对象集合
校验、旧式完整集合到 `LEGACY` 活动指针的不覆盖原子提交，以及 Compose 从单一指针整组
注入 secret/installation-id/三个 volume name 已落地为工程候选。FRESH 首次初始化的源码/E1
切片也已使用严格内部 journal 创建随机 `RuntimeGeneration`、generation secret 目录和三个
随机卷，并以无覆盖 pointer 提交；该 journal 不是本契约的公开交换对象。`RESTORE` 的严格
构造器与活动快照也已用于 Compose 卷归属和本机备份的卷/secret/helper identity；这仍不等于
RESTORE 提交或可恢复性已实现。新空
PostgreSQL named volume、`pg_restore`、数据库/审计链证据重算、日志与 secrets 的原子
提交、签名安装包集成、实际 Docker named volume 演练、异机 Windows 11 x64 恢复与
RPO/RTO 仍为 `NOT_RUN/BLOCKED`。

本轮 `scripts/test-postgres-e2.sh` 在 disposable PostgreSQL 15 退出 `0`，其 PostgreSQL pytest 段
`30 passed`，并已让标准 `--exclude-schema=des_phase_a_qualification` dump 在空数据库 `pg_restore`
成功。该探针只证明 schema-exclusion 的 dump/restore 引用完整性；它不创建产品 named volume、不会
bootstrap 私有 ledger/issuance epoch，也不改变本节系统恢复仍为 `NOT_RUN/BLOCKED` 的结论。

因此普通单包 `restore_package` 固定返回 `RESTORE_PAIR_REQUIRED`。内部
`stage-restore-pair` 成功完成认证与解包后也必须返回非成功状态
`RESTORE_STAGED_COMMIT_BLOCKED`。Launcher 的完整 restore 参数入口已接入这一 E1 helper：
必须先证明没有旧身份、代际、运行 secret、产品容器或产品卷，只用固定无网络容器读取两行
标准输入中的恢复秘密，并在成功 staging 后继续返回同一阻断码；不得创建/覆盖卷或开放升级。代码、
journal 或 staging 文件存在都不能表述为“Windows 可恢复门禁已通过”。

## 2. 停写与一致性边界

- Launcher 先调用固定 lifecycle helper 进入 draining，证明没有活动 Execution 或
  RecoveryProbe，再停止 `web/api/worker/egress-guard`；PostgreSQL 只在生成逻辑备份时
  保持运行。
- **Phase-A public-row backup gate。** 当前 Launcher 在 `pg_dump` 前，及 `pg_dump` 成功后但
  PostgreSQL 尚在运行时，各执行一次固定的 `psql` 检查：`SELECT NOT EXISTS (SELECT 1 FROM
  public.executions WHERE authorization_mode = 'PHASE_A_HARNESS')`。只有精确 `t` 才可继续；任一
  `PHASE_A_HARNESS` 行（历史、排队、失败或终态行同样阻断）或任何非 `t` 输出返回
  `BACKUP_PHASE_A_PRIVATE_EXECUTION_PRESENT`，`psql` 正常完成但退出非零返回
  `BACKUP_PHASE_A_PRIVATE_EXECUTION_CHECK_FAILED`。子进程启动、等待或超时的底层 Launcher 错误也必须
  直接阻断备份。两种检查结论都必须失败关闭，不能仅依赖
  `--exclude-schema=des_phase_a_qualification` 后继续导出。前后双检避免 private public Execution
  元数据或以 execution ID 命名的日志与被排除的 PEA/PAG ledger 静默配对。**受保护 Phase-A
  backup/restore 目前未实现**；不得以跳过此 gate、按表名过滤或把标准包标为“私有备份”替代它。
- 数据库必须由固定 PostgreSQL 容器执行参数数组形式的
  `pg_dump --format=custom --compress=0 --serializable-deferrable`
  `--exclude-schema=des_phase_a_qualification` 并取得单一一致性快照；该排除项是
  Launcher 固定字面量，不能由用户、环境变量或备份请求改写。该私有 schema 当前包含 Phase-A 的三张
  ledger 表、schema 内触发器、私有 ledger guard functions 和私有 0021/0022/0023 `SECURITY DEFINER`
  issuer/consumer/lock-fence entrypoints；PEA 与未接线 runner lock primitive 已在同一完整 schema exclusion
  范围内。保护 public `executions`
  trigger 的 `public.des_phase_a_execution_mode_guard()` 则故意不被排除，必须随标准 dump/restore 保留；
  它仍由无登录 ledger owner 持有，并向 `PUBLIC`、runtime、issuer 与 consumer 撤销执行权。使用 schema
  排除而不是 `--exclude-table-data`，以避免 custom dump 留下私有 schema/function metadata。禁用 dump 压缩是为了让导出前的部署 secret 精确 byte 扫描可执行。helper 只接受
  以 `PGDMP` 开头的普通文件，不接受物理
  `des-postgres-data` volume 归档。
- 逻辑 dump 的宿主 staging 文件必须位于 Launcher 创建的受限 ACL 随机目录；分包完成或
  失败后都必须清理。若清理失败，Launcher 不得执行 `resume`，而是返回稳定错误并要求
  Operator 先核验当前服务状态、人工处置；不得把可能遗留的明文 staging 与恢复运行同时
  伪装成成功。该短暂明文 staging 是尚待真实 Windows 验收的残余风险，不得伪装为“从不落明文”。
- DATA/SECRETS 输出路径必须是父目录已存在但自身尚不存在的新叶子目录，由 Launcher
  创建后收紧 ACL；不得为备份改写用户已有目录的权限。
- helper 只能来自发布锁定的 Worker `repository@sha256:<64 hex>` 镜像，使用参数数组，
  `network=none`、只读根文件系统、`cap_drop=ALL`、`no-new-privileges`。
- 密码只经标准输入传给一次性 helper，不得进入参数、环境、日志、JSON 结果或 Git。
- DATA/SECRETS 两把恢复 key 必须与安装目录、应用数据目录和运行 secret 目录路径分离，
  并与全部数据库密码、JWT、HMAC、KEK 及 32-byte secret 的十六进制编码做值域分离。该
  集合包括 `egress_lease_creation_capability`；它是 32 个 OS CSPRNG 原始字节编码成的
  64 个 ASCII 小写十六进制字符，且必须与四个数据库角色密码分别不同。

## 3. DATA 固定 allowlist

DATA 包只允许以下归档项：

| 归档路径 | 来源 | 约束 |
|---|---|---|
| `database/postgres.dump` | 已通过 Phase-A public-row backup gate、且排除完整 `des_phase_a_qualification` 私有 schema 的一致性 `pg_dump` custom-format 文件 | 普通文件、`PGDMP` magic、长度和 SHA-256 与清单一致；任何 `PHASE_A_HARNESS` 行存在时不得创建 |
| `logs/` | 只读活动 `RuntimeGeneration` 所指定的 log named volume（LEGACY 为 `des-log-data`） | 只允许 `<execution UUID>/<attempt UUID>.log`；只在同一轮 Phase-A public-row gate 通过时读取，不能导出 private execution 的日志 |
| `metadata/compose.yaml` | 发布制品 | 固定文件、大小和 SHA-256 与清单一致 |
| `metadata/images.release.env` | 发布制品 | 固定文件、大小和 SHA-256 与清单一致 |
| `metadata/release-manifest.json` | 发布制品 | 固定文件、大小和 SHA-256 与清单一致 |

下列对象绝不进入 DATA 包：

- `des-workspace-data`、任何运行时工作目录或 `job.json`；
- `des-postgres-data` 物理卷、数据库数据目录、WAL 或 Docker volume tar；
- Launcher keyring、数据库密码、`egress_lease_creation_capability`、JWT 私钥、HMAC、
  KEK、数据源明文凭据；
- `des_phase_a_qualification` 整个私有 schema（当前 `phase_a_qualification_nonces`、
  `phase_a_qualification_grants`、`phase_a_execution_authorizations`、schema 内触发器、私有 ledger guard
  functions、私有 0021/0022/0023 `SECURITY DEFINER` issuer/consumer/lock-fence entrypoints 及其记录；PEA 仅可含 nonce
  SHA-256，绝不可含 raw nonce），以及任何
  QH/PAG/PEA/QR/private qualification source；标准 backup 与 diagnostics 均不得携带这些受保护
  资格材料；
- 未知元数据文件、链接、设备、FIFO、socket 或未声明归档路径。

导出 DATA 前，helper 必须读取并校验固定 secret 集合但不得将其归档，用于：

1. 在 dump、日志和发布元数据中搜索当前部署秘密的精确 byte 值；
2. 对日志再次运行与 Worker 相同的结构化脱敏器；
3. 拒绝私钥标记、DataX `job/reader/writer` 组合和任何 `job.json` 路径。

发现疑似泄露时返回 `BACKUP_SECRET_LEAK_DETECTED` 或
`BACKUP_DATA_ALLOWLIST_REJECTED`，且不得发布 `.dxdata`。

当前 Launcher 的运行集合恰好包含十个文件：四个数据库角色密码、
`egress_lease_creation_capability`、JWT 公私钥、两个 HMAC key 和当前
`credential-kek-v1.key`。备份验证将前九个名称视为固定 allowlist，并要求至少一个符合
`credential-kek-[a-z0-9][a-z0-9_.-]{0,62}.key` 的 32-byte KEK，以支持已批准的历史 KEK
保留；缺失固定名称、未知名称、链接/特殊文件、长度或格式错误，或该能力值与任一数据库
密码复用都返回 `BACKUP_SECRET_SET_INVALID`。这些值只用于 SECRETS 包的加密归档和 DATA
泄露扫描，绝不写入 manifest、结果或日志。

## 4. DATA/SECRETS 分包

一次受控备份固定产生两类包：

| 包 | 后缀 | 内容 | 保管要求 |
|---|---|---|---|
| 数据包 | `.dxdata` | 已排除完整 `des_phase_a_qualification` 私有 schema 的 PostgreSQL 逻辑 dump、脱敏日志、固定发布/迁移元数据 | 可放入受控备份介质 |
| 密钥包 | `.dxkeys` | PostgreSQL 管理密码、egress-guard/API/Worker 独立数据库角色密码、`egress_lease_creation_capability`、JWT 密钥、HMAC、全部受支持 KEK | 与数据包分开保管 |

两包必须使用不同的高熵恢复秘密。密钥包通过
`related_data_backup_id` 精确绑定数据包；检查时还要比较 `installation_id`、产品版本和
迁移版本。缺包、错包、错密码、密钥集合不完整、公私钥不匹配、四类数据库角色密码、
`egress_lease_creation_capability`、HMAC/KEK 任意重用或未知密钥对象一律失败关闭。`installation_id` 位于加密清单内，不以
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

由于标准 backup 在任一 `PHASE_A_HARNESS` public Execution 存在时必须拒绝导出，并且标准 DATA dump
特意不含整个 `des_phase_a_qualification` schema，任何未来完整恢复也**不得**复活备份时存在的
QH/PAG/PEA 或重放防护状态。受保护 Phase-A backup/restore 是独立的未来能力，当前不存在。恢复后的数据库仍会携带 `alembic_version=20260802_0023`，
却不会有该 schema、其私有 0021/0022/0023 `SECURITY DEFINER` issuer/consumer/lock-fence entrypoints 或无登录 ledger roles；
`public.des_phase_a_execution_mode_guard()` 会随 public trigger 保留；所以当前真实
`pg_restore`、应用启动和迁移后的 ledger bootstrap 均保持
`BLOCKED`，不得把空 probe restore 写成可恢复系统。未来完整恢复必须先在受保护的 restore
bootstrap 中创建空 ledger、生成不随备份恢复的 issuance epoch，并只接受该 epoch 后重新验证
P/QH、原子消费的新 nonce 与新 PAG，以及每条新 Execution 的新 PEA。当前没有这种 issuer/source
或完整 restore，因此本规则
只是失败关闭的设计约束，不是“已恢复资格”或 E3/E4 证据。

以上门禁及干净 Windows 11 x64 异机演练完成前，恢复和覆盖升级必须保持失败关闭。普通
`start` 不得把部分恢复当作全新安装，也不得生成替代 KEK。当前 Launcher 已在
`start/backup` 的任何初始化或备份读取前检查固定应用数据根下的 `system-restore`；只要
该状态存在（包括未知、损坏或未完成状态）就返回 `RESTORE_IN_PROGRESS`，检查本身失败则
返回 `RESTORE_STATE_CHECK_FAILED`。这只是不破坏现有 staging 的 E1 门禁，不代表继续恢复、
授权清理或 Windows E4 已完成。

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
  密码、`egress_lease_creation_capability`、JWT、HMAC、KEK 或 32-byte secret 的十六进制编码。
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

### 6.2 已部分接入、但恢复仍关闭的提交边界

ADR-0008 已决定用受 ACL 保护并原子创建的 `runtime-generation.json` 同时选择
installation-id、独立 secret 目录和三个随机 named volume；Compose 的逻辑 volume key
不变，实际名称由 Launcher 明确注入。Docker named volume 本身仍不提供安全
rename/compare-and-swap，因此 V1 restore 只允许无旧 installation-id、无活动代际、无
产品容器和产品卷的干净目标，不覆盖已有安装。

当前代码已有运行代际 JSON Schema、域分离摘要、严格来源/路径/卷集合/UTC 时间校验，以及
`FRESH/RESTORE` 的受限构造器。系统备份先在无 reparse 的应用根目录中复核 ACL 受控的
pointer，再冻结一个活动快照；config、preflight、停应用、`pg_dump`、停 PostgreSQL、包导出
和 resume 的 Compose 环境/容器归属均显式使用该快照的 installation-id、三卷和 secret 目录，
并在 Compose 命令前后重读 pointer 作精确等值复核。pointer 变化时不得用新身份继续或 resume；
DATA/SECRETS helper identity 也包含 generation ID/状态摘要。当前 FRESH 初始化先以 ACL 受控的
内部 journal 固定一个随机 generation、installation identity、secret 目录和三卷名；进入
FRESH 后不得读取/写 root `installation-id`、root secret 或固定 LEGACY 卷。完整 FRESH secret
集合与同代际卷标签复核后，pending pointer 先刷盘并限制 ACL，再以同目录、
`MOVEFILE_WRITE_THROUGH` 且不含 replace flag 的 rename 提交；目标已存在、链接、摘要篡改、
journal/identity/对象集合不一致时均拒绝覆盖。中断只能继续同一 journal，半套 secret 不会被
删除或替换。既有工程候选安装只有固定卷、固定 secret 集和旧 installation-id 全部通过原有
身份检查后才可一次性创建 `LEGACY` pointer；所有 Compose 子进程先移除宿主同名环境变量，再
从已验证 pointer 整组注入五个值。内部 FRESH journal 不新增公开 Schema，活动 pointer 仍由
`runtime-generation.v1.schema.json` 定义。

备份 package manifest 也尚未记录 generation identity，因此不能把当前 helper identity 或
snapshot 重读表述为完整包对/恢复绑定。现有失败关闭的
`restore` 分支仍位于 secrets/volume 初始化之前，不会读取恢复 key、生成替代 KEK/密码或
创建固定卷。

后续实现至少必须在产品服务和出站网络完全停止的隔离阶段：

1. 以随机名创建带 installation-id、role 和 restore-journal-id 标签的新空 PostgreSQL、
   日志与 workspace 卷，并证明没有产品容器引用；
2. 在 `network=none` 或只含临时 PostgreSQL 的专用隔离网络中初始化空数据库，以参数数组
   执行 `pg_restore --exit-on-error --single-transaction --no-owner --no-privileges`；
3. 在 staging 数据库上执行迁移版本、约束、行数、审计链、JobVersion/Execution、日志、
   Envelope/KEK 解密探针和发布制品证据重算；
4. 以崩溃可恢复的单一提交点创建 installation-id、secret 目录和三个 active volume
   引用；提交前任何失败只清理 journal 记录的新对象；V1 没有旧活动集合，也不执行覆盖；
5. 在干净 Windows 11 x64 上覆盖掉电、Docker/WSL2 中断、错包/错密码/错版本、空间不足、
   `pg_restore` 失败、证据失败、提交中断和旧卷保留的 E4 演练。

上述接入和真实演练未完成前，`launcher.exe restore ...` 只能在干净目标完成受认证 E1
staging，并稳定返回 `RESTORE_STAGED_COMMIT_BLOCKED`；不得停止既有服务、创建或修改运行卷、
提交活动代际或返回恢复成功。
