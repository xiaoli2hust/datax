# 机器可校验契约

本目录中的文件负责可机器校验的字段、类型、枚举和约束形状；PRD 负责产品结果与范围，ADR 负责架构决策。发生冲突必须阻断实现并同步修复，不能用“机器契约优先”覆盖产品语义：

- `openapi.yaml`：HTTP API。
- `job-spec.v1.schema.json`：平台任务契约。
- `schema-snapshot.v1.schema.json`：MySQL/PostgreSQL 表结构的确定性、无秘密快照；发布校验与 Worker preflight 共同使用。
- `plugin-manifest.v2.schema.json`：现行插件能力、分级认证、依赖/许可、证据与 UI 阻断契约；
  `WINDOWS_E4_CERTIFIED` 只描述精确最终候选的 Phase-B E4，普通用户执行还必须由同一最终
  候选的 `release_promotion_ref` 证明有效公开发布晋级。
- `plugin-manifest.v1.schema.json`：仅保留为历史契约，不再由当前 `/plugins` 返回。
- `upstream-plugin-inventory.v1.schema.json`：从固定 Alibaba DataX 根 POM、模块 POM 与
  `plugin.json` 重建的 Reader/Writer 源码能力目录。对应规范化制品位于
  `runtime/upstream-plugin-inventory.v1.json`；当前 72 项都只证明 `SOURCE_PRESENT`，固定
  `ordinary_user_executable=false`。`V1_BUSINESS` 与 `INTERNAL_SMOKE` 只是候选分类，不能
  当作 `PACKAGED/CONTRACTED/E3/E4` 证据。
- `capability-target-set.v1.schema.json`：以同一锁定上游为输入的完整产品**目标集**；对应
  `runtime/capability-target-set.v1.json`。当前冻结 83 项：72 个 Reader/Writer、6 个
  native Transformer 和 5 个跨插件 SQL/任意 Job JSON/外部 Transformer 执行入口。每项绑定
  上游文件 SHA-256、风险分类、V1 处置及未来 E3/E4 test ID，且统一
  `ordinary_user_executable=false`。它不是插件 manifest 或发布资格：
  `windows_e4_certified_count=0`，不能把目标项、源码项或 test ID 当成已打包、已认证或可执行。
  V1 明确禁止的任意 SQL、脚本/外部 Transformer 仍被列出为
  `EXPLICITLY_UNSUPPORTED_V1`，以便后续“完整 DataX”声明必须正面处理而不能静默遗漏。
- `audit-event.v1.schema.json`：审计事件最小结构；包含保留维护开始、完成、失败三类
  SYSTEM 事件，但不把到期扫描声明成数据库外 WORM 锚定。
- `verification-oracle.v1.schema.json`：独立数据核验规范和结果证据；使用规范化行多重集，不依赖 DataX 自报统计。
- `acceptance-manifest.v1.schema.json`：候选版本的精确“需求 ID + 测试 ID”对、oracle 与
  证据文件清单；同一可复核执行可显式覆盖多个需求，但每个需求必须独立绑定结果与证据；
  E3 数据 oracle 和 E4 Windows 证据必须以结构化 JSON 绑定候选版本、commit、需求、测试、
  环境及执行身份，普通文本、截图或自声明 `PASS` 不能通过发布 validator。
  只要 manifest 含有 Windows E4 evidence，就必须同时声明 scenario profile/result catalog；每个
  E4 artifact 必须引用其精确 profile ID、profile/result 的 SHA-256 和结果中的断言集合，不能让
  某个测试的 PASS 借给另一个测试。
  该兼容修复把 manifest 与 requirements catalog 的 `schema_version` 提升为 `1.1`；旧
  `1.0` 清单缺少 `evidence_requirements/windows_evidence` 及 oracle binding，必须重新生成，
  不允许原样晋级。
- `windows-e4-scenario-profile.v1.schema.json` 与
  `windows-e4-scenario-profile.v1.json`：Windows E4 的权威场景语义目录。当前 `windows-e4-v1`
  将权威 requirements catalog 中全部 `WINDOWS_E4` 条目精确覆盖为 **23 个唯一 test/profile
  ID、25 个 requirement/test 对**；每个 profile 固定类别、需求绑定和必需断言 ID。profile
  的原始字节也必须与仓库中的权威文件相同，不能在候选目录中临时删减场景。
- `windows-e4-scenario-result.v1.schema.json`：某一精确候选的完整 Windows 场景结果目录。它必须
  绑定 profile SHA-256、release candidate 与完整 commit SHA，并为全部 23 个 profile 给出恰好一项
  结果。已执行的 `PASSED/FAILED` 项必须固定执行时间、environment ID/manifest SHA、Windows
  baseline、harness version、精确 assertion IDs 及其 RFC 8785 SHA-256；`NOT_RUN` 不得伪造上述
  执行数据。该 Schema 和 source profile 只提供 E1 语义/校验基础，当前没有受信 harness 产生的
  result catalog，更没有 E4 结论。
- `candidate-root.v1.schema.json`：ADR-0010 的 canonical Windows 候选证据根基础契约。
  `scripts/acceptance/candidate_root.py` 以外部 CI 身份参数绑定固定仓库、release workflow、
  run/attempt、保护环境、source ref、commit、tag、candidate，并把候选目录中除候选根自身
  以外的全部普通文件按安全相对路径、大小和 SHA-256 进行完整有序盘点；Setup、Launcher、
  final release manifest 1.1、Compose、顶层/内嵌镜像 lock、Linux build evidence 中生成的
  image lock、ACL helper、SPDX SBOM index、
  acceptance/environment/catalog 和 Windows build environment 还必须映射到该完整盘点并
  通过跨文件身份/hash 校验；manifest 内三项资源摘要与 canonical signer SHA-256 allowlist
  也须复核。生成/验证还强制传入候选目录之外的、由 GitHub-hosted attestor 独立下载的
  Linux build artifact evidence 目录，并递归比较它与候选内 `linux-evidence/` 的全部普通文件路径、大小和
  SHA-256；三份镜像 lock 仍须逐字节一致，避免 Windows handoff 在交接后替换已扫描的
  `repository@sha256` 集合。Acceptance 不是抽查少数字段，而是复用权威 Schema、需求矩阵、catalog、
  environment/evidence root 和完整语义 validator。路径逃逸、大小写
  冲突、符号链接/Windows reparse point、额外/缺失/被改文件、重复 JSON key 和非 canonical
  JSON 均失败关闭。校验器只接受当前 checkout 中固定权威 Schema，并在 Schema 外再次硬
  断言 BLOCKED 语义，调用方不能用宽松 `--schema` 放开。当前 `1.0` 只允许 `root_status=BLOCKED`、
  `release_approved=false`；虽然仓库已有 E1 的权威 scenario profile 与 result Schema，但 v1
  candidate root 内的机器场景 profile/result、Windows baseline、harness 边界和 E3/E4 证据包仍必须
  显式为 `null` 并给出阻塞原因；它不能表达可发布 PASS。Release workflow
  中 Windows job 生成的顶层 `SHA256SUMS` 只负责 self-hosted → GitHub-hosted 的交接完整性；
  托管 job 还会独立下载并验证 Linux build artifact 的 `SHA256SUMS`，再验证候选内
  `linux-evidence/` 与该来源完全一致；成功后删除候选顶层的瞬时清单，再生成 candidate root。
  最终候选不得保留一个未覆盖
  candidate root 的旧 `SHA256SUMS` 并把它声称为完整清单，完整库存职责由 canonical
  candidate root 承担。
- `windows-e4-preflight.v1.schema.json`：未来受保护 Windows E4 harness 的本机前置观察
  记录；对应 `scripts/acceptance/windows_e4_preflight.ps1` 和
  `validate_windows_e4_preflight.py` 只能检查 Windows/WSL2/Docker、候选哈希/签名与
  固定产品残留，并固定 `e4_result=NOT_RUN`、`release_approved=false`。当前仓库只对该
  脚本与契约做 E1 静态/结构测试；即使未来本机记录为 `READY`，也不是 E4、不是 golden-image
  或 runner 信任证明，不能写入 `candidate-root.v1` 或用于发布晋级。
- `release-payload.v1.schema.json`、`harness-qualification.v1.schema.json` 与
  `phase-a-qualification-grant.v1.schema.json`：ADR-0011 的不可变 P、短期 QH 与受保护私有
  Phase-A 单 pair 授权记录。后者固定 P/harness/QH/Reader-Writer 的精确绑定和生命周期形状，
  但不是普通 API、Worker、Compose 或用户可提交的契约，更不是 E3/E4 或发布结论。
- `datax_studio.qualification.private_harness_loader`（J0c-1）是**内部 E1 实现，不是新 JSON
  Schema、公开 API 或普通配置格式**。它仅接受未来受保护基础设施显式注入的 trusted private
  filesystem root、hash-pinned P/QH 文件、独立 P root 与固定 harness identity；返回不含 raw QH/raw
nonce 的不可序列化事实，且不消费 nonce、不写 grant、不创建 Execution 或启动 DataX。它没有
Settings/env/API/Worker/标准 Compose/Launcher 接线，不能当作可信 harness、private source/override 或
`E3/E4`/发布证据；不具备安全 descriptor-open primitive 的宿主固定失败关闭，未提供 Windows
harness source provisioning。
- `phase-a-execution-authorization.v1.schema.json`：J0b.1 的**E1 私有 PEA read-record**
  形状，精确对应 0022 consumer `des_read_active_phase_a_execution_authorization` 的返回列。
  0022 的 immutable PEA 对 `grant_id` 和 `execution_id` 各自唯一，绑定一个既有 PAG 到一个精确
  Execution、JobVersion、两侧 Datasource/EndpointPolicy revision、TransferPolicy、TargetNamespace
  和 P/runtime/harness/QH（仅 `nonce_sha256`，绝无 raw nonce）摘要。PEA 无独立 `state`，只在
  PAG 当前 `ACTIVE`、QH 时间窗有效且全量 current-fact 联结相等时由 read 函数返回。该 Schema 不是
  私有 API/Worker 通道；当前没有私有 Phase-A Worker/runner，保持硬禁用。0023 的 lock/fence
  前置原语也不能替代完整 PEA/current-fact/confirmation、audit checkpoint 与凭据/日志/维护隔离，
  因而不给普通用户能力，也不形成 E3/E4、QR 或发布结论。
- `phase-a-execution-lock.v1.schema.json`：0023 private reader 的**E1 私有 lock/fence read-record**
  形状。它复用 `public.target_copy_locks`、`public.execution_attempts` 和
  `public.executions.fence_epoch`，而不创建平行私有锁；故 `STANDARD` 与
  `PHASE_A_HARNESS` 对同一 `TargetNamespace` 共用一个 partial-unique 排他约束。
  它只描述受限 `SECURITY DEFINER` reserve/claim/heartbeat/recovery/release/read 的非秘密事实；
  没有 private Worker/runner、Compose credential、普通路径创建/私有 rerun、Popen、完整 PEA/current-fact
  revalidation、confirmation 或 audit 接线，保持硬禁用，不是 E3/E4 或公开 capability。
- `phase-a-execution-lifecycle.v1.schema.json`：0024 private issuer 的**E1/E2 原子创建最终 receipt**。
  它只允许同一已提交事务的 `LOCK_RESERVED`，固定
  `execution_process_state=QUEUED`、`queue_eligibility_state=BLOCKED`、
  `queue_block_reason=PHASE_A_PRIVATE_WORKER_NOT_IMPLEMENTED` 与 `target_lock_state=RESERVED`，并固定
  `ordinary_path_authorized=false`、`evidence_conclusion=NOT_E3_OR_E4`。它不表达可独立提交的
  `EXECUTION_CREATED`/`PEA_BOUND`，不携带 nonce/QH/凭据/DSN/命令/日志/结果，也不是 API/UI/Worker/Compose/
  Settings/Launcher/runner 契约。0024 的真实 PostgreSQL migration/atomicity/lifecycle 测试已在
  2026-08-02 取得受限 E2；create 函数在读 current facts 前先以 `SELECT ... FOR UPDATE` 锁定
  `public.system_control(singleton_id=1)`，只由无登录 ledger owner 持有行锁所需 `UPDATE(singleton_id)`，
  issuer/普通角色无直接权限。downgrade 在检查前对 public execution/attempt/target-lock 与私有 grant/PEA/
  checkpoint 取得 `ACCESS EXCLUSIVE` 锁，任一 protected state 存在即拒绝。这不构成 private runner、E3 或 E4。
- `egress-guard-attestation.v1.schema.json`：共享网络命名空间内出口守卫的实时证明。
- `egress-guard-lease.v1.schema.json`：精确 selected-IP `/32|/128 + TCP port` 短租约请求与响应。
- `egress-guard.v1.md`：守卫只读数据库视图、loopback HTTP、nftables 和 fail-closed 边界。
- `system-backup-manifest.v1.schema.json`：系统 DATA/SECRETS 分包、版本、数据树摘要与配对清单。
- `system-restore-journal.v1.schema.json`：双恢复秘密认证的 staging journal、包证据、
  状态和事件结构；不包含最终卷提交成功状态。
- `runtime-generation.v1.schema.json`：Launcher 原子选择 installation-id、secret 目录和
  三个 Docker named volume 的活动运行代际指针。
- `runtime-db-write-matrix.v1.json`：ADR-0013 的 API/Worker 最小写权限矩阵。当前是
  `ACCEPTED_BASELINE_NOT_GRANT_READY`；它记录 003A 的显式 grant/trigger/function 目标和
  pre-implementation blockers，管理面分组仍须展开为逐表/逐列 grant，不能被当作 PostgreSQL
  权限已生效或可直接生成迁移的证据。
- `system-backup.v1.md`：Windows Launcher 调用备份 helper 的停机、加密、恢复 journal 与失败关闭边界；0022/0024 后标准 backup 会在 `pg_dump` 前后重验无任何 `PHASE_A_HARNESS` public Execution，存在/非 `t` 输出或 psql 非零均拒绝导出，受保护 Phase-A backup/restore 未实现。

ADR-0011 的 Phase-A 契约基础件现包括 `release-payload.v1.schema.json`、
`harness-qualification.v1.schema.json`、`phase-a-qualification-grant.v1.schema.json`、
`phase-a-execution-authorization.v1.schema.json`、`phase-a-execution-lock.v1.schema.json` 与
`phase-a-execution-lifecycle.v1.schema.json`：前者
定义不含 QH/PAG/QR/最终安装包的不可变 P 及其 `payload_root_sha256`，第二者定义最长 24 小时、
一次性、域分隔 Ed25519 QH；PAG 则只记录一个受保护私有 Phase-A 授权的 `grant_id`、精确
P/harness binding、完整 P binding 的 `payload_binding_sha256`、QH
`issuer_key_id/qualification_id/document_sha256/nonce_sha256`、一个 Reader/Writer pair、时间窗口
和单调 state。
`payload_binding_sha256` 是 `SHA-256(RFC8785(QH.payload_binding))`，`document_sha256` 是包含
`signature` 的 canonical signed QH document 的 SHA-256（不是 raw nonce），`nonce_sha256`（即
QH nonce hash）是 `SHA-256(UTF8(QH.nonce))`；三者均不得附加域前缀。PAG 不保存原始
nonce、凭据、命令、测试结果或可配置公钥；其
`ordinary_path_authorized=false` 与 `evidence_conclusion=NOT_E3_OR_E4` 是失败关闭边界，
不是可由调用方删除的提示。对应的
`datax_studio.release_qualification` 只接受 raw UTF-8/JCS、独立传入且与 P 自身 root 一致的
预期 payload root；QH 的 signed binding 必须与 P 的 identity、平台、全部镜像、Runtime、
插件和 artifacts 精确相等，且 root 同时承诺 P 内未重复的 HQA keyring。公钥只能从该 P 的
`hqa_keyring` 按 `issuer_key_id` 取得；P key ID 的排序/唯一性、QH 的 `(issuer_key_id, nonce)`
一次性 ledger 语义、最大 JSON 深度和跨字段时间窗口由 parser 失败关闭，nonce 只能在所有
签名/绑定检查后原子消费。它没有设置项、环境变量、Compose/API/Worker 接线或普通用户认证
source，因此仍不能产生 E3/E4、插件状态、普通执行能力或公开发布结论；仓库也尚无可用的
HQA keyring/P/QH 实例。

PAG 当前是**E1、进行中**的 private Phase-A payload/runtime/job binding 与 durable nonce/grant
persistence 基础件；它仍不是可运行的 qualification 通道。受保护消费者必须先独立验证 P 和 QH，
再精确比较 PAG 的所有 binding；原始 QH nonce 只可由独立 durable nonce ledger 原子消费，grant
只允许 `ACTIVE -> REVOKED|EXPIRED` 的单调终态，且其有效窗口必须落在 QH 有效窗口内。
`20260802_0021` 新增无登录 ledger owner / issuer / consumer、最小 `SECURITY DEFINER`
issue/revoke/read 函数和只接受未来 protected Engine 注入的 private adapter。issue 必须在一个事务写
nonce 与 PAG；read 只返回 current `ACTIVE` grant。J0a 刻意不含 `execution_id` linkage；`20260802_0022`
以独立 PEA 补充它：issuer `des_authorize_phase_a_execution` 只能对一个 pending 的
`PHASE_A_HARNESS` Execution 和仍有效 PAG 进行锁定后原子写入；记录对 `grant_id`/`execution_id`
各自唯一、append-only，冻结 `job_version_id/version_artifact_hash/spec_hash`、两侧
DatasourceRevision/EndpointPolicyRevision 的 ID+hash、TransferPolicy `scope_hash/row_version`、
TargetNamespace identity，以及 PAG/P/runtime/harness/QH 和**仅 nonce SHA-256**的交叉检查摘要。
consumer `des_read_active_phase_a_execution_authorization` 只有在 PAG `ACTIVE`、QH 时窗和全部 current
facts 仍相等时返回该 PEA；PEA 不存独立 `state`。0022 还令普通 Worker claim 只领取 `STANDARD`，
绝不领取 `PHASE_A_HARNESS`。`qualification.execution_authorization` 的 private issuer/consumer adapter
只调用这两个受限函数，并从 read record 重建、复检非秘密 binding；它不创建/claim/reconcile Execution、
不解密凭据也不启动 DataX。普通 API、Worker 与 recovery/reconciler 都只处理 `STANDARD`，不能读取、
修改、领取或推进 PEA/private Execution。每次未来 private rerun 都是新 Execution 和新 PEA，不得复制
旧 PEA；Schema 不证明函数调用、跨对象相等、时钟、角色隔离或私有 Worker 接线。

0022 source/migration 还为 `datax_api/datax_worker/datax_egress_guard` 在 `executions` 和 execution/probe-linked
attempt/lock/event/cancel/log/recovery/evidence/work-termination descendants 启用 parent-linked RLS；普通 runtime DB
直连不能从这些表读取或写入 private row。issuer authorize 后 row 仍为
`BLOCKED/PHASE_A_PRIVATE_WORKER_NOT_IMPLEMENTED`。本轮真实 PostgreSQL 15 E2 已以 API/Worker direct DB
验证普通路径/RLS 边界（脚本退出 `0`，pytest `32 passed`），但它仍不是 private Worker/runner、E3 或 E4。

`20260802_0023` 在同一 private schema 新增 NOLOGIN `datax_phase_a_runner` 和仅该角色可调用的
六个 `SECURITY DEFINER` lock/fence entrypoint。它使用**既有**全局 `TargetCopyLock` partial unique
index，私有 reservation 会阻止同 namespace 的标准创建；RLS 隐藏私有 row 时，普通 API 的既有
`IntegrityError -> TARGET_ACTIVE_EXECUTION` 映射仍只返回通用冲突，不泄露 private execution。
私有 lifecycle 仅为 `RESERVED -> ACTIVE -> RECOVERY_REQUIRED -> RELEASED`，撤回/过期 PAG 会使
heartbeat 失败关闭；`RECOVERY_REQUIRED` 不自动释放、重试或重新领取。0023 不提供 runner login
provisioning、任何标准 Settings/Compose/API/Worker/Launcher 接线或 DataX 进程启动。

0024 仅允许 private issuer 在**一个**受保护数据库事务中创建 private Execution、PEA 和同一
public `TargetCopyLock=RESERVED`；任一授权、current-fact、人工确认或 shared partial-unique lock 冲突时全部回滚。
在读取 business current facts 前，该函数先对 `public.system_control(singleton_id=1)` 执行
`SELECT ... FOR UPDATE`，与 Launcher/Worker 的本地 stop/drain 更新线性化，不能在陈旧 admission 观察后提交。
只有无登录 ledger owner 持有 PostgreSQL 行锁所需的窄 `UPDATE(singleton_id)`；issuer 与普通/runtime 角色无
直接权限。
成功后的 Execution 固定 `QUEUED/BLOCKED/PHASE_A_PRIVATE_WORKER_NOT_IMPLEMENTED`，无 Attempt/fence；
`RESERVED` 不表示可 claim/Popen/DataX。其内部 checkpoint 不构成外部或可重放 capability，外部 Schema 只允许
最终 `LOCK_RESERVED` receipt。它不接普通 API/Worker/UI/Compose/Settings/Launcher，也不 provision runner；
新增真实 PostgreSQL migration/atomicity/lifecycle/role 测试已在 2026-08-02 随 `32 passed` 验证（含所有运行角色、issuer、consumer、runner 对 checkpoint direct-DML 的拒绝）。仍没有私有 rerun、private API/Worker 四检查点、Compose credential provisioning、
QH/PAG/PEA source/override、受保护 harness、QR reader 或真实 E3/E4 证据。不得把 PAG 或 PEA 放入标准 Compose/Setup/Launcher、公开候选、备份/诊断包、
环境变量、普通 API/UI、Plugin Manifest 或普通 Worker 检查点；它们不得改变
`ordinary_user_executable`、创建 E3/E4 PASS、`WINDOWS_E4_CERTIFIED`、QR 或公开发布批准。
当前没有 protected private disposition workflow；普通维护、标准 backup/restore 或 migration rollback 都不能
处置 private state。任一 private Execution 继续阻断标准 backup，私有 backup/restore 仍 `BLOCKED`。标准产品没有
issuer login 或普通 API 调用；protected disposition、runner、backup/restore 都是未完成的独立门槛。
标准系统备份与诊断必须固定排除完整 `des_phase_a_qualification` schema；普通 restore 不得复制、
恢复或重新激活任何 Phase-A nonce/grant/PEA/checkpoint authority。当前 schema head 的 dump 会保留 `alembic_version=20260802_0024` 却排除
该 schema，因此真实 restore/bootstrap/start 不是现有能力且继续 `BLOCKED`。若未来需要继续资格化，
只能由独立受保护 issuer 在新 restore epoch 后重新验证 P/QH 并重新签发。

本轮 `scripts/test-postgres-e2.sh` 已在临时、一次性真实 PostgreSQL 15 容器退出 `0`，PostgreSQL pytest
取得 `32 passed`：覆盖 0021 role/function、issuer → consumer → revoke 与 role-collision fail-closed，
0022 PEA authorization、普通路径拒绝、API/Worker RLS，以及 0023 global lock/fence、标准同目标
unique-conflict、私有 lock/attempt RLS 隐藏、双 claim/旧 fence 拒绝和 PAG revoke heartbeat fail-closed，以及
0024 issuer-only create→PEA→public `RESERVED`、失败零残留、lifecycle function 和 checkpoint direct-DML role boundary；
同轮验证 private schema exclusion 的 TOC 与空数据库
`pg_restore` 探针。这只是受限 PostgreSQL **E2**：不启动产品 Compose、API/Worker/DataX/MySQL 或独立数据
oracle，也不验证 restore bootstrap/start，因而不是 DataX E3、Windows E4、私有 harness 验收或任何发布结论；
测试/脚本文件存在本身不能代替这次 `32 passed` 运行记录。
0024 已在上述受限 PostgreSQL E2 覆盖内，但不能由此推断 private runner、DataX E3、完整 restore 或 Windows E4。

`ReleasePayload`、`PhaseAHarnessAuthorization` 与 `PhaseAExecutionBinding` 的进程内 provenance
marker 只能捕获同一 Python 进程中的意外构造或篡改；Python 内存不是 protected issuer/consumer
信任边界。跨进程消费者可从 dedicated durable grant lookup 重建 binding，但 Engine 凭据和 QH
source 仍须由未来 protected harness 保护；不得反序列化调用方 dataclass、请求体或 marker 来授予资格。

`release-qualification`、candidate-root.v2、受保护 qualification override、受信 reader、真实
Phase-A/Phase-B harness、签名/OIDC 证据仍未实现；PAG/PEA 的 private API/Worker/Compose 接线与
四检查点也仍未实现。Windows E4 profile/result 的 E1 语义契约
不等于这些最终发布契约，也不提供其受信结果。现有 candidate-root.v1 继续只允许
BLOCKED/release_approved=false；不得用新增可选字段、宽松 schema、测试注入、环境变量或自签
公钥伪造资格。普通生产路径继续 deny-all。

截至 2026-08-01，Datasource、Job、Execution、日志与恢复处置契约已有候选代码消费方，
但真实四方向 DataX（E3）和 Windows 11 安装链路（E4）仍为 `NOT_RUN/BLOCKED`。
系统备份契约已有 DATA/SECRETS 分包导出，以及双包认证、配对、受认证 journal 和空目录
staging 的 E1 候选实现；`LEGACY` 指针原子提交与 Compose 消费也已有候选实现。FRESH 首次
初始化的随机 generation/secret/三卷/无覆盖 pointer 源码切片已接入，但其 journal 是 Launcher
内部状态，未新增公开 Schema，且没有真实 Windows Docker/E4 证据。新空 PostgreSQL volume、
`pg_restore`、证据重算、`RESTORE` 原子还原提交与升级路径仍未实现并保持失败关闭，不能把导出包、
journal、pointer 或 staging 文件存在当作恢复验收。

实现阶段 CI 必须完成：

1. 文件可解析。
2. JSON Schema 通过对应 Meta Schema 校验。
3. OpenAPI 1.2.0 示例和本地引用有效，Execution 的三类状态与独立 oracle 一致；项目可读
   Datasource 响应只能使用 `DatasourceRedactedSummary`，真实连接定位只允许
   `DatasourceAdminDetail` 与 Admin-only revision 路由。
   OpenAPI `servers` 只能声明 Windows 本地工作站入口
   `http://127.0.0.1:17860/api/v1`；部署验证必须证明仅 `web` 映射该 loopback 端口，
   `api`、`worker`、`postgres` 无宿主端口，Health 也不得从 LAN/公网到达。
4. 前后端生成类型与契约一致。
   Datasource PATCH 的非秘密连接定位字段必须先真实探针、后新增不可变 revision；
   密码轮换必须先用新 secret 探针、后原子切换。Datasource 与 metadata 列表的 cursor
   必须签名并绑定 actor、资源、筛选和排序，不能忽略、跨用户复用或返回重复第一页。
5. JobSpec 固定安全的一次性复制策略和 V1 脏数据阈值 `record_count=0/percentage=0`；
   非空目标、任一脏行、未确认源静默、目标排他声明版本非 `1.0`、缺少有限
   `valid_until`、`confirmed_at >= valid_until`、状态非 `ACTIVE` 或未通过恢复门禁均有
   反例，UI/API 不提供正数阈值。
   Schema 快照哈希固定为
   `SHA-256(UTF8("DXSCHEMASNAPSHOTv1\n") || RFC8785(snapshot))`；快照本身不包含哈希或
   观测时间。列必须按连续 `ordinal_position` 排序且名称唯一，constraint/trigger 使用
   稳定顺序。发布校验器和 Worker preflight 必须用同一适配器重算；任意形状、类型映射、
   约束、触发器或表属性差异都以 `SCHEMA_DRIFT_DETECTED` 阻断，不接受调用方自报哈希。
   目标空表证据哈希固定为
   `SHA-256(UTF8("DXTARGETEMPTYv1\n") || RFC8785(evidence_without_evidence_hash))`；
   Worker 写入前与服务端接受时都必须重算，不接受调用方自报哈希。
6. OpenAPI 对 EndpointPolicyRevision、PhysicalEndpointIdentity、TargetNamespace、
   TransferPolicy 精确 `scope_json/scope_hash`、CredentialSecret/Envelope 生命周期、
   EndpointConnectionEvidence、RecoveryProbe/Attempt、目标排他撤回/破坏报告接口、LogGap
   与四类日志计数提供外部契约。Execution 必须表达目标声明
   `ACTIVE/REVOKED/EXPIRED`、撤回时间与原因；撤回接口写
   `TARGET_EXCLUSIVITY_REVOKED` 审计，且不能把未收到撤回报告当作对全部外部 DML/DDL 的
   技术证明。
   TransferPolicy 创建输入必须给出两侧 catalog/database/schema/table 与显式列，
   `ALL_COLUMNS` 先展开；提交/审批固定 `expected_scope_hash`，修改范围使旧审批失效，任务
   mapping 必须是当前 ACTIVE scope 的子集。
7. 验收清单的 `requirement_priority` 只允许 `V1-MUST/POST-V1`，缺陷
   `defect_severity` 只允许 `P0/P1/P2/P3`；`gate_result=PASS` 时不得存在任何
   `P0/P1`，即使其状态为 `ACCEPTED`，`ACCEPTED` 只能用于不阻塞发布的 P2/P3。
   同时拒绝用 `BLOCKED/NOT_RUN` 或“无 P0”伪装需求通过。
8. 发布 CI 按 Markdown 表格表头定位并只解析 `需求/规则/验收 ID`、`需求级别`、
   `测试 ID`、`Oracle`、`最低证据` 和 `证据字段` 的对应列，不得从整行其他需求 ID 或
   `NFR-PERF/NFR-SEC` 字符串中猜测测试 ID。随后生成规范化需求 catalog，重算
   `requirements_catalog_sha256`，并以独立 validator 比较 catalog 与 entries 的
   `requirement_id/requirement_priority/test_id/minimum_evidence_level/evidence_requirements`
   五元组及 V1-MUST
   集合。Manifest entry 必填 `minimum_evidence_level`；Schema 拒绝 PASS 的实际
   `evidence_level` 不精确等于该等级，validator 还必须拒绝运行器自行修改 catalog 等级。
   它必须验证 `expected_v1_must_count=covered_v1_must_count=当前 catalog 中的
   V1-MUST 数`、`catalog_exact_match=true`、缺失数组为空、重复“需求 ID + 测试 ID”数组
   为空；JSON Schema 不承担跨数组计数相等。
9. Oracle 未启动时 Execution 保持 `NOT_STARTED` 且 acceptance 的 oracle 为 null；只有已启动
   但无法形成结论才是 `INCONCLUSIVE`。产物必须带对排除自身字段后 RFC 8785 文档计算的
   `artifact_sha256`；`INCONCLUSIVE` 必有原因，`PASSED` 固定静默/锁/目标排他窗口为 true、
   目标声明 `statement_version='1.0'`、`status=ACTIVE`、`revoked_at=null`、差异为 0、
   相等标志为 true，且目标计数与摘要来自带 ID 和起止边界的单一一致性读事务。独立
   validator 仍须重算 hash，比较源/目标行数、distinct digest 数和 multiset hash，并验证
   `target_exclusivity.target_snapshot_id=target_result.snapshot_id`，以及
   `confirmed_at` ≤ `target_empty_checked_at` ≤ `target_result.snapshot_started_at` ≤
   `target_result.snapshot_finished_at` ≤ `valid_until`。
   源/目标各自的 read 起止必须落在 oracle `started_at..finished_at` 全局窗口内，distinct
   digest 数不得大于行数；entry `executed_at` 定义为测试尝试完成时间，不得早于 oracle
   `finished_at`，environment `captured_at` 不得晚于该完成时间。
   `VERIFICATION_ORACLE_V1` 条目的 oracle binding 必须逐字段匹配 acceptance candidate、
   commit、requirement/test、环境清单 SHA、execution/job version，并实际解析引用的
   `verification-oracle.v1` JSON，完成 Schema、RFC 8785 哈希和跨字段语义校验；只验证外层
   文件 SHA 不足以成为 PASS。同一个 oracle artifact path/hash 或 execution ID 不得在多个
   manifest entry 间重放。`WINDOWS_E4` 条目必须引用结构化 Windows E4 JSON，绑定同一
   candidate/commit/requirement/test/environment，证明干净 Win11 x64、签名制品、唯一
   loopback 端口和逐项断言；`assertions` 必须包含 binding 中的精确 `test_id`，不能借用
   另一个测试的 PASS；同时必须落入权威 profile 的精确 assertion 集，并与同一候选的完整
   result catalog（profile SHA、candidate、commit、environment、baseline、harness 和 assertion
   hash）一致。Setup/Launcher 必须是 evidence-root 中可读取并重算 SHA-256 的实际文件，不能
   只填裸摘要，其嵌套证据也必须重算 SHA-256。
   `--require-pass` 还必须由可信发布编排从 Git checkout/tag 上下文分别传入
   `--expected-commit` 与 `--expected-release-candidate`；缺失或与 manifest 不同即失败。
   这些检查只证明证据包结构、身份引用和内部一致性，不证明 JSON 由可信 Windows harness
   产生，也不验证 Authenticode、物理/虚拟机洁净度或真实设备行为；必须另由受保护 Windows
   runner 执行签名验证和 E4 取证，不能把自声明 `VALID` 当作签名证明。
   Candidate-root Schema、BLOCKED 生成/验证器及
   `scripts/acceptance/verify_candidate_attestation.py` 的 E1 基础件已经存在。后者在前后两次
   复核完整 candidate file set 以及候选内 Linux evidence 与调用方传入的独立 hosted copy
   的完整绑定，再以参数数组调用调用方指定绝对路径的 `gh attestation verify`，固定 repository、
   signer workflow/digest、source ref/digest、GitHub Actions OIDC issuer、SLSA predicate，
   并传入 `--deny-self-hosted-runners`；成功后还复核证书中的 hosted runner、精确
   run/attempt URI、workflow、commit、candidate-root subject SHA 和 verified timestamp，最后
   再次重算文件集。但路径/文件类型检查不能证明该 verifier 二进制可信；托管 attestor
   workflow 尚未把该 TCB 锁作为 wrapper 可独立验证的权威 descriptor 前，即使低层策略
   全部匹配，wrapper 也必须非零返回
   `TRUSTED_ATTESTATION_VERIFIER_TCB_NOT_IMPLEMENTED`，不得返回 `ready=true` 或
   attestation-valid。Release workflow 已有 E1 接线候选：托管 Ubuntu job 先独立下载并验证
   Linux build artifact，再下载并验证 Windows 交接清单，生成/复核 BLOCKED candidate root，以固定 commit 的
   `actions/attest` 签发 provenance，并通过 `trusted_gh_cli.py` 将 GitHub CLI 2.97.0 的
   release URL、archive SHA-256 和解包后二进制 SHA-256 固定后执行低层反向验证；随后必须
   精确得到上述 TCB blocker 才允许上传名称含 `blocked` 的候选/证明制品。该 workflow 尚未
   在受保护 Windows runner 与真实签名 secrets 上执行；现有机器场景 profile/result Schema 仅是
   E1 语义基础，尚无受保护 Windows E4 harness、真实 result catalog/bundle 证据或完整发布语义
   编排。因此
   `--require-pass` 仍无条件返回 `TRUSTED_RELEASE_ATTESTATION_NOT_IMPLEMENTED`；非发布校验
   即使得到结构 `gate_result=PASS`，也固定返回 `release_approved=false`。
10. `data_effect=CONFIRMED` 只表示目标影响已测得，测得值可以是 0 行，不代表内容正确；
    空源成功固定为 `SUCCEEDED/CONFIRMED/PASSED`。
11. Execution 创建事务原子写 `QUEUED+TargetCopyLock=RESERVED`；同一 TargetNamespace 的
    部分唯一索引覆盖 `RESERVED/ACTIVE/RECOVERY_REQUIRED`。同目标不同幂等键在 API 冲突，
    Worker 领取原子转 ACTIVE 并创建 Attempt/fence，未领取取消必须释放预留。
12. 恢复声明固定 `action/cleanup_performed/reason/confirmed_at`；无需清理时如实记录
    `NO_CLEANUP_REQUIRED/false`，但任何情况都必须经过独立 RecoveryProbe 空表复检。
13. Windows `Setup.exe`/`launcher.exe` 生命周期不进入业务 OpenAPI；launcher 只在
    loopback ready=200 后打开浏览器，强制停止后的已领取工作必须由 reconciler 收敛
    `LOST`。运行态 PostgreSQL、脱敏日志和无秘密、受限的 oracle 产物使用固定 Docker
    named volumes；明文 `job.json`、临时凭据、未脱敏日志和 DataX 进程工作目录只能进入
    Worker 的受限 tmpfs。DATA 备份只允许一致性 PostgreSQL 逻辑 dump、脱敏日志和固定
    发布元数据，绝不归档 workspace、`job.json` 或物理数据库卷，SECRETS 必须独立加密。
    staging journal 只能授权配对包解包与限定范围清理；新空目标卷 `pg_restore`、证据
    重算与原子提交完成前，恢复和升级保持失败关闭。
14. `egress-guard` 内部 HTTP 不进入产品 OpenAPI。API/Worker 必须共享守卫 netns；
    ACTIVE CIDR 只作准入，实际 nft allow 只能来自守卫生成的 selected-IP 短租约。
15. 破坏性变更提升版本并提供迁移说明。

不得直接修改生成代码来绕过契约。
