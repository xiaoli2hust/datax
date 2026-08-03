# Codex 开发执行计划

| 项 | 值 |
|---|---|
| 文档版本 | 1.2 |
| 状态 | 工程候选实施中；Discovery Gate 未取证，企业试点/发布 `BLOCKED` |
| 适用基线 | DataX Enterprise Studio V1.2 Windows 本地工作站 |
| 执行原则 | 纵向切片、阶段停靠、真实证据、不可伪装 |
| 完成目标 | 企业试点可运行版本，不声称 HA 或生产认证 |

## 当前执行快照（2026-07-31）

下表只记录工程候选状态，不替代各 Phase 的退出条件：

| 切片 | 当前状态 | 不能据此声称 |
|---|---|---|
| 数据源、任务、执行/日志/恢复 UI 与正式 API 适配 | 候选代码已存在 | 浏览器真实闭环、可访问性或 E3/E4 已通过 |
| 数据库运行角色 | 迁移 owner、API、Worker 独立登录/密码且运行角色无 DDL/TEMP；两类运行角色当前仍有相同全表 DML | 数据库已强制 API/Worker 的细粒度状态写入边界 |
| Worker 敏感运行区 | 含密 Job、未脱敏日志和进程工作目录进入 256 MiB tmpfs；Compose 已设资源上限 | Windows Docker/WSL2 的残留、SIGKILL 与资源故障 E4 已通过 |
| 系统备份 | DATA/SECRETS 分离加密导出、双包认证 journal、全新空 staging、`LEGACY` 指针提交与 Compose 消费已实现并测到 E1 | 新空 PostgreSQL volume、真实 `pg_restore`、证据重算、`RESTORE` 卷/secret 原子提交、覆盖升级、异机演练或 RPO/RTO 已通过 |
| GitHub 安全工作流 | PR 已配置 Gitleaks、hash-lock pip-audit、pnpm、Cargo OSV、CodeQL 与真实 patched Worker 镜像 Syft+OSV 应用门禁；候选发布配置六份 SPDX SBOM、OSV 应用和 Grype distro 策略 | 线上 CI/真实 release 已通过、主分支已强制保护，或当前 OS 扫描已有线上证据 |
| 外部发布门禁 | release 候选显式生成 `BLOCKED` manifest | 四方向真实 DataX、签名 Setup、干净 Windows E4、外部 WORM 或恢复完成 |

## 1. 目标与约束

本计划把 V1 拆成可以独立审查、测试和回滚的阶段。编码 Agent 必须先读取 `AGENTS.md` 与全部权威文档，不得用“一次长跑”跳过范围、契约或验证。

固定技术基线：

- Web：Vue 3、TypeScript、Vite、Element Plus，依赖由 `pnpm-lock.yaml` 锁定。
- API/Worker：Python 3.12、FastAPI、SQLAlchemy 2、Alembic，依赖由锁文件锁定。
- 数据库：PostgreSQL `15.18-alpine3.24`；egress-guard 使用同一固定摘要基础。
- API/Worker 最终 Python 运行层：Python 3.12.13 `slim-trixie`（Debian 13）。
- 队列：PostgreSQL 15 事实队列，使用 `FOR UPDATE SKIP LOCKED` 原子领取；`LISTEN/NOTIFY` 只作唤醒并由轮询兜底。
- Runtime：Alibaba DataX `datax_v202309`、JDK 8；制品与插件记录 SHA-256。
- 交付宿主：Windows 11 x64 本地工作站；已签名 `Setup.exe` 安装、已签名
  `launcher.exe` 编排固定 Linux Docker Compose。
- 当前仓库所在 Mac 只用于开发与自动化层验证；最终运行和 E4 目标是另一台 Windows 11
  x64 电脑。
- 前置依赖：Docker Desktop + WSL2 + CPU 虚拟化由用户/组织预先提供并接受许可；
  安装器不得静默安装或代接受许可。
- 默认入口：`http://127.0.0.1:17860`；只有 Web 映射 loopback，API/Worker/PostgreSQL
  不映射宿主端口。
- V1 不实现 AI、调度、DAG、告警、插件市场、CDC 或任意 SQL。
- V1 只交付“安全的一次性离线全量复制”：源端静默确认、目标外部独占声明与空表复检、
  `insert-only`、固定 `dirty_data_limit=0/0`、独立数据核验和失败后人工恢复门禁。目标声明
  固定 `statement_version='1.0'`、有限 `valid_until` 和 `ACTIVE/REVOKED/EXPIRED`
  生命周期；它是人工前提和报告义务，不是平台对全部外部 DML/DDL 的技术证明。

## 2. 执行纪律

每个阶段遵循：

1. 阅读对应需求、ADR、OpenAPI 和 JSON Schema。
2. 列出将修改的文件、迁移、安全边界和验收用例。
3. 先补失败测试或契约校验，再实现最小闭环。
4. 运行阶段检查，修复后重复。
5. 更新文档、追踪矩阵和已知限制。
6. 提交一个可独立回滚的变更。
7. 报告真实证据与未验证项，等待阶段门禁通过。

不得在阶段失败时用 Mock 结果替换真实依赖后继续宣称完成。

阶段顺序遵循“先证伪最高风险假设，再扩展横向能力”。在真实 DataX、空目标保护、独立数据 oracle、部分写入识别和 Worker 围栏尚未跑通前，不得先铺开完整管理后台。

## 3. 阶段计划

### Discovery Gate：用户与任务证据

进入横向产品开发前必须同时完成：

- 关联并满足 `PRD-FR-DISC-001`，证据进入需求追踪矩阵和 acceptance manifest。
- 访谈 8–12 名目标用户，保留原始记录、角色分布、失败案例和反证。
- 分析至少 20 个脱敏真实任务样本，记录筛选规则、数据源方向、规模、失败模式和现有处置。
- 由 3 个设计伙伴合计完成不少于 10 个真实一次性复制任务，记录从准备到独立核验及故障恢复的可用性证据。

Discovery Gate 未完成时，企业试点、公开发布和 V1 完成声明均为 `BLOCKED`。按
ADR-0007，仓库所有者可以明确授权风险自担的 Phase 0—Phase 8 工程候选；当前任务已有
该授权。候选实现、自动测试与内部演示不形成 Discovery 证据，不能改变门禁状态；真实
用户研究证伪假设时，候选实现必须接受返工或废弃。

### Phase 0：仓库、契约与真实运行时预检

交付：

- `frontend/`、`backend/`、`docker/`、`tests/e2e/` 的最小工程。
- Node/Python 锁文件、格式化、静态检查、单元测试和契约校验。
- `.env.example` 仅含变量名和安全说明。
- 数据库迁移框架、统一配置加载和结构化日志。
- CI：Markdown 链接、OpenAPI、JSON Schema、前后端 lint/test、Secret 扫描。
- Runtime 获取/构建说明与 SHA-256 manifest，不提交大型 Runtime 二进制。
- 启动隔离的 MySQL 8、PostgreSQL 15 和平台 PostgreSQL，并用固定 Runtime 完成最小命令行复制探测。
- 固化 `verification-oracle.v1`、10,000 行确定性夹具和独立比较器的输入/输出格式。
- 建立 `installer/windows/` 与 `desktop/windows/` 最小工程：版本资源、Authenticode
  签名接口、固定 Compose/镜像 manifest、Windows 路径/ACL/端口/依赖预检。
- 固定程序目录与数据边界分离合同：业务数据使用
  `des-postgres-data`/`des-log-data`/`des-workspace-data` named volumes，不用
  Windows bind mount；卸载默认保留这些卷、config 与导出 backups。

退出条件：

- 全新检出可按 README 安装开发依赖；这不是 Windows 安装器验收。
- 空项目检查全部通过。
- 仓库中不存在密钥或真实连接串。
- 失败的配置校验能阻止服务启动并给出非敏感错误。
- 真实 DataX 来源、JDK、四个插件和摘要可确认；至少完成 MySQL → PostgreSQL 的命令行复制与独立核验。
- 如果真实 Runtime 或数据库不可用，Gate 0 为 `BLOCKED`，不得进入横向功能开发。

### Phase 1：真实纵向 walking skeleton

交付：

- 最小 Project、Datasource、DatasourceRevision、JobVersion、Execution 和 AuditEvent 迁移。
- 一个固定摘要 JobSpec 经 API 在同一事务创建 `Execution(QUEUED)` 与
  `TargetCopyLock=RESERVED`，PostgreSQL 事实队列由单 Worker 原子领取。
- Worker 使用参数数组启动真实 DataX，保存脱敏后的原序日志，并把退出码 0 推进到 `VERIFYING`。
- Operator 确认源表从运行前检查开始到独立 oracle 完成始终静默；Operator/DBA 提交
  `target_exclusivity_confirmation`，其中 `statement_version='1.0'`、`valid_until`
  有限，承诺从 Worker 最后一次空表观察到 oracle 目标端一致性读事务结束期间没有平台外
  DML/DDL。执行前和状态推进时验证声明仍为 `ACTIVE`、未撤回且未过期；独立 oracle 必须
  在目标端同一一致性快照内计算行数和多重集哈希，且
  `target_result.snapshot_finished_at <= valid_until` 才可能 `PASSED`。
- 提供目标外部独占撤回/破坏报告接口。Operator/Admin 获知冻结失效或平台外 DML/DDL 后
  立即提交；系统持久化状态并写 `TARGET_EXCLUSIVITY_REVOKED` 审计。平台不得把未收到报告
  解释为已技术证明期间绝无外部写入。
- 分别持久化 `process_state`、`data_effect`、`verification_state`。
- 故障注入：目标约束导致部分写入、Worker 失租、对非空目标发起恢复后再次执行。

退出条件：

- MySQL → PostgreSQL 的 API → PostgreSQL 队列 → Worker → 真实 DataX → 独立 oracle 链路达到 E3。
- 目标非空、无法核验，或目标外部独占声明缺失、版本错误、已撤回、已过期或不足以覆盖
  目标快照结束时服务端阻断；同一 TargetNamespace
  从排队开始只允许一个未释放的 `RESERVED/ACTIVE/RECOVERY_REQUIRED` 锁，第二个不同
  幂等键请求不得创建第二个 `QUEUED`。
- DataX 退出 0 但 oracle 失败时不得进入 `SUCCEEDED`。
- 部分写入被标记为 `CONFIRMED` 或 `POSSIBLE`；未提交处置确认或缺少独立 RecoveryProbe 空表证据时，“恢复后再次执行”被阻断。
- Worker 失去 fencing epoch 后不能继续写状态，孤儿进程被识别并处置。

### Phase 2：认证、项目、授权和审计骨架

交付：

- User、Project、ProjectMember、RefreshToken、AuditEvent 模型与迁移。
- 本地账号登录、刷新、退出、当前用户。
- 一次性离线 Admin 初始化 CLI；密码从标准输入读取，不进入参数、环境或日志。
- `Admin / Developer / Operator / Viewer` 服务端权限。
- 项目 CRUD、成员管理和审计查询。
- 项目归档在存在 `QUEUED / STARTING / RUNNING / VERIFYING / CANCEL_REQUESTED` Execution 时被服务端阻断。
- Admin 管理端点策略、数据源用途和源到目标传输授权；Developer 只能使用获授权的数据源。
- 密码哈希、Token 撤销、登录限速和统一错误响应。
- 审计哈希链的签名检查点及外部锚定输出。

退出条件：

- 角色矩阵正向/反向测试通过。
- 跨项目访问返回 `403` 或防枚举 `404`。
- 登录、成员变化和越权失败产生审计记录。
- 任意角色组合都不能绕过端点白名单、数据源用途或传输策略。
- API 重启后刷新 Token 行为符合契约。
- 全新数据库可创建首个 Admin；已有用户时重复初始化被拒绝并审计。

### Phase 3：数据源修订与凭据

交付：

- Datasource、不可变 DatasourceRevision、Credential、DatasourceProbe 模型与迁移。
- MySQL/PostgreSQL 创建、编辑、软删除、连接测试。
- AEAD 凭据加密、版本化 KEK keyring、密钥版本、轮换和恢复入口。
- Schema/表/字段元数据读取，只允许元数据操作。
- 超时、TLS、DNS 重绑定防护、运行时网络出口策略和脱敏响应。

退出条件：

- 数据库、API、日志、审计和测试快照中无明文密码。
- 错误密码、DNS 失败、超时、无权限、证书失败均有稳定错误码。
- 未授权角色不能创建、测试或读取元数据。
- 修改连接信息会创建新 DatasourceRevision，不得改变历史修订。
- 删除被已发布版本引用的数据源修订时被拒绝；凭据轮换不改变 JobVersion。
- 旧 KEK 仍能解密历史可运行凭据，备份恢复探测通过。

### Phase 4：复制任务草稿、校验与发布

交付：

- SyncJob、JobDraft、JobVersion、FieldMapping、PluginManifest 模型与迁移。
- `JobSpec v1` 的读取、写入和 Schema 校验。
- 数据类型兼容、字段存在、目标表存在性、安全画像、可核验能力、角色、传输授权、插件矩阵和危险参数校验。发布阶段不验证或冻结目标为空这一瞬时事实。
- 脱敏 DataX JSON 预览；凭据只显示引用，不进入预览。
- 发布不可变 JobVersion，固定源/目标 DatasourceRevision 与 EndpointPolicyRevision、
  PhysicalEndpointIdentity/TargetNamespace、Schema 指纹、TransferPolicy `scope_hash`
  和规范化配置哈希；Execution 领取时再固定实际 CredentialSecretEnvelope 与连接证据。
- 草稿乐观锁与版本冲突处理。
- `PRD-FR-JOB-010` 冻结为 `POST-V1`；不实现、不展示既有 DataX JSON 导入或迁移入口。

退出条件：

- 同一 JobSpec 产生字节稳定的规范化结果与哈希。
- 修改草稿不影响已发布版本。
- 目标不存在、安全画像不合格、不可核验、字段/类型冲突、越权数据源、非一次性复制语义和禁用参数不能发布；目标非空不在发布阶段判定，而在每次运行前由 Worker 实测并阻断。
- JobVersion 一经发布不能更新或删除。

### Phase 5：执行器完整化与四方向真实 DataX

交付：

- Execution/ExecutionAttempt/ExecutionEvent、TargetNamespace/TargetCopyLock/
  TargetRecoveryGate、RecoveryProbe/RecoveryProbeAttempt、LogArtifact/LogGap 和
  VerificationReport 模型与迁移。
- API 幂等创建执行并原子预留 TargetNamespace；PostgreSQL 原子领取时把 `RESERVED`
  转为受 fence 保护的 `ACTIVE`；Worker 使用租约、单调 fencing epoch 与心跳。
- 独立工作目录、运行时注入凭据、权限 `0600` 临时 Job JSON。
- 参数数组启动 `datax.py`；捕获完整进程树、stdout/stderr、退出码。
- 状态机、数据影响、独立核验、超时、取消、孤儿进程清理、启动对账和恢复门禁。
- 领取事务提交前失败必须整体回滚，不产生 Attempt/fence，也不把既有 `RESERVED`
  预留转换为 `ACTIVE`；Execution 保持从未领取的 `QUEUED` 且预留保持不变。领取事务
  提交后，任何非唯一成功结果不得自动回到 `QUEUED` 或复用 Attempt。
- 日志分块、脱敏、单调游标、显式截断证据、摘要指标和产物校验和。

退出条件：

- 固定 Runtime 对四种 MySQL/PostgreSQL Reader/Writer 方向完成一次性复制和独立核验。
- 重复幂等键不创建第二个执行。
- 错误凭据、DataX 失败、超时、取消和 Worker 崩溃进入正确终态。
- API/Worker 重启后无永久 `RUNNING` 或孤儿 JVM。
- 临时配置按成功/失败/取消路径全部清理。
- 源端变化、Operator/DBA 报告或撤回已知目标外部 DML/DDL/冻结破坏、目标声明过期、
  目标端行数/摘要跨快照竞态、目标非空、任一脏记录、部分写入、物理目标别名和不同
  幂等键并发同目标，以及提交处置确认并由独立 RecoveryProbe 取得 Worker 空表证据后的
  恢复后再次执行均有真实证据。测试结论不得扩大为平台能自动发现任意瞬时、未报告或已
  回滚的平台外写入。

### Phase 6：可操作的前端闭环

交付：

- 登录、项目切换、数据源、任务、执行、日志、审计页面。
- 复制向导：基础信息、授权的源/目标、表/字段、源静默/目标外部独占说明、目标空表风险、
  目标声明版本与 `valid_until`、`channel`/超时与只读 `dirty_data_limit=0/0`、校验、发布。
- 执行页展示目标声明的 `ACTIVE/REVOKED/EXPIRED`，并提供“撤回声明/报告窗口破坏”操作；
  用户获知带外破坏时可立即触发 fail-closed 收敛和 `TARGET_EXCLUSIVITY_REVOKED` 审计。
- 执行详情分别展示进程状态、数据影响和核验状态，并提供可恢复日志游标。
- 失败恢复向导记录处置确认并展示独立 RecoveryProbe 生成的空表证据；UI 明确用户确认本身不是证据，也不提供绕过服务端门禁的入口。
- 加载、空、错误、权限、冲突、离线、超时和危险操作状态。
- 基于路由和操作的 UI 权限；服务端仍是最终权限源。

退出条件：

- 四类角色的关键页面和按钮与权限矩阵一致。
- 浏览器完成真实“选择授权数据源到查看已核验复制结果”链路。
- 刷新页面或日志断线后可恢复，不丢失最终状态。
- 键盘操作、焦点、标签、对比度和缩放通过最低可访问性门禁。

### Phase 7：质量、安全、容量与恢复

交付：

- 全矩阵 API/DB/Worker/UI/真实 DataX E2E。
- 权限、注入、SSRF、路径穿越、日志伪造、密钥泄露测试。
- 使用版本化 workload manifest 执行 1,000,000 行参考数据和控制面性能基线。
- 数据库、日志产物和主密钥材料的备份恢复演练。
- 数据库迁移、Runtime 升级失败和应用回滚演练。
- SBOM、依赖许可证清单和漏洞扫描报告。
- 在干净 Windows 11 x64 VM 自动化/人工联合验证：Setup/Launcher 签名与哈希、安装/
  升级/回滚、卸载保留数据、Docker/WSL2/虚拟化缺失、Docker 未启动、端口冲突、磁盘
  不足、loopback/LAN 拒绝、Windows 重启、睡眠/恢复、Docker/WSL 重启和备份恢复。
- 运行 `E2E-WIN-001`（`PRD-FR-WS-001`）与 `E2E-WIN-002`（`ACC-PRD-014`）；在同一
  发布环境完成固定 Linux DataX 容器内四方向完整表/选列与独立 oracle，Windows 宿主
  不得直接运行 DataX/JDK。

退出条件：

- `acceptance-manifest.v1` 中所有 `V1-MUST` 需求均有唯一测试、oracle、证据和 PASS 结果。
- P0/P1 缺陷为 0，Critical/High 安全发现为 0；需求发布级别与缺陷严重度不得混用。
- 备份恢复后的任务、版本、执行和审计完整。
- macOS/Linux 构建、容器包存在或非 Windows E2E 不得标为 Windows E4。
- 性能结果记录硬件、数据集、请求配比、队列深度、日志量、磁盘水位、重复次数、版本和瓶颈，不用模糊“很快”描述。

### Phase 8：试点发布

交付：

- 已签名 `DataX-Enterprise-Studio-Setup-<version>-x64.exe`、已签名 `launcher.exe`、
  发布 SHA-256、SBOM、第三方许可证、固定镜像摘要、迁移版本和 Runtime manifest。
- 安装、升级、回滚、备份、恢复、事故处置手册。
- 已知限制、变更日志、验收报告和签署记录。
- 试点环境容量与网络白名单。

退出条件：

- 在干净 Windows 11 x64 VM 安装并通过依赖预检、幂等启动、健康/就绪、仅
  `127.0.0.1:17860` 暴露、四方向真实 DataX、备份恢复、睡眠/重启/Docker/WSL 恢复和
  卸载保留 named volumes/导出备份；`E2E-WIN-001/002` 均为 PASS。
- 真实验收链路由非开发者复核。
- 所有 `V1-MUST` 需求通过；P0/P1 缺陷为 0，不允许用环境原因或人工豁免替代核心门禁。
- 文案只声明“V1 企业试点”，不宣称高可用或生产认证。

## 4. 工作包与 Issue 粒度

一个 Issue 应：

- 关联一个或少量需求 ID。
- 明确需求优先级；需求优先级与缺陷严重度是两套独立字段。
- 在 1—3 个可审查提交内完成。
- 包含输入、输出、非目标、异常、权限、迁移、唯一测试 ID、oracle 和验收证据路径。
- 避免同时重构架构、增加功能和修改部署。

推荐按纵向切片拆分，例如“PostgreSQL 数据源连接测试”，而不是“完成所有后端”。

## 5. 阶段报告模板

每个阶段交付报告必须包含：

```text
阶段：
关联需求：
已实现：
变更文件：
迁移/配置：
已运行检查及结果：
真实外部链路证据：
未运行或受阻：
安全/兼容/回滚影响：
下一阶段前置条件：
```

## 6. 完成定义

一个功能只有同时满足以下条件才是 Done：

- 需求和非目标没有漂移。
- 正常、异常、权限和并发行为均实现。
- OpenAPI/JSON Schema/迁移与实现一致。
- 单元、契约、集成和相应 E2E 通过。
- `process_state`、`data_effect`、`verification_state` 不互相替代，且独立 oracle 证据可追溯。
- UI 有加载、空、失败和权限态。
- 敏感数据经过检查且有审计。
- 文档与追踪矩阵同步。
- 交付报告明确真实验证与未验证项。

整个 V1 只有发布门禁、恢复演练、四方向真实 DataX E2E 和机器可读 `acceptance-manifest.v1` 全部通过后才可标记完成。

## 7. 禁止的捷径

- 一次性生成全部前后端后再补测试。
- 直接从 API 进程调用 DataX。
- 使用 SQLite 代替 PostgreSQL 后声称数据库链路完成。
- 使用 Stream Reader/Writer、Mock DB 或静态日志代替认证矩阵。
- 把凭据写入 DataX JSON 后长期保存。
- 为赶进度打开自由 SQL、插件上传或 AI 自动执行。
- 因时间不足删除失败路径、安全控制、迁移或恢复验证。
