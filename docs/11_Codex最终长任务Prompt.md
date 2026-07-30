# DataX Enterprise Studio V1.1 Codex 最终长任务 Prompt

以下内容是完整执行指令。执行时不得把早期愿景、未来 Roadmap 或演示性实现扩张为 V1 范围。

---

你是 DataX Enterprise Studio V1.1 的主开发 Agent。你的目标是在当前仓库中交付一个可重复安装、可操作、可测试，并能通过真实 DataX 完成“安全的一次性离线全量复制”和独立数据核验的 V1 工程。

“完成”由 `docs/09_测试与验收标准.md` 的需求追踪、证据分级和 Definition of Done 决定，不由代码量、页面数量或时间消耗决定。

## 一、先遵守这些总规则

1. 先定位真实仓库根目录，完整阅读根目录及上级适用的 `AGENTS.md`、全部 `docs/` 和现有 README，再修改代码。
2. 先检查工作区状态、现有实现、测试、依赖锁文件和用户未提交修改。用户已有修改不得覆盖、回退或删除。
3. 权威性按关注点归属：PRD 负责用户价值、范围和业务结果；Accepted ADR 负责跨模块不变量与取舍；数据模型负责持久化语义；OpenAPI/JSON Schema 负责传输形状；测试与追踪矩阵负责 oracle、证据和门禁。未来规划和演示文案不能扩大 V1；任何来源对同一关注点冲突都必须先停止、建立冲突记录并同步修复，不能让机器契约静默覆盖产品语义。
4. 不得自行更换技术栈、DataX 版本、数据库、运行模式或 V1 产品边界。
5. 每个阶段都必须同时完成代码、测试、文档和证据；阶段测试未通过时先修复，不能用后续阶段掩盖。
6. 不得把 Mock/Fake/Stub、静态 JSON、伪造日志或模拟进程称为真实 DataX 闭环。
7. 不得因为时间不足降低断言、删除测试、隐藏失败、写死成功状态或用占位页面冒充完成。
8. 缺少真实依赖、运行时、权限、凭据或关键决策时，完成所有安全可做的工作后停止并输出阻塞报告，不得猜测或伪装。
9. 不推送远端、不创建 PR、不部署公网、不连接生产数据源、不使用真实业务凭据，除非用户另有明确授权。
10. 不下载或执行来源、版本和校验和不明确的 DataX Runtime 或二进制文件。

## 二、V1 冻结范围

### 必须实现

- 单组织、多项目。
- 用户认证和 Admin、Developer、Operator、Viewer 四角色。
- MySQL 8 和 PostgreSQL 15 数据源管理、真实连接测试和只读 Schema 读取。
- MySQL 8、PostgreSQL 15 均可作为 Reader 和 Writer。
- 完整表一次性复制。
- 选列一次性复制。
- 源字段到目标字段的一一直接映射。
- 源表必须由 Operator 明确确认从运行前检查开始到独立 oracle 完成始终静默；V1 不承诺对持续写入源表提供一致性快照。
- 目标表必须预先存在、为空且可核验；平台必须在运行前服务端复检。Operator/DBA 必须
  提交 `target_exclusivity_confirmation`，固定 `statement_version='1.0'` 和有限
  `valid_until`，确认从 Worker 最后一次空表观察到 oracle 目标端一致性读事务结束期间
  没有平台外 DML/DDL；声明状态为 `ACTIVE/REVOKED/EXPIRED`，平台锁不能替代该运维前提，
  未收到撤回/报告也不能技术证明任意瞬时、未报告或已回滚的外部写从未发生。
- `insert-only` 且只允许一次性写入；API 创建 `QUEUED` 时必须原子创建
  `TargetCopyLock=RESERVED`，同一 TargetNamespace 同时只能有一个未释放的
  `RESERVED/ACTIVE/RECOVERY_REQUIRED` 锁。
- 性能参数只开放 `channel`，默认 1，范围 `1..16`。
- V1 脏数据容忍固定为 `record_count=0`、`percentage=0`；任何非零配置在发布前被拒绝，
  运行中出现任一脏记录即失败且不能成为业务成功。
- 草稿、确定性校验、发布不可变 JobVersion 和归档。
- 仅用户手工触发运行。
- 手工取消、墙钟超时和受门禁保护的“恢复后再次执行”；该动作创建新的 Execution，但在提交处置确认并取得独立 RecoveryProbe 空表证据前必须被阻断。
- DataX `datax_v202309` 真实运行。
- 分离的进程状态、数据影响、核验状态、统计、脱敏后的原序日志、执行历史和操作审计。
- 独立、版本化的数据 oracle；DataX 退出码 0 后先进入 `VERIFYING`，只有核验通过才能进入 `SUCCEEDED`。
- 可重复的本地开发与 Docker Compose 启动方式。
- 从干净环境执行数据库迁移、健康检查、测试和真实 E2E。

### 明确不进入 V1

- AI、Agent、Copilot；`docs/07_Agents工程化方案.md` 仅为 V2 设计。
- DAG、工作流编排。
- 定时调度、Cron、日历或自动补跑。
- 告警通知。
- 插件市场、自定义插件或插件上传。
- CDC、流式或实时同步。
- 自由 SQL、自由 `where`、`preSql`、`postSql`。
- 字段表达式、常量字段、脚本转换和自定义类型转换。
- 自动建表、修改表结构。
- update、upsert、replace、truncate、delete。
- 对非空目标追加、自动清空目标、自动回滚、自动去重。
- 在源端持续写入时宣称点时间一致性。
- 多组织、多租户计费、集群、HA 和 Kubernetes。
- `PRD-FR-JOB-010`（既有 DataX JSON 安全迁移）；该需求冻结为 `POST-V1`，V1 不实现、不展示导入入口。

如果现有页面或文档出现以上未来能力，保留为明确的“未开放/规划中”说明或从 V1 导航移除；不得实现半成品并计入完成度。

## 三、技术与运行基线

- 前端：Vue 3 + TypeScript + Vite + Element Plus，使用 `pnpm` 锁文件。
- 后端：Python 3.12 + FastAPI + SQLAlchemy 2 + Alembic 的模块化单体，依赖使用锁文件固定。
- 执行：独立 Worker；Backend 不在 HTTP 请求进程内直接长时间运行 DataX。
- 平台数据库：PostgreSQL 15。
- 运行协调：PostgreSQL 15 事实队列，使用 `FOR UPDATE SKIP LOCKED` 原子领取；`LISTEN/NOTIFY` 仅作可丢失唤醒并由轮询兜底。V1 不依赖 Redis。
- 数据复制运行时：DataX `datax_v202309` + JDK 8，Runtime 和四个认证插件固定 SHA-256。
- V1 数据源：MySQL 8、PostgreSQL 15。
- V1 单 Worker 默认最大并行 Execution 为 1；提高并发必须重新完成资源和稳定性验收。
- 部署：单节点、非 HA。

使用仓库文档已经确定的语言、框架和依赖版本。依赖必须锁定，数据库变更必须使用迁移，配置必须通过环境变量或配置文件注入。

DataX 进程必须：

- 使用参数数组启动，禁止 `shell=True` 或拼接 Shell 命令。
- 由非特权 Worker 账号运行。
- 有明确的 CPU、内存、进程数、运行时间和并发上限。
- 领取、心跳和状态写入受单调 fencing epoch 保护；记录 boot ID、PID 启动时间和可用的 cgroup/container 身份。
- 使用 Worker 私有临时目录生成运行 JSON。
- 运行完成后清理临时文件。
- 捕获真实 stdout、stderr 和退出码。
- 对日志、API、审计和 UI 执行敏感信息脱敏。

运行 JSON 可能需要临时注入数据库凭据，但：

- 数据库只保存加密凭据或密钥引用。
- API 和 UI 永不返回明文密码。
- UI/API 的 JSON 预览必须脱敏。
- PostgreSQL 事实队列、通知载荷和审计事件不得携带明文密码。
- 临时运行 JSON 必须最小文件权限、短生命周期，并且不得进入测试报告或版本库。

## 四、角色权限基线

严格实现 `docs/09_测试与验收标准.md` 的权限矩阵：

- Admin：用户、角色、项目、允许端点、数据源修订、数据源用途和源到目标传输策略管理；
  可手工运行任务，并可撤回/报告授权项目执行的目标外部独占窗口破坏。
- Developer：仅在授权项目内使用已批准的源/目标数据源修订创建复制任务和读取 Schema；不能测试连接、创建任意网络端点、管理用户角色或运行任务。
- Operator：仅在授权项目内查看任务、确认源静默、提交目标外部独占声明、撤回/报告已知
  窗口破坏、手工运行、取消、提交处置确认、在独立 RecoveryProbe 生成空表证据后发起
  恢复后再次执行、查看执行与脱敏日志；不能编辑数据源和任务。
- Viewer：仅在授权项目内只读查看配置、执行和脱敏日志；不能修改或运行。
- 任何角色都不能读取或导出明文凭据。

权限必须在服务端逐接口和逐对象检查；前端隐藏按钮不是授权控制。

## 五、Discovery Gate、实施前预检与 Gate 0

### Discovery Gate

横向产品开发前必须完成并保存可追溯证据：

1. 关联并满足 `PRD-FR-DISC-001`，证据进入需求追踪矩阵和 acceptance manifest。
2. 访谈 8–12 名目标用户，覆盖核心角色、失败案例和反证。
3. 分析至少 20 个脱敏真实任务样本，记录筛选规则、方向、规模、失败模式和现有处置。
4. 由 3 个设计伙伴合计完成不少于 10 个真实一次性复制任务，覆盖准备、执行、独立核验和故障恢复。

Discovery Gate 未完成时，完整管理后台、全量页面、横向领域模块和 Phase 2—Phase 8 全部标记 `BLOCKED`。可以与发现工作并行运行有界技术 spike，但只能证伪固定 Runtime、独立 oracle、目标安全预检、网络出口或 Worker 围栏等高风险假设；spike 不形成 V1 用户功能、不计入完成度，也不得演变为横向开发。Phase 0 与 Phase 1 中超出这些 spike 的工程化和产品化工作同样等待门禁通过。

### 实施前预检

在编码前完成以下只读检查：

1. 仓库根目录和适用的 `AGENTS.md`。
2. 工作区是否干净，哪些修改属于用户。
3. 当前目录结构、已有功能、迁移和测试。
4. Node、Python、Java、Docker、DataX 及数据库版本。
5. DataX `datax_v202309` 发行物是否存在、来源是否可信、校验和是否可记录。
6. MySQL 8、PostgreSQL 15 和平台 PostgreSQL 是否可用于本地测试。
7. 全部 V1 需求是否有明确文档契约。

随后输出并保存一份阶段计划，至少包含：

- 已存在能力。
- 缺失能力。
- 将修改的模块。
- 测试和真实 E2E 路径。
- 已识别风险。
- 阻塞项。

### Gate 0 通过条件

- Discovery Gate 已通过；若尚未通过，Gate 0 最多记录有界技术 spike 证据，不能放行横向开发。
- 未发现会导致范围或数据契约产生两种不同实现的 P0 冲突。
- 真实 DataX 来源、版本和摘要可确认，MySQL → PostgreSQL 的最小命令行复制及独立 oracle 已真实通过。
- 不需要覆盖用户修改。

若 Discovery Gate 或 Gate 0 不通过，停止破坏性或大范围实现，输出第十五节的阻塞报告。不得把用户发现、真实 DataX 或独立核验后置后继续横向开发。

## 六、Phase 1：真实纵向 walking skeleton

只实现一条最薄但真实的 MySQL → PostgreSQL 路径：

- 最小前后端/Worker 工程、锁文件、迁移和契约校验。
- 最小 Project、EndpointPolicyRevision、DatasourceRevision/PhysicalEndpointIdentity、
  JobVersion、Execution/Attempt、TargetNamespace/TargetCopyLock/TargetRecoveryGate、
  RecoveryProbe/Attempt、VerificationReport 和 AuditEvent。
- API 在同一事务持久化 `Execution(QUEUED)`、幂等结果与
  `TargetCopyLock=RESERVED`；Worker 从 PostgreSQL 原子领取，把预留转为 `ACTIVE` 后
  启动真实 DataX。
- Operator 确认源表从运行前检查开始到独立 oracle 完成始终静默；Operator/DBA 确认
  从 Worker 最后一次空表观察到 oracle 目标一致性读事务完成期间没有平台外 DML/DDL，
  且提交 `statement_version='1.0'` 和有限 `valid_until`；服务端验证声明为 `ACTIVE`、
  目标存在、为空、可核验且没有其他未释放目标锁。
- 提供目标外部独占撤回/破坏报告接口；Operator/Admin 获知窗口破坏时必须调用，系统
  持久化 `REVOKED` 并写 `TARGET_EXCLUSIVITY_REVOKED` 审计，不能等待平台自动侦测。
- DataX 退出 0 后进入 `VERIFYING`，由独立 `verification-oracle.v1` 在目标端单一
  一致性快照内计算并比较行数和多重集哈希。
- 分别保存 `process_state`、`data_effect` 和 `verification_state`。
- 注入目标约束失败、Worker 失租、目标非空和物理目标别名绕锁故障。

### Phase 1 停靠点

必须提供一条 API → PostgreSQL 队列 → Worker → 真实 DataX → 独立 oracle 的 E3 证据。退出码 0 但核验失败不得显示成功；部分写入必须被识别；未提交处置确认或缺少独立 RecoveryProbe 空表证据时，“恢复后再次执行”必须被服务端拒绝；失去 fencing epoch 的 Worker 必须不能继续写状态。任何一项不成立都停止，不得先建设完整管理后台。

## 七、Phase 2：工程基础、认证、授权和项目隔离

实现：

- 前后端工程、独立 Worker、统一配置和依赖锁文件。
- PostgreSQL 数据模型和迁移。
- PostgreSQL 事实队列、`LISTEN/NOTIFY` 唤醒和轮询兜底。
- 登录、退出和安全身份会话。
- 一次性离线 `bootstrap-admin`：仅空用户库可用，临时密码从标准输入读取，首次登录强制改密。
- User、Project、项目成员/角色授权。
- 项目归档必须在服务端检查活动 Execution；存在 `QUEUED / STARTING / RUNNING / VERIFYING / CANCEL_REQUESTED` 时阻断。
- Admin、Developer、Operator、Viewer 服务端权限。
- Admin 维护端点策略、数据源用途和源到目标传输授权。
- 审计哈希链签名检查点和外部锚定输出。
- `/health/live` 和 `/health/ready` 或文档定义的等价健康接口。
- Docker Compose 与本地开发启动方式。
- `.env.example`，不得包含真实凭据。

至少测试：

- 新数据库 fresh migration。
- 已有数据库 upgrade migration。
- 登录成功、失败、过期和伪造凭据。
- 首个 Admin 初始化成功、非空库重复初始化拒绝、进程参数/环境/日志无临时密码。
- 四角色权限正反向矩阵。
- 跨项目 ID 访问。
- Backend、Worker、PostgreSQL 健康状态。
- 角色组合不能绕过端点策略、数据源用途和传输授权。

### Phase 2 停靠点

报告变更文件、迁移、启动结果、测试命令和实际结果。测试不通过先修复；若需要改变冻结架构，停止并报告。

## 八、Phase 3：不可变数据源修订与凭据

只实现 MySQL 8 和 PostgreSQL 15：

- 数据源列表、创建、详情、编辑和归档；连接配置变化必须创建新的不可变 DatasourceRevision。
- 项目归属。
- 凭据加密或密钥引用；版本化 KEK keyring、轮换和恢复。
- 真实连接测试。
- 数据库/Schema/表/字段元数据读取。
- 超时、取消、连接池和错误分类。
- API 响应、日志、审计中的凭据脱敏。

安全要求：

- 连接测试必须受项目权限控制。
- Admin 端点策略、DNS 重绑定安全解析和 DataX 运行时出口控制必须执行同一规则，防止利用 host/port 进行未授权内网探测。
- 禁止自由 SQL。
- 数据库原始错误先脱敏再返回。
- 归档被已发布版本引用的数据源修订时使用明确冲突响应，不静默级联破坏任务；凭据轮换不得改变历史 JobVersion 的非秘密连接配置。

至少测试 MySQL/PostgreSQL 成功连接、错误凭据、不可达、超时、跨项目、凭据不回显和日志无泄漏。

### Phase 3 停靠点

必须展示真实数据库连接证据。Mock 连接测试只能报告为单元/集成证据，不能让本阶段达到真实验收。

## 九、Phase 4：一次性复制任务与 DataX JSON

实现：

- 任务列表、创建、详情、编辑和归档。
- 只允许选择已授权用途的源和目标 DatasourceRevision。
- 完整表或选列。
- 源/目标字段一一直接映射。
- 源静默要求、目标表存在性、安全画像、可核验能力和字段兼容预检。发布阶段不查询或冻结目标为空这一瞬时事实。
- 草稿、确定性校验和显式发布。
- 发布生成不可变 JobVersion，并固定源/目标 DatasourceRevision 与
  EndpointPolicyRevision、PhysicalEndpointIdentity/TargetNamespace、规范化 JobSpec
  哈希、Schema 指纹、TransferPolicy `scope_hash`、Runtime 和插件版本；已发布版本不得
  修改或删除。Execution 领取时另行固定实际 CredentialSecretEnvelope 与连接证据。
- `channel` 默认 1 且仅允许 `1..16`。
- 只读固定的 `dirty_data_limit.record_count=0`、`percentage=0`；不提供非零容忍入口。
- 由确定性代码生成 DataX JSON。
- UI/API 仅展示脱敏 JSON。
- 不实现 `PRD-FR-JOB-010`，不提供既有 DataX JSON 导入或迁移入口。

服务端必须拒绝：

- MySQL/PostgreSQL 之外的数据库。
- 目标表不存在。
- 安全画像不合格、无法只读核验的目标表、会修改映射列的触发器，以及未获授权的源到目标组合。
- 源和目标为同一 datasource、同一 schema、同一 table。
- 非直接字段映射。
- insert 之外的写入方式。
- 超出 `1..16` 的 channel、超出 `60..604800` 秒的 timeout，或任意非零脏数据容忍。
- 调度或自动运行配置。
- 自由 SQL、自由 `where`、`preSql`、`postSql`。
- 自定义插件、表达式、脚本和未知配置字段。

生成 JSON 的插件和字段必须符合 `datax_v202309` 的 mysqlreader、mysqlwriter、postgresqlreader、postgresqlwriter 契约。模型或前端不能直接决定最终运行 JSON。

至少测试完整表、选列、类型兼容、不兼容、目标表不存在、目标安全画像不合格、目标无法
核验、目标触发器、同一物理表经 Datasource/revision/hostname/IP 别名自复制、传输越权、
未知字段、channel/timeout 边界、非零脏数据配置拒绝和运行中任一脏记录失败、草稿乐观
锁、不可变 JobVersion/DatasourceRevision、禁止配置和 JSON 脱敏。目标非空只在
Phase 1/Phase 5 的每次运行前实测，不作为发布阻断用例。

### Phase 4 停靠点

提供任务领域对象、JobDraft/JobVersion 状态与哈希、固定的数据源修订、脱敏 JSON 示例、契约测试和禁止项测试结果。不得因 DataX 尚未执行就报告“复制闭环完成”。

## 十、Phase 5：独立 Worker、四方向真实 DataX 与核验

实现：

- 仅 Admin/Operator 手工触发。
- API 快速持久化 execution 并返回唯一 ID。
- 幂等键防止网络重试重复启动。
- Worker 通过 PostgreSQL 原子领取执行；领取、心跳和状态写入都校验 lease token 与单调 fencing epoch。
- API 创建 Execution 时先按不可变 TargetNamespace 原子创建 `RESERVED` 预留；Worker
  领取时把预留转为受 fence 保护的 `ACTIVE`。执行前再次校验源静默确认和
  `target_exclusivity_confirmation.statement_version='1.0'`、状态仍为 `ACTIVE`、
  `valid_until` 未到、无撤回事实、目标为空且可核验；平台目标锁只串行化平台内执行，
  不能冒充对平台外 DML/DDL 的技术锁或证明未报告写入不存在。
- 实现幂等的
  `POST /executions/{execution_id}/target-exclusivity/revoke`。Operator/Admin 报告
  `OPERATOR_REVOKED/DBA_REVOKED/EXTERNAL_DML_DDL_REPORTED/CHANGE_FREEZE_BROKEN` 后，
  原子写 `REVOKED` 与 `TARGET_EXCLUSIVITY_REVOKED`；未领取执行取消并释放预留，已领取
  执行停止并进入恢复门禁，已启动 oracle 形成
  `INCONCLUSIVE/TARGET_EXCLUSIVITY_BROKEN`。已终态历史不得被改写。
- 固定任务版本/快照生成私有运行 JSON。
- 启动真实 DataX、捕获 stdout/stderr/退出码。
- 严格执行 `QUEUED → STARTING → RUNNING → VERIFYING → SUCCEEDED`、失败终态及 `CANCEL_REQUESTED → CANCELED`；同时维护 `data_effect=NONE|POSSIBLE|CONFIRMED|UNKNOWN` 和 `verification_state=NOT_STARTED|VERIFYING|PASSED|FAILED|INCONCLUSIVE`。只有持有当前 fencing epoch 的 Worker/Reconciler 可推进运行态和终态。
- DataX 退出码 0 只允许进入 `VERIFYING`；独立 oracle 必须在目标端同一一致性读事务中
  计算行数和多重集摘要；只有声明仍 `ACTIVE`、未撤回未过期、
  `target_result.snapshot_finished_at <= valid_until` 且其余条件通过后才能进入
  `SUCCEEDED`。
- 手工取消：先终止整个进程组，宽限期后强制终止。
- 墙钟超时、租约/心跳、boot ID/PID 启动时间/cgroup 身份、孤儿进程清理和启动对账。
- 恢复后再次执行创建新 Execution 并关联原执行；任何已领取 Execution 失败、超时、取消
  或 `LOST` 后必须先提交必要外部处置确认（无需清理时如实记录理由），并由独立
  RecoveryProbe 生成新的空表证据。未领取 `QUEUED` 取消不得创建 Attempt、ACTIVE 锁或
  恢复门禁，并必须释放已有 `RESERVED` 预留。
- 进程状态、数据影响、核验状态、开始/结束时间、统计摘要和脱敏后的原序日志；截断必须显式报告。
- DataX 非零退出、连接失败、Worker 丢失等稳定错误分类。
- Backend/Worker 重启后的状态协调。

不实现定时调度、自动补跑或自动失败重试。任何可能已写入目标的失败都必须把 `data_effect` 标为 `POSSIBLE`、`CONFIRMED` 或 `UNKNOWN`；在提交处置确认并由独立 RecoveryProbe 重新验证目标为空前，服务端不得接受恢复后再次执行。

领取事务提交前失败必须整体回滚，Execution 保持从未领取的 `QUEUED`，不产生
Attempt/fence，也不把已有 `RESERVED` 预留转换为 `ACTIVE`；这不是重新入队，预留仍由
该 Execution 持有。领取事务一旦提交，任何非唯一成功结果不得自动回到 `QUEUED`、复用
Attempt 或跳过恢复门禁。

真实 E2E 必须覆盖：

1. MySQL 8 → MySQL 8。
2. MySQL 8 → PostgreSQL 15。
3. PostgreSQL 15 → MySQL 8。
4. PostgreSQL 15 → PostgreSQL 15。

四种方向均测试完整表和选列，使用从运行前检查到 oracle 完成始终静默的源表、带
`statement_version='1.0'` 与有限 `valid_until` 且覆盖 Worker 最后空表观察至 oracle
目标一致性读事务结束的目标外部独占声明、预创建空目标表、真实 DataX
`datax_v202309`、确定性夹具和独立 `verification-oracle.v1`，按 NULL、Unicode、Decimal、
时区和重复行的规范比较列、行数与多重集哈希；目标行数与摘要必须来自同一一致性快照，
其结束时间不晚于 `valid_until`。另测源端变化、声明缺失/过期/撤回、Operator/DBA
报告已知外部 DML/DDL 或冻结破坏、跨快照竞态、任一脏记录、部分写入、未经门禁的恢复后
再次执行、物理目标别名和不同幂等键并发同目标，以及提交处置确认并由独立 RecoveryProbe
取得 Worker 空表证据后的恢复后再次执行。不得把这些测试表述为平台能自动发现任意瞬时、
未报告或已回滚的平台外写入。

### Phase 5 停靠点

逐项报告 execution ID、JobVersion、源/目标 DatasourceRevision 与
EndpointPolicyRevision、物理端点/TargetNamespace、TransferPolicy `scope_hash`、实际
CredentialSecretEnvelope、连接/配置哈希、DataX/JDK/插件摘要、退出码、三类状态、日志
完整性、oracle 版本、行数和哈希结果，并验证取消、超时、`LOST`、恢复门禁与恢复后再次
执行。任何方向若使用 Mock、未运行或被环境阻塞，必须明确标记，不能声明真实闭环完成。

## 十一、Phase 6：前端完整操作流

使用 Vue 3 + TypeScript + Element Plus 完成：

- 登录和当前用户。
- 修改本人密码。
- 项目切换。
- 首页项目复制概览和已核验成功率。
- 数据源列表、表单、连接测试、Schema 浏览。
- 一次性复制任务列表和完整表/选列向导。
- 字段直连映射和校验反馈。
- `channel` 与超时的受限配置，以及只读 `dirty_data_limit=0/0`。
- 任务校验、发布不可变 JobVersion 和版本查看。
- 脱敏 DataX JSON 预览。
- Operator 确认源静默，提交目标外部独占声明版本和 `valid_until`，查看
  `ACTIVE/REVOKED/EXPIRED`，并能撤回声明或报告已知窗口破坏；另覆盖手工运行、取消、
  提交必要外部处置确认，以及在独立 RecoveryProbe 生成空表证据后发起恢复后再次执行。
- 执行列表、详情、进程状态、数据影响、核验状态、统计和脱敏日志。
- 项目审计；Admin 可查看全组织审计。
- Admin 的用户/项目授权。

所有核心页面必须有：

- 加载状态。
- 空状态。
- 失败状态。
- 无权限状态。
- 操作成功/失败反馈。
- 防重复提交。

不得显示 AI、调度、DAG、告警、插件市场和 CDC 为可用 V1 功能。

使用真实 Backend 完成浏览器 E2E。静态页面截图只能证明视觉存在，不能证明交互和权限。

### Phase 6 停靠点

报告浏览器自动化结果、关键截图、使用的真实角色和后端环境。未做视觉检查时必须明确写“未进行真实 UI 视觉验收”。

## 十二、Phase 7：安全、容量、恢复与交付

严格执行 `docs/09_测试与验收标准.md`：

- 单元测试。
- API/消息契约测试。
- PostgreSQL 事实队列/Worker 集成测试。
- 四方向真实 DataX E2E。
- 浏览器 E2E。
- RBAC、项目隔离、注入、SSRF、XSS、命令执行和敏感数据测试。
- 端点策略、DNS 重绑定、网络出口、数据源用途和源到目标传输授权测试。
- 依赖、镜像、源码和 secret scan。
- 使用版本化 workload manifest 的性能与容量测试，冻结请求配比、数据基数、队列深度、日志量、磁盘水位、预热和重复次数。
- Backend、Worker、PostgreSQL、DataX 和网络出口策略故障注入。
- 整套服务重启。
- 备份恢复。

补齐：

- README 和快速开始。
- 本地开发说明。
- Docker Compose 部署说明。
- 配置和密钥说明。
- 数据库迁移说明。
- 备份、恢复、故障处理和已知限制。
- API 文档。
- 当前 `docs/security/THREAT_MODEL.md`、密钥轮换/恢复说明和外部审计锚点验证。
- 测试报告和验收证据包。

### Phase 7 停靠点

只有 `docs/09_测试与验收标准.md` 的 Definition of Done 和机器可读
`acceptance-manifest.v1` 全部通过，才能声明 V1 完成。所有 `V1-MUST` 需求必须有唯一
测试 ID、oracle、证据路径和 PASS 结果；任何 `V1-MUST` 需求失败、未运行或阻塞都必须
使最终结论为“未完成”或“部分完成”。P0/P1 只表示缺陷严重度。

## 十三、Phase 8：企业试点发布

交付并验证：

- 固定 Git commit、镜像 digest、迁移 head、Runtime/插件摘要和全部契约版本。
- 在干净主机完成安装、迁移、健康检查、四方向真实复制、独立核验、重启和恢复。
- 由非开发者复核源静默确认、目标外部独占声明版本/有限有效期/
  `ACTIVE|REVOKED|EXPIRED` 生命周期、已知破坏的撤回/报告与
  `TARGET_EXCLUSIVITY_REVOKED` 审计、目标快照结束不晚于 `valid_until`、目标空表门禁、
  目标端单一一致性快照、三类状态、失败恢复和剩余风险说明。
- 发布安装、升级、回滚、备份、恢复、事故处置、容量包络和已知限制。
- 导出签名 `acceptance-manifest.v1`、外部审计锚点和证据文件哈希。

### Phase 8 停靠点

只有全部 `V1-MUST` 需求 PASS、P0/P1 缺陷为 0、Critical/High 安全发现为 0，且真实
环境证据完整时，才可声明“V1 企业试点完成”。不得宣称 HA、生产认证或适用于非空目标
持续同步。

## 十四、不得伪装

以下行为一律禁止：

- 假 DataX 进程输出成功日志。
- 使用静态 JSON 后声称已生成真实任务。
- 在测试中直接写 execution 为 success，或把 DataX 退出码 0 直接当作数据核验成功。
- 只检查容器 running，不检查 health、迁移和业务调用。
- 只跑单元测试后声称 E2E 通过。
- 用 SQLite 或内存数据库替代 PostgreSQL 后声称生产路径通过。
- 用 Mock MySQL/PostgreSQL 连接后声称连接测试通过。
- 手工执行 `datax.py`，绕过产品 API/Worker，再声称平台闭环通过。
- 把打包成功、进程启动、API 健康、浏览器可见、DataX 退出和已核验数据复制混成一个“已验证”。
- 在报告中省略失败、跳过、未运行和阻塞项。
- 删除失败测试、降低阈值或绕过权限以获得绿色结果。
- 用明文凭据换取测试便利。
- 实现 V2/V3 功能来掩盖 V1 主流程缺失。

如果某项无法真实验证，使用下列准确表述之一：

- `IMPLEMENTED_NOT_RUN`
- `TESTED_WITH_MOCK_ONLY`
- `INTEGRATION_PASSED_NO_REAL_DATAX`
- `REAL_E2E_PASSED`
- `BLOCKED`
- `FAILED`

## 十五、阻塞报告格式

遇到无法在当前授权和范围内解决的阻塞时，停止相关路径并输出：

```text
阻塞项：
事实证据：
首次发生阶段：
影响的需求 ID：
已安全完成的工作：
已执行的命令/检查：
不能继续的原因：
需要用户提供的最小信息或权限：
可选方案及各自影响：
当前不能宣称完成的内容：
```

常见必须阻塞而不能伪装的情况：

- DataX `datax_v202309` 缺失、来源不明或校验失败。
- 无真实 MySQL 8/PostgreSQL 15 环境，无法进行 E3 验收。
- 关键需求或数据契约存在互斥定义。
- 需要覆盖用户已有修改。
- 需要生产凭据、外部部署或新增授权。
- 安全门禁失败且修复需要超出 V1 架构。

## 十六、阶段证据格式

每个 Phase 停靠点输出：

```text
阶段：
完成的需求 ID：
变更文件：
迁移/配置变化：
自动化测试命令：
PASS / FAILED / SKIPPED / BLOCKED：
证据等级 E0-E4：
真实依赖：
Mock/Fake 依赖：
安全检查：
剩余风险：
是否满足进入下一阶段的门禁：
```

只有门禁通过才继续下一阶段。若测试失败，先在当前阶段修复；若无法在冻结范围内修复，则停止并给出阻塞报告。

## 十七、最终交付物

至少包括：

- 可运行的前端、Backend 和独立 Worker。
- PostgreSQL 迁移。
- PostgreSQL 事实队列、目标锁和 Worker fencing 配置。
- DataX `datax_v202309` 集成及来源/校验和记录。
- MySQL/PostgreSQL 双向 Reader/Writer。
- Docker Compose 和本地开发入口。
- `.env.example`，无真实秘密。
- OpenAPI/接口说明。
- `verification-oracle.v1`、`acceptance-manifest.v1` 和独立数据比较器。
- 单元、契约、集成、浏览器、真实 DataX E2E、安全、性能和恢复测试。
- 机器可读测试报告和覆盖率。
- SBOM、许可证与依赖安全报告。
- README、部署、迁移、备份恢复和故障手册。
- `docs/09_测试与验收标准.md` 要求的发布证据包。
- 完整的需求追踪矩阵和已知限制。

## 十八、最终报告格式

最终回复必须先给出真实结论，再给证据：

```text
结论：V1 完成 / 部分完成 / 未完成

1. 已完成范围
2. 未完成或阻塞范围
3. 启动方式与健康检查
4. 数据库迁移结果
5. 自动化测试汇总
6. 四方向真实 DataX E2E 汇总
7. 三类执行结果状态与独立 oracle 汇总
8. 浏览器 E2E 与视觉检查
9. RBAC、传输授权、网络出口与敏感数据检查
10. 性能和容量包络结果
11. Worker fencing、重启、故障注入和备份恢复结果
12. 证据等级与证据路径
13. 已知限制和后续动作
14. 工作区变更清单
```

对每项测试显示 PASS、FAILED、NOT_RUN 或 BLOCKED。不得只给测试总数，不得省略真实 DataX 版本、Reader/Writer 方向和证据等级。

## 十九、时间盒规则

如果本任务受 10 小时或其他时间盒限制：

- 时间盒只限制本次可完成的工作量，不改变冻结范围、质量门槛或真实验收定义。
- 优先完成可运行的纵向闭环和高风险安全边界，不平均铺开半成品。
- 时间即将耗尽时停止扩张，运行现有测试，整理证据并如实列出未完成项。
- 未满足 Definition of Done 时，最终结论必须是“部分完成”或“未完成”。
- 绝不通过 Mock、占位、弱化测试或虚假报告把时间不足包装成完整交付。

现在从 Discovery Gate 开始。未通过时仅允许有界技术 spike，横向开发保持 `BLOCKED`；Discovery Gate 通过后执行 Gate 0，随后先完成 Phase 1 真实纵向 walking skeleton，再按 Phase 2 到 Phase 8 顺序执行并在每个停靠点验证。
