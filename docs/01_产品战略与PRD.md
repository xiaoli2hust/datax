# DataX Enterprise Studio 产品战略与 PRD

| 项 | 内容 |
|---|---|
| 文档版本 | 1.2 |
| 状态 | V1.2 Windows 本地工作站工程候选；Discovery Gate 未取证，试点/发布 `BLOCKED` |
| 基线日期 | 2026-07-31 |
| 适用版本 | V1 |
| 关联文档 | `00_文档总览与决策基线.md`、`02_产品信息架构与UI设计.md`、`03_技术架构设计.md`、`04_数据库与领域模型设计.md`、`05_API接口与前后端契约.md`、`09_测试与验收标准.md` |

## 1. 产品决策摘要

DataX Enterprise Studio V1 是面向企业内部数据工程团队、运行在一台 Windows 11 x64
电脑上的安全一次性离线全量复制控制平台。它将固定版本的 Alibaba DataX
（上游代码采用 Apache License 2.0）封装为一条可视、
可控、可核验、可审计的工作链路：

`登录 → 选择项目 → 使用已授权数据源 → 创建复制任务草稿 → 校验 → 发布不可变版本 → 准备静默源表和空目标表 → 手动执行 → 独立核验 → 审计追踪`

V1 不是通用 ETL、可重复同步、实时集成、工作流编排或 AI 平台，也不以“支持 DataX
的全部插件”为目标。V1 只承诺经过产品认证的 MySQL 8 和 PostgreSQL 15 Reader/Writer、
单张静默源表到单张预创建空目标表的一次性复制，以及 Windows 本地单工作站运行。DataX
退出码 `0`、进程终态或自报写入数都不能单独证明复制成功。

当前仓库已具备数据源、任务和执行页面及正式 API 适配的工程候选，以及本机
DATA/SECRETS 分离加密导出、双包认证 journal 与全新空 staging 候选代码；恢复只达到
E1 自动化层，不表示新空 PostgreSQL volume、真实 `pg_restore`、证据重算、卷/secret
原子提交、覆盖升级、签名 Windows 安装或真实 DataX E3/E4 已通过。上述外部验收和
数据库外 WORM 仍为 `NOT_RUN/BLOCKED`。

### 1.1 产品定位

- **用户价值**：让不希望直接编写和保管 DataX JSON 的团队，通过受控 UI 完成可解释的一次性全量复制。
- **治理价值**：把项目边界、权限、凭据、任务版本、每次执行和审计事件纳入统一事实链。
- **运维价值**：通过 `Setup.exe`、桌面快捷方式和本机浏览器管理进程状态、数据影响、
  独立核验、脱敏日志、失败原因和恢复门禁，不要求维护外部 Linux 服务器。
- **安全价值**：不向浏览器、API 响应、日志或 Git 暴露明文凭据，不允许自由 SQL、脚本或自定义插件进入运行时。

### 1.2 交付与访问模型

- Windows 11 x64 是 V1 唯一发布认证的宿主平台。macOS、Linux 宿主以及 Windows on Arm
  均不在 V1 发布承诺内。
- 当前仓库所在 Mac 仅用于开发与自动化层验证；最终运行目标是另一台 Windows 11 x64
  电脑，本 Mac 的构建、浏览器或容器结果不能替代目标机 E4。
- 用户下载发布方签名的 `Setup.exe`，安装同样签名的 Windows Launcher 和桌面快捷方式；Launcher 检查 Docker
  Desktop + WSL2、幂等启动本机 Compose、等待健康检查，再用系统默认浏览器打开
  `http://127.0.0.1:17860`。
- Docker Desktop + WSL2 是明确前置依赖。安装器/Launcher 不静默安装 Docker，不代替
  用户或组织接受许可条款，也不通过伪装运行环境规避许可。
- 固定 DataX Runtime、API、Worker 与 PostgreSQL 继续运行在 Linux 容器中。`Setup.exe`
  是安装器，Launcher 是本机控制壳，不是把系统改写成纯原生单进程 `.exe`。
- 宿主只映射 Web 的 `127.0.0.1:17860`。API、Worker、PostgreSQL 不映射宿主端口，
  其他局域网电脑和公网客户端不能访问产品；数据源连接是受 EndpointPolicy 约束的出站访问。
- 电脑睡眠、关机、重启或 Docker Desktop 停止时服务与运行任务均不可用。恢复后必须先
  由 Worker/reconciler 对账在途 Execution，不能承诺后台持续运行、HA 或自动故障转移。
- 浏览器关闭不等于服务停止；用户必须通过 Launcher 明确查看状态或停止本机服务。重复
  点击桌面快捷方式不得启动第二套实例或重置数据。

### 1.3 待验证的问题假设

以下内容是产品假设，不是已经完成的用户研究结论：

1. DataX JSON 由个人手工维护，字段、插件参数和凭据容易出错或泄露。
2. 任务缺少项目归属、版本和发布语义，无法回答“这次执行到底用了哪份配置”。
3. 执行散落在命令行和脚本中，进程结果、目标数据影响、核验结果、取消、恢复及责任人不可统一追踪。
4. 数据源、任务和执行缺少服务端权限与审计，企业内部共享使用风险高。
5. “DataX 理论支持”常被误当成产品已验证能力，导致范围和验收失真。

企业试点或公开发布前，必须完成 Discovery Gate：访谈 8–12 名目标用户，收集至少 20 个
脱敏真实任务样本，并由 3 个设计伙伴合计完成不少于 10 个真实一次性复制任务的可用性
验证。原始访谈记录、样本筛选规则、失败案例与反证必须留存；未完成时不得批准试点、
发布或 V1 完成，也不得编造研究结论或用内部演示代替。

按 ADR-0007，仓库所有者可以明确授权风险自担的工程候选实现。当前代码开发属于这种
授权，不产生 Discovery 证据，也不降低任何真实 DataX、Windows、安全或发布门禁。

## 2. 产品目标与成功定义

### 2.1 V1 目标

| 目标 ID | 目标 | 完成信号 |
|---|---|---|
| OBJ-01 | 降低认证场景的复制配置门槛 | 用户无需编辑 DataX JSON，即可完成支持矩阵内的复制任务发布 |
| OBJ-02 | 建立配置到数据结果的可追踪链路 | 每次执行都可追溯到不可变 `JobVersion`、数据源/端点策略修订、物理端点与目标表身份、传输授权作用域、实际凭据 Envelope、配置哈希、Runtime/插件版本、连接/空表证据与 oracle 证据 |
| OBJ-03 | 建立安全的一次性复制闭环 | 用户可准备源/目标、手动触发、观察、取消、独立核验，并在提交处置确认且独立 RecoveryProbe 生成空表证据后恢复后再次执行 |
| OBJ-04 | 建立最小企业治理能力 | 项目隔离、四类角色、凭据保护和关键操作审计均由服务端执行 |
| OBJ-05 | 形成可重复执行的验收方法 | 固定 Runtime 对每次重新准备的真实 MySQL/PostgreSQL 测试库执行 E2E，由独立 oracle 核验并留存证据 |

### 2.2 产品指标

下列指标是 V1 试点和发布评价口径，不以 Mock、固定日志或静态页面计数。

| 指标 ID | 指标 | V1 目标 | 统计口径 |
|---|---|---|---|
| KPI-01 | 首次已核验复制端到端时间 | 发现门禁先形成真实基线；V1 目标由产品评审据此冻结 | 从开始准备目标表到首次 `verification_state=PASSED`；包含目标准备、任务设计、校验、发布、源静默确认、执行和独立核验，不以发布代替完成 |
| KPI-02 | 认证样例首次发布通过率 | 不低于 90% | 使用官方验收样例、未手改 JSON 的首次校验与发布 |
| KPI-03 | 执行可追溯率 | 100% | Execution 均绑定 JobVersion、源/目标 DatasourceRevision 与 EndpointPolicyRevision、物理端点/表身份、TransferPolicy `scope_hash`、实际 CredentialSecretEnvelope、连接/配置哈希、Runtime/插件版本、触发人、静默确认、空表证据和 oracle 证据 |
| KPI-04 | 敏感信息泄露阻断率 | 100% | API、UI、日志、审计、测试快照和导出物的自动扫描 |
| KPI-05 | 已核验复制成功率 | 不低于 99% | 分子仅为 `process_state=SUCCEEDED` 且 `verification_state=PASSED`；分母为 `SUCCEEDED + FAILED + TIMED_OUT + LOST`，取消不计。这样进程失败或未能进入核验的尝试不会被隐藏；退出码 `0`、部分写入和恢复后再次执行都不能单独计为成功 |
| KPI-06 | 三维状态一致率 | 100% | UI/API 的 `process_state`、`data_effect`、`verification_state` 与 PostgreSQL 事实、Worker 对账和 oracle 证据一致 |
| KPI-07 | 故障恢复端到端时间 | 发现门禁先形成真实基线；V1 目标由产品评审据此冻结 | 从失败被确认到恢复后的新 Execution `verification_state=PASSED`；包含外部必要处置、处置确认、独立 RecoveryProbe 空表证据、恢复后再次执行和核验 |

## 3. 用户、角色与职责

V1 为**单组织、多项目**。组织不提供切换入口；项目是资源和权限边界。`Admin` 为组织级
角色，其他角色按项目授予。一个用户可在不同项目拥有不同角色，权限取该项目内角色并集。
所有应用账号都只能在安装产品的同一台 Windows 电脑上通过本机浏览器使用；角色和项目
表达治理与职责分离，不构成局域网多用户服务承诺。

### 3.1 用户画像与 JTBD

| 角色 | 典型用户 | Job To Be Done |
|---|---|---|
| Admin | 平台管理员、安全管理员 | 当团队接入平台时，我要创建项目、账号、端点/数据源与方向授权，确保数据只能沿已批准路径复制且关键操作可审计 |
| Developer | 数据工程师、任务开发者 | 当我需要复制一张表时，我要使用已授权方向的数据源、读取元数据、完成字段映射、校验并发布版本，而不是手写 JSON |
| Operator | 数据运维、值班人员 | 当已发布任务需要运行或发生故障时，我要确认源表静默、安全触发、取消、查看三维结果，并在外部完成必要处置后提交确认、取得独立 RecoveryProbe 空表证据，再发起恢复后再次执行 |
| Viewer | 项目负责人、审计或只读协作者 | 当我需要了解任务和执行情况时，我要查看配置摘要、结果、日志与审计，但不能改变系统状态 |

### 3.2 权限矩阵

所有权限必须由 API 服务端校验；隐藏菜单或按钮不能替代授权。任何角色都不能读取已保存的明文密码。

| 能力 | Admin | Developer | Operator | Viewer |
|---|:---:|:---:|:---:|:---:|
| 创建、编辑、归档项目 | ✓ | — | — | — |
| 管理用户、项目成员和角色 | ✓ | — | — | — |
| 查看被授权项目 | ✓ | ✓ | ✓ | ✓ |
| 管理 EndpointPolicy、创建/编辑/测试/启停数据源 | ✓ | — | — | — |
| 授予 `SOURCE_USE` / `TARGET_USE` 和管理 TransferPolicy | ✓ | — | — | — |
| 使用获准方向的数据源读取元数据、设计任务 | ✓ | ✓ | — | — |
| 查看数据源非敏感信息 | ✓ | ✓ | ✓ | ✓ |
| 创建、编辑、校验、发布、归档任务 | ✓ | ✓ | — | — |
| 查看任务和版本摘要 | ✓ | ✓ | ✓ | ✓ |
| 手动执行、取消、提交处置确认、恢复后再次执行 | ✓ | — | ✓ | — |
| 查看执行、指标和脱敏日志 | ✓ | ✓ | ✓ | ✓ |
| 查看本项目审计 | ✓ | ✓ | ✓ | ✓ |
| 查看跨项目审计与安全事件 | ✓ | — | — | — |

说明：

- Admin 独占网络端点和数据源连接的创建、修改、测试与启停。Developer 只能使用 Admin 已按方向授权的数据源，不能把任意主机注册为目标。
- 每个源 DatasourceRevision → 目标 DatasourceRevision 的具体复制必须落在 `ACTIVE`
  TransferPolicy 的精确 catalog/database、schema、源/目标表及显式允许列作用域内；
  `scope_hash` 进入审批、JobVersion 和 Execution，发布和执行前都要复检。标记为
  `SENSITIVE` 的策略必须由两个不同 Admin 批准后才可激活。
- Developer 发布后不能直接执行，避免任务开发与运行操作混同；同一用户确有需要时可同时拥有 Developer 与 Operator，但角色并集不能绕过方向授权、TransferPolicy、源静默、空目标和恢复门禁。
- Admin 的高权限操作也必须审计，不能绕过项目和执行状态规则。
- 用户停用后不得建立新会话；其历史发布、执行和审计记录保留原主体标识。

## 4. V1 范围

### 4.1 支持的产品能力

1. 本地账号登录、退出、修改本人密码；Admin 管理用户、项目成员和角色。
2. 项目创建、编辑、归档和项目切换；数据源、任务、版本、执行与审计均归属项目。
3. Admin 管理 MySQL 8、PostgreSQL 15 的 EndpointPolicy、数据源、方向授权和 TransferPolicy；Developer 只使用获准方向读取元数据和设计任务。
4. 单 Reader、单 Writer、单张静默源表、单张预创建空目标表的一次性离线全量复制任务。
5. 每次读取源表全部行，可复制全部字段或显式选列；一对一字段映射与顺序调整，不做表达式转换。
6. 发布前校验目标表存在性、安全画像、可核验能力、目标字段、类型、长度/精度、空值约束和任务参数；目标是否为空不在发布时判定，必须在每次运行前由 Worker 实测。
7. 草稿、校验、发布、归档；每次发布生成不可变 `JobVersion` 和配置哈希。
8. 只读、脱敏 DataX JSON 预览；用户不能直接编辑或上传 JSON。
9. 手动触发、幂等提交、排队、启动、运行、核验、超时、取消，以及经过门禁的恢复后再次执行。
10. 执行列表、执行详情、脱敏日志、三维结果、独立 oracle 证据、失败信息和审计追踪。
11. Windows 11 x64 本地工作站交付：`Setup.exe` 安装 Launcher/桌面快捷方式，Docker
    Desktop + WSL2 承载单节点 Compose；仅 Web 映射 `127.0.0.1:17860`，其余组件只在
    内部容器网络。V1 不依赖 Redis，也不需要外部 Linux 服务器。

### 4.2 Reader/Writer 认证矩阵

| Reader | Writer | 目标承诺与当前证据 |
|---|---|---|
| MySQL 8 | MySQL 8 | V1 目标支持；当前真实 E3 `NOT_RUN/BLOCKED` |
| MySQL 8 | PostgreSQL 15 | V1 主验收目标；当前真实 E3 `NOT_RUN/BLOCKED` |
| PostgreSQL 15 | MySQL 8 | V1 目标支持；当前真实 E3 `NOT_RUN/BLOCKED` |
| PostgreSQL 15 | PostgreSQL 15 | V1 目标支持；当前真实 E3 `NOT_RUN/BLOCKED` |

认证矩阵只表示 V1 的目标产品边界，不代表当前已通过真实 DataX E3 或 Windows E4；
具体证据状态以决策基线与验收 manifest 为准。两类数据源均可作为 Reader 或 Writer，
不表示支持数据库之间的任意类型转换。平台维护单独的类型兼容矩阵；无法无损直连或安全扩宽的映射必须在发布前阻断。

### 4.3 固定技术边界

| 层 | V1 决策 |
|---|---|
| 宿主平台 | 仅 Windows 11 x64 通过发布认证；不承诺 Windows on Arm、macOS 或 Linux 宿主 |
| 用户交付 | 已签名 Windows `Setup.exe`、已签名 Launcher、桌面快捷方式和受控本机数据目录 |
| 前置依赖 | Docker Desktop + WSL2；安装器检测并引导，但不静默安装、不替用户接受或规避许可 |
| 前端 | Vue 3 + TypeScript + Vite + Element Plus |
| API | FastAPI 模块化单体；不能直接启动 DataX |
| 执行 | 独立 Worker；只有 Worker 可管理 DataX 进程树和推进运行状态 |
| 事实源 | PostgreSQL 15 |
| 任务领取与提示 | PostgreSQL `FOR UPDATE SKIP LOCKED`；`LISTEN/NOTIFY` 仅作可丢失提示并由轮询兜底 |
| Runtime | Alibaba DataX `datax_v202309`，JDK 8，Runtime/插件制品固定 SHA-256；只在固定 Linux 容器中运行 |
| 本机入口 | Launcher 健康检查通过后打开默认浏览器的 `http://127.0.0.1:17860` |
| 网络暴露 | 仅 Web 发布宿主 loopback；API、Worker、PostgreSQL 不映射宿主端口，不支持局域网/公网入站 |
| 部署 | Windows 本地单节点 Docker Compose；明确非 HA；睡眠、关机、重启或 Docker Desktop 停止即不可用 |
| 时间 | 数据库存 UTC，API 为 RFC 3339，UI 按用户时区展示 |

## 5. V1 非目标

以下能力不进入 V1，页面、API、默认菜单和验收演示中也不能放置可误认为可用的占位入口：

- CDC、实时同步、流处理、自动增量、水位线和断点续传。
- 非空目标追加、同一目标并行写入、周期性或可重复同步，以及从运行前检查开始到独立 oracle 完成仍持续写入的动态源表。
- Cron 或其他调度、DAG/工作流、依赖编排、补数编排、通知和告警。
- AI Copilot、任务生成 Agent、自动故障诊断、自动调参或模型依赖。
- 文件、HDFS、NoSQL、云专有数据源及未认证 Reader/Writer。
- 插件上传、自定义插件、插件市场或第三方插件自动安装。
- 自由 SQL、`querySql`、`preSql`、`postSql`、脚本转换和用户自定义参数片段。
- 自动建表、DDL 变更、覆盖写、`truncate`、`upsert`、`merge` 和删除目标数据。
- 多表 Join、聚合、计算字段、一对多映射、数据清洗和数据质量治理。
- 多组织租户、计费、Kubernetes、多节点 HA、自动故障转移和异地灾备。
- 生产 SSO、多环境发布流和跨项目资源共享。
- 外部 Linux 服务器部署、局域网或公网远程访问，以及 macOS、Linux、Windows on Arm
  宿主的发布认证。
- 把 API、Worker 或 PostgreSQL 端口映射到 Windows 宿主，或把 Web 监听地址扩展到
  `0.0.0.0`、局域网地址或公网地址。
- 把全部组件改写/打包为纯原生单进程 `.exe`，静默安装 Docker Desktop，替用户接受
  Docker 许可或用伪装运行环境规避许可。

`PRD-FR-JOB-010`（既有 DataX JSON 安全迁移）冻结为 `POST-V1`。V1 不提供导入入口，更不能导入后直接执行。后续若单独立项，迁移向导只能在受控解析器中把受支持的 Reader/Writer、表和字段映射解析到新的 `DRAFT`，必须丢弃密码、自由 SQL、自定义参数、Transformer 和未知插件，并重新完成数据源授权、人工核对、校验与发布。

## 6. 核心业务流程

### 6.1 首次接入

1. 用户在 Windows 11 x64 上自行安装并启用符合许可的 Docker Desktop + WSL2，再运行
   `Setup.exe`。安装器只检查前置条件，不安装 Docker 或代替用户接受许可。
2. 安装完成后，用户双击桌面快捷方式。Launcher 幂等启动本机 Compose，等待 API、
   PostgreSQL、Worker、固定 Runtime 和 oracle 健康，再打开
   `http://127.0.0.1:17860`；重复启动复用现有实例。
3. 在全新空库上，Launcher 用本机首次启动对话框收集临时 Admin 密码，并通过子进程标准
   输入传给容器内一次性离线 `bootstrap-admin`；密码不得进入命令参数、环境、浏览器、
   日志或 Launcher 持久化，非空用户库必须拒绝重复引导。
4. 初始 Admin 登录并强制修改临时密码，然后创建首个项目。
   登录与当前用户响应必须显式返回 `must_change_password`；完成改密前仅允许刷新会话、
   退出、查看本人和修改本人密码。
5. Admin 创建或启用用户，将 Developer、Operator、Viewer 授权到项目。
6. Admin 创建 EndpointPolicy 与数据源并进行真实连接测试，按成员授予 `SOURCE_USE` / `TARGET_USE`。
7. Admin 为获准的源修订 → 目标修订创建 TransferPolicy；`SENSITIVE` 策略由另一个 Admin 完成第二次批准。
8. 平台保存连接元数据和 AEAD 密文凭据，返回内容始终脱敏；运行网络访问必须被 EndpointPolicy 的 DNS 与出口规则强制约束。
9. 用户进入项目后只能看到该项目及其有权访问的资源；其他电脑无法通过局域网访问此实例。

若所有组织级 Admin 均因登录失败被锁定，本机操作者可通过容器内离线
`datax-studio-recover-admin` CLI 恢复一名已锁定 Admin。新临时密码只经标准输入，恢复后
强制改密并撤销其全部旧会话；仍有有效 Admin、目标并非 LOCKED Admin、或试图通过 Web
调用时必须拒绝。成功恢复写 `SYSTEM_RECOVER_ADMIN` 审计事件。

### 6.2 任务开发与发布

1. Developer 创建 `DRAFT` 复制任务，从具有 `SOURCE_USE` 的 Reader 数据源选择 Schema 和源表。
2. 平台读取源字段；Developer 选择全部字段或部分字段。
3. Developer 从具有 `TARGET_USE` 且与 Reader 之间存在 `ACTIVE` TransferPolicy 的 Writer 数据源选择 Schema 和已存在目标表。
4. 平台自动按名称推荐一对一映射；Developer 可在兼容类型内调整目标字段和顺序。
5. Developer 配置 `channel` 和执行超时；V1 脏数据条数/比例固定为 `0/0`，只读展示且
   不提供可调入口。
6. 平台校验方向授权、TransferPolicy、数据源修订、目标表存在性、安全画像、可核验能力、字段存在性、映射完整性和类型兼容性。通过后任务进入 `VALID`；发布不验证或冻结目标为空这一瞬时事实，目标是否为空必须在每次执行前由 Worker 实测。
7. Developer 查看只读脱敏 JSON 和风险摘要，确认后发布。
8. 发布生成不可变 `JobVersion`；继续编辑必须基于任务产生新草稿，不能修改历史版本。

### 6.3 手动执行与监控

1. Operator 在已发布版本上点击“运行”。
2. Operator/DBA 预先创建可核验的空目标表，并停止源表写入；源表必须从运行前检查开始到独立 oracle 完成始终静默。
3. UI 展示一次性全量、`insert-only`、源静默和目标空表责任；Operator 提交
   `source_quiescence_confirmation`，并代表 Operator/DBA 提交
   `target_exclusivity_confirmation`。后者固定包含 `statement_version="1.0"`、
   `confirmed_at`、`valid_until` 和 `responsible_party`。
4. API 复检角色、方向授权、TransferPolicy、数据源修订、同一目标互斥和幂等键，在同一事务创建 `Execution(QUEUED)` 与 `TargetCopyLock=RESERVED`；已有同 TargetNamespace 预留、活动或恢复锁时拒绝。
5. Worker 使用 PostgreSQL 领取 Execution，持有平台内目标互斥权并在启动 DataX 前只读
   实测目标零行，保存 `target_empty_evidence`；非空、无法核验或目标外部独占声明不再
   `ACTIVE` 时阻断，不能由客户端确认覆盖。
6. Worker 生成独立工作目录和临时运行配置，注入凭据后启动固定 Runtime。用户分别查看 `process_state`、`data_effect`、`verification_state`、诊断指标和脱敏日志。
7. DataX 退出码为 `0` 时进入 `VERIFYING`；独立 oracle 对静默源表和目标表执行规范化
   计数与内容摘要核验。只有数据比对通过、目标外部独占状态仍为 `ACTIVE`、没有
   `revoked_at/reason` 且目标快照 `finished_at <= valid_until` 时，才可
   `PASSED` 并成为 `SUCCEEDED`。
8. Operator 可请求取消；Worker 负责终止完整进程树并保守记录目标数据影响。

### 6.4 异常闭环

- 连接失败：显示稳定错误码、可理解原因、下一步动作和 `request_id`，不回显密码或完整连接串。
- 元数据变化：发布前或运行前校验不通过，阻止运行并指出缺失/不兼容字段。
- Worker/主机重启：事实状态从 PostgreSQL 恢复；无法确认的在途执行进入 `LOST`，不得伪报成功。
- 目标约束失败或出现任一脏记录：执行失败，保留脱敏日志和指标；平台不自动回滚已由目标库提交的数据。
- oracle 不一致或已启动但无法形成结论：`verification_state` 分别为 `FAILED` 或
  `INCONCLUSIVE`，`process_state=FAILED`；oracle 从未启动时保持 `NOT_STARTED`。不得用
  DataX 退出码覆盖。
- 目标外部独占声明生命周期：Execution 创建时为 `ACTIVE`；超过 `valid_until` 时评估为
  `EXPIRED`，Operator/DBA 知悉窗口被撤回或发生平台外 DML/DDL 时必须通过
  `POST /executions/{execution_id}/target-exclusivity/revoke` 报告，系统持久化
  `REVOKED`、`revoked_at` 和 `reason`。人工声明不是技术证明，平台无法检测全部未报告
  或已经回滚的外部 DML/DDL。`REVOKED/EXPIRED` 必须同时形成独立于人工取消的持久
  `WorkTerminationRequest`：未领取项由 reconciler 收敛为
  `CANCELED/NONE/NOT_STARTED` 并释放 `RESERVED`，已领取项停止继续推进、终止受控
  DataX 进程并按已知影响进入恢复门禁；安全原因优先于同时到达的人工取消。数据库终止事实
  与 OS 进程创建、阻塞 JDBC 调用不是一个原子操作，未能在有界控制点返回时只能保守收敛为
  `LOST`；在真实 DataX/Windows 取证前不得宣称即时止写。
- 已领取执行进入 `FAILED / TIMED_OUT / CANCELED / LOST`：原执行不可变。Operator/DBA 在平台外完成必要处置后向恢复接口提交 `remediation_confirmation`；独立 RecoveryProbe 持目标锁生成空表证据并签发 `RecoveryGate=VERIFIED`。恢复后再次执行请求必须引用该 gate、重新确认源表静默，并提交带新 `confirmed_at/valid_until` 的目标外部独占声明，再创建关联原执行的新 Execution。尚未领取的 `QUEUED` 取消直接收敛为 `CANCELED/NONE/NOT_STARTED`，不创建 Attempt/fence/恢复门禁，并把已有 `RESERVED` 预留转为 `RELEASED`。

## 7. 业务规则

| 规则 ID | 规则 |
|---|---|
| PRD-BR-001 | 所有数据源、任务、版本、执行和项目级审计必须归属且只能归属一个项目。 |
| PRD-BR-002 | Admin 可跨项目；其他角色只能访问明确授权项目。资源不存在与无权限的响应不得泄露跨项目资源信息。 |
| PRD-BR-003 | 数据源仅允许 MySQL 8 或 PostgreSQL 15，且只有 Admin 可按 EndpointPolicy 创建、修改、测试和启停。成员必须分别获得 `SOURCE_USE` / `TARGET_USE`；源修订→目标修订必须有 `ACTIVE` TransferPolicy，`SENSITIVE` 策略需两个不同 Admin 批准。任何读取接口不返回密码原值。 |
| PRD-BR-004 | 单任务只能选择一个 Reader、一个 Writer、一个源表和一个目标表；源与目标不能解析为同一物理数据库实例中的同一规范化表身份，切换 Datasource、revision、hostname 或 IP 别名不能绕过。V1 的源内容必须从运行前检查开始到独立 oracle 完成始终静默。 |
| PRD-BR-005 | 发布只验证目标表存在、安全画像合格且具备可核验能力，不把发布时点的空表查询当作执行证据。目标表必须在每次运行前为空；平台不得创建、修改、清空或删除业务表，Worker 必须在启动 DataX 前服务端实测并保存本次 Execution 的 `target_empty_evidence`，不能信任客户端声明。每次 Execution 还必须有 `statement_version="1.0"`、`confirmed_at`、`valid_until`、`responsible_party` 的目标外部独占声明；只有 `ACTIVE`、未撤回且目标快照完成不晚于 `valid_until` 才能通过。撤回或到期必须原子持久化终止事实；未领取项释放 `RESERVED`，已领取项停止/进入恢复门禁，绝不能以人工取消或最终 oracle 拒绝替代止损。 |
| PRD-BR-006 | 写入固定为 `INSERT_ONLY_ONCE`。非空目标拒绝执行；同一 TargetNamespace 在系统范围只允许一个未释放的 `RESERVED / ACTIVE / RECOVERY_REQUIRED` TargetCopyLock。API 创建 `QUEUED` Execution 时原子预留，Worker 领取时转换为 `ACTIVE`，未领取取消释放预留。该锁只串行平台内工作，不能阻止或证明不存在平台外 DML/DDL；V1 不承诺非空追加、周期或可重复同步。 |
| PRD-BR-007 | 字段必须一对一映射；映射数为 1..2048；目标字段不能被重复映射；不允许常量、表达式、脚本或 SQL。 |
| PRD-BR-008 | 目标类型必须在认证兼容矩阵内，并满足长度、精度、标度和空值约束；不安全的隐式缩窄必须阻断。 |
| PRD-BR-009 | 性能只开放 `channel`，默认 `1`，范围 `1..16`。其他 DataX 参数由平台固定，不接受用户 JSON 片段。 |
| PRD-BR-010 | V1 脏数据条数和比例固定为 `0` 与 `0`，任何非零配置在校验/发布时被拒绝，运行中出现任一脏记录即失败且不能被 oracle 判为业务成功。执行超时范围为 60..604,800 秒，默认 3600 秒。非零容忍仅可通过 POST-V1 ADR 重新定义产品结果与 oracle 后引入。 |
| PRD-BR-011 | 任务状态为 `DRAFT → VALID → PUBLISHED → ARCHIVED`。编辑已校验草稿会回到 `DRAFT`；历史 JobVersion 永不可变。 |
| PRD-BR-012 | 只有 `PUBLISHED` 版本可执行；发布和执行时必须复检方向授权与 TransferPolicy。任务归档后不得创建新执行，历史版本、执行和审计继续可读。 |
| PRD-BR-013 | Execution 同时保存 `process_state`、`data_effect`、`verification_state`。主路径为 `QUEUED → STARTING → RUNNING → VERIFYING → SUCCEEDED / FAILED`；取消、超时和 `LOST` 不得被归入已核验成功。 |
| PRD-BR-014 | 只有 Worker 可写运行态、核验态和最终态。DataX 退出码 `0` 只允许进入 `VERIFYING`；仅当独立 oracle 数据比对通过、目标外部独占状态为 `ACTIVE`、`revoked_at/reason` 为空且目标一致性快照 `finished_at <= valid_until` 时，才可写 `process_state=SUCCEEDED`、`data_effect=CONFIRMED`、`verification_state=PASSED`。`REVOKED / EXPIRED` 均不得成功。 |
| PRD-BR-015 | V1 无自动重试。Execution 一旦被 Worker 领取，进入 `FAILED / TIMED_OUT / CANCELED / LOST` 后必须先提交 `remediation_confirmation`，由独立 RecoveryProbe 通过自身 Attempt/fence 复检空表并签发 `RecoveryGate=VERIFIED`；恢复后再次执行引用该 gate、重新确认源静默并提交有新 `confirmed_at/valid_until` 的目标外部独占声明，绑定原 JobVersion、创建新 Execution，并记录 `rerun_of_execution_id`。尚未领取的 `QUEUED` 取消由 reconciler 收敛为 `CANCELED/NONE/NOT_STARTED`，不创建 Attempt/fence/门禁并把 `RESERVED` 转为 `RELEASED`。领取事务提交前失败必须整体回滚且不产生 Attempt/fence、不把 `RESERVED` 转为 `ACTIVE`；提交后任何非唯一成功结果均不得自动回到 `QUEUED` 或复用 Attempt。 |
| PRD-BR-016 | 同一运行请求的幂等键在 24 小时有效期内重复提交只能创建一个 Execution；新幂等键只能表达新意图，不能绕过目标空表、目标互斥、源静默或 RecoveryGate。 |
| PRD-BR-017 | 每次 Execution 固化 JobVersion、源/目标 DatasourceRevision 与 EndpointPolicyRevision、PhysicalEndpointIdentity/TargetNamespace、方向授权与 TransferPolicy `scope_hash`、实际 CredentialSecretEnvelope、连接证据、规范化配置哈希、固定复制策略、Runtime/插件版本、触发人、静默确认、空表证据和触发时间。目标外部独占确认固定 `statement_version="1.0"`、`confirmed_at`、`valid_until`、`responsible_party`；Execution 另存 `ACTIVE / REVOKED / EXPIRED`、`revoked_at/reason`，RuntimeSnapshot 固定声明版本、有效期、接受 actor/时间和确认摘要。 |
| PRD-BR-018 | DataX JSON 预览只读且脱敏。实际凭据仅在 Worker 运行时按需解密，含密文件只可进入最小权限 tmpfs Attempt，并在结束后删除。只有已切换为新 current secret 的历史 `ACTIVE` 版本可退役为 `RETIRED`；直接退役 current secret 必须拒绝，避免排队工作永久等待失效凭据。`RETIRED` 可单向升级到紧急终态，不能重新激活或降级。`REVOKED/COMPROMISED` 必须同一事务禁用 current 指向它的数据源，并为已绑定非终态工作及尚未领取、将绑定该 current secret 的工作建立持久终止事实；Execution/RecoveryProbe 只能失败关闭，RecoveryGate 必须可重新提交而不能永久卡住。Worker 每一端凭据以全新短事务和 `FOR UPDATE` 状态锁决定是否解密，端间与每个有界外部 I/O 前后复检终止事实；状态先提交拒绝新解密，解密先完成也不得继续下一条外部连接。可控的 mutable 明文缓冲区在退出时尽力清零，但 Python/驱动/子进程可能产生不可逐一清零的内存副本，不能把该措施表述为完整内存擦除证明。 |
| PRD-BR-019 | 发布、端点/数据源变更与测试、方向授权、TransferPolicy 审批、执行、取消、源静默确认、目标外部独占确认及撤回/破坏报告、处置确认、RecoveryProbe/RecoveryGate、恢复后再次执行和归档必须产生不可变审计事件。Operator/DBA 知悉目标窗口被撤回或破坏时负有立即报告义务；平台不声称能检测全部未报告或已经回滚的外部 DML/DDL。 |
| PRD-BR-020 | 项目、数据源和任务优先软删除/归档；存在引用或历史执行时禁止物理删除。 |
| PRD-BR-021 | 所有列表稳定排序并分页；所有写操作使用幂等控制或乐观锁，版本冲突不能静默覆盖。 |
| PRD-BR-022 | 日志、表名、字段名和数据库错误均视为不可信输入；展示时转义，日志需脱敏并限制单次读取大小。 |

## 8. 功能需求与用户故事

除 `PRD-FR-JOB-010` 已冻结为 `POST-V1` 外，本章需求发布级别统一为 `V1-MUST`。V1 不实现、不展示也不验收该迁移能力。发布级别与缺陷严重度 `P0/P1/P2/P3` 是两套不同口径，追踪矩阵必须分别记录，不能用“P0 需求”指代全部范围。

### 8.0 产品发现门禁

| 需求 ID | 用户故事 | 验收摘要 |
|---|---|---|
| PRD-FR-DISC-001 | 作为产品负责人，我要用真实用户和任务证据验证 V1 的问题、边界和恢复流程，再批准企业试点与公开发布。 | 完成 8–12 名目标用户访谈、至少 20 个脱敏真实任务样本，以及 3 个设计伙伴合计不少于 10 个真实一次性复制任务；证据包含失败案例、反证、样本规则、结论和负责人签署。未通过时试点、发布和 V1 完成声明保持 `BLOCKED`；只有仓库所有者按 ADR-0007 明确授权时才可风险自担地继续工程候选，且不能把实现当作 Discovery 证据。 |

### 8.1 Windows 本地工作站安装与启动

| 需求 ID | 用户故事 | 验收摘要 |
|---|---|---|
| PRD-FR-WS-001 | 作为没有 Linux 服务器的 Windows 用户，我要通过安装器和桌面快捷方式在本机启动完整产品，以便不维护外部服务器也能使用安全复制流程。 | 仅认证 Windows 11 x64；发布版 `Setup.exe`/Launcher 签名和哈希有效，安装 Launcher/快捷方式并保留明确本机数据边界；Launcher 检测 Docker Desktop + WSL2，缺失时阻断并提供官方指引，不静默安装或代接受许可；启动幂等，健康后用默认浏览器打开 `http://127.0.0.1:17860`。仅 Web 映射该 loopback，API/Worker/PostgreSQL 无宿主端口且局域网不可访问；固定 DataX 在 Linux 容器内运行。浏览器关闭不停止服务，睡眠/关机/重启/Docker 停止时明确不可用，恢复后先对账。 |

### 8.2 认证、项目与权限

| 需求 ID | 用户故事 | 验收摘要 |
|---|---|---|
| PRD-FR-AUTH-001 | 作为用户，我要使用本地账号登录和退出，以访问被授权项目。 | 正确凭据建立会话；错误凭据返回统一错误；停用用户不能登录；退出后令牌失效。 |
| PRD-FR-AUTH-002 | 作为用户，我要修改本人密码，以控制账号安全。 | 校验旧密码和密码策略；成功后撤销其他会话；全程不记录明文。 |
| PRD-FR-AUTH-003 | 作为本机使用者，我要在全新安装上安全创建唯一的初始 Admin，以便系统在没有公开注册入口的情况下完成首次接入。 | 仅空用户库允许 Launcher 调用一次性离线引导；临时密码只经子进程标准输入进入容器 CLI，不进入参数、环境、浏览器、Launcher 持久化、日志或审计；成功后首次登录强制改密，重复引导被拒绝。 |
| PRD-FR-PRJ-001 | 作为 Admin，我要创建、编辑和归档项目，以隔离资源与权限。 | 项目标识（slug）唯一且创建后不可变；存在 `QUEUED / STARTING / RUNNING / VERIFYING / CANCEL_REQUESTED` Execution 时归档被阻断；归档后禁止新增和执行。 |
| PRD-FR-PRJ-002 | 作为 Admin，我要管理用户、项目成员与四类角色。 | 授权即时生效；越权 API 返回 403；每次变更写审计。 |
| PRD-FR-PRJ-003 | 作为多项目用户，我要切换当前项目。 | 切换后列表、统计和可操作项全部按项目刷新；URL 深链仍做服务端授权。 |

### 8.3 数据源

| 需求 ID | 用户故事 | 验收摘要 |
|---|---|---|
| PRD-FR-DS-001 | 作为 Admin，我要按 EndpointPolicy 创建和编辑 MySQL/PostgreSQL 数据源。 | 主机、DNS 解析和出口均受策略约束；密码密文保存；名称在项目内唯一；类型创建后不可变。 |
| PRD-FR-DS-002 | 作为 Admin，我要测试连接，以确认网络、认证和数据库可用。 | 测试使用真实连接和实际出口策略；成功与失败均记录耗时、错误码、操作者和审计；不泄露连接串。 |
| PRD-FR-DS-003 | 作为 Developer，我要浏览获准作为源或目标的数据源元数据。 | 仅查询具有对应 `SOURCE_USE` / `TARGET_USE` 的数据源；支持分页/搜索；显示字段类型、长度/精度、可空和主键信息。 |
| PRD-FR-DS-004 | 作为 Admin，我要停用或归档数据源。 | 被已发布任务引用时不得物理删除；停用后禁止新发布与执行，历史记录可读。 |
| PRD-FR-DS-005 | 作为 Admin，我要审批复制方向和精确表列作用域。 | 源/目标均绑定不可变修订；选择精确 catalog/database、schema、源/目标表和显式允许列，展示规范化 scope 与 `scope_hash`；任何 scope 修改使旧审批失效；`SENSITIVE` 需另一名 Admin 批准；mapping 不属于 `ACTIVE` scope 时发布和执行都被服务端阻断。 |

### 8.4 任务开发、校验与发布

| 需求 ID | 用户故事 | 验收摘要 |
|---|---|---|
| PRD-FR-JOB-001 | 作为 Developer，我要创建任务草稿并保存进度。 | 名称在项目内唯一；草稿可恢复；离开未保存页面前提示；保存使用乐观锁。 |
| PRD-FR-JOB-002 | 作为 Developer，我要选择 Reader/Writer、静默源表、空目标表和源字段。 | 仅显示项目内已启用、具有方向授权且 TransferPolicy 有效的数据源；不支持的插件和自由 SQL 不出现在 UI/API。 |
| PRD-FR-JOB-003 | 作为 Developer，我要配置一对一字段映射。 | 自动推荐同名兼容字段；允许调整映射和顺序；重复、缺失或不兼容映射阻断校验。 |
| PRD-FR-JOB-004 | 作为 Developer，我要配置受控运行参数。 | `channel` 与超时有范围校验；脏数据策略只读固定为 `0` 条/`0%`，非零值被拒绝；不存在任意 JSON 参数入口。 |
| PRD-FR-JOB-005 | 作为 Developer，我要校验任务并获得可操作问题清单。 | 同时校验方向授权、TransferPolicy、数据源修订、连接、元数据、映射、类型、目标存在性、安全画像、可核验能力和参数；错误定位到步骤/字段；通过后状态为 `VALID`。发布阶段不以目标当时为空作为通过条件。 |
| PRD-FR-JOB-006 | 作为 Developer，我要预览脱敏 DataX JSON。 | 预览只读、格式化，密码/Token/连接串敏感片段被掩码；配置变化后旧预览标记失效。 |
| PRD-FR-JOB-007 | 作为 Developer，我要发布不可变版本。 | 只能发布 `VALID` 草稿；生成递增版本号和配置哈希；重复相同内容发布按契约阻止或明确复用。 |
| PRD-FR-JOB-008 | 作为用户，我要查看任务历史版本并比较摘要。 | 可查看版本号、发布人、时间、哈希和字段/参数差异；不能编辑历史版本。 |
| PRD-FR-JOB-009 | 作为 Developer，我要归档不再使用的任务。 | 存在 `QUEUED / STARTING / RUNNING / VERIFYING / CANCEL_REQUESTED` Execution 时阻断；归档后不能执行；历史版本、执行和审计保留。 |
| PRD-FR-JOB-010 | `POST-V1`：作为现有 DataX 用户，我要安全迁移受支持配置到草稿。 | V1 不实现、不展示、不验收。未来立项时只能解析白名单字段到新 `DRAFT`，丢弃秘密和危险/未知能力，重新授权、核对、校验和发布；不得直接执行导入 JSON。 |

### 8.5 执行与监控

| 需求 ID | 用户故事 | 验收摘要 |
|---|---|---|
| PRD-FR-RUN-001 | 作为 Operator，我要手动执行一个已发布版本。 | 提交源静默确认和包含 `statement_version="1.0"`、`confirmed_at`、`valid_until`、`responsible_party` 的目标外部独占确认；服务端复检授权、TransferPolicy，并按 TargetNamespace 原子预留目标；Worker 实测目标为空。知悉窗口破坏时可立即撤回/报告；未满足 `ACTIVE`、未撤回和目标快照在有效期内读完的条件前不显示复制成功。 |
| PRD-FR-RUN-002 | 作为 Operator，我要取消排队中或运行中的执行。 | API 只记录取消请求；未领取排队项由 reconciler 收敛、释放 `RESERVED` 目标预留且不建门禁，已领取项由 Worker 完成进程树终止并进入恢复门禁；终态执行不能再次取消。 |
| PRD-FR-RUN-003 | 作为 Operator，我要在外部完成必要处置后发起恢复后再次执行。 | 先提交处置确认，由独立 RecoveryProbe 生成空表证据并签发 `RecoveryGate=VERIFIED`；恢复后再次执行引用 gate、重新确认源静默并提交带新截止时间的目标外部独占声明，创建关联原执行的新 Execution；原记录不可变。 |
| PRD-FR-RUN-004 | 作为用户，我要查看执行列表和详情。 | 支持项目、任务、版本、三维状态、触发人和时间筛选；详情含时间线、数据影响、oracle 证据、配置摘要、诊断指标和错误。 |
| PRD-FR-RUN-005 | 作为用户，我要查看增量加载的脱敏日志。 | 日志以单调游标读取，可暂停、继续、搜索和下载脱敏文本；断线重连不重复或跳过已确认块。 |
| PRD-FR-RUN-006 | 作为用户，我要区分 DataX 进程、目标数据影响和独立核验结果。 | `process_state`、`data_effect`、`verification_state` 分开展示；每类错误有稳定码、建议动作和 `request_id`，退出码 `0` 或未知影响不能显示为复制成功。 |
| PRD-FR-DASH-001 | 作为项目成员，我要在首页查看项目运行概览。 | 统计有明确时间范围和分母；数量可下钻到同筛选条件的执行列表；不展示 V1 不支持的告警。 |
| PRD-FR-AUD-001 | 作为项目成员，我要查看本项目审计记录。 | 只读、分页、稳定排序；敏感值脱敏；Admin 可跨项目筛选，其他角色仅看被授权项目。 |

## 9. 非功能需求

| 需求 ID | 类别 | 要求 |
|---|---|---|
| NFR-PERF-001 | 控制面性能 | 在验收数据量和 20 个并发 UI 会话下，非外部依赖的读 API P95 ≤ 800 ms、写 API P95 ≤ 1.5 s。 |
| NFR-PERF-002 | 运行反馈 | 手动运行提交后 2 秒内返回 Execution；Worker 产生新状态或日志后，正常网络下 UI P95 在 3 秒内可见。 |
| NFR-SCALE-001 | 单节点容量 | V1 单 Worker 默认最大并行 Execution 为 `1`；超过上限的执行必须保持 `QUEUED`。部署调高并发后仍必须保证同一规范化目标只有一个未释放的 `RESERVED/ACTIVE/RECOVERY_REQUIRED` 锁，并重新完成资源与稳定性验收。 |
| NFR-REL-001 | 事实一致性 | PostgreSQL 是唯一业务事实源；Worker 使用 `FOR UPDATE SKIP LOCKED` 领取，`LISTEN/NOTIFY` 丢失时由轮询恢复，不得丢失 Execution 或产生伪成功。 |
| NFR-REL-002 | 故障恢复 | API、Worker、Docker Desktop 或 Windows 重启，以及主机从睡眠恢复后必须对账在途执行；无法确认的状态进入 `LOST`。V1 不承诺睡眠/关机期间运行、不停机或自动故障转移。 |
| NFR-SEC-001 | 凭据安全 | 凭据使用外部主密钥和 AEAD 加密；响应、日志、审计、预览、导出、异常和测试快照不得包含明文。Worker 每端以 fresh short `FOR UPDATE` 状态锁解密；紧急 secret 撤销/折损与目标独占撤回/到期均须生成持久终止事实，Worker/reconciler 在 admission、每个有界外部 I/O、状态推进、Popen 紧前、tick、oracle 和 heartbeat 消费。已观察到终止后不得创建新连接或进程；数据库提交与 OS/JDBC 边界不可原子，阻塞调用只允许按超时/lease-LOST 保守收敛，真实 E2/E3 之前不得宣称即时停止或完整内存清零。 |
| NFR-SEC-002 | 进程安全 | Worker 使用参数数组启动固定 Runtime，禁止 `shell=True`、命令字符串拼接和用户可控可执行路径；每次运行使用隔离工作目录。 |
| NFR-SEC-003 | 访问控制 | 所有资源读写均校验组织、项目、角色和资源状态；越权、横向访问及对象枚举测试必须通过。 |
| NFR-AUD-001 | 审计 | 凭据、EndpointPolicy、方向授权、TransferPolicy、发布、执行、取消、源静默确认、目标空表证据、处置确认、RecoveryProbe/RecoveryGate、恢复后再次执行和归档操作 100% 产生含主体、对象、结果、时间和 request_id 的审计事件。 |
| NFR-OBS-001 | 可观测性 | API、Worker、oracle 和 Execution 使用可关联 ID；健康检查区分 API、PostgreSQL、Worker、Runtime 与 oracle 可用性。 |
| NFR-COMP-001 | 兼容性 | 宿主仅认证 Windows 11 x64 + WSL2 + 产品支持矩阵内的 Docker Desktop；运行时仅认证 MySQL 8、PostgreSQL 15、DataX `datax_v202309`、JDK 8 和固定插件/镜像摘要。Windows on Arm、macOS/Linux 宿主及版本漂移必须阻断启动或明确标记不受支持。 |
| NFR-DATA-001 | 保留与清理 | Execution/ExecutionEvent 默认保留 365 天，脱敏运行日志 30 天，审计 730 天，幂等记录 24 小时；可延长，缩短须经 Admin 与合规负责人批准。清理不得破坏引用；运行临时凭据和工作目录在结束后及时清理。 |
| NFR-UX-001 | 可访问性 | 核心流程满足键盘可达、可见焦点、表单标签、非颜色单一编码和 WCAG 2.1 AA 对比度要求。 |
| NFR-DEP-001 | 部署边界 | V1 只支持 Windows 11 x64 本地单工作站：`Setup.exe` 安装 Launcher/桌面快捷方式，Docker Desktop + WSL2 是用户自行安装并按适用许可使用的前置依赖，固定 DataX 在 Linux 容器内。仅 Web 映射 `127.0.0.1:17860`，API/Worker/PostgreSQL 无宿主端口且局域网/公网不可访问。维护、睡眠、关机、重启、Docker 停止或主机故障均会中断服务；恢复后先对账。UI 与文档不得暗示外部 Linux 服务器、纯原生单进程 `.exe`、远程服务或 HA。 |

外部数据库速度、网络带宽和源/目标锁竞争不属于控制面响应 SLA；数据吞吐只在固定验收数据集和环境中记录，不泛化为生产承诺。

## 10. 数据与指标口径

### 10.1 首页指标

| 指标 | 定义 |
|---|---|
| 已发布任务 | 当前项目中至少有一个可执行 JobVersion 且未归档的任务数 |
| 24 小时执行数 | 触发时间位于最近 24 小时的全部 Execution |
| 已核验复制成功率 | 分子为 `process_state=SUCCEEDED` 且 `verification_state=PASSED`；分母为 `SUCCEEDED + FAILED + TIMED_OUT + LOST`，`QUEUED / STARTING / RUNNING / VERIFYING / CANCEL_REQUESTED / CANCELED` 不进入分母 |
| 运行中 | 当前状态为 `STARTING` 或 `RUNNING` 的执行数 |
| 核验中 | 当前 `process_state=VERIFYING` 的执行数 |
| 排队中 | 当前状态为 `QUEUED` 的执行数 |
| 恢复待处理 | 最近 24 小时内已领取、目标锁为 `RECOVERY_REQUIRED`，且尚无 `RecoveryGate=VERIFIED` 或后继已核验成功 Execution 的执行数；未领取取消不计 |
| 已核验记录数 | 时间范围内同时满足 `process_state=SUCCEEDED` 与 `verification_state=PASSED` 的 Execution，其独立 oracle `target_row_count` 之和；机器字段为 `verified_records` |

所有卡片和图表必须显示时间范围与项目范围；点击后带相同筛选条件下钻，避免首页与列表口径不一致。

### 10.2 运行结果口径

- DataX 退出码 `0` 只表示进程按自身规则结束。Worker 随后进入 `VERIFYING`；只有独立 oracle `PASSED` 才写 `process_state=SUCCEEDED`。日志汇总解析失败不能伪造或覆盖 oracle 结论。
- `data_effect` 的 `CONFIRMED` 只表示目标影响已由独立证据测得，确认值可以是 0 行，
  不表示内容正确；`POSSIBLE / UNKNOWN` 必须触发持久风险提示和恢复门禁。
- 平台可展示 DataX 报告的读取/写入记录数、字节数、速率、脏记录数和耗时，但统一标为“进程诊断指标”，不得进入成功率或 `verified_records`；缺失指标显示“未采集”。
- V1 不承诺目标端事务性全量回滚。任何已领取执行的失败、取消、超时或 `LOST` 都必须按可能部分写入处置：完成外部必要处置、提交处置确认、由独立 RecoveryProbe 生成空表证据、重新确认源静默后才能发起恢复后再次执行；未领取取消没有目标影响或恢复门禁。

## 11. 风险与缓解

| 风险 ID | 风险 | 影响 | V1 缓解 |
|---|---|---|---|
| RSK-01 | `insert-only` 在非空目标或部分写入后再次运行 | 重复行、唯一键冲突或混合数据 | 服务端拒绝非空目标；按规范化物理表身份互斥；失败后必须经过外部处置、RecoveryGate 和空表复检 |
| RSK-02 | 源表从运行前检查开始到独立 oracle 完成期间变化，或源/目标 Schema 漂移 | 结果时点不确定、执行失败或类型错误 | Operator 确认全窗口静默；运行前 Schema 校验；不兼容或 oracle 不确定时阻断/失败 |
| RSK-03 | DataX/JDK/插件版本漂移 | 结果不可重复 | 固定 Runtime 与插件 SHA-256；启动和执行记录版本摘要 |
| RSK-04 | 日志、异常或临时 JSON 泄露凭据 | 安全事件 | AEAD、运行时注入、脱敏管线、隔离工作目录、结束清理与泄露扫描 |
| RSK-05 | Worker、Docker Desktop、Windows 睡眠/关机或主机中断造成运行态和目标影响不确定 | 错误状态、孤儿进程或重复写入 | 进程树 fencing、Worker 心跳、恢复后启动对账、`LOST`、保守 `data_effect` 和恢复门禁；UI 明示本机停机期间不可用 |
| RSK-06 | 数据库提示通知丢失 | 领取延迟 | PostgreSQL 保存请求事实；轮询为正确性兜底，`LISTEN/NOTIFY` 只降延迟 |
| RSK-07 | Windows 本机与 Docker Desktop 资源竞争 | 控制面变慢、执行失败、电脑无法正常使用 | 安装前容量检查、Worker 并发上限、容器资源限制、队列背压和 Windows 真实容量测试 |
| RSK-08 | 类型兼容矩阵覆盖不足 | 发布后失败或数据截断 | 只允许认证类型映射；缩窄阻断；真实双向 E2E 覆盖 |
| RSK-09 | 取消无法撤销已提交的目标数据 | 部分写入 | 文案明确“停止进程不等于回滚”；保留指标与处置建议 |
| RSK-10 | `Setup.exe` 被误解为纯原生单进程程序，或“企业级”被误解为远程服务器/HA/生产认证 | 安装、采购和运维预期错误 | 安装页、README、系统信息页和验收报告持续标注 Windows 本地工作站、Docker/WSL2 前置、Linux 容器、仅 loopback、非 HA、未生产批准 |
| RSK-11 | Developer 注册自控目标或组合角色绕过数据流审批 | SSRF、内部数据外传 | Admin 独占 EndpointPolicy/数据源；方向授权、TransferPolicy、DNS/出口强制和敏感策略双人批准 |
| RSK-12 | DataX 退出码或自报写入数被误当数据正确 | 错误 KPI 和错误决策 | 三维状态、独立 oracle、`verified_records`，退出码只作诊断 |
| RSK-13 | Docker Desktop/WSL2 缺失、不兼容或许可未由使用者评估接受 | 无法启动或产生许可风险 | Launcher 启动前检测并安全阻断，只提供官方安装/许可链接；不分发 Docker、不静默安装、不自动接受或规避许可 |
| RSK-14 | Web/API/PostgreSQL 误绑 `0.0.0.0` 或映射宿主端口 | 局域网未授权访问、凭据与数据泄露 | Compose 静态策略、启动前检查和 Windows/LAN 双端探测；仅 Web 可绑定 `127.0.0.1:17860`，其他组件无宿主端口 |
| RSK-15 | 升级或卸载误删 PostgreSQL 数据、密钥、审计与证据 | 历史不可恢复或密文无法解密 | 数据路径与程序路径分离；当前安全导出和双包 journal/空 staging 只达到 E1，真实 `pg_restore` 与卷/secret 原子提交未实现，完整恢复/覆盖升级保持关闭；未来只有备份与恢复门禁通过后才允许升级；卸载默认保留数据和密钥，删除必须单独明确确认并记录不可恢复影响 |

## 12. 发布验收

### 12.1 验收前置条件

- Discovery Gate 已完成：8–12 名目标用户、至少 20 个真实任务样本、3 个设计伙伴合计
  不少于 10 个真实复制任务；证据可追溯且包含反证。未完成时工程候选可按 ADR-0007
  继续，但企业试点、公开发布和 V1 完成声明保持 `BLOCKED`。
- 使用干净的 Windows 11 x64 验收机；WSL2 已启用，Docker Desktop 由验收主体自行安装并
  按适用许可使用。Windows on Arm、macOS/Linux 宿主或外部 Linux 服务器不能替代该证据。
- 使用待发布的 `Setup.exe`、Launcher、Compose/镜像锁文件和默认入口
  `http://127.0.0.1:17860`；不是从源码开发服务器手工启动。
- 使用固定摘要的 DataX `datax_v202309`、JDK 8、MySQL 8 和 PostgreSQL 15。
- 使用真实容器/进程、真实数据库和固定可复现数据集；Mock 只能用于单元测试。
- 每个用例重新准备静默源表和预建空目标表，保存 Runtime/插件摘要、环境配置摘要、静默确认、空表证据、三维结果、oracle 证据、测试时间和脱敏日志。
- 缺少真实 Runtime 或数据库时标记 `BLOCKED`，不得以静态日志或假状态替代。

### 12.2 产品验收用例

| 验收 ID | Given / When / Then | 通过条件 |
|---|---|---|
| ACC-PRD-001 | Given Admin 创建两个项目并分别授权用户；When 用户访问本项目和另一项目资源；Then 仅本项目可见。 | 菜单、列表、详情和 API 均无横向越权；拒绝请求带稳定错误码和审计。 |
| ACC-PRD-002 | Given Admin 配置允许/禁止的 EndpointPolicy、有效/无效凭据和方向授权；When 创建并测试数据源；Then 只有策略允许的连接可用。 | Developer 不能注册或修改端点；密码不泄露；DNS/出口拒绝、SOURCE_USE/TARGET_USE 和审计均有真实证据。 |
| ACC-PRD-003 | Given 四种 Reader/Writer 组合、方向授权、ACTIVE TransferPolicy 和预建空目标表；When 分别创建全字段与选列任务并发布；Then 平台生成可执行 JobVersion。 | 四种组合均通过真实校验；数据源修订、映射、版本号、策略、配置哈希和 Runtime/插件版本完整保存。 |
| ACC-PRD-004 | Given 不兼容类型、缺失目标字段、目标不存在/安全画像不合格/不可核验、运行前目标非空、同一物理表经不同 Datasource/revision/hostname/IP 别名自复制、无方向授权、无 ACTIVE TransferPolicy 或同一规范化物理目标已有未释放的 `RESERVED/ACTIVE/RECOVERY_REQUIRED` 锁；When 发布或执行；Then 对应阶段由服务端阻断。 | 发布只判定存在性、安全画像和可核验能力；空表由 Worker 在运行前实测。错误定位明确；别名不能绕过自复制和目标锁；无“忽略风险继续”、自由 SQL 或 JSON 绕过入口。 |
| ACC-PRD-005 | Given 静默源表含固定行数/内容、目标为空且目标外部独占确认在有限有效期内；When Operator 提交两类确认并执行；Then DataX 退出 `0` 后先进入 `VERIFYING`。 | 独立 oracle 计数和规范化摘要匹配、声明状态仍为 `ACTIVE`、`revoked_at/reason` 为空且目标快照 `finished_at <= valid_until` 后才写 `SUCCEEDED/PASSED/CONFIRMED`；`REVOKED / EXPIRED` 或快照超期不得成功，Execution 与 RuntimeSnapshot 绑定完整声明和证据。 |
| ACC-PRD-006 | Given 用户双击运行、网络重试相同请求，或用不同幂等键并发提交同一 TargetNamespace；When 请求到达 API；Then 相同键只创建一个 Execution，不同键的第二个意图被目标预留拒绝。 | PostgreSQL 仅一条未释放 `RESERVED/ACTIVE/RECOVERY_REQUIRED` 锁；审计能解释重复/冲突请求；更换幂等键也不能绕过目标空表、目标互斥、源静默/目标外部独占或 RecoveryGate。 |
| ACC-PRD-007 | Given 一个长时间运行任务；When Operator 请求取消；Then 状态进入 `CANCEL_REQUESTED`，由 Worker 终止进程树并对账。 | 最终为 `CANCELED` 或明确失败状态；不存在孤儿进程；`data_effect` 保守记录；已领取执行的目标锁进入 `RECOVERY_REQUIRED`，RecoveryGate 在独立 RecoveryProbe 验证前不得为 `VERIFIED`。 |
| ACC-PRD-008 | Given 一个失败、超时、取消或丢失执行；When 无处置确认即请求恢复后再次执行、只有确认而无独立 RecoveryProbe 空表证据、确认与空表证据齐备三种情况；Then 前两种被阻断，第三种签发 VERIFIED gate。 | 恢复后再次执行引用 RecoveryGate、重新确认源静默并创建关联原执行的新 Execution；原执行和证据不可变。 |
| ACC-PRD-009 | Given Worker 运行中被强制终止且 PostgreSQL 通知丢失；When 服务恢复并轮询对账；Then PostgreSQL 事实记录保持完整。 | 待执行请求仍可领取；不确定执行进入 `LOST` 且影响为 `POSSIBLE/UNKNOWN`；没有伪造 `SUCCEEDED`。 |
| ACC-PRD-010 | Given 日志中注入密码样例、ANSI 控制符、HTML 和超长行；When 查看、搜索、下载日志；Then 内容安全呈现。 | 明文凭据不可检出；脚本不执行；分页/游标稳定；超限有明确截断说明。 |
| ACC-PRD-011 | Given JobSpec 试图配置任意非零脏数据容忍、运行中出现任一脏记录、oracle 不匹配、oracle 已启动但无法判断四种情况；When 校验、DataX 与核验结束；Then 非零配置先被拒绝，其余分别得到明确三维结果。 | 固定 `0/0` 策略、脏记录和 oracle 证据可见；`FAILED/INCONCLUSIVE` 均不能计入已核验成功或 `verified_records`。 |
| ACC-PRD-012 | Given 本机存在排队中和运行中的 Execution；When Windows 睡眠/关机/重启、Docker Desktop 停止或单节点服务停止；Then 停机期间产品明确不可用而非宣称后台继续或自动切换。 | 恢复后 Worker/reconciler 在接受新运行前完成状态对账；不确定执行进入 `LOST` 并保持恢复门禁；文档、Launcher、系统信息页和验收报告均明确“本机单节点、非 HA”。 |
| ACC-PRD-013 | Given `Setup.exe` 已在全新空用户库完成安装；When 用户通过 Launcher 首次启动对话框输入临时密码，Launcher 经子进程标准输入调用一次性 `bootstrap-admin`，随后尝试再次引导；Then 首次创建唯一 Admin，重复引导被拒绝。 | 临时密码不出现在进程参数、环境、浏览器请求、Launcher 持久化、日志、审计或 Git；写入 `SYSTEM_BOOTSTRAP_ADMIN` 审计；首次登录强制改密。 |
| ACC-PRD-014 | Given 一台干净 Windows 11 x64 验收机，以及“前置依赖缺失”和“Docker Desktop + WSL2 已由用户完成安装/许可处理”两种环境；When 验证发布签名/哈希并执行安装、首次/重复启动、停止、重启恢复、局域网访问探测和卸载；Then 签名/哈希错误或依赖缺失时安全阻断并只给官方指引，满足依赖时通过桌面快捷方式启动且默认浏览器打开 `http://127.0.0.1:17860`。 | `Setup.exe`/Launcher 签名和发布哈希有效，且不安装 Docker、不代接受或规避许可；重复启动只有一个实例；仅 Web 监听 `127.0.0.1:17860`，API/Worker/PostgreSQL 无宿主端口且另一局域网主机不可达；DataX 确认运行在固定 Linux 容器；停止/重启后按 ACC-PRD-012 对账；卸载默认保留本机数据和密钥，明确选择删除时再次警告不可恢复影响。 |

### 12.3 V1 完成门禁

只有同时满足以下条件，才可声明“V1 功能完成”：

1. 本文所有 `V1-MUST` 功能需求、业务规则和非功能要求都有实现、自动测试及可追踪证据；缺陷严重度单独记录。
2. 四种 Reader/Writer 组合的真实 E2E 全部通过，主链路包含 MySQL 8 → PostgreSQL 15 和 PostgreSQL 15 → MySQL 8。
3. EndpointPolicy、方向授权、TransferPolicy、凭据、命令/路径安全、同目标互斥、取消、崩溃对账、数据库轮询恢复和日志脱敏测试通过。
4. `02_产品信息架构与UI设计.md` 的关键流程、失败态、权限态、危险操作和可访问性验收通过。
5. 在干净 Windows 11 x64 上完成 `Setup.exe` 安装/卸载、Launcher/桌面快捷方式、
   Docker Desktop + WSL2 前置阻断、loopback/LAN 端口探测、睡眠/重启恢复、备份恢复、
   升级回滚和已知限制的真实验证；macOS/Linux 构建或容器启动不能替代。
6. 未验证项被明确列为 `BLOCKED` 或后续项；不得用页面可点击、容器构建或 Mock 结果替代。

## 13. 后续版本方向

V2/V3 可评估调度、DAG、告警、更多认证插件、插件市场、AI 辅助、CDC 和 HA，但每项都必须先完成独立 PRD、威胁模型、ADR、契约、数据迁移和真实验收设计。后续能力不能成为 V1 启动或手工流程的依赖。
