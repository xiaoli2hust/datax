# DataX Enterprise Studio

DataX Enterprise Studio 是面向企业内部数据工程团队的 DataX 可视化控制平台。V1 把数据源授权、一次性复制任务设计、版本发布、受控执行、独立核验、故障恢复和审计串成一条可追踪的安全离线全量复制闭环。

> 当前仓库状态：**V1.2 Windows 本地工作站工程候选**。仓库已包含固定 DataX Runtime
> 构建、后端/Worker、数据源/任务/执行 Vue 页面与正式 API 适配、Windows Compose、
> Launcher/Setup 骨架、API/Worker 独立数据库登录、敏感 tmpfs/资源上限、DATA/SECRETS
> 分离加密导出、双包认证 journal/空 staging 及 GitHub 安全工作流；这些仍是工程候选，
> 不是已发布产品。旧式完整对象集合到 `LEGACY` 运行代际的不可覆盖原子指针、以及 Compose
> 对该指针的整组消费已有工程候选；恢复仍只达到 E1 staging，真实 `pg_restore`、证据重算、
> `RESTORE` 卷/secret 原子提交和覆盖升级保持失败关闭。Discovery Gate、真实四方向 DataX E3、发布镜像 digest、
> 主机/容器级
> 默认拒绝 egress 的 Windows 实测、数据库外审计锚定/WORM、代码签名和干净 Windows 11
> x64 E4 均为 `NOT_RUN/BLOCKED`，因此不声明生产能力。

2026-08-02 第一性原理/对抗式复审还确认了验收证据语义绑定、恢复 staging 后
普通启动、核验取消、数据库职责权限、数据源外部 I/O 持锁、容器出口、Worker secret 闭包、运行中撤回止损、
凭据紧急终止、认证取证自举和 Windows 发布供应链等 P0/P1 问题。权威问题状态、
责任人、关闭证据和修复顺序见
[第一性原理问题台账与开发修复计划](docs/14_第一性原理问题台账与开发修复计划.md)。

同轮审查发现并在源码层修复了两条本机入口资源耗尽路径：登录在数据库/Argon2/审计前
实行全局准入，审计 readiness 使用水位线和有界重放而不在每次请求全量验链。它们受
[ADR-0012](docs/adr/0012-本机入口准入与审计就绪有界核验.md) 约束，仅适用于单 API
进程；真实 PostgreSQL 压力与 Windows E4 证据仍未完成。

仓库已按 [ADR-0009](docs/adr/0009-DataX完整上游与认证能力分级.md) 接受“完整上游
随包、逐级可证明认证”的长期目标。V1 产品范围只定义 MySQL/PostgreSQL 四个候选
Reader/Writer；当前生产证据源为 deny-all，普通用户实际开放能力为 **0 个**。任何候选
未达到精确最终 Windows E4 与公开晋级前，都不得在普通用户 UI 中执行或宣称稳定支持。

`GET /api/v1/plugins` 现按 `plugin-manifest.v2` 返回上游锁定、制品、
依赖/许可、网络/文件边界、oracle、候选证据和阻断原因。
生产默认没有可信 Windows E4 证据源，因此四个 V1 候选最多只会
显示为 `PACKAGED` 且 `ordinary_user_executable=false`；普通 Execution 创建、
恢复 `rerun`、Worker 领取和 Worker 启动四个检查点都会失败关闭。测试注入证据不属于公开契约，
也不会被 `/plugins` 序列化为普通用户可执行事实。

2026-08-02 已通过 [ADR-0011](docs/adr/0011-两阶段插件运行时资格认证与发布晋级链.md)
接受未来的“两阶段资格认证 + 最终发布晋级”设计：先固定不可变 Runtime payload，在
受保护 harness 中以短期签名资格取得真实取证，再以 detached 签名资格构建私有最终候选，
最后对精确安装包完成 Windows E4、候选根与 hosted provenance。该 ADR 只解决安全自举和
哈希循环的设计，不改变当前行为：QH/QR、受信 reader、payload root v1、candidate-root
v2、真实 Windows/E3/签名/OIDC 证据都尚未实现，普通路径仍默认拒绝、发布仍为 BLOCKED。

## V1 一句话范围

在一台 Windows 11 x64 电脑上，以本地工作站方式支持 MySQL 8 与 PostgreSQL 15 之间安全地执行一次性离线全量表复制。每次执行要求源表从运行前检查开始到独立 oracle 完成始终保持静默；目标表由用户预先创建且为空并可核验，Operator/DBA 还必须提交有版本、有限有效期的目标外部独占声明，并在知悉窗口被破坏时立即报告。平台只做 `insert-only` 写入，不把 DataX 退出码 `0` 单独当作业务成功。

## 最终交付形态

V1 的发布交付物是已签名的 Windows `Setup.exe`、已签名 Launcher、桌面快捷方式和本机数据目录。用户从桌面快捷方式
打开 Windows Launcher；Launcher 检查前置条件、启动本机容器、等待健康检查通过，再用
默认浏览器打开 `http://127.0.0.1:17860`。不需要购买、登录或维护一台外部 Linux
服务器。

这不是把所有组件改写成一个纯原生、单进程 `.exe`。Windows 11 x64 是 V1 唯一发布
认证的宿主平台；Docker Desktop 与 WSL2 是明确的前置依赖，固定 DataX Runtime 继续在
Linux 容器中运行。宿主机只把 Web 入口映射到 `127.0.0.1:17860`；API、Worker 和
PostgreSQL 不映射宿主端口，其他局域网电脑不能访问本产品。电脑睡眠、关机、重启或
Docker Desktop 停止期间服务不可用，恢复后必须先完成执行状态对账。

当前承载本仓库的 Mac 仅用于源码开发、静态检查和自动化层验证，不是 V1 运行目标。
最终产品应安装并运行在另一台 Windows 11 x64 电脑上；所有 Setup、Docker Desktop/WSL2、
真实 DataX、恢复和 E4 结论都必须在该 Windows 环境重新取证。

安装器和 Launcher 只能检测 Docker Desktop/WSL2 并给出官方安装指引，不得静默安装、
自动接受许可条款或用替代技术规避许可。用户或其组织必须自行评估并接受适用的 Docker
许可后才能继续安装和使用。

### V1 包含

- 本地账号认证和 `Admin / Developer / Operator / Viewer` 四类角色。
- MySQL 8、PostgreSQL 15 的 Reader/Writer 认证矩阵。
- Admin 管理网络端点与数据源，并按成员授予 `SOURCE_USE` / `TARGET_USE`；复制方向必须具备有效 `TransferPolicy`。
- 数据源连接测试、Schema/表/字段元数据读取。
- 完整表或选定字段的一对一映射；发布只验证目标表存在、安全画像合格且具备可核验能力，是否为空必须在每次运行前由 Worker 服务端实测。
- 目标外部独占声明固定包含 `statement_version="1.0"`、`confirmed_at`、`valid_until` 和
  `responsible_party`，生命周期为 `ACTIVE / REVOKED / EXPIRED`。只有声明仍为 `ACTIVE`、
  未撤回，且 oracle 目标快照在 `valid_until` 前读完时才可能核验通过。
- 人工声明不是技术证明；平台无法检测全部未报告或已经回滚的外部 DML/DDL。
  `TargetCopyLock` 只串行平台内工作，Operator/DBA 知悉窗口被破坏时必须通过执行撤回/报告
  接口留痕，并保存 `revoked_at/reason`。
- 固定 `insert-only` 的单次写入；任务草稿、校验、发布和不可变版本。
- V1 脏数据容忍固定为 `0` 条、`0%`；任何脏记录或 oracle 差异都不能成为已核验成功。
- 手动触发、幂等提交、超时、取消、三维结果状态、独立数据核验和受门禁保护的恢复后再次执行。
- 脱敏后的原序日志、解析指标、运行状态、凭据保护和审计。
- Windows `Setup.exe`、Launcher、本机 Docker Compose 的目标交付合同，以及备份恢复和
  升级回滚的发布门禁说明；安全导出和 E1 journal/staging 存在不表示完整恢复、签名
  安装包或 Windows 实机验收已完成。

### V1 明确不包含

- 非空目标表追加、同一目标并行写入、周期性或可重复同步。
- 从运行前检查开始到独立 oracle 完成仍持续写入的动态源表。
- 实时/CDC 同步、自动增量游标、流式处理。
- Cron 调度、DAG/工作流、告警通知。
- 任意 SQL、`preSql`、`postSql`、自定义转换代码。
- 插件上传、插件市场、未认证的 Reader/Writer。
- AI Copilot 或 Agent 的生产执行。
- 多租户计费、Kubernetes、多节点高可用和跨地域容灾。
- 外部 Linux 服务器部署、局域网/公网远程访问、macOS/Linux 宿主发布认证，以及纯原生
  单进程 Windows `.exe`。

这些能力进入后续版本前必须单独评审，不得以隐藏开关混入 V1。

### Discovery Gate（企业试点与发布门禁）

当前用户痛点与价值判断仍是待验证假设。企业试点或公开发布前必须完成 8–12 名目标用户
访谈、至少 20 个脱敏真实任务样本分析，并由 3 个设计伙伴完成合计不少于 10 个真实
一次性复制任务；不得以代码、内部演示或编造研究结论替代。

按 [ADR-0007](docs/adr/0007-Discovery-Gate与工程实施分离.md)，仓库所有者已明确授权
风险自担的工程候选实现。该授权允许继续编码，但 Discovery 状态仍为 `NOT_EVIDENCED`，
企业试点、公开发布和 V1 完成声明保持 `BLOCKED`。

`PRD-FR-JOB-010`（既有 DataX JSON 安全迁移）冻结为 `POST-V1`。V1 不提供导入入口，更不能导入后直接执行；后续若立项，只能把白名单字段解析为新的待核对 `DRAFT`，丢弃凭据、SQL、Transformer、自定义参数与未知插件，并重新完成授权、校验和发布。

## 文档导航

| 文档 | 用途 |
|---|---|
| [文档总览与决策基线](docs/00_文档总览与决策基线.md) | 权威范围、术语、文档优先级和变更规则 |
| [产品战略与 PRD](docs/01_产品战略与PRD.md) | 用户、场景、需求、业务规则、指标和产品验收 |
| [信息架构与 UI 设计](docs/02_产品信息架构与UI设计.md) | 页面、流程、状态、字段、交互和 UI 验收 |
| [技术架构设计](docs/03_技术架构设计.md) | 组件边界、数据流、执行状态机和故障恢复 |
| [数据库与领域模型](docs/04_数据库与领域模型设计.md) | 实体、字段、约束、关系、保留和迁移 |
| [API 与前后端契约](docs/05_API接口与前后端契约.md) | HTTP/流式接口、错误、幂等和权限 |
| [Codex 开发执行计划](docs/06_Codex开发执行计划.md) | 分阶段实施、停靠点、交付物和完成定义 |
| [Agents 工程化方案](docs/07_Agents工程化方案.md) | V2 AI 边界、工具、审批、隐私、降级和评测 |
| [GitHub 工程规范与开源规划](docs/08_GitHub工程规范与开源规划.md) | 仓库、分支、CI、发布、依赖和许可证治理 |
| [测试与验收标准](docs/09_测试与验收标准.md) | 自动测试、真实 DataX E2E、安全、恢复和证据 |
| [部署运维与安全方案](docs/10_部署运维与安全方案.md) | Windows 安装/Launcher、Compose 拓扑、密钥、监控、备份、升级和事故处置 |
| [Codex 最终长任务 Prompt](docs/11_Codex最终长任务Prompt.md) | 可直接交给编码 Agent 的受控执行任务书 |
| [需求追踪矩阵](docs/12_需求追踪矩阵.md) | 需求到数据、API、页面和测试的映射 |
| [原始文档评审与修订说明](docs/13_原始文档完整性评审与修订说明.md) | 原始包为何不完整、如何补齐及修订后边界 |
| [第一性原理问题台账与开发修复计划](docs/14_第一性原理问题台账与开发修复计划.md) | 当前 P0/P1、冲突、责任、证据、分阶段 DoD 和 DataX 能力分级 |

机器可校验契约位于 [`docs/contracts`](docs/contracts)，架构决策记录位于 [`docs/adr`](docs/adr)。各文档按关注点负责：PRD 定义产品结果，ADR 定义已接受决策，机器契约定义可交换结构。任何来源出现语义冲突都必须先阻断实现并共同修正，不能用机器契约静默覆盖产品或架构决策。

## 已冻结的工程方向

- 前端：Vue 3、TypeScript、Vite、Element Plus。
- API：FastAPI 模块化单体。
- 执行：独立 Worker 使用参数数组调用固定 DataX Runtime，绝不拼接 shell。
- 持久化与领取：PostgreSQL 是唯一事实源；Worker 使用数据库锁领取任务，`LISTEN/NOTIFY` 仅作可丢失的低延迟提示并由轮询兜底；V1 不依赖 Redis。
- Runtime：Alibaba DataX `datax_v202309`，镜像与插件必须固定摘要；Runtime 在 Worker
  的固定 Linux 容器中运行。
- 容器基线：PostgreSQL/egress-guard 基于固定摘要的 PostgreSQL `15.18-alpine3.24`；
  API 与 Worker 的最终 Python 运行层基于固定摘要的 Python 3.12.13
  `slim-trixie`（Debian 13）。
- 宿主：Windows 11 x64 是唯一发布认证平台；不要求外部 Linux 服务器。
- 安装与启动：`Setup.exe` 安装 Windows Launcher 和桌面快捷方式；Launcher 以幂等方式
  管理本机 Compose，并打开默认浏览器。
- 前置依赖：Docker Desktop + WSL2；安装器只检测和引导，不替用户接受或规避许可。
- 网络：只将 Web 映射到 `127.0.0.1:17860`；API、Worker、PostgreSQL 无宿主端口，
  不支持局域网或公网入站访问。
- 可用性：单台本地电脑、非 HA；睡眠、关机、重启和 Docker Desktop 停止均会中断服务。
- 交付口径：`Setup.exe` 是安装器，Launcher 是本机控制壳；核心服务仍由容器组成，不是
  纯原生单进程 `.exe`。
- AI：V1 无模型依赖；V2 仍必须保留完整手工流程，AI 只生成草稿或建议。
- 供应链：源码 SBOM 从候选的精确 Git commit archive 生成；候选发布为源码及五个运行
  镜像分别生成 SPDX SBOM，并配置 OSV 应用依赖与 Grype 发行版包策略。工作流配置和本地
  Worker 扫描证据不等于线上候选发布已经通过。

## 项目状态与证据

“文件存在”“自动测试通过”“容器启动”“DataX 进程退出 `0`”“真实数据库复制已独立核验”“生产验收”是六种不同证据。只有 [测试与验收标准](docs/09_测试与验收标准.md) 中要求的真实链路通过后，才能声明 V1 完成；Mock、静态日志、DataX 自报指标和模拟成功状态不能替代真实复制与独立核验。

## 上游与许可证

DataX 上游为 [alibaba/DataX](https://github.com/alibaba/DataX)，上游代码采用 Apache
License 2.0。该事实不自动决定本仓库原创代码的许可证；在仓库所有者明确选择并加入
`LICENSE` 前，本仓库不授予额外开源许可。依赖、插件和镜像必须分别记录来源、版本、
许可证与校验和。

## 参与方式

开始开发前请完整阅读根目录 [AGENTS.md](AGENTS.md) 和 [CONTRIBUTING.md](CONTRIBUTING.md)。涉及 V1 范围、持久化模型、API、执行安全或权限边界的变更，必须同步更新文档、契约、测试和 ADR。
