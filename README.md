# DataX Enterprise Studio

DataX Enterprise Studio 是面向企业内部数据工程团队的 Apache DataX 可视化控制平台。它把数据源管理、同步任务设计、版本发布、受控执行、日志监控和审计串成一条可追踪的离线批同步闭环。

> 当前仓库状态：**V1 工程文档基线**。仓库尚未包含已验收的产品代码，也不声明已经具备生产能力。

## V1 一句话范围

在单组织、多项目、单节点部署条件下，支持 MySQL 8 与 PostgreSQL 15 之间的离线批量表同步；用户可以安全保存数据源、读取元数据、创建并发布不可变任务版本、生成脱敏 DataX JSON、手动执行、取消、查看日志与审计记录。

### V1 包含

- 本地账号认证和 `Admin / Developer / Operator / Viewer` 四类角色。
- MySQL 8、PostgreSQL 15 的 Reader/Writer 认证矩阵。
- 数据源连接测试、Schema/表/字段元数据读取。
- 完整表或选定字段的一对一映射；目标表由用户预先创建。
- `insert-only` 写入；任务草稿、校验、发布和不可变版本。
- 手动触发、幂等提交、超时、取消、失败记录和历史重跑。
- DataX 原始日志、解析指标、运行状态、凭据脱敏和审计。
- Docker Compose 单节点部署、备份恢复和升级回滚说明。

### V1 明确不包含

- 实时/CDC 同步、自动增量游标、流式处理。
- Cron 调度、DAG/工作流、告警通知。
- 任意 SQL、`preSql`、`postSql`、自定义转换代码。
- 插件上传、插件市场、未认证的 Reader/Writer。
- AI Copilot 或 Agent 的生产执行。
- 多租户计费、Kubernetes、多节点高可用和跨地域容灾。

这些能力进入后续版本前必须单独评审，不得以隐藏开关混入 V1。

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
| [部署运维与安全方案](docs/10_部署运维与安全方案.md) | Compose 拓扑、密钥、监控、备份、升级和事故处置 |
| [Codex 最终长任务 Prompt](docs/11_Codex最终长任务Prompt.md) | 可直接交给编码 Agent 的受控执行任务书 |
| [需求追踪矩阵](docs/12_需求追踪矩阵.md) | 需求到数据、API、页面和测试的映射 |
| [原始文档评审与修订说明](docs/13_原始文档完整性评审与修订说明.md) | 原始包为何不完整、如何补齐及修订后边界 |

机器可校验契约位于 [`docs/contracts`](docs/contracts)，架构决策记录位于 [`docs/adr`](docs/adr)。

## 已冻结的工程方向

- 前端：Vue 3、TypeScript、Vite、Element Plus。
- API：FastAPI 模块化单体。
- 执行：独立 Worker 使用参数数组调用固定 DataX Runtime，绝不拼接 shell。
- 持久化：PostgreSQL 是唯一事实源；Redis 只用于队列、短期事件和分布式协调。
- Runtime：Alibaba DataX `datax_v202309`，镜像与插件必须固定摘要。
- 部署：V1 为单节点 Docker Compose，明确不具备高可用。
- AI：V1 无模型依赖；V2 仍必须保留完整手工流程，AI 只生成草稿或建议。

## 项目状态与证据

“文件存在”“自动测试通过”“容器启动”“真实数据库同步成功”“生产验收”是五种不同证据。只有 [测试与验收标准](docs/09_测试与验收标准.md) 中要求的真实链路通过后，才能声明 V1 完成；Mock、静态日志和模拟成功状态不能替代真实 DataX 执行。

## 上游与许可证

DataX 上游为 [alibaba/DataX](https://github.com/alibaba/DataX)，上游代码采用 Apache License。该事实不自动决定本仓库原创代码的许可证；在仓库所有者明确选择并加入 `LICENSE` 前，本仓库不授予额外开源许可。依赖、插件和镜像必须分别记录来源、版本、许可证与校验和。

## 参与方式

开始开发前请完整阅读根目录 [AGENTS.md](AGENTS.md) 和 [CONTRIBUTING.md](CONTRIBUTING.md)。涉及 V1 范围、持久化模型、API、执行安全或权限边界的变更，必须同步更新文档、契约、测试和 ADR。
