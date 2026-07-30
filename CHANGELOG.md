# 变更记录

## 2026-07-30 — V1.1 第一性原理文档修订

- 将 V1 产品承诺收敛为“安全的一次性离线全量复制”，明确排除非空目标追加、周期性和可重复同步。
- 增加源端静默确认、目标空表强制复检、同目标活动锁、失败恢复门禁和独立数据核验。
- 将目标外部独占声明固化为 `statement_version='1.0'`、有限 `valid_until` 与
  `ACTIVE/REVOKED/EXPIRED` 生命周期，增加撤回/破坏报告接口及
  `TARGET_EXCLUSIVITY_REVOKED` 审计；明确 oracle 成功时间覆盖和平台不能证明全部带外写入。
- 将执行结果拆分为 `process_state`、`data_effect`、`verification_state`；DataX 退出码 `0` 不再等同于业务成功。
- 增加不可变 DatasourceRevision、数据源用途与传输授权、DNS/网络出口控制和仓库威胁模型。
- 使用 PostgreSQL 事实队列替代 Redis V1 依赖，增加 Worker fencing、进程身份和孤儿处置约束。
- 增加版本化 Verification Oracle 与 Acceptance Manifest，修复需求追踪、日志截断、容量和发布门禁。
- 将真实 DataX walking skeleton 提前到横向功能开发之前，并增加用户发现与既有 JSON 安全迁移门禁。

## 2026-07-30 — V1 文档基线

- 将 11 份方向提纲重构为一致、可实施、可验收的工程文档。
- 冻结 MySQL 8/PostgreSQL 15 离线批同步 V1 范围。
- 明确模块化单体、独立 Worker、PostgreSQL 事实源和单节点部署。
- 增加不可变 JobVersion、执行状态机、凭据、审计、恢复和安全控制。
- 增加 OpenAPI、JobSpec、Plugin Manifest 和 AuditEvent 机器契约。
- 增加 Agent V2 边界、测试证据分级、阶段开发 Prompt、ADR 和 GitHub 模板。
- 明确文档完成不等同于代码或生产验收。
