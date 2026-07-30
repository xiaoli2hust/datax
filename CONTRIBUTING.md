# 参与贡献

感谢参与 DataX Enterprise Studio。当前仓库以 V1.1 实施候选文档为评审基线；开始前请阅读 `AGENTS.md`、`docs/00_文档总览与决策基线.md`、相关 Accepted ADR 和 `docs/security/THREAT_MODEL.md`。

## 提交变更

1. 从最新 `main` 创建短期分支：`feature/`、`fix/`、`docs/` 或 `agent/`。
2. 用 Issue 关联需求 ID、需求优先级、唯一测试 ID、oracle 和可执行验收证据。
3. 实现最小纵向切片，同步测试、迁移、契约与文档。
4. 运行与风险相称的检查。
5. 提交 PR，说明真实验证、未验证项和回滚方式。

## 必须遵守

- 不提交 Secret、真实连接串、客户数据、数据库转储或运行日志。
- 不用 Mock、静态日志或固定成功响应冒充真实 DataX E2E。
- 不擅自扩大 V1 数据源、SQL、插件、调度、AI 或部署范围。
- 不把一次性全量复制描述为可重复同步；不得绕过源静默确认、目标空表复检、同目标锁、
  独立核验或失败恢复门禁。目标外部独占声明必须使用 `statement_version='1.0'`、有限
  `valid_until` 和 `ACTIVE/REVOKED/EXPIRED` 生命周期；已知窗口破坏必须经专用接口报告/
  撤回并审计。不得声称平台能证明或自动发现所有未报告、瞬时或已回滚的外部 DML/DDL。
- 不把 DataX 退出码、日志文本或自报写入数直接映射为已核验成功。
- 不允许 Developer 注册任意端点或绕过数据源用途、TransferPolicy、DNS/网络出口策略。
- 不在未更新 OpenAPI/JSON Schema 时改变接口行为。
- 不在没有迁移和恢复方案时改变持久化结构。
- 新依赖需记录用途、版本、许可证和安全影响。

## PR 最低证据

- 关联需求/Issue。
- 变更前后的可观察行为。
- 执行过的测试命令及结果。
- 真实数据库/Runtime 是否参与。
- `process_state`、`data_effect`、`verification_state` 与独立 oracle 证据。
- 权限、密钥、迁移、兼容和回滚影响。
- `acceptance-manifest.v1` 中对应需求、测试和证据结果。
- 未完成或受阻内容。

纯文档变更也必须校验内部链接、OpenAPI、全部 JSON Schema、ADR/威胁模型引用，以及 PRD、数据模型、机器契约、测试和追踪矩阵的跨文档一致性。

## 评审关注

评审人优先检查：范围漂移、数据外传、凭据泄露、三维状态错误、非空目标、重复执行、部分写入、Worker 围栏、孤儿进程、迁移不可逆、假 E2E、oracle 自证和文档/实现不一致。
