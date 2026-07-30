# 机器可校验契约

本目录中的文件负责可机器校验的字段、类型、枚举和约束形状；PRD 负责产品结果与范围，ADR 负责架构决策。发生冲突必须阻断实现并同步修复，不能用“机器契约优先”覆盖产品语义：

- `openapi.yaml`：HTTP API。
- `job-spec.v1.schema.json`：平台任务契约。
- `plugin-manifest.v1.schema.json`：认证插件能力与参数 UI 契约。
- `audit-event.v1.schema.json`：审计事件最小结构。
- `verification-oracle.v1.schema.json`：独立数据核验规范和结果证据；使用规范化行多重集，不依赖 DataX 自报统计。
- `acceptance-manifest.v1.schema.json`：候选版本的需求、唯一测试 ID、oracle 与证据文件清单。

实现阶段 CI 必须完成：

1. 文件可解析。
2. JSON Schema 通过对应 Meta Schema 校验。
3. OpenAPI 1.1.0 示例和本地引用有效，Execution 的三类状态与独立 oracle 一致；项目可读
   Datasource 响应只能使用 `DatasourceRedactedSummary`，真实连接定位只允许
   `DatasourceAdminDetail` 与 Admin-only revision 路由。
4. 前后端生成类型与契约一致。
5. JobSpec 固定安全的一次性复制策略和 V1 脏数据阈值 `record_count=0/percentage=0`；
   非空目标、任一脏行、未确认源静默、目标排他声明版本非 `1.0`、缺少有限
   `valid_until`、`confirmed_at >= valid_until`、状态非 `ACTIVE` 或未通过恢复门禁均有
   反例，UI/API 不提供正数阈值。
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
8. 发布 CI 从权威追踪矩阵生成规范化需求 catalog，重算
   `requirements_catalog_sha256`，并以独立 validator 比较 catalog 与 entries 的
   `requirement_id/requirement_priority/test_id/minimum_evidence_level` 四元组及 V1-MUST
   集合。Manifest entry 必填 `minimum_evidence_level`；Schema 拒绝 PASS 的实际
   `evidence_level` 低于该下限，validator 还必须拒绝运行器自行下调 catalog 下限。
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
10. `data_effect=CONFIRMED` 只表示目标影响已测得，测得值可以是 0 行，不代表内容正确；
    空源成功固定为 `SUCCEEDED/CONFIRMED/PASSED`。
11. Execution 创建事务原子写 `QUEUED+TargetCopyLock=RESERVED`；同一 TargetNamespace 的
    部分唯一索引覆盖 `RESERVED/ACTIVE/RECOVERY_REQUIRED`。同目标不同幂等键在 API 冲突，
    Worker 领取原子转 ACTIVE 并创建 Attempt/fence，未领取取消必须释放预留。
12. 恢复声明固定 `action/cleanup_performed/reason/confirmed_at`；无需清理时如实记录
    `NO_CLEANUP_REQUIRED/false`，但任何情况都必须经过独立 RecoveryProbe 空表复检。
13. 破坏性变更提升版本并提供迁移说明。

不得直接修改生成代码来绕过契约。
