# ADR-0006：PostgreSQL 事实队列与执行围栏

- 状态：Accepted
- 日期：2026-07-30

## 背景

V1 为单节点、单 Worker。额外的 Redis 队列没有承载不可替代业务状态，却增加部署、
恢复和双写一致性成本。另一方面，数据库租约加 PID/PGID 不能阻止失租 Worker 或 PID
重用后的错误进程继续写状态或目标数据。

## 决策

- PostgreSQL 是 V1 唯一事实队列。Worker 在短事务中使用
  `FOR UPDATE SKIP LOCKED` 领取 `QUEUED` Execution 与 `QUEUED` RecoveryProbe。
  项目公平性使用数据库持久 `last_service_sequence` 和全局 service sequence；先选最久
  未服务 eligible 项目，再按 class/priority/queued_at/id 选择，只有成功领取才推进游标。
- `LISTEN/NOTIFY` 仅发送 `work_kind + work_id` 作为低延迟提示；通知可丢失，Worker 以
  5 秒默认、可配置且带抖动的轮询保证恢复。V1 Compose、readiness 和备份不包含 Redis。
- API 创建 `QUEUED` Execution 时，在同一事务按 TargetNamespace 创建
  `TargetCopyLock=RESERVED`、初始 Event/Audit 和幂等结果；部分唯一索引拒绝第二个同目标
  排队意图。
- 领取 Execution 时，在同一事务锁定其 `RESERVED` 预留、创建 Attempt、递增
  `fence_epoch` 并设置 `active_attempt_id`、lease token 哈希与到期时间；同事务固定
  EndpointPolicyRevision、TargetNamespace、两个 ACTIVE CredentialSecret/Envelope，并
  把预留转换为 `ACTIVE`，提交前禁止外部连接。
- 所有心跳、事件、`process_state`、`data_effect`、`verification_state` 和终态写入都
  必须满足当前 `active_attempt_id + fence_epoch + lease_token_hash`；0 行更新等同失租，
  Worker 必须停止工作并终止其进程树。
- 进程证据记录 `host_boot_id`、`pid`、`pid_start_time`、`process_group_id` 和
  `cgroup_identity`。reconciler 只有在全部身份匹配时才可发送信号，避免 PID 重用误杀。
- 同一不可变 TargetNamespace 使用数据库唯一未释放锁，状态为
  `RESERVED/ACTIVE/RECOVERY_REQUIRED`。预留从 Execution 创建开始，活动锁从领取延续到
  oracle 核验结束；
  Execution 一旦已领取，只有 `SUCCEEDED/CONFIRMED/PASSED` 释放锁，任何其他结果（含
  启动前失败、取消和 `data_effect=NONE`）均转 `RECOVERY_REQUIRED`。
- RecoveryProbe 使用独立表、ProbeAttempt、lease token 和单调 `fence_epoch`；只有当前
  probe fence 写入的 `SUCCEEDED+EMPTY` 可原子关闭 gate/lock。ExecutionAttempt 不得
  充当恢复围栏，probe 失败/非空/不确定/取消/LOST 不自动重新入队。
- reconciler 独立扫描尚未领取的 `QUEUED + PENDING CancelRequest`，不创建 Attempt，
  原子释放 `RESERVED` 预留并收敛到 `CANCELED/NONE/NOT_STARTED`；Worker 正忙不能阻塞
  该路径。
- TargetCopyLock 只串行化平台内 Execution/RecoveryProbe，不能阻止平台外 DML/DDL。
  Worker 最后一次空表观察至 oracle 目标端一致性读事务结束必须由 Operator/DBA 的
  `target_exclusivity_confirmation` 覆盖；声明固定 `statement_version='1.0'`、有限
  `valid_until` 和 `ACTIVE/REVOKED/EXPIRED` 状态。Worker/oracle 要求声明未撤回未过期，
  且 `target_result.snapshot_finished_at <= valid_until`；缺少、版本错误、非 `ACTIVE`
  或时间窗未覆盖时 fail closed。
- Operator/Admin 获知平台外 DML/DDL、冻结失效或 DBA 撤回承诺时，通过专用接口原子写
  `REVOKED` 和 `TARGET_EXCLUSIVITY_REVOKED` 审计。未领取 Execution 由 reconciler 收敛
  取消并释放 `RESERVED`；已领取 Execution 停止并进入 `RECOVERY_REQUIRED`；已启动 oracle
  形成 `INCONCLUSIVE/TARGET_EXCLUSIVITY_BROKEN`。平台锁和队列事实不能证明未报告、瞬时
  或已回滚的外部写从未发生。
- 默认 200 GiB 主机采用日志/数据库/工作区/安全保留分区预算、绿色/黄色/红色水位
  admission 与 20 小时/24 小时服务预算。轻量 200 次/天和大表 20 次/天是不同组合档，
  不能与单执行 100 MiB 日志硬上限同时取峰值。
- 超过容量公式/队列 200/预计 8 小时 backlog 时拒绝普通新运行请求并暴露稳定原因；
  既有事实保持 `QUEUED`。不得通过增加未验收并发静默扩容。

## 后果

- Execution 创建、排队和取消可以在一个数据库事务内完成，恢复路径更短。
- 通知丢失最多增加一个轮询间隔，不会丢任务；PostgreSQL 不可用时系统停止领取。
- 旧 Worker 无法在失租后覆盖新 Attempt 的状态，但数据库围栏不能单独撤回已经发往
  外部数据库的 JDBC 写入，因此进程终止、目标活动锁和失败恢复门禁必须同时存在。
- 目标锁也不能证明外部数据库用户没有写入，因此目标外部独占声明生命周期、报告义务和
  oracle 的单一一致性目标快照同样是成功判定前提；它们提供 fail-closed 证据，不提供
  任意带外写入的完整侦测。
- Worker/reconciler 重启不会重置项目公平顺序；未领取取消和 RecoveryProbe 不再依赖
  DataX 槽位才有机会推进。
- 容量是可计算的组合约束，并带事实发现、eligible 等待、RecoveryProbe 和取消收敛
  SLO；超水位 fail closed。
- 多 Worker、跨节点 HA 或外部队列均不属于 V1；引入时必须以新的 ADR 重新证明队列
  一致性、围栏和目标锁语义。
