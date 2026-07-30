# ADR-0002：V1 采用模块化单体与独立 Worker

- 状态：Accepted
- 日期：2026-07-30

## 背景

原始架构同时描述 API Gateway、多服务拆分和单一 backend，部署边界不清。

## 决策

- 业务 API 使用 FastAPI 模块化单体。
- DataX 执行使用独立 Worker 进程。
- PostgreSQL 同时是业务事实源和 V1 的唯一任务队列。Worker 使用
  `FOR UPDATE SKIP LOCKED` 公平领取可运行的 Execution。
- PostgreSQL `LISTEN/NOTIFY` 只作为可丢失的低延迟唤醒提示；Worker 必须以有上限的
  轮询恢复漏掉的通知。V1 不依赖 Redis。
- Web 入口提供静态资源与同源反向代理。
- DataX Runtime 作为 Worker 内的固定 CLI 制品，不作为网络服务。
- API 只能在创建初始 `QUEUED` 的同一事务创建
  `TargetCopyLock=RESERVED`/Event/Audit/幂等事实，以及记录取消请求；只有 Worker 及其
  内置 reconciler 可以转换预留并推进运行态、核验态和终态。

## 后果

- V1 部署、调试和事务边界较简单，Execution 不存在数据库与外部队列双写不一致。
- API 故障不直接杀死运行进程，Worker 可独立对账。
- 数据库短暂不可用时停止领取新任务；恢复后由轮询继续处理，不需要重建外部队列。
- 队列公平性、锁等待、最老排队时长和 PostgreSQL 容量成为强制监控与验收项。
- 未来拆服务必须基于度量与明确边界另建 ADR。
