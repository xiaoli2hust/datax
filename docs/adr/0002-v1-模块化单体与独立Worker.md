# ADR-0002：V1 采用模块化单体与独立 Worker

- 状态：Accepted
- 日期：2026-07-30

## 背景

原始架构同时描述 API Gateway、多服务拆分和单一 backend，部署边界不清。

## 决策

- 业务 API 使用 FastAPI 模块化单体。
- DataX 执行使用独立 Worker 进程。
- PostgreSQL 是事实源。
- Redis 只承担队列、短期事件和协调。
- Web 入口提供静态资源与同源反向代理。
- DataX Runtime 作为 Worker 内的固定 CLI 制品，不作为网络服务。

## 后果

- V1 部署、调试和事务边界较简单。
- API 故障不直接杀死运行进程，Worker 可独立对账。
- 未来拆服务必须基于度量与明确边界另建 ADR。
