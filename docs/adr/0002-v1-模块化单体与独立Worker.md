# ADR-0002：V1 采用模块化单体与独立 Worker

- 状态：Accepted
- 日期：2026-07-30

## 背景

原始架构同时描述 API Gateway、多服务拆分和单一 backend，部署边界不清。V1 后续确认
运行宿主是一台 Windows 11 x64 本地电脑而非外部 Linux 服务器，还需要明确 Windows
Launcher、WSL2/Linux 容器、宿主端口和现有 API/Worker 职责之间的边界。

## 决策

- 业务 API 使用 FastAPI 模块化单体。
- DataX 执行使用独立 Worker 进程。
- 发布版 Windows `Setup.exe` 和 Launcher 必须签名；`Setup.exe` 只安装产品文件、
  Launcher、桌面快捷方式和卸载入口；Windows
  Launcher 只负责前置条件检测、幂等 Compose 启停、健康等待、首次 Admin 的受控 CLI
  调用、诊断摘要和打开系统默认浏览器。Launcher 不保存业务事实、不启动 DataX、不推进
  Execution 状态，也不得嵌入另一套 API。
- Windows 11 x64 是唯一发布认证宿主；Docker Desktop + WSL2 是用户自行安装并按适用
  许可使用的前置依赖。安装器/Launcher 只能检测和提供官方指引，不得静默安装、代接受
  或规避许可。
- PostgreSQL 同时是业务事实源和 V1 的唯一任务队列。Worker 使用
  `FOR UPDATE SKIP LOCKED` 公平领取可运行的 Execution。
- PostgreSQL `LISTEN/NOTIFY` 只作为可丢失的低延迟唤醒提示；Worker 必须以有上限的
  轮询恢复漏掉的通知。V1 不依赖 Redis。
- Web 入口提供静态资源与同源反向代理。
- 宿主只发布 Web 的 `127.0.0.1:17860`。API、Worker、PostgreSQL 均不配置宿主端口，
  只在 Compose 内部网络通信；其他局域网设备和公网不能访问产品。数据源连接是受
  EndpointPolicy 约束的容器出站流量，不改变产品入站边界。
- DataX Runtime 作为 Worker 的固定 Linux 容器内 CLI 制品，不作为 Windows 原生程序
  或网络服务。
- API 只能在创建初始 `QUEUED` 的同一事务创建
  `TargetCopyLock=RESERVED`/Event/Audit/幂等事实，以及记录取消请求；只有 Worker 及其
  内置 reconciler 可以转换预留并推进运行态、核验态和终态。

## 后果

- 用户不需要购买或管理外部 Linux 服务器，但需要一台满足虚拟化、WSL2、Docker Desktop、
  内存和磁盘要求的 Windows 11 x64 电脑。
- `Setup.exe` 提供 Windows 安装体验，但系统不是纯原生单进程 `.exe`；Docker/WSL2
  前置条件与许可责任必须在下载页、安装器、Launcher 和验收报告中持续可见。
- V1 部署、调试和事务边界较简单，Execution 不存在数据库与外部队列双写不一致。
- API 故障不直接杀死运行进程，Worker 可独立对账。
- 数据库短暂不可用时停止领取新任务；恢复后由轮询继续处理，不需要重建外部队列。
- 队列公平性、锁等待、最老排队时长和 PostgreSQL 容量成为强制监控与验收项。
- 浏览器关闭不会自动停止容器；Launcher 的显式停止、Windows 睡眠/关机/重启和 Docker
  Desktop 停止会造成中断。恢复后 Worker/reconciler 必须先完成在途对账，再接受新运行。
- Windows 发布验收必须证明只有 Web 监听 `127.0.0.1:17860`，API/Worker/PostgreSQL
  无宿主端口且局域网不可达；不得仅检查 Compose 文件文本。
- 卸载默认保留本机数据和密钥；删除必须单独明确确认。安装器/Launcher 故障不能改变
  PostgreSQL 的事实源地位。
- 未来拆服务必须基于度量与明确边界另建 ADR。
