# 变更记录

## 2026-07-31 — Windows 候选镜像匿名拉取门禁

- 发布流水线使用全新空 `DOCKER_CONFIG`，在不继承 registry 凭据的条件下逐项拉取
  PostgreSQL、API、egress-guard、Worker 和 Web 的固定 `linux/amd64` digest。
- 任一镜像不是公开可匿名读取时不生成 Windows 候选包；PASS 证据写入
  `anonymous-image-pulls.json` 并由 Windows 候选验证器与最终镜像锁逐项复核。
- Launcher 仍不提供或保存 GHCR/Docker Hub 登录凭据；已登录发布 runner 的成功不能替代
  独立 Windows 电脑的公开读取能力。

## 2026-07-31 — MySQL DataX TLS 身份校验修复

- 将固定 Runtime 的 MySQL Connector/J 从 `5.1.47` 升级并锁定为 `9.7.0`，校验 Maven
  制品 SHA-256，改用 `com.mysql.cj.jdbc.Driver`，并随 Runtime 分发完整上游许可。
- MySQL `VERIFY_CA` 明确映射为 `sslMode=VERIFY_CA`，`VERIFY_FULL` 明确映射为
  `sslMode=VERIFY_IDENTITY`；禁止用不能表达主机名校验的旧 TLS 参数冒充。
- Runtime manifest 固定 Reader/Writer 两份 Connector/J 路径与摘要；旧版或重复 MySQL
  驱动使 readiness 失败关闭。真实 CA/hostname TLS 正负例仍保留为 Windows E3 门禁。

## 2026-07-30 — V1.2 Windows 本地工作站架构

- 将唯一发布认证宿主收敛为 Windows 11 x64；用户通过 `Setup.exe` 安装并从桌面快捷方式
  启动，不再要求购买或维护外部 Linux 服务器。
- 明确 Docker Desktop + WSL2 为前置依赖；固定 DataX Runtime 继续运行在 Linux 容器中，
  不把交付描述为纯原生单进程 `.exe`。
- 固定本机入口为 `http://127.0.0.1:17860`；仅 Web 映射 loopback，API、Worker 和
  PostgreSQL 不映射宿主端口，也不提供局域网或公网入站访问。
- 增加 Windows Launcher 的前置检查、幂等启动、健康等待、默认浏览器打开、停止和恢复
  语义；睡眠、关机、重启或 Docker Desktop 停止期间明确不可用。
- 增加干净 Windows 环境的安装/卸载、端口边界、首次引导、停机恢复和真实 DataX E2E
  验收；安装器不得静默安装 Docker、自动接受或规避其许可。

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
- 明确模块化单体、独立 Worker、PostgreSQL 事实源和当时的单节点部署基线；该宿主形态
  已由 V1.2 的 Windows 本地工作站决策取代。
- 增加不可变 JobVersion、执行状态机、凭据、审计、恢复和安全控制。
- 增加 OpenAPI、JobSpec、Plugin Manifest 和 AuditEvent 机器契约。
- 增加 Agent V2 边界、测试证据分级、阶段开发 Prompt、ADR 和 GitHub 模板。
- 明确文档完成不等同于代码或生产验收。
