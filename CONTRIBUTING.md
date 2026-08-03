# 参与贡献

感谢参与 DataX Enterprise Studio。当前仓库以 V1.2 Windows 本地工作站实施候选文档为评审基线；开始前请阅读 `AGENTS.md`、`docs/00_文档总览与决策基线.md`、相关 Accepted ADR 和 `docs/security/THREAT_MODEL.md`。

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
- 不把 V1 改成外部 Linux 服务器、macOS/Linux 宿主、局域网服务或纯原生单进程 `.exe`。
  Windows 11 x64 是唯一发布认证平台；Docker Desktop + WSL2 是显式前置依赖，固定
  DataX Runtime 在 Linux 容器中运行。
- 仅 Web 可映射 `127.0.0.1:17860`；API、Worker、PostgreSQL 不得映射宿主端口或监听
  局域网/公网地址。Launcher 只管理本机前置/制品校验、基础设施 secrets 与 ACL、固定
  Compose、迁移/生命周期/首次管理员/备份/诊断 helper、健康检查和默认浏览器；不保存
  业务状态、不读取业务数据源凭据，也不承载复制逻辑。
- 不静默安装 Docker Desktop、不替用户接受其许可条款，也不以伪装运行环境或未经批准的
  替代实现规避许可。依赖检测失败必须给出可操作指引并安全停止。
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
- 是否在干净 Windows 11 x64 环境验证 `Setup.exe` 安装/卸载、桌面快捷方式、Docker
  Desktop/WSL2 前置检查、首次/重复启动、停止、睡眠/重启恢复和默认浏览器入口。
- 宿主监听证据：只有 Web 位于 `127.0.0.1:17860`，API、Worker、PostgreSQL 无宿主
  端口，局域网其他设备不可访问。
- Docker Desktop 许可由谁评估/接受；自动化不得代替用户或组织作出许可同意。
- `process_state`、`data_effect`、`verification_state` 与独立 oracle 证据。
- 权限、密钥、迁移、兼容和回滚影响。
- `acceptance-manifest.v1` 中对应需求、测试和证据结果。
- 未完成或受阻内容。

纯文档变更也必须校验内部链接、OpenAPI、全部 JSON Schema、ADR/威胁模型引用，以及 PRD、数据模型、机器契约、测试和追踪矩阵的跨文档一致性。

## 评审关注

评审人优先检查：范围漂移、数据外传、凭据泄露、三维状态错误、非空目标、重复执行、部分写入、Worker 围栏、孤儿进程、迁移不可逆、假 E2E、oracle 自证和文档/实现不一致。
