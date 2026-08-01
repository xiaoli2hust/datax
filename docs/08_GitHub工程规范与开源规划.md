# GitHub 工程规范与开源规划

| 项 | 决策 |
|---|---|
| 仓库 | `xiaoli2hust/datax` |
| 默认分支 | `main` |
| 开发模式 | 受保护主干 + 短期分支 + Pull Request |
| 发布单位 | Windows 11 x64 已签名 Setup/Launcher、源码标签、镜像摘要、迁移版本、Runtime manifest、哈希与 SBOM |
| 当前许可证 | 仓库所有者尚未选择；公开源码前必须完成 |

> 当前远端治理边界：下述“受保护主干”是发布目标。当前线上快照为 0 个 ruleset，
> `main` 未保护；需要先推送当前工作流，再由仓库管理员配置必需检查。工作流文件或本地
> 扫描结果不能表述为线上合并强制门禁。仓库发布工作流仍生成 `gate_result=BLOCKED`
> 且需求项为 `NOT_RUN/E0` 的候选证据，不批准公开发布。

## 1. 仓库目标

仓库同时承载：

- 权威产品和工程文档。
- 前端、API、Worker 与部署代码。
- 机器可校验的 API、JobSpec、Plugin、Audit、Verification Oracle 和 Acceptance Manifest 契约。
- 自动测试、迁移、构建、SBOM 和发布证据。

不承载：

- 生产密钥、连接串、业务数据或运行日志。
- 未经校验的 DataX 二进制和插件 JAR。
- 模型密钥或 Provider 响应样本中的敏感数据。
- 无来源、无许可证或无摘要的大型制品。

## 2. 目标目录

```text
.
├── .github/
│   ├── ISSUE_TEMPLATE/
│   ├── workflows/
│   └── PULL_REQUEST_TEMPLATE.md
├── frontend/
│   └── src/
├── backend/
│   ├── src/
│   │   └── datax_studio/
│   │       ├── api/
│   │       ├── auth/
│   │       ├── audit/
│   │       ├── datasources/
│   │       ├── jobs/
│   │       ├── executions/
│   │       └── worker/
│   ├── migrations/
│   └── tests/
├── installer/
│   └── windows/
├── desktop/
│   └── windows/
├── deploy/
│   └── windows/
├── scripts/
│   ├── acceptance/
│   ├── release/
│   └── security/
├── docs/
│   ├── adr/
│   ├── contracts/
│   └── security/
├── AGENTS.md
├── CONTRIBUTING.md
├── SECURITY.md
└── README.md
```

DataX Runtime 由构建脚本获取或从受控制品库下载，按 manifest 校验，不直接提交到 Git。
Docker Desktop 与 WSL2 是用户自行安装和按适用许可使用的 Windows 前置依赖；仓库与
安装器不得捆绑 Docker Desktop、静默安装/启用 WSL2，或代替用户/组织接受、规避许可。

## 3. 分支规则

- `main`：始终可构建；禁止日常直接推送。
- `feature/<slug>`：用户能力。
- `fix/<slug>`：缺陷。
- `docs/<slug>`：纯文档或契约。
- `security/<slug>`：私密协作后公开的安全修复。
- `agent/<slug>`：编码 Agent 发起的受审查变更。

不维护长期 `develop` 分支，减少双主干漂移。分支应短命，合并后删除。

空仓库的首次文档基线可以作为 bootstrap 提交建立 `main`；从下一次变更起执行 PR 规则。

## 4. 提交与 PR

提交信息使用简短动词，例如：

- `建立 V1 文档基线`
- `实现数据源连接测试`
- `修复执行取消后的孤儿进程`

每个 PR 必须包含：

- 变更目的和关联需求/Issue。
- 用户或运维影响。
- 架构、数据迁移、权限和兼容性影响。
- 已执行检查与结果。
- 真实外部链路是否验证。
- 未验证项、风险和回滚方式。
- 文档、契约和追踪矩阵是否同步。
- PRD、ADR、数据模型与机器契约在各自关注点上是否一致；任何冲突必须列为阻塞项。
- 需求优先级、唯一测试 ID、oracle、证据路径和结果是否进入 `acceptance-manifest.v1`。
- 若影响 Windows 交付，列出 Setup/Launcher、升级/卸载数据边界、loopback 监听、
  Docker Desktop/WSL2 前置检查、睡眠/重启恢复与干净 Windows 11 VM 证据。

禁止把无关格式化、依赖升级和功能改动塞入同一 PR。

## 5. 主分支保护

仓库管理员应在首次代码 PR 前启用：

- 必须通过 PR 合并，至少 1 名审批人。
- 代码所有者路径需要对应审批。
- 所有必需 CI 状态通过。
- 分支必须与 `main` 保持最新。
- 禁止 force push 和删除 `main`。
- 合并后自动删除分支。
- 安全敏感目录建议 2 名审批人。

建议使用 squash merge；PR 标题成为主干提交摘要。

## 6. CI 门禁

当前已配置的安全工作流为：

- checksum 固定的 Gitleaks `8.30.1` 全 Git 历史秘密扫描；
- hash-lock 的 pip-audit `2.10.1`，覆盖 Python 构建、运行、开发和扫描工具锁文件；
- `pnpm audit --audit-level high`，覆盖 JavaScript 全依赖；
- checksum 固定的 OSV-Scanner `2.4.0`，扫描 Windows Launcher 的 `Cargo.lock`；
- CodeQL `v4.37.4`，覆盖 JavaScript/TypeScript、Python、Rust 和 GitHub Actions；
- PR 安全工作流从当前 `backend/Dockerfile.worker` 构建真实 patched
  Worker `linux/amd64` 镜像，以 checksum 固定的 Syft `1.50.0` 生成最终镜像 SPDX
  SBOM，再由 OSV 执行应用依赖门禁。本地证据为 0 个未处理、未使用或歧义项；6 个
  Logback `1.2.13` 项逐条使用精确补偿控制例外，统一到期日为 `2026-09-30`，不得写成
  “应用生态零漏洞”。
- 候选发布从 release context 绑定的精确 40 位 Git commit 执行 `git archive`，再生成
  源码 SPDX SBOM；同时为 PostgreSQL、API、egress-guard、Worker、Web 五个固定 digest
  镜像分别生成 SBOM。六份 SBOM 均进入 OSV 应用扫描，五个运行时镜像另进入 Grype
  发行版包扫描。
- Grype candidate 模式会直接阻断已有修复版本的 High/Critical；对无修复或明确
  `wont-fix` 的 High/Critical 全量记录 `review_required`，只允许继续生成仍明确
  `BLOCKED` 的候选证据。promotion 默认继续阻断，只有逐项精确且不超过 90 天的例外才
  可放行；这不是“镜像漏洞已清零”。
- `dependabot.yml` 已配置 GitHub Actions、backend pip、security-tooling pip、npm 和
  Windows Cargo 的每周版本更新。GitHub 仓库外部设置中的 Dependabot security updates
  当前仍为 disabled，版本更新配置不能冒充安全更新服务已经启用。

这些是仓库配置和本地证据，不是“线上已经通过”的证据。当前改动仍需推送，`main` 尚未
由 ruleset 强制这些检查；真实 GitHub candidate/release、Grype OS 状态、Windows
release runner 和签名结果均未在线验证。Java 源码也没有独立的 PR 级 CodeQL 构建分析；
当前 Maven 暴露主要由最终 Worker 镜像 SBOM/OSV 应用门禁覆盖。

### 文档阶段

- Markdown 格式和内部链接。
- OpenAPI 语法与示例校验。
- JSON Schema 解析、Meta Schema 和示例校验。
- ADR 状态、威胁模型、逐条需求追踪和无错位引用检查。
- JobSpec、OpenAPI、数据枚举和验收 manifest 的跨契约一致性检查。
- Secret/高熵字符串扫描。

### 工程阶段

- 前端格式化、lint、类型检查、单元测试和构建。
- 后端格式化、lint、类型检查、单元和 API 集成测试。
- Alembic 从空库升级、前后版本兼容与恢复测试。
- Docker 镜像构建、健康检查、非 root 和制品摘要检查。
- 真实 DataX E2E 由隔离测试环境执行；必须包含源静默确认、空目标复检、目标外部独占
  `statement_version='1.0'`/`valid_until`/`ACTIVE|REVOKED|EXPIRED` 生命周期、已知窗口破坏的
  Operator/DBA 撤回或报告与 `TARGET_EXCLUSIVITY_REVOKED` 审计、独立 oracle、部分写入、
  并发同目标、Worker fencing 和恢复后再次执行。Oracle `PASSED` 必须要求声明未撤回、
  未过期且目标快照结束不晚于 `valid_until`；测试不得声称平台能自动发现任意瞬时、未报告
  或已回滚的平台外 DML/DDL。没有真实凭据时明确为未运行，不能替换成 Mock 绿灯。
- SAST、依赖漏洞、SBOM、许可证和容器扫描。

### Windows 交付阶段

- Windows runner 负责 Launcher/Setup 的编译、静态测试、安装脚本测试和未签名制品复现；
  CI runner 成功不等于 Windows 11 E4 验收。
- 签名只在受保护发布环境执行，使用不可导出的代码签名凭据和可信时间戳。Fork PR、
  普通分支与日志不得获得证书私钥或签名服务权限。
- 发布流水线必须校验 Authenticode 签名、签名时间戳、发布 SHA-256、版本单调性、
  Setup/Launcher SBOM、第三方许可证清单和固定容器镜像 digest；任一不一致即失败关闭。
- Linux 镜像锁生成后、Windows 候选包生成前，流水线必须用全新临时
  `DOCKER_CONFIG`（固定空 `auths`、不继承 `DOCKER_AUTH_CONFIG` 或
  `REGISTRY_AUTH_FILE`）逐项执行五个固定 `linux/amd64` digest 的匿名 pull。API、
  egress-guard、Worker、Web 或 PostgreSQL 任一镜像不能在无注册表凭据条件下公开读取，
  都不得生成候选安装包。门禁只接受固定仓库的 `repository@sha256:<64 hex>`，不能把
  tag、已登录 runner 的缓存或 Launcher 登录流程当作替代。
- Compose 静态策略和运行时探测必须证明只有 Web 映射
  `127.0.0.1:17860`，API/Worker/PostgreSQL 无宿主端口，且未挂载 Docker Socket、
  Windows 命名管道或用户目录。
- `E2E-WIN-001` 与 `E2E-WIN-002` 必须在干净 Windows 11 x64 VM 执行，覆盖安装、
  依赖缺失、首次/重复启动、端口冲突、磁盘不足、停止、Windows 重启、睡眠/恢复、
  Docker/WSL2 中断、卸载保留 named volumes/备份、重装恢复和 LAN 拒绝。
- Windows VM 内还须完成四方向真实 DataX 和独立 oracle、备份恢复。macOS/Linux
  构建、包存在、容器启动或非 Windows E2E 均不能把 Windows 测试标为 PASS。

高风险 CI 所需密钥只使用受保护环境和最小权限短期凭据，不向 Fork PR 暴露。

## 7. Issue 规范

功能 Issue 至少包含：

- 背景和用户价值。
- 关联需求 ID。
- 输入、输出和非目标。
- 正常/失败/权限/并发路径。
- 数据、API、UI、迁移和安全影响。
- 可执行验收标准，包括唯一测试 ID、oracle、证据等级和证据路径。

Bug Issue 应包含版本、环境、复现步骤、预期/实际、脱敏日志和影响；不得粘贴密码、连接串或业务数据。

## 8. 版本与发布

采用语义版本：

- `0.x`：企业试点，可能有受控破坏性变更。
- `1.0.0`：完成生产认证门禁后。

发布候选必须固定：

- Git commit 和标签。
- 已签名 `DataX-Enterprise-Studio-Setup-<version>-x64.exe` 与其内
  `launcher.exe` 的 Authenticode 发布者、证书指纹、可信时间戳和 SHA-256。
- PostgreSQL、API、egress-guard、Worker、Web 五个运行时镜像 digest；PostgreSQL 与
  egress-guard 基线固定为 PostgreSQL `15.18-alpine3.24`，API/Worker 最终 Python
  运行层固定为 Python 3.12.13 `slim-trixie`（Debian 13）。
- 五个固定 digest 使用空临时 Docker registry 配置完成匿名 pull 的
  `anonymous-image-pulls.json`；证据必须与最终 `images.release.env` 逐项一致。
- 数据库迁移 head。
- DataX 版本、Runtime 包 SHA-256、每个插件 JAR SHA-256，以及固定 Connector/J 版本、
  Reader/Writer 两份驱动 JAR 路径与 SHA-256。
- OpenAPI/JobSpec/Plugin Manifest 版本。
- Verification Oracle、Acceptance Manifest 和外部审计锚点格式版本。
- 从精确候选 Git commit archive 生成的源码 SBOM、五个固定 digest 镜像 SBOM、许可证
  清单和逐项已知漏洞例外；当前 6 个 Logback 例外最晚到 `2026-09-30`，promotion 例外
  不得超过 90 天。
- Windows 11 x64 支持矩阵、Docker Desktop/WSL2 前置与许可责任说明。
- 升级、回滚、数据备份和卸载默认保留 Docker named volumes
  （`des-postgres-data`、`des-log-data`、`des-workspace-data`）及导出备份的说明。
- 干净 Windows 11 x64 VM 的 `E2E-WIN-001`、`E2E-WIN-002`、四方向 DataX、
  签名/哈希、端口、恢复和备份证据。

当前 release workflow 只生成 Linux 工程候选和显式 `BLOCKED` manifest；没有签名 Setup、
真实 Windows 11 E4、四方向 DataX、外部 WORM 或恢复证据时，不得创建公开发布结论。

禁止使用可漂移的 `latest` 作为发布依据；禁止只上传 ZIP、未签名 EXE 或镜像后宣称
Windows 可交付。版本制品、哈希、SBOM、许可证与证据包必须原子发布或整体撤回。

## 9. 上游与依赖治理

每个第三方组件记录：

- 名称、来源、版本/commit。
- 直接或传递依赖。
- 许可证与 NOTICE 义务。
- 下载地址和摘要。
- 漏洞状态、维护状态和替代方案。

DataX 上游代码采用 Apache License；如果分发其二进制或修改版本，必须保留相应 LICENSE/NOTICE 并单独记录修改。插件许可证和数据库驱动许可要逐项检查，不能用上游总体许可代替。

当前凭据与端点安全切片新增/固定的直接依赖：

| 依赖 | 用途 | 上游许可证 | 不采用的替代 |
|---|---|---|---|
| `cryptography==49.0.0` | AES-256-GCM、AES-256-KWP 与既有 Ed25519 | Apache-2.0 / BSD-3-Clause | 不自实现密码算法 |
| `dnspython==2.8.0` | 有界 A/AAAA/CNAME 解析与 TTL 证据 | ISC | 不只使用不可审计 TTL/CNAME 的简化主机解析 |
| `PyMySQL==1.2.0` | MySQL 8 参数化元数据探针与固定 peer 连接 | MIT | 不使用 shell 客户端或把密码放入命令行 |
| `com.mysql:mysql-connector-j:9.7.0` | DataX MySQL 8 Reader/Writer；以 `VERIFY_IDENTITY` 实现平台 `VERIFY_FULL` | GPLv2 + Universal FOSS Exception 1.0；完整上游许可随 Runtime 分发 | 保留 `5.1.47` 时只能把 MySQL `VERIFY_FULL` 失败关闭，无法满足已接受的 hostname identity 合同；不自研 TLS SocketFactory |

Windows 安装器、Launcher 框架、代码签名工具、WebView/浏览器组件和容器基础镜像也必须
逐项记录许可证与再分发条件。Docker Desktop 不属于本产品分发物；其资格、订阅和许可
接受由用户或其组织负责，产品只能检测状态并链接官方说明。

## 10. 本仓库许可证决策

仓库公开不等于自动授予开源许可。在所有者明确选择前：

- 不添加推测性的 `LICENSE`。
- README 明确当前无额外许可授予。
- 允许公开阅读，但不得对再分发或商业使用作承诺。
- 首次公开源码发布前，由所有者在 Apache-2.0、其他许可证或闭源策略中做出明确决定。

## 11. 安全响应

安全报告遵循根目录 `SECURITY.md`。仓库管理员应启用 GitHub Private Vulnerability Reporting；含密钥、利用细节或客户数据的问题不得建立公开 Issue。

## 12. 开源路线

1. **文档基线**：公开范围、架构和贡献规则。
2. **可复现试点**：发布无生产数据的完整源码、固定 Compose 和测试；Windows 制品仍需
   通过签名与干净 VM 门禁。
3. **Windows 本地交付**：发布签名 Setup/Launcher、哈希、SBOM、许可证与
   `E2E-WIN-001/002` 证据。
4. **供应链透明**：发布 SBOM、Runtime manifest、许可证清单。
5. **社区扩展**：在插件安全模型成熟后开放插件 SDK。
6. **生态治理**：只有签名、审计、兼容和撤回机制齐全后才建设插件市场。
