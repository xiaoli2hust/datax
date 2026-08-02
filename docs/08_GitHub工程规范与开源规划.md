# GitHub 工程规范与开源规划

| 项 | 决策 |
|---|---|
| 仓库 | `xiaoli2hust/datax` |
| 默认分支 | `main` |
| 开发模式 | 受保护主干 + 短期分支 + Pull Request |
| 发布单位 | Windows 11 x64 已签名 Setup/Launcher、源码标签、镜像摘要、迁移版本、Runtime manifest、哈希与 SBOM |
| 当前许可证 | 仓库所有者尚未选择；公开源码前必须完成 |

> 当前远端治理边界：截至 2026-08-02，`main` 已启用经典分支保护，严格要求分支最新、
> 线性历史、PR、会话解决以及本文列出的 12 个 CI/安全检查，且禁止强推和删除；管理员
> 同样受约束。当前仓库只有一名维护者，为避免自提交 PR 永久不可合并，审批数暂为 0，
> 因而不能把该设置表述为独立人工复核。`dependabot.yml` 已声明版本更新，但 2026-08-02
> GitHub REST 的 `security_and_analysis.dependabot_security_updates.status` 仍为 `disabled`；
> 漏洞告警与 Dependabot security updates 是不同控制，后者必须由 Repository Owner 在管理面启用
> 并保存证据，当前为 `BLOCKED_EXTERNAL`。
> `windows-candidate-signing` GitHub Environment 当前尚未配置（2026-08-02 API 返回 0 个
> environment）；引用不存在的名称会被 GitHub 自动创建为无保护环境。发布工作流先由一个
> 不声明 `environment`、不读取 signing secrets/发布 variables 的 GitHub-hosted preflight GET
> 该 Environment，并只输出 immutable ID 与 canonical protection SHA-256；签名 job `needs` 此
> 输出，再在导入 PFX 前二次 GET 并精确比对。这样不能由签名 job 自己的首次 Environment 引用
> 伪造“已预先配置”事实；缺失、策略/API 读取失败、删除/重建或 hash 不符均失败关闭。该 E1
> 接线不替代实际在 GitHub 配置审批人、分支/标签策略、环境专属 secrets 或管理员绕过禁用，
> 也尚无 `windows-candidate-signing` 的在线 preflight、审批或签名运行证据。无发布权限的
> GitHub-hosted Windows E1 预检已有成功运行，但不能证明签名发布控制。GitHub 默认允许管理员
> bypass protection rules，而 REST Get Environment
> 与当前 GraphQL `Environment` 类型不返回 `can_admins_bypass`；verifier 不得声称验证它。
> Release Owner 必须在 Settings UI 取消 **Allow administrators to bypass configured protection rules**
> 并保存带时间/Environment/操作者的截图或等价配置记录；迁入 Organization 后还需保存
> `environment.update_protection_rule` audit 记录的 `can_admins_bypass=false`，以及签名窗口无反向
> 修改的审计查询。
> 当前也没有可用 self-hosted runner。更根本的是该 public repo owner type 为 `User`，而
> `datax-release-signing` custom runner group 是 GitHub Organization/Enterprise 管理边界；当前
> repository/org runner-group API 均无法提供该组。这是 `BLOCKED_DECISION`：首选迁入或转让到
> Organization 后配置专用 group；否则必须先新增 Accepted ADR 决定等价的新签名信任架构。
> 在决策前，签名 job 保持只路由到该 group 与
> `self-hosted/windows/x64/datax-release-windows11` labels 的交集，缺组或缺 runner 保持阻断，
> 不能回退到任意同标签 runner。
> 同一线上快照还显示仓库 Actions policy 为 `allowed_actions=all`、`sha_pinning_required=false`，
> `main` 的 required approving review count 为 0 且未要求 CODEOWNERS review；源码中 action 已固定
> SHA，但远端没有强制这些供应链/独立复核治理。迁入 Organization 后，Repository Owner 必须以
> 规则集、允许动作策略、SHA pinning 和安全敏感路径独立复核（或 Accepted ADR 记录的等效控制）
> 关闭该外部门禁；不得把当前 12 个必需检查或 PR 存在当作其替代。
> 仓库发布工作流仍生成 `gate_result=BLOCKED` 且需求项为 `NOT_RUN/E0` 的候选证据，不批准公开发布。

> ADR-0011 已接受未来的两阶段插件/Runtime qualification 与发布晋级链：不可变 payload
> 先在受保护 Windows harness 中取得 Phase A 私有 qualification（不是 E4 或 Plugin Manifest
> 状态），独立签发 detached QR 后才构建私有最终候选；再在无 QH 的 Phase B 中验证精确
> 安装包，才可派生 Windows E4 插件状态并交给 ADR-0010 hosted attestor/PR 公开晋级。
> 当前已有 P/QH/PAG Schema、失败关闭 P/QH parser、私有 payload/runtime/job binding 与
> PostgreSQL nonce/grant E1 基础账本；`20260802_0021` 还增加了无登录 ledger owner / issuer /
> consumer、最小 `SECURITY DEFINER` 签发/撤回/读取函数和未接入标准路径的 private adapter。它们
> 不等于已签发 P/QH、可运行的 qualification workflow 或 release approval：没有标准角色凭据、
> QH/PAG source/override、私有 API/Worker Execution authorization、受保护 harness、QR reader、
> candidate-root.v2 或真实 Windows/签名/OIDC 证据，发布仍只能生成显式 BLOCKED 候选。

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

当前 `main` 已启用：

- 必须通过 PR 合并；当前单维护者阶段审批数为 0，增加独立维护者后应提升到至少 1。
- 所有 12 个必需 CI/安全状态通过：后端与契约、PostgreSQL 迁移往返、前端、Windows
  Launcher、全历史秘密扫描、依赖审计、Worker Runtime 审计、四语言 CodeQL 和 CodeQL
  聚合门禁。
- 分支必须与 `main` 保持最新。
- 禁止 force push 和删除 `main`。
- 要求线性历史并解决所有会话。
- 管理员不得绕过以上保护。

代码所有者审批、至少 1 名独立审批人、合并后自动删除分支，以及安全敏感目录 2 名审批
仍是增加协作者后的治理目标；当前不得把 0 审批配置称为“四眼原则”已经实现。

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
  Windows Cargo 的每周版本更新。2026-08-02 线上 REST 显示漏洞告警可用，但
  `Dependabot security updates` 为 `disabled`；Repository Owner 启用并留存配置证据前，
  不得把配置文件存在写成线上自动安全更新已启用。

最新 PR 的 CI、安全工作流与 CodeQL 聚合门禁已在线通过，PR 开放 CodeQL 告警为 0；
`main` 的经典分支保护已强制上述检查。这不等于 candidate/release、Grype OS 状态、
Windows release runner 或签名结果已经在线验证。Java 源码也没有独立的 PR 级 CodeQL
构建分析；当前 Maven 暴露主要由最终 Worker 镜像 SBOM/OSV 应用门禁覆盖。

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
- 改动 ADR-0011 Phase-A 基础件时，必须验证 P/QH/PAG Schema、失败关闭 parser/binding，及
  PostgreSQL nonce/grant 的重放、不可变、生命周期、标准运行角色 direct-table-denial、issuer/consumer
  的函数最小权限、原子 nonce+grant 签发与 current-grant 读取。它们不得被 Settings、标准 Compose、
  API 或普通 Worker 接入；还必须验证预存私有角色名/成员关系失败关闭，以及 ledger owner 后续
  新建函数默认无 `PUBLIC EXECUTE`。
  该临时 PostgreSQL 容器检查最多是数据库 E2；未启动产品 Compose、API、Worker、DataX、
  MySQL 或独立 oracle 时，绝不能称为 Phase-A E3、Windows E4 或发布证据。
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
- 签名 job 使用前，`windows-candidate-signing` 必须已在 GitHub 管理面预先创建，并至少配置
  一名 required reviewer 且禁止发起人自审。必须先由 GitHub-hosted preflight（无 job-level
  `environment`、无 signing secret/发布 variable）读取 REST Environment，验证后只输出 immutable
  ID 与不含 reviewer identity 的 canonical protection SHA-256；签名 job 必须 `needs` 此输出，且在
  导入 PFX 前再次读取并精确比对。空/隐式创建的 Environment、缺审批、允许 self-review、未知
  policy、API 不可读、identity/hash 变化或空输出均不得触及证书导入。
  GitHub 默认允许管理员绕过环境规则，且可读 REST/GraphQL Environment 表示不提供
  `can_admins_bypass`；因此 verifier 不能宣称这项通过。Release Owner 必须在 UI 显式禁用 bypass
  并保存证据；迁入 Organization 后还要保留 `environment.update_protection_rule` 审计记录中
  `can_admins_bypass=false` 与签名窗口无反向修改的查询结果。
  签名 job 还固定要求 `datax-release-signing` runner group 与
  `self-hosted/windows/x64/datax-release-windows11` 标签交集；该 group 只能向本仓库暴露可还原、
  一次性 Windows Release runner，不能把宽泛的默认组或单一标签当作等价隔离。
  因当前 repo 为 User-owned，custom group 的创建/绑定是外部 `BLOCKED_DECISION`：Release Owner
  必须优先把仓库迁入 Organization，或在新增 Accepted ADR 后才能采用不同的信任边界；不得仅为
  让 workflow 排队消失而放宽该 group。
  `CARGO_PATH`、`MAKENSIS_PATH`、`RUSTC_PATH` 与 `SIGNTOOL_PATH` 必须作为发布环境配置的
  显式本机绝对路径提供；工作流在导入 PFX 前拒绝空路径、网络/相对路径、重解析点、错误文件名
  或 dirty/untracked checkout，还拒绝 `RUSTC_WRAPPER`、`RUSTFLAGS`、
  `CARGO_ENCODED_RUSTFLAGS`、`CARGO_BUILD_RUSTFLAGS`、`CARGO_TARGET_*`、`CARGO_HOME`
  等环境覆盖。Cargo 调用把 `RUSTC` 固定为显式 `RUSTC_PATH`，并在候选组装/验证后、证书
  清理和候选上传前重新检查 tracked source。该最终 `git diff` 只覆盖 tracked source，不覆盖
  后来建立的 untracked 工作区输入或 `RUNNER_TEMP` 候选输出。拒绝环境中的 `CARGO_HOME` 只会
  使 Cargo 回落到 runner 用户 profile 的默认 Cargo home；该 profile 的 config/cache 仍须作为
  runner provisioning/ACL 门禁单独取证。绝对路径和结构检查只消除经 `PATH` 选择工具和显而易见的
  工作区污染；它不证明所执行字节就是批准工具，不能消除检查后到执行前的替换（TOCTOU），也不证明
  工具 hash/Authenticode、父目录 ACL、runner 恢复基线或私钥不可导出性。因此仍只是 E1，不能关闭
  FP-P1-015。
  Release Owner 还必须在 GitHub 为 `main` 与精确发布 tag 配置符合本仓库发布策略的部署/规则集
  限制，并把签名 secrets 仅存于该 Environment；这一远端配置不是 YAML 文件存在就能证明的。
- 发布流水线必须校验 Authenticode 签名、签名时间戳、发布 SHA-256、版本单调性、
  Setup/Launcher SBOM、第三方许可证清单和固定容器镜像 digest；任一不一致即失败关闭。
- Linux 镜像锁生成后、Windows 候选包生成前，流水线必须用全新临时
  `DOCKER_CONFIG`（固定空 `auths`、不继承 `DOCKER_AUTH_CONFIG` 或
  `REGISTRY_AUTH_FILE`）逐项执行五个固定 `linux/amd64` digest 的匿名 pull。API、
  egress-guard、Worker、Web 或 PostgreSQL 任一镜像不能在无注册表凭据条件下公开读取，
  都不得生成候选安装包。门禁只接受固定仓库的 `repository@sha256:<64 hex>`，不能把
  tag、已登录 runner 的缓存或 Launcher 登录流程当作替代。
- Windows 候选的顶层 `images.release.env`、安装器内嵌的同名 lock 与 Linux build evidence
  中生成的 `linux-evidence/images.release.env` 必须逐字节一致；Windows 验证器复核该 lock
  绑定。托管 attestor 还必须独立下载 Linux build artifact、验证其 `SHA256SUMS`，并让候选根
  递归比对候选内 `linux-evidence/` 与独立来源的全部文件路径、大小和 SHA-256。仅重新计算
  自托管 Windows runner 中被替换的 lock/hash 不足以证明其来自已扫描 Linux 构建，也不能证明
  unsigned Windows 二进制或工具链来自审核源码。
- Compose 静态策略和运行时探测必须证明只有 Web 映射
  `127.0.0.1:17860`，API/Worker/PostgreSQL 无宿主端口，且未挂载 Docker Socket、
  Windows 命名管道或用户目录。
- `E2E-WIN-001` 与 `E2E-WIN-002` 必须在干净 Windows 11 x64 VM 执行，覆盖安装、
  依赖缺失、首次/重复启动、端口冲突、磁盘不足、停止、Windows 重启、睡眠/恢复、
  Docker/WSL2 中断、卸载保留 named volumes/备份、重装恢复和 LAN 拒绝。
- Windows VM 内还须完成四方向真实 DataX 和独立 oracle、备份恢复。macOS/Linux
  构建、包存在、容器启动或非 Windows E2E 均不能把 Windows 测试标为 PASS。

高风险 CI 所需密钥只使用受保护环境和最小权限短期凭据，不向 Fork PR 暴露。

ADR-0011 要求把未来 release workflow 拆成以下不可互相替代的阶段：

1. 先以精确 commit 构建不可变 payload P，并在不含 QH/QR/最终 Setup 的情况下计算
   payload root；改变镜像、Runtime、插件、内置公钥或锁即产生新 P。
2. 受保护 HQA 仅为指定 P、固定 harness、一次性 nonce 和短有效期签发 QH。QH 只能经
   私有 override 给 Phase A harness，不能出现在标准 Compose、Setup、公开 artifact、
   settings 或普通用户能力目录。
3. 真实 E3/私有 Windows harness/payload qualification（不是 E4）的独立复核通过后，独立
   RQA 才能签发 detached QR。HQA、RQA、Authenticode 证书和 GitHub OIDC 不是同一把密钥或
   同一角色。
4. QR 进入私有最终 F 后，Phase B 必须在无 QH 的标准 Launcher/Compose 上运行精确
   Setup/Launcher 的 Windows E4；只有该证据才可派生 `WINDOWS_E4_CERTIFIED`，随后生成
   同时绑定 P、QR、F 和最终证据的 candidate-root v2，由 hosted attestor 验证来源并由
   发布 validator 形成 PR。E4 状态本身不等于公开晋级。

任何阶段缺少真实外部 TCB、签名、场景/证据或负向验证时只生成 BLOCKED 候选。不得通过
把 QR 写进 Worker 镜像、让 QR 绑定包含它的 Setup/manifest、使用环境变量放行，或把
self-hosted runner 的自述 JSON 当作公开 release 证明。

当前的 E1 状态包括 P/QH parser、私有 payload/runtime/job binding 与 durable nonce/grant
账本；`20260802_0021` 已用无登录 dedicated role 与精确 `SECURITY DEFINER` 函数把 atomic
nonce+PAG issue/revoke 与 current-grant read 分离，并提供只接受未来受保护 Engine 注入的 private
adapter。它没有 private override、Execution authorization、普通 API/Worker 接线或受保护 harness；
因此不能产生 QH、普通运行路径的 PAG 消费、QR、E3/E4、普通用户能力或可发布候选。

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
- ADR-0011 的 payload root、私有 Phase A 非 E4 资格证据摘要和由独立 RQA 签发的 QR；
  QH 只保留在受保护 harness 的短生命周期证据区，不进入公开候选或安装包。
- 精确最终 F 与其 Phase B Windows E4 证据；它可派生插件 `WINDOWS_E4_CERTIFIED`，但普通
  用户可执行性和公开分发还必须有同一 F 的有效 PR。最终 candidate-root.v2 必须绑定 P、QR、
  F、acceptance/environment/scenario/SBOM/许可证和 hosted provenance。现有 v1 根只能表示
  BLOCKED，不能代替该项。
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

当前远端因缺少 signing Environment 和受限 Windows runner，release workflow 不能实际生成
签名 Setup。即使未来补齐这些前置条件，现有 workflow 也只会生成名称和根语义均为
`BLOCKED` 的候选，而非公开 release；没有真实 Windows 11 E4、四方向 DataX、外部 WORM
或恢复证据时，不得创建公开发布结论。

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
