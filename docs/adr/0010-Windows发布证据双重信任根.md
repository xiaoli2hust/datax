# ADR-0010：Windows 发布证据采用双重信任根

- 状态：Accepted（工程实施）；运行器、保护环境和证书启用仍为 Owner/Release 阻塞项
- 日期：2026-08-01
- 决策者：仓库所有者
- 关联：`docs/14_第一性原理问题台账与开发修复计划.md`、
  `docs/contracts/acceptance-manifest.v1.schema.json`、
  `docs/contracts/windows-e4-scenario-profile.v1.schema.json`、
  `docs/contracts/windows-e4-scenario-result.v1.schema.json`、
  `docs/contracts/candidate-root.v1.schema.json`、`.github/workflows/release.yml`

## 背景

当前候选可以在受保护的 Windows job 中构建并验证 Authenticode，但 release workflow
有意生成 `BLOCKED/NOT_RUN` acceptance manifest。结构化 JSON、文件 SHA-256 和调用方
传入的 commit 只能证明“这些字段彼此一致”，不能证明证据确实来自干净 Windows 11、
真实 Docker Desktop/WSL2、真实数据库和固定候选。让同一个自托管 Windows runner 既
执行测试、又自行声明“我是可信 runner”，同样不能建立独立发布信任根。

最终用户不应为运行本机产品部署 GitHub runner 或外部 Linux 服务器；这里需要解决的是
发布取证和候选不可替换问题，不是增加产品运行依赖。

## 决策

### 1. 发布取证使用两个职责分离的信任角色

1. **Windows E4 harness**：专用、受保护、可还原到已登记干净基线的 Windows 11 x64
   自托管 runner 执行安装、Docker Desktop/WSL2、端口/LAN、四方向 DataX、故障、备份
   恢复和卸载场景。该 runner 是物理行为证据的操作信任根，不运行 PR 代码，不接受来自
   待验证 manifest 的命令、路径、测试集合或期望结果。签名 workflow 只能以
   `runs-on.group=datax-release-signing` 加
   `self-hosted/windows/x64/datax-release-windows11` labels 路由到该隔离组；缺组或缺 runner
   必须阻断，不能因任意同标签 runner 可用而回退。
   当前远端 `xiaoli2hust/datax` 的 owner type 为 `User` 且为 public；GitHub 的 custom runner
   group 是 Organization/Enterprise 管理边界，`/repos/.../actions/runner-groups` 与
   `/orgs/xiaoli2hust/...` 当前均不能提供该组。因此这是 `BLOCKED_DECISION`：首选把发布仓库
   迁入/转让给 Organization 后再配置该组；若所有者不接受迁移，必须先用新的 Accepted ADR
   选择等价但不同的签名信任架构。不得把现有 group 要求静默降级成任意 self-hosted runner。
2. **候选根 attestor**：后续 GitHub 托管 runner 重新下载 Windows 证据，验证候选根和
   全部哈希，再使用 GitHub Actions OIDC/Sigstore artifact attestation 对候选根签发构建
   来源证明。发布 validator 必须要求该证明来自固定仓库、固定 release workflow、受保护
   主分支的精确 commit，并拒绝由 self-hosted runner 签发的候选根证明。

Windows runner 不能签发最终候选根证明；GitHub 托管 attestor 不能替代 Windows E4
行为测试。任一角色缺失、跳过或身份不符都保持 `BLOCKED`。

### 2. 候选根固定绑定整个发布事实

新增 canonical candidate-root 契约，至少绑定：

- `xiaoli2hust/datax`、release workflow 路径、run ID/attempt、受保护环境、commit、tag 和
  release candidate；
- `Setup.exe`、`launcher.exe`、最终 release manifest、镜像 digest lock、SBOM/许可清单、
  acceptance manifest、environment manifest 的相对路径、大小和 SHA-256；
- 需求 catalog、场景 profile catalog 和逐场景结果 catalog 的 SHA-256；
- Windows 基线身份、harness 版本、开始/结束边界以及真实 E3/E4 证据包根摘要。

候选根只引用 candidate directory 内无重解析点的普通文件。路径集合、排序、编码、字段和
哈希必须 canonical；取证后改变任一代码、制品、manifest、场景或证据都会产生新的候选根，
必须重新运行相关验收。

### 3. 发布 validator 必须做密码学来源验证

`--require-pass` 不能接受“已验证”布尔值或调用方伪造的 verification JSON。它必须以参数
数组调用受信 `gh attestation verify`（或后续 Accepted ADR 指定的等价 verifier），对实际
candidate-root 和 attestation bundle 做密码学验证，并同时固定：

- repository：`xiaoli2hust/datax`；
- signer workflow：本仓库固定 release workflow；
- source ref：受保护主分支或发布 tag；
- source digest：外部 CI 上下文中的精确 candidate commit；
- OIDC issuer：GitHub Actions；
- signer runner：必须通过 `--deny-self-hosted-runners` 证明候选根由托管 attestor 签发。

通过 attestation 之后仍须重新计算候选根引用的全部文件哈希，并执行 acceptance schema、
场景 profile、oracle、Windows E4、缺陷和发布门禁语义验证。密码学来源正确不能把
`FAIL/BLOCKED/NOT_RUN` 变成 PASS。

### 4. 签名 Environment 必须在导入证书前失败关闭

签名 job 使用 `windows-candidate-signing` 之前，必须由一个 GitHub-hosted、无
`environment` 声明的 `signing-environment-preflight` job 通过 GitHub REST API 读取已存在的
同名 Environment；YAML 名称或 workflow 首次引用均不构成保护存在。该 preflight 不读取签名
secrets 或发布环境 variables，因而不会先通过 job-level Environment 引用触发 GitHub 的隐式创建。
它只输出 `ready`、不可变 `environment_id` 与 canonical `protection_sha256`，绝不输出 reviewer
姓名、登录名、数值身份或 token。预检要求：

- 恰好一个非空 `required_reviewers` protection rule；
- reviewer 总数为 1–6，且 User/Team 身份唯一；
- `prevent_self_review=true`；
- canonical hash 必须涵盖 reviewer 集合、`prevent_self_review`、受支持的 `wait_timer` 和
  deployment branch policy。GitHub REST 会把正常的分支/标签限制表示为一个 `branch_policy`
  protection rule：只允许恰好一个，且仅当可读 `deployment_branch_policy` 的
  `protected_branches` 与 `custom_branch_policies` 恰有一个为 `true` 时接受；其规则与 selector
  均进入 hash。缺 rule、重复 rule、空/双真/双假的 selector、畸形 policy、未知保护规则、
  Environment 缺失、规则为空/重复/畸形、允许自审或 API 读取失败时，均在导入证书、设置
  signing 变量或调用签名工具前终止。

当 `custom_branch_policies=true` 时，Environment 响应本身不携带具体 pattern。两次预检都必须
额外读取 `GET /repos/{owner}/{repo}/environments/{environment}/deployment-branch-policies?per_page=100`，
校验 `total_count` 与返回数组精确相等且不超过该完整页上限，并把每个 selector 的正整数 REST
ID、精确 `name` 与（若 GitHub 返回）`type` 规范排序后纳入 hash；未知字段、重复 ID/name、畸形
响应、分页溢出或 selector 读取失败均失败关闭。`protected_branches=true` 时该 endpoint 不是
selector 事实源，不得由调用方伪造一个空 selector JSON 代替。

`protected_branches=true` 只把 GitHub 当时的“受保护分支”选择模式本身纳入 hash；REST
Environment 响应不能枚举实际受保护分支、ruleset 或 tag 规则。若仓库没有分支保护，GitHub
会把该模式视为允许所有分支。因此它不能单独证明只允许 `main` 与精确 semver tag：Release Owner
必须另留分支/ruleset/tag 治理证据，或采用可完整 hash 的 custom selectors。两种模式均为本 ADR
允许的配置；若要在源码中强制 custom-only，必须先更新本 ADR。

GitHub 默认允许管理员绕过 Environment protection rules。Release Owner 必须在 GitHub Settings UI
显式取消 **Allow administrators to bypass configured protection rules**，并保存含 Environment 名称、
时间、设置值与操作者的 UI 配置证据；仓库迁入 Organization 后，还必须保存
`environment.update_protection_rule` 审计事件中 `environment_id`、`environment_name` 与
`can_admins_bypass=false` 的证据，并证明签名窗口内无把该值改回 `true` 的事件。GitHub 的
[REST Get environment](https://docs.github.com/en/rest/deployments/environments#get-an-environment)
响应和当前 GraphQL `Environment` 类型均不公开这个开关；`verify_signing_environment.py` 只能验证
其可见规则/身份/hash，**不得**声称校验了管理员绕过禁用状态。

任何会产生候选副作用的 job（包括 Linux 镜像构建/推送）和签名 job 都必须 `needs` 这个 root
preflight，只有 `ready=true` 才能进入执行；这样缺失或失配 Environment 不会先发布 GHCR 候选。即使 preflight
与签名 job 之间发生删除、重建或策略修改，签名 job 也必须在导入 PFX 前再次 GET，并要求当前
`environment_id` 与 `protection_sha256` 精确等于 preflight 输出；任一不匹配、空输出或 API 错误
均失败关闭。这样既阻止“先引用而后检查”的隐式创建时序漏洞，也不把两次读取之间的远端变更
包装成已审批事实。

`cargo.exe`、`makensis.exe`、`rustc.exe` 与 `signtool.exe` 必须由发布环境显式提供本机
绝对路径；workflow 和 release scripts 不得从 PATH 自动发现。导入 PFX 前必须拒绝 dirty/
untracked checkout、相对/网络/重解析工具路径和错误文件名，还必须拒绝 Cargo wrapper、flags、
target/home 等环境覆盖。Cargo 调用必须把 `RUSTC` 固定为显式 rustc 路径；候选组装/验证后、
证书清理和候选上传前还必须复核 tracked source 未变化。该最终复核不盘点随后出现的 untracked
输入或候选输出。拒绝环境 `CARGO_HOME` 只使 Cargo 使用 runner profile 的默认 Cargo home，
其 config/cache 仍是 provisioning/ACL 的独立取证对象。这是对 PATH shim 和意外工作区污染的
最小失败关闭：绝对路径不证明执行字节的工具身份，也不能阻止检查后/执行前替换（TOCTOU）。它不
替代工具 hash/签名、父目录 ACL、受保护且可还原的一次性 runner，或不可导出 HSM/远程签名；这些
仍是 E3/E4 门禁。

该双阶段预检只确认两次所读取的 Environment 身份和形状；它不替代 owner 对管理员绕过禁用、
secrets 作用域、`main` 与精确 release tag 部署限制、真实审批记录、Organization runner group
或受控 Windows runner 的独立取证。后者仍必须以 E4 release evidence 单独证明。

### 5. 明确信任声明的上限

GitHub artifact attestation 能证明候选根由指定 workflow/commit 产生且之后未被替换；它
不能自行证明 Windows 机器真的干净、测试脚本没有受运维人员篡改、外部数据库行为真实，
也不能替代代码签名证书和 RFC 3161 时间戳验证。因此 E4 runner 还必须：

- 每次从登记的 golden image 还原，使用一次性 runner 注册和一次性工作目录；
- 记录 Windows edition/build/架构、Secure Boot/virtualization、`wsl --status`、Docker/WSL
  版本、runner image ID 和运维审批；`DefaultVersion=1` 只作诊断，若 `wsl --status` 与实际
  Docker Linux/amd64 backend 都健康，不能阻断 READY 或把该主机判为失败；
- 在测试后销毁工作目录、runner token 和临时凭据；失败或无法证明基线时不生成 PASS；
- 由与代码作者分离的 Release/QA 责任人复核关键物理场景。

这是受控工程信任链，不宣传成对被攻陷宿主的数学证明。

### 6. 产品运行形态不增加服务器依赖

上述 GitHub/runner 只参与构建、签名和发布。最终 Windows 用户仍通过 `Setup.exe` 安装，
在本机 Docker Desktop + WSL2 中运行固定 Linux 容器，通过
`http://127.0.0.1:17860` 使用产品；不需要自建 Linux 服务器，也不需要把目标 Windows
电脑长期注册为 GitHub runner。

### 7. 与 ADR-0011 的衔接

ADR-0011 将插件/Runtime 的不可变 payload、受保护 harness 的短期资格、detached
release qualification、最终安装包和公开晋级拆开。这里的双重信任根不被 QR 替代：

- 自托管 Windows harness 可在 Phase A 对 payload 进行真实 E3/私有 Windows harness/payload
  qualification（明确不是 E4 或 Plugin Manifest 状态），并在 Phase B 对精确最终
  Setup/Launcher 做无 harness override 的正常模式 E4；只有后者才可派生
  `WINDOWS_E4_CERTIFIED`，且它仍不能自行签发公开候选根。
- hosted attestor 必须在 Phase B 之后重新验证 final candidate root，且 root 必须同时
  绑定 payload root、QR、最终 Setup/Launcher/manifest、最终场景和验收证据。OIDC
  provenance 只能证明来源和不可替换性，不能将 QR 或 Windows JSON 变成物理行为证明。
- 现有 candidate-root.v1 的 BLOCKED 语义保持不变。未来需要独立的 v2 契约表达最终
  promotion；不得放宽 v1，或让 QH/QR/manifest 自身声称 release_approved=true。

## 实施门禁

1. 先固化机器场景 profile 和 candidate-root Schema/生成器/验证器及负向测试。当前已在 E1
   固化 source profile（23 个唯一 test/profile ID、25 个 requirement/test 对）和 result Schema；
   这不等于 harness 已执行或存在可用结果。
2. 再把受保护 Windows E4 harness 输出接入候选根，保持未执行项为 `BLOCKED`。
3. 在 GitHub 托管 job 中使用完整 commit SHA 锁定 attestation action，签发并立即反向验证
   bundle；发布 job 不接受浮动 action tag。
4. 在任何 signing job 进入执行并在运行时引用 Environment 前，以无 Environment/secrets 的 hosted preflight 取得
   API 身份与 canonical protection hash；signing job 依赖该输出并在导入证书前二次读取、精确
   比对。只有一个 1–6 人的 required-reviewers 规则且禁止 self-review；任何读取/形状/快照
   比对失败均不得触及证书。另须有 GitHub UI 和（Organization 后）audit-log 证据证明
   `can_admins_bypass=false`；API verifier 不能替代该证据。
5. 只有真实 PASS manifest、完整场景结果、可信 attestation 和 P0/P1=0 同时满足时，
   `--require-pass` 才可返回 `release_approved=true`。
6. 在 protected environment、一次性 Windows runner、证书、真实数据库和外部复核均未
   配置前，不触发公开发布，也不上传名为 stable/release 的 EXE。

## 当前实施状态（2026-08-02）

已完成仅限 E1 可审查基础件：

- `windows-e4-scenario-profile.v1.json` 已作为权威 source profile 固定 requirements catalog 中
  全部 `WINDOWS_E4` 条目：23 个唯一 test/profile ID、25 个 requirement/test 对及每 profile 的
  assertion 集。`windows-e4-scenario-result.v1.schema.json` 与 acceptance 语义验证要求未来结果
  全量覆盖 profile，并不可变绑定 profile SHA、candidate、commit、environment、Windows baseline、
  harness、执行时间和 RFC 8785 assertion hash。此项仅防止候选临时缩减或错绑场景；当前没有
  受保护 harness 生成的 result catalog，因而没有 E4 PASS 或 release approval。
- `candidate-root.v1.schema.json` 固定候选身份和十二项必需制品，并要求候选目录中除
  `candidate-root.v1.json` 自身外的全部文件进入安全相对路径、大小、SHA-256 的 canonical
  有序清单；生成器/验证器拒绝重复 JSON key、路径逃逸、大小写冲突、symlink/reparse、
  非普通文件、额外/缺失文件及内容或身份篡改。
- 生成器交叉核对 release context、最终 release manifest 1.2（含精确 `release_candidate`）、Compose、顶层/内嵌 image
  lock 与 Linux build evidence 生成的 image lock（这三者必须逐字节一致）、ACL helper、
  canonical signer SHA-256 allowlist、acceptance/environment/
  requirements catalog、SPDX SBOM index 及 Windows build environment；只允许当前 checkout
  的固定权威 Schema，并在 Schema 外独立硬断言 BLOCKED 语义；acceptance 复用现有权威
  Schema、矩阵、catalog、environment/evidence root 和完整语义 validator，而非字段抽查。
  候选根还要求一个位于 Windows handoff 外的、独立下载 Linux build artifact，并递归比较它和
  候选内 `linux-evidence/` 的全量文件路径、大小及 SHA-256，不能只比较三份 image lock。
  当前 v1 根只允许
  `BLOCKED/release_approved=false`；场景 profile/result、Windows baseline/harness 时间边界
  和 E3/E4 bundle 必须显式 `null` 并记录阻塞原因，不存在“空字段也算完成”的路径。
- 独立 attestation wrapper 使用参数数组调用 `gh attestation verify`，固定 repo、signer
  workflow/digest、source ref/digest、OIDC issuer、SLSA predicate，并要求
  `--deny-self-hosted-runners`。除命令退出码外，它还复核已验证证书中的 hosted runner、精确
  run/attempt URI、workflow/commit、候选根 subject SHA 和 verified timestamp；调用前后均
  重新验证完整 candidate file set。当前代码只能检查调用方给出的 `gh` 是固定绝对路径的
  普通文件，不能证明其版本、摘要或发布者；在托管 attestor workflow 固定该 verifier TCB
  前，即使低层策略匹配也必须非零返回
  `TRUSTED_ATTESTATION_VERIFIER_TCB_NOT_IMPLEMENTED`，不得返回 `ready=true` 或
  attestation-valid。
- Release workflow 已增加 E1 接线候选。`ubuntu-24.04` 托管 job 先独立下载 Linux build artifact
  并验证其 `SHA256SUMS`；Windows self-hosted job 上传的顶层 `SHA256SUMS` 只作为交接清单，
  托管 job 随后完整验证该清单和候选内 Linux evidence 的来源绑定，再删除候选顶层的瞬时清单并
  生成/复核 canonical BLOCKED candidate root，从而避免最终候选同时保留一个
  未覆盖 candidate root 的旧“完整”清单。托管 job 使用固定 commit
  `actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d` 对 candidate root 签发
  provenance；GitHub CLI 固定为 2.97.0，
  release URL、Linux amd64 archive SHA-256 与解包后二进制 SHA-256 均由
  `trusted_gh_cli.py` 硬锁并在调用前复核。低层 provenance 全部匹配后，workflow 仍必须精确
  得到 `TRUSTED_ATTESTATION_VERIFIER_TCB_NOT_IMPLEMENTED`，并只上传名称含 `blocked` 的
  完整候选及证明制品；该接线不会批准发布。
- Windows signing job 现在还固定选择 `datax-release-signing` runner group 与四个精确标签，
  并要求发布环境给出 `CARGO_PATH`、`MAKENSIS_PATH`、`RUSTC_PATH`、`SIGNTOOL_PATH`；它在
  导入 PFX 前检查 checkout 和工具路径，工具执行后重查 tracked source。新增的 hosted
  `signing-environment-preflight` 是 root job，不声明 Environment、不读取 signing secrets，并在
  `custom_branch_policies=true` 时读取、规范化部署 selector；它只输出预先存在的 Environment
  immutable ID 与 canonical protection SHA-256。Linux 镜像构建和 Windows signing job 都被其
  `ready=true` 失败关闭，后者在 PFX 前再读 REST 并精确比对。当前远端没有该 Environment、runner，也因 User-owned repo 没有可配置该
  custom runner group 的 Organization 边界，因此这只是静态 E1 fail-closed 控制和
  `BLOCKED_DECISION/BLOCKED_EXTERNAL` 记录。绝对路径不等于工具身份或不可替换性，仍不是受控
  runner、工具 hash/ACL、TOCTOU 防护、不可导出证书或 Windows E4 证据。

尚未完成：上述 workflow 尚未在受保护 Windows runner、真实签名 secrets 和 GitHub
attestation 服务上运行，因而没有真实 bundle/反向验证证据；虽已有 source profile/result Schema
的 E1 语义契约，但没有受保护 Windows E4 harness、真实 result catalog、把固定 verifier TCB
变成 wrapper 可独立验证的权威 descriptor，以及 attestation 后的完整 acceptance/oracle/E4/P0-P1
聚合门禁。本切片没有放开
`validate_acceptance_manifest.py --require-pass`；正式发布仍稳定返回
`TRUSTED_RELEASE_ATTESTATION_NOT_IMPLEMENTED`。

ADR-0011 在 2026-08-02 已落地 P/QH/PAG/PEA/lifecycle Schema、失败关闭 P/QH parser、私有
payload/runtime/job binding 与 durable nonce/grant/PEA/checkpoint E1 基础件；`20260802_0021/0022` 还以无登录的
ledger owner / issuer / consumer 与最小 `SECURITY DEFINER` issue/revoke/read/PEA-authorize 函数建立了私有
PostgreSQL role/function 边界，0022 的 PEA 对 `grant_id`/`execution_id` 双唯一、仅保存 nonce SHA-256，
普通 Worker 只领取 `STANDARD`，adapter 只接受未来 harness 注入的 Engine。0024 仅以 private issuer 的
受保护事务（先锁 `SystemControl` row，与 draining 串行）创建 Execution→PEA→public `RESERVED`；成功仍
`QUEUED/BLOCKED/PHASE_A_PRIVATE_WORKER_NOT_IMPLEMENTED`，错误完整回滚。创建函数在读 current facts 前先以
`SELECT ... FOR UPDATE` 锁 `public.system_control(singleton_id=1)`，与本地 stop/drain 线性化；行锁所需
`UPDATE(singleton_id)` 只授予无登录 ledger owner。downgrade 在检查前以 `ACCESS EXCLUSIVE` 锁 public
`executions`、`execution_attempts`、`target_copy_locks` 和私有 grant、PEA、checkpoint，protected state 存在即
fail-closed。其 2026-08-02 PostgreSQL E2 已通过；不等于 runner 或可运行 qualification workflow。标准产品没有
issuer login/API 调用；protected disposition、runner、backup/restore 尚未完成。它不代表已有已签发
P/QH、protected harness credential provisioning、私有 Execution rerun、private API/Worker/Compose
override、四检查点、受保护 harness、QR schema/reader、candidate-root.v2 或 Phase A/Phase B workflow；也
不能产生 E3/E4、改变 candidate-root.v1 的 BLOCKED 语义，或代替真实 Windows/签名/OIDC 证据。上述
项目继续为 BLOCKED。
当前没有 protected private disposition workflow；任一 private Execution 阻断标准 backup，私有
backup/restore 继续 `BLOCKED`，不能以 migration rollback 或普通维护冒充处置。

## 后果

- 自造 Windows JSON、替换候选制品或在取证后修改代码不能通过正式发布门禁。
- 发布过程依赖 GitHub Actions artifact attestation 服务，但已安装产品的本机运行不依赖
  该服务。
- 仍需一台可受控还原的 Windows 11 x64 机器、真实 MySQL/PostgreSQL、签名证书和人员
  复核；当前 macOS 开发机不能关闭 E3/E4。
- 若未来迁离 GitHub，必须用新 ADR 选择等价的独立签名/证明根并迁移验证器，不能退回
  manifest 自声明。

## 参考

- [GitHub：使用 artifact attestations 建立构建来源](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
- [GitHub CLI：`gh attestation verify`](https://cli.github.com/manual/gh_attestation_verify)
