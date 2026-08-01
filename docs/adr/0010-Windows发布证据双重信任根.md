# ADR-0010：Windows 发布证据采用双重信任根

- 状态：Accepted（工程实施）；运行器、保护环境和证书启用仍为 Owner/Release 阻塞项
- 日期：2026-08-01
- 决策者：仓库所有者
- 关联：`docs/14_第一性原理问题台账与开发修复计划.md`、
  `docs/contracts/acceptance-manifest.v1.schema.json`、
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
   待验证 manifest 的命令、路径、测试集合或期望结果。
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

### 4. 明确信任声明的上限

GitHub artifact attestation 能证明候选根由指定 workflow/commit 产生且之后未被替换；它
不能自行证明 Windows 机器真的干净、测试脚本没有受运维人员篡改、外部数据库行为真实，
也不能替代代码签名证书和 RFC 3161 时间戳验证。因此 E4 runner 还必须：

- 每次从登记的 golden image 还原，使用一次性 runner 注册和一次性工作目录；
- 记录 Windows edition/build/架构、Secure Boot/virtualization、Docker/WSL 版本、runner
  image ID 和运维审批；
- 在测试后销毁工作目录、runner token 和临时凭据；失败或无法证明基线时不生成 PASS；
- 由与代码作者分离的 Release/QA 责任人复核关键物理场景。

这是受控工程信任链，不宣传成对被攻陷宿主的数学证明。

### 5. 产品运行形态不增加服务器依赖

上述 GitHub/runner 只参与构建、签名和发布。最终 Windows 用户仍通过 `Setup.exe` 安装，
在本机 Docker Desktop + WSL2 中运行固定 Linux 容器，通过
`http://127.0.0.1:17860` 使用产品；不需要自建 Linux 服务器，也不需要把目标 Windows
电脑长期注册为 GitHub runner。

## 实施门禁

1. 先固化机器场景 profile 和 candidate-root Schema/生成器/验证器及负向测试。
2. 再把受保护 Windows E4 harness 输出接入候选根，保持未执行项为 `BLOCKED`。
3. 在 GitHub 托管 job 中使用完整 commit SHA 锁定 attestation action，签发并立即反向验证
   bundle；发布 job 不接受浮动 action tag。
4. 只有真实 PASS manifest、完整场景结果、可信 attestation 和 P0/P1=0 同时满足时，
   `--require-pass` 才可返回 `release_approved=true`。
5. 在 protected environment、一次性 Windows runner、证书、真实数据库和外部复核均未
   配置前，不触发公开发布，也不上传名为 stable/release 的 EXE。

## 当前实施状态（2026-08-01）

已完成仅限 E1 可审查基础件：

- `candidate-root.v1.schema.json` 固定候选身份和十二项必需制品，并要求候选目录中除
  `candidate-root.v1.json` 自身外的全部文件进入安全相对路径、大小、SHA-256 的 canonical
  有序清单；生成器/验证器拒绝重复 JSON key、路径逃逸、大小写冲突、symlink/reparse、
  非普通文件、额外/缺失文件及内容或身份篡改。
- 生成器交叉核对 release context、最终 release manifest 1.1、Compose、顶层/内嵌 image
  lock、ACL helper、canonical signer SHA-256 allowlist、acceptance/environment/
  requirements catalog、SPDX SBOM index 及 Windows build environment；只允许当前 checkout
  的固定权威 Schema，并在 Schema 外独立硬断言 BLOCKED 语义；acceptance 复用现有权威
  Schema、矩阵、catalog、environment/evidence root 和完整语义 validator，而非字段抽查。
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

尚未完成：机器场景 profile/result 契约、受保护 Windows E4 harness、GitHub 托管 attestor
job 对 verifier 路径/版本/摘要的固定、真实 attestation bundle、release workflow 接线，
以及 attestation 后的完整
acceptance/oracle/E4/P0-P1 聚合门禁。本切片没有修改 `.github/workflows/release.yml`，也没有
放开 `validate_acceptance_manifest.py --require-pass`；正式发布仍稳定返回
`TRUSTED_RELEASE_ATTESTATION_NOT_IMPLEMENTED`。

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
