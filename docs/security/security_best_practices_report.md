# 对抗式安全审查报告

| 项 | 值 |
|---|---|
| 审查日期 | 2026-08-02 |
| 审查范围 | Windows Launcher/Setup、Compose/egress-guard、API/Worker 租约客户端、GitHub Windows 签名链，以及其权威契约与验收追踪 |
| 方法 | 从攻击者可控制的环境变量、同 netns 调用、同名容器、安装器参数、Runner 工具路径和工作区污染出发；每项都要求失败关闭或明确外部阻塞 |
| 当前结论 | 源码层已修复 5 项可利用问题并补齐 1 项追踪闭包；Windows 实机、真实签名和发布仍 `BLOCKED` |

## 证据等级

- **E1**：源码、静态检查、单元测试或本机构建。
- **E2**：受控集成环境；不能替代真实 DataX 或 Windows 交付。
- **E3**：固定 Runtime 上的真实 MySQL/PostgreSQL 产品链路。
- **E4**：干净 Windows 11 x64、Docker Desktop/WSL2、签名候选和真实宿主行为。

本报告只记录 E1/E2 结论，除非明确写出 E3/E4 证据；没有把测试、候选文件或浏览器页面当成安装/发布验收。

## 已修复的发现

### ASR-001 — High — 共享 netns 可未授权创建出口租约

攻击路径：API、Worker 与 guard 共享 loopback netns，而旧 `POST /v1/leases` 没有创建者认证。普通同 netns 调用者可申请当前 ACTIVE policy 中的 selected-IP/port，并消耗租约上限。

修复：Launcher 生成 32 个 OS CSPRNG 原始字节编码的 64 字符小写十六进制能力值，Compose 仅挂载给 guard/API/Worker。guard 在读取 body、策略、controller 或 nftables 前要求唯一 header，并使用常量时间比较；缺失、重复、格式错误和错误值统一返回 `401 LEASE_CREATION_AUTH_INVALID`。实现见 `deploy/windows/egress-guard/guard.py:L708-L748`、`L1201-L1288`、`L1401-L1449`；客户端只在 POST 时读取 secret 并禁用代理，见 `backend/src/datax_studio/egress_attestation.py:L176-L217`、`L350-L450`、`L491-L532`。

验证：guard HTTP/loader 回归 21/21 通过；后端 egress/worker/backup 定向测试 66/66 通过；完整后端测试通过。残余风险：DataX 是 Worker 同 UID、同文件系统的子进程；同 UID RCE 仍可读取 Worker 的 Docker secret。这不是 sandbox，也未被本修复消除。

### ASR-002 — High — Docker/Compose 环境注入与失败 helper 残留

攻击路径：用户环境可改变 Docker/Compose 的 transport、platform、proxy、BuildKit 或行为；Docker CLI timeout/解析失败可留下带 bind mount 的 backup/restore helper。

修复：Launcher 显式移除 Docker、Compose、BuildKit 和大小写 proxy 覆盖；备份/恢复 helper 使用由 role 与输入派生的不透明名称和双标签，失败后只按重新核验过标签的 immutable container ID 清理。名称重用、标签不匹配、枚举/inspect/remove 失败均升级为失败，不删除未验证容器或 named volume。实现见 `desktop/windows/src/lib.rs:L54-L112`、`L4260-L4480`、`L6046-L6058`。

验证：Rust 格式检查、58 个 Launcher 库测试和 Clippy `-D warnings` 均通过。残余风险：未在真实 Docker Desktop/Windows 上测 timeout、ACL、重名竞争与容器清理，故仍不是 E4。

### ASR-003 — High — Windows 签名链可受 PATH、Cargo 覆盖与 Runner 污染影响

攻击路径：自托管 Runner 的 PATH shim、Cargo wrapper/flags/target/home 覆盖、工作区污染或工具替换可改变被签名二进制。

修复：签名 job 固定 `datax-release-signing` group 与精确 Windows labels；导入 PFX 前拒绝 dirty/untracked checkout、非固定盘/重解析工具路径和常见 Cargo 编译覆盖；`cargo.exe`、`rustc.exe`、`makensis.exe`、`signtool.exe` 均由显式路径提供，Cargo 强制使用显式 rustc，工具链执行后再次检查 tracked source。实现见 `.github/workflows/release.yml:L226-L236`、`L351-L480`、`L695-L842` 及三个 PowerShell release scripts。

验证：release workflow、Environment verifier 与 Setup 源码的 16 个定向测试通过，release YAML BaseLoader 解析通过。残余风险：绝对路径只消除 PATH 选择，不证明工具字节身份、父目录 ACL、默认 Cargo profile/config、链接器、TOCTOU、私钥不可导出性或 source-to-binary provenance；这些仍要求受控 Runner/HSM/远程签名和 E3/E4 证据。

### ASR-004 — Medium — NSIS 安装/repair/uninstall 路径可偏离固定根

攻击路径：NSIS 默认 `/D` 可覆盖安装路径，`/NCRC` 可绕过 CRC；无效候选可能先停止旧服务；同版本 repair 和临时 self-copy 卸载可能处理错误路径。

修复：固定当前用户安装根，在 `.onInit` 拒绝 `/D`，以 `CRCCheck force` 拒绝 `/NCRC`；先核验临时候选再停止同版本服务；repair 禁止 skip 并显式解除受控资源只读属性；卸载从 HKCU 安装记录重新绑定固定根。实现见 `installer/windows/DataXEnterpriseStudio.nsi:L41-L95`、`L155-L206`、`L248-L326`。

验证：安装器源码负向测试 3/3 通过。CRC 仅检测损坏，不是 Authenticode 信任证明；本机没有 NSIS、PowerShell 或 Windows 11 x64 环境，因此尚未编译/运行已签名 Setup。

### ASR-005 — Medium — 安全控制与验收追踪出现闭包缺口

发现：新 secret 已加入运行面，但既有 Worker secret-closure 测试和两个 Worker settings fixture 最初没有同步。完整后端回归立即暴露该漂移。

修复：将能力 secret 纳入 exact Compose closure、Worker settings fixture、备份固定 secret 集合、威胁模型、部署/架构契约和机器验收 catalog；新增 `SEC-EGRESS-LEASE-001`，catalog 现在是 81 个需求、91 个 requirement/test 对。

验证：完整后端测试、48 个 acceptance 回归和 requirements catalog canonical check 通过，catalog SHA-256 为 `5c5e50bc98fb02a4cda9a7d066c7bb36e8150975db05d589d88ba90a8d072350`。

### ASR-006 — High — Environment 保护检查发生在 signing job 已引用名称之后

攻击路径：GitHub 会在 workflow job 首次引用不存在的 `environment` 名称时隐式创建无保护
Environment。旧流程虽在导入 PFX 前 GET 并检查 reviewer，但同一个 signing job 已先声明
`environment: windows-candidate-signing`，所以它不能证明此 Environment 在引用前已经存在；删除/重建
或审批策略在检查后变化也没有身份绑定。

修复：新增 GitHub-hosted `signing-environment-preflight`，它没有 job-level `environment`、不读取
signing secrets/发布 variables，只 GET 并严格验证既有 Environment。它只将 immutable Environment ID
与 canonical protection SHA-256 传给 downstream，不输出 reviewer login/name/numeric ID/token。signing
job 必须 `needs` 该成功快照，仍声明固定 Environment，但在导入 PFX 前二次 GET 并要求 ID/hash 精确
相同；缺失、隐式创建、删除/重建、未知/畸形策略、自审、API 错误或变更均失败关闭。两次响应都不
输出到日志，Windows job 的完整 REST response 在成功或失败后清理。

兼容性修复：GitHub REST 的正常分支/标签限制会同时给出 `type=branch_policy` 与非空
`deployment_branch_policy`。verifier 现只接受一个 `branch_policy`，并要求
`protected_branches`/`custom_branch_policies` 恰有一个为 `true`；规则与 selector 均进入
canonical hash。重复、缺配对、双真/双假、畸形或其他未知 rule 仍失败关闭，避免把真实受限
Environment 错误拒绝或静默放宽。

验证：Environment verifier 的快照/身份/策略变更负向测试与 release workflow 静态拓扑测试通过（16
个定向测试）；仅为 E1。残余风险：远端当前仍为 0 个 Environment、没有在线 workflow/审批记录，且
`datax-release-signing` custom runner group 在当前 User-owned public repo 上需要所有权/ADR 决策；因此
本修复不能声明真实签名或 E4。补充对抗发现：GitHub 默认允许管理员 bypass protection rules；官方
REST Get Environment schema 和当前 GraphQL `Environment` 类型不公开 `can_admins_bypass`，所以
verifier/ID-hash 快照不能证明它已禁用。Release Owner 必须保存 Settings UI 中关闭该开关的记录；
迁入 Organization 后，还须保存 `environment.update_protection_rule` audit event 的
`can_admins_bypass=false` 与签名窗口无反向修改查询。没有这组外部证据，reviewer gate 不可视为独立。

## 未关闭的发布阻塞

1. GitHub 当前 `environments` 数为 **0**，尚不存在受保护的 `windows-candidate-signing` Environment；源码的双阶段 ID/hash 流程只证明 E1 失败关闭，尚无在线运行或审批记录。即使未来 reviewer 规则可见，管理员 bypass 默认允许，且 REST/GraphQL verifier 无法读取 `can_admins_bypass`；UI/audit-log 禁用证据仍是独立阻塞项。
2. 当前 public repo owner type 为 **User**；GitHub custom runner group 是 Organization/Enterprise 管理边界，强制的 `datax-release-signing` group 因此是 `BLOCKED_DECISION`。首选迁入/转让到 Organization；否则必须先接受新的 ADR，不能删除 group 回退到任意 runner。
3. GitHub 当前 repository self-hosted runner 数为 **0**，不存在可承载 `datax-release-signing` group/labels 的 Windows 11 x64 Runner。
4. 本机没有 `pwsh`、NSIS 或 Windows 11 x64 + Docker Desktop/WSL2，无法执行 PowerShell runtime、真实 PFX 签名、Setup 安装/卸载、宿主端口或 Docker helper 清理验收。
5. 真实 MySQL 8/PostgreSQL 15 四方向 DataX、独立 oracle、恢复、睡眠/重启和 LAN 负例仍未达到 E3/E4。

因此不得发布 `Setup.exe`、不得声称“Windows 已稳定运行”或“企业级已完成”。下一次外部验收必须先由仓库所有者作出 Organization 迁移或新 ADR 的签名信任决策，再配置受保护 Environment、独立 reviewer、受控干净 Windows Runner、工具 hash/ACL 取证与不可导出签名能力，并运行同一精确候选的 E3/E4。

## 本轮已执行的检查

| 检查 | 结果 | 证据等级 |
|---|---|---|
| `git diff --check` | 通过 | E1 |
| guard 单元/HTTP 合约 | 21/21 通过 | E1 |
| 后端完整测试 | 通过（含预期 skip） | E1/E2 |
| acceptance 测试 | 64/64 通过（含 hosted Windows 预检和本地 E4 前置观察器负向边界） | E1 |
| GitHub-hosted Windows 预检 `30724285608` | Windows Server 上的 Launcher 测试/release 构建、固定 NSIS hash、临时 installer 编译与删除均通过；无签名、上传或安装 | E1 |
| release/Environment/Setup 定向测试 | 20/20 通过 | E1 |
| Launcher Rust 库测试 | 58/58 通过 | E1 |
| Rust format + Clippy | 通过 | E1 |
| Ruff | 通过 | E1 |
| requirements catalog + release YAML parse | 通过 | E1 |

这些检查是可复现的源码证据，不是 Windows E4、真实签名或外部数据库 E3 证据。
