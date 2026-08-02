# DataX Enterprise Studio V1.2 威胁模型

> 状态：V1 发布门禁输入
>
> 更新日期：2026-08-02
> 适用范围：Windows 11 x64 本地工作站、单组织、多项目、单节点、安全的一次性离线全量复制

> 实现口径：表中的“V1 强制控制”是发布前必须满足的控制集合，不等于当前全部已实现。
> 当前已有 DATA/SECRETS 分离加密导出、双包认证 journal 与全新空 staging，恢复只达到
> E1；旧式完整对象集合的 `LEGACY` 指针原子登记与 Compose 整组消费已有候选实现，但新空
> PostgreSQL volume、真实 `pg_restore`、证据重算、`RESTORE` 卷/secret 原子提交和覆盖
> 升级保持关闭。数据库外审计 checkpoint/WORM、公钥 keyring、真实默认拒绝 egress 的
> Windows Docker Desktop/WSL2 实测闭环、真实 Windows 签名制品及 E4 验收仍缺失。
> egress-guard、journal/staging、安全工作流或本地单元/镜像扫描不能替代真实内核、完整
> 恢复或 Windows 证据。当前 Mac 只用于开发验证，最终证据必须来自另一台 Windows 11
> x64 目标机；未闭合门禁保持 `BLOCKED_NOT_IMPLEMENTED`、
> `BLOCKED_NOT_VERIFIED` 或 `NOT_RUN`。
> 已新增的 Windows E4 scenario profile/result Schema 只是在 source 层精确规定 23 个
> test/profile ID、25 个 requirement/test 对和 candidate/commit/environment/harness/assertion-hash
> 绑定；没有受保护 harness 产生的 result catalog，故它是 E1 反伪造语义控制，不是 E4 证据。
> 同轮新增的 P/QH parser、私有 payload/runtime/job binding 与 PostgreSQL Phase-A nonce/grant/PEA
> 账本属于 E1 基础件：`20260802_0021` 已有无登录 ledger owner / issuer / consumer、最小
> `SECURITY DEFINER` issue/revoke/read 函数与未接入标准路径的 private adapter；`20260802_0022`
> 已有 private PEA table、issuer authorize/consumer read 及普通 API/Worker/recovery 仅处理 `STANDARD` 的边界。
> `20260802_0023` 仅为未来私有 runner 增加复用全局 `TargetCopyLock` 与 `Execution` fence 的数据库原语，属于
> PostgreSQL E2 前置；它没有 runner 凭据或 API/Worker/Compose/Launcher 接线。
> 仍没有 protected harness credential provisioning、私有 Execution 创建/rerun、private API/Worker/Compose
> override、四检查点、受保护 harness、QR reader 或真实 E3/E4；普通产品路径继续 deny-all。

## 1. 安全目标与非目标

安全目标：

1. 只有被授权的人能把被授权的源表复制到被授权的空目标表。
2. 任何一次复制都能追溯到不可变任务、端点策略/连接修订、物理表身份、精确表列授权、
   凭据/Envelope、实际 IP/egress、运行时、进程和核验证据。
3. 平台控制面、日志、审计和临时文件不泄露明文凭据。
4. 失租、崩溃、取消和超时不能静默产生第二个写入者，也不能伪装为成功。
5. 发布目标要求：数据库管理员离线改写同一 PostgreSQL 后，审计篡改可由精确定义的
   checkpoint 前像、独立公钥 keyring 和外部锚点发现；当前只实现同库追加哈希链，
   尚不具备这一抗数据库管理员能力。

V1 不承诺抵抗已完全控制宿主机内核和独立密钥保管系统的攻击者，也不提供多节点 HA。
这不降低最小权限、备份隔离和恢复演练要求。

## 2. 资产与数据分级

| 资产 | 分级 | 主要保护 |
|---|---|---|
| 数据源密码、DEK/KEK、JWT/审计签名私钥、refresh/idempotency HMAC keys、egress lease bearer token、lease 创建能力 | Secret | 不回显、独立生成、信封加密或受限 Secret 文件、lease token 只返回一次并仅存内存摘要；创建能力只以 Docker secret 挂载给 guard/API/Worker，分离备份、最小读权限 |
| 源/目标策略/连接修订、物理身份、表列 scope、日志 | Confidential | 项目授权、脱敏、保留限制、下载审计 |
| JobVersion、Execution、核验证据 | Integrity critical | 不可变版本、哈希、围栏、追加事件 |
| 审计事件；未来公钥 keyring 与外部锚点 | Integrity critical | 当前为精确事件前像/同库哈希链；双签轮换、外部锚定和双人恢复仍是发布门禁 |
| Runtime、插件与镜像 | Supply-chain critical | digest/SHA-256、SBOM、签名/来源验证 |
| P binding/PAG/PEA 私有 qualification 元数据；原始 QH 与 nonce | Integrity critical；原始 QH/nonce 为 Secret | 原始 QH/nonce 不进入普通产品、公开制品、日志或数据库；当前 ledger 只保存 nonce SHA-256、不可变 grant binding 和 PEA 的 nonce SHA-256/nonsecret cross-check facts，均位于 closed-default `des_phase_a_qualification` schema。标准 API/Worker/egress 无直接权限；无登录 issuer/consumer 只可执行各自的 `SECURITY DEFINER` entrypoint，0023 的无登录 runner 也只能执行其 lock/fence entrypoint；它没有产品运行凭据或 API/Worker/Compose/Launcher 接线。标准 backup/diagnostics/restore 不得携带该 schema 或其 authority |
| `Setup.exe`、`launcher.exe`、升级清单 | Supply-chain critical | Authenticode 信任链、固定发布证书 DER SHA-256、离线 SHA-256、版本/降级策略、发布 SBOM |
| Windows 配置/导出备份与 `des-postgres-data`/`des-log-data`/`des-workspace-data` | Confidential / Integrity critical | 用户 ACL、named volume 隔离、卸载默认保留、备份加密、异机恢复演练 |

表名、列名、元数据值、错误消息和 DataX 输出均是不可信输入；不得当作路径、HTML、SQL、
命令、日志格式串或提示词直接解释。

## 3. 参与者与信任边界

- Admin：管理端点策略、数据源、授权、传输策略、用户和恢复；仍不是数据库 Secret
  明文读取者。
- Developer：只能使用 Admin 显式授权方向的数据源设计和发布任务，不能创建任意端点。
- Operator：只能执行/取消已发布任务和完成获授权的恢复流程，不能改变传输目的地。
- Viewer：只读获授权项目；日志下载仍受数据分级和审计约束。
- API：控制面，不启动 DataX，不直接推进运行态。
- egress-guard：唯一持有 `NET_ADMIN` 的共享 netns 守卫；只读当前 ACTIVE policy view，
  独立审批 selected-IP 租约并原子维护 nftables，不读取数据源凭据或承载业务状态。
- Worker/reconciler：唯一执行/RecoveryProbe 与运行状态写入者；reconciler 独立收敛
  未领取取消，Execution/Probe 使用不同 fence。迁移 0013 已把 owner、API、Worker
  登录/密码分离并禁止运行角色 DDL/TEMP，但 API/Worker 当前仍有相同的全表 DML；
  细粒度状态权限主要由应用层执行，不能声称数据库已强制职责隔离。Worker 只拥有一个
  pool=4/无 overflow/5 秒超时的 Engine；角色 cap=12 和 30 秒空闲/15 秒空闲事务超时是
  对异常重启残留的服务器端有界回收，不是高可用或无限重试保证。
- Phase-A qualification ledger（E1 基础件；0023 仅为受限 PostgreSQL E2 前置）：`20260802_0020` 的 closed-default
  `des_phase_a_qualification` schema 中 nonce/grant 记录 QH nonce SHA-256 和精确
  P/harness/Reader-Writer binding；`20260802_0021` 将 ownership 移给无登录 ledger owner，创建
  无登录 issuer/consumer 及最小 `SECURITY DEFINER` issue/revoke/read entrypoints。`20260802_0022`
  增加第三张 append-only PEA 表：`grant_id`/`execution_id` 各自唯一，保存**仅 nonce SHA-256**和
  existing PAG/Execution/JobVersion/revision/policy/namespace/P/runtime/harness/QH nonsecret facts；
  issuer authorize 在锁定的 pending `PHASE_A_HARNESS` Execution 上原子写入，consumer read 只在
  PAG `ACTIVE`、QH 时间窗及所有 current facts 一致时返回。它撤销 `PUBLIC`、标准运行角色和
  issuer/consumer 对 schema/table/sequence 的直接权限；entrypoint 固定 `search_path=pg_catalog,pg_temp`
  并以 `session_user` 复核 caller。普通 API、Worker 与 recovery/reconciler 只处理 `STANDARD`，
  因此不能读取、修改、领取或推进 PEA。`20260802_0023` 另创建无登录 private runner role，并通过仅限
  reserve/claim/heartbeat/recovery/release/read 的 `SECURITY DEFINER` 函数复用全局 `TargetCopyLock` 与
  `Execution` fence；它不 provision runner，也没有 API/Worker/Compose/Launcher 接线。它仍没有
  标准 API/Worker/Compose 路径、角色凭据、私有创建/rerun 或 DataX start 能力，也不影响普通执行
  deny-all。migration owner/数据库管理员、一个将来可登录的 issuer 帐户、private adapter 或 PEA JSON
  都不是 HQA/RQA 的替代信任根。
  0021 对预存私有角色名或成员关系失败关闭，不尝试就地规范化，并撤销 ledger owner 后续新建函数的
  全局 `PUBLIC EXECUTE` 默认权。
- 外部 MySQL/PostgreSQL、DNS、镜像仓库和备份系统均跨越信任边界。
- Windows 11 宿主、当前登录用户、浏览器、`launcher.exe`、Docker Desktop/WSL2 与
  Linux 容器之间均是独立信任边界。Docker Desktop 管理权限等价于本机高权限，不授予
  Web/API/Worker 容器访问 Docker Socket、Windows 命名管道或宿主敏感目录。
- ADR-0011 的 HQA、RQA、受保护 Windows qualification harness、Authenticode 签名服务与
  hosted candidate-root attestor 是彼此分离的发布 TCB。当前 P/QH parser、私有
  payload/runtime/job binding、nonce/grant/PEA 账本及其 0021/0022 role/function/adapter 与 0023 lock/fence
  数据库原语已是 E1 基础件加受限 PostgreSQL E2 前置；HQA/RQA、protected harness credential provisioning、私有 Execution 创建/rerun、
  private override、四检查点、harness、QR reader 与真实外部证据均未实现。QH 未来只能跨越至受保护 harness；QR 未来只能作为被安装包
  哈希约束的只读资源进入私有最终候选；GitHub OIDC provenance 只跨越候选根来源边界，不能
  替代 Windows/数据库行为边界。不得由普通用户设置或产品运行时网络调用替代。

## 4. 主要威胁与控制

| ID | 威胁 | 攻击路径/失败方式 | V1 强制控制 | 验证证据 |
|---|---|---|---|---|
| TM-01 | 数据外传 / confused deputy | 组合 Developer、Operator 角色，把未批准表/列复制到攻击者数据库 | Admin-owned 不可变 EndpointPolicyRevision、UsageGrant、精确 catalog/schema/table/allowed_columns 的 TransferPolicy scope；发布/运行双检；共享 netns 默认拒绝，外部 allow 只来自守卫独立复核的 exact-IP 短租约 | 越权/越列 API 测试、scope hash 变更、网络层拒绝、审计 |
| TM-02 | SSRF / DNS rebinding | 恶意 hostname 先解析到允许地址后切换到内网/元数据地址，或 JDBC 在同一允许 CIDR 内二次解析到另一地址 | 各连接阶段固定 policy revision；校验全部 A/AAAA/CNAME；守卫重新读取 ACTIVE view，CIDR 只作准入，nft 只放 selected IP `/32|/128` + port；运行时 `control` 子网地址一律不发租约；5 秒续租/15 秒内核失效；验证 peer IP/TLS hostname 并保存证据 | DNS 变更、混合地址、IPv6、TTL、同 CIDR 不同 IP、control 子网、peer 偏移、私网/metadata、租约过期用例 |
| TM-03 | 任意代码或 SQL | 元数据/JobSpec 注入路径、SQL、JAR 或 shell 参数 | additionalProperties=false、结构化 JDBC 模板、固定插件、参数数组、只读 runtime、禁用自由 SQL/插件上传 | Schema 负例、命令参数测试、镜像文件校验 |
| TM-04 | 凭据泄露/轮换破坏 | 响应、日志、持久工作卷或异常终止后的临时文件泄露；把 KEK version 放进数据 AAD 导致重包裹后不可解密 | 稳定 CredentialSecret ciphertext/AAD（不含 KEK）；独立 Envelope 重包裹；领取事务先固定 ACTIVE secret/envelope；明文 Job/未脱敏 Runtime 日志只进 256 MiB 私有 tmpfs，目录 0700、文件 0600 且原子防跟随创建；启动/领取前验证产品标记并清残留，失败阻断；Worker 限 2 GiB/2 CPU/256 PID/nofile 4096/8192；先脱敏、分离备份 | SIGKILL/容器重启后的 tmpfs 与持久卷 Secret 扫描、未知/伪造目录拒绝领取、资源耗尽、ciphertext/AAD 不变证明、新旧 Envelope/旧备份恢复 |
| TM-05 | 重复或孤儿写入 | 两个同目标请求先后排队；lease 丢失、PID 重用、Worker 重启后旧 JVM 继续写；恢复探针复用错误 fence | API 原子创建 `QUEUED+RESERVED`，部分唯一索引覆盖 `RESERVED/ACTIVE/RECOVERY_REQUIRED`；Execution 与 RecoveryProbe 各自 Attempt/fence、条件写、boot/PID start/cgroup identity、失租终止 | 不同幂等键并发、两类失租/重启/PID 重用、ExecutionAttempt 关闭 gate 拒绝 |
| TM-06 | 部分写入后错误再次执行 | insert-only 失败、取消、超时、preflight 失败或 LOST 后全量追加 | 领取后除唯一成功组合外统一 `RECOVERY_REQUIRED`；提交处置确认；独立 RecoveryProbe `SUCCEEDED+EMPTY` 才关门禁 | 启动前失败/部分提交/取消/LOST、probe 非空/失租、再次执行拒绝 |
| TM-07 | 源数据运行中变化 | 全量扫描没有一致性快照，结果为混合时点；未报告或瞬时后回滚的写入可能逃过前后指纹 | 源所有者提交 `confirmed=true/confirmed_at` 的持续静默承诺；preflight/verification 保存前后指纹，不一致即 fail closed；UI 明示人工承诺和指纹都不是数据库快照或“窗口内绝无写入”的技术证明 | 缺失确认、并发写入、前后指纹不一致；记录瞬时/回滚写入的剩余风险，不虚构过期/撤回用例 |
| TM-08 | 伪成功 | DataX exit 0、存在脏记录，或目标行数与摘要跨快照读取，却被标为正确 | 固定 `dirty_data_limit=0/0`；exit 0 进入 VERIFYING；独立 oracle 在目标端同一一致性读事务计算行数和多重集摘要；PASSED 才 SUCCEEDED；三组状态分别保存 | 脏记录、跨快照竞态、oracle 故障注入与差异证据 |
| TM-09 | 日志投毒/泄露/截断隐瞒 | ANSI/控制字符、超大日志、脱敏/存储故障被当作完整 | 先脱敏；raw/redacted/stored/dropped 四计数；所有缺口追加 LogGap；转义展示；Gap 后持续标不完整 | 控制字符、Secret、超长行/总量、读取/脱敏/存储故障 |
| TM-10 | 审计篡改/换钥断链 | DB 管理员重写事件/锚点，或替换公钥后伪造 checkpoint；或应用旁路写入/尾部漂移后健康检查继续报告正常 | 当前：同库 `DXAUDITv1` 追加哈希链加 `audit_chain_watermarks`。所有 writer 同事务锁组织、核对实际 tail 并推进 head；ready 正常路径只比 watermark/tail，完整重放最多每 60 秒、最多 30 秒，缺 state、漂移、过期、超时或 CAS 竞争均 DOWN，FAILED sticky。发布缺口仍是 `DXAUDITCHECKPOINTv1`、独立只读公钥 keyring、双签轮换、外部 WORM；同库水位线不能抵抗能同时改写事件和 watermark 的 DB 管理员 | 当前：migration、尾部漂移/历史篡改、CAS/timeout/并发与不读 event_json 的回归；发布前补逐字节签名、轮换/妥协、外部重放和真实 PostgreSQL/Windows 证据 |
| TM-11 | 密钥丢失、错误轮换或紧急撤销不生效 | 只保留最新 KEK；已泄露 secret 仍被新连接使用、撤销提交后终态覆盖终止事实，或 RecoveryProbe 在撤销后发布 EMPTY | 版本化 KEK/Envelope、公钥/指纹；旧 key 保留到备份窗口；只有已切换 current 的历史 secret 可 ACTIVE→RETIRED，直接退役 current secret 必须拒绝，RETIRED 仅可升级到 REVOKED/COMPROMISED；Worker 每端解密以新短事务的强制刷新 `FOR UPDATE` Secret 状态锁决定，锁不跨越外部 I/O；紧急状态与每个已绑定非终态 Execution/Probe 的持久终止事实同事务；若紧急 secret 仍是 current，还覆盖无 secret 绑定但不可变引用该 DatasourceRevision 的排队 Execution/Probe，并按 work row 与终态写序列化。Execution 的端间解密、预检每个有界 DNS/JDBC/schema/fingerprint/count I/O（含 connector probe 的查询间隙）、Popen 紧前/tick/oracle/heartbeat 与 Probe 的 heartbeat/DNS/连接/schema/count 边界消费；late EMPTY 必须失败关闭，Probe lease-LOST 重开 Gate=REJECTED。检查只阻止已观察到的终止；数据库提交与实际连接/Popen 之间没有同一原子提交，发布仍须 E3 测量并给出可接受的启动/egress 收敛边界。阻塞 JDBC 只可由超时/lease-LOST 收敛 | 新旧 Envelope、旧备份、撤销前/后/运行中/核验中 terminal-ordering、current secret 退役拒绝与无绑定队列、RETIRED 升级、双 secret、短事务解密顺序、probe 查询间隙/预检/Popen 终止边界、Probe late-EMPTY/lease-LOST、PostgreSQL 并发与真实数据库终止边界 |
| TM-12 | 资源耗尽/队列饥饿 | 日志保留组合超 200 GiB；长任务、单项目或取消请求被唯一 Worker 饿死；控制、凭据和心跳各自创建默认 pool，或异常重启残留会话耗尽数据库角色预算；失控本机进程以未知邮箱反复触发 DB/Argon2/失败审计，或以 health poll 诱导整条审计链重放 | 分档组合公式、60 GiB 日志预算、绿黄红 admission、持久项目 service cursor、reconciler 独立取消、队列 SLO；Worker 单共享 pool=4/无 overflow/5 秒超时、角色 cap=12、30 秒空闲/15 秒空闲事务 server-side 回收。登录在单 API 进程中于 router/DB/Argon2/audit 前执行账号无关 token-bucket + 非阻塞并发准入，统一 429/60 秒且不留主体数据；ready 用 1 秒缓存和 nonblocking singleflight，不能配置 Uvicorn workers/API scale/旁路入口 | 存储计算/水位故障、重启 cursor、取消 SLO、跨项目压测、真实 PostgreSQL 正常/异常 Worker 重启、连接预算耗尽和回收恢复；429 无 DB/Argon2/audit、非法 Host 不耗额度、singleflight/尾检查/超时及未来 Windows 本机压力证据 |
| TM-13 | 供应链漂移 | 镜像、JDK、DataX 或插件被替换；或 Linux build evidence 产生后 Windows handoff 替换其副本；或缺失 GitHub Environment 被隐式创建而没有独立签名审批 | 固定 digest/SHA-256、来源清单、只读挂载；PostgreSQL/egress-guard 固定 `15.18-alpine3.24`，API/Worker 最终层固定 Python 3.12.13 `slim-trixie`（Debian 13）。Windows handoff 验证器要求 Linux build evidence、顶层和内嵌三份 `images.release.env` 逐字节一致；GitHub-hosted attestor 另行下载 Linux build artifact、验证其 `SHA256SUMS`，并要求 candidate root/attestation 递归比对候选 `linux-evidence/` 和该独立来源的全量文件清单。签名 job 在导入证书前读取 `windows-candidate-signing` Environment，要求恰好一个非空 required-reviewers 规则和 `prevent_self_review=true`；API 读取失败也关闭。PR 配置 Gitleaks、hash-lock pip-audit、pnpm、Cargo OSV、四语言 CodeQL，以及真实 patched Worker 镜像 Syft+OSV 应用门禁；本地为 0 未处理项、6 个逐项 Logback 1.2.13 短期例外（到期 `2026-09-30`）。candidate release 从精确 commit archive 生成源码 SBOM，并为五镜像生成 SBOM/OSV/Grype 证据；Grype candidate 对可修复 High/Critical 阻断，无修复项进入 `review_required` 且候选仍 `BLOCKED`，promotion 默认阻断或仅接受逐项不超过 90 天例外。非发布的 hosted Windows 预检只下载固定 SHA-256 的 NSIS 3.11 压缩包，在无 Environment/secrets/OIDC/签名/发布/制品上传的 Windows Server job 中进行临时编译后删除；下载哈希或路径异常均失败，不允许 PATH/Chocolatey fallback。它最多提供 E1 原生构建证据，不能成为候选、签名或 Windows E4 工具链。2026-08-02 线上快照：最新 PR 的 CI/安全/CodeQL 门禁通过，开放 CodeQL 告警为 0；`main` 经典分支保护严格要求 12 个检查、PR、分支最新、线性历史和会话解决，禁止强推/删除且管理员不可绕过；漏洞告警可用，但 `Dependabot security updates=disabled`；Actions policy 为 `allowed_actions=all`、`sha_pinning_required=false`，required approving review count 为 0、未要求 CODEOWNERS review，hosted Windows E1 也不是 required check。GitHub Environment 列表为空，因此审批 gate 未取证；这些远端治理缺口与真实 release/OS/Windows 扫描均保持 `BLOCKED_EXTERNAL` | 工作流与本地 Worker policy 证据；源码 commit/SBOM 绑定；独立 Linux artifact 与候选 evidence 的全量比较、三份 lock、候选与 promotion 策略负例；固定 NSIS URL/SHA-256、无权限/无上传的 hosted 预检负例；线上 Environment/审批/分支或 tag 规则、Actions/SHA/独立 review policy、必需检查、Grype DB/报告、Windows release 状态；启动自检、制品替换负例 |
| TM-25 | 伪造插件认证或证据降级 | 将 Runtime 心跳、测试注入、过期 E4、其他 candidate/commit/image 或未审查依赖冒充为普通用户可执行 | 公开 `plugin-manifest.v2` 不包含测试证据类型；生产证据源默认 deny-all；只有受信发布证明绑定当前 candidate/commit/Worker image/Runtime/插件哈希、E3/E4 引用、有效期、完整依赖和已记录再分发许可时才进入 E4；普通创建、恢复 rerun、Worker 领取和启动四个检查点复检；UI 只消费目录并显示阻断原因 | v2 Schema 真实响应校验；测试证据不公开、降级、伪造、哈希/候选/镜像错配、过期、依赖路径穿越和许可未记录负例 |
| TM-14 | 备份越权 | DB 备份与 KEK 同处、DATA/SECRETS/key 未分离，或恢复环境暴露 Secret | 当前导出强制 `.dxdata/.dxkeys` 分包、不同恢复秘密、allowlist/秘密扫描和用户选择的分离路径；Launcher 先证明无旧身份/代际/运行 secret/产品容器/产品卷，再用固定 `network=none` helper 从双行标准输入认证双包、写双秘密认证 journal 与 ACL staging，达到 E1。ADR-0008 以单一运行代际指针共同选择 installation-id、独立 secret 目录和三个随机卷；Schema、严格 Rust 校验、FRESH 内部 journal 的随机对象/无覆盖 pointer 提交、旧式完整集合的 `LEGACY` 不覆盖原子登记与 Compose 单指针消费已有源码/E1 候选。FRESH journal 不是公开恢复格式，且 RESTORE 新空 PostgreSQL volume、真实 `pg_restore`、证据重算、`RESTORE` 代际提交、最小恢复人员、隔离环境、双人审批与恢复后销毁仍是发布缺口 | 导出 ACL/分包与 journal 篡改/错包/staging/代际指针负例；发布前完成真实 Windows 导出、卷提交和异机恢复演练 |
| TM-15 | 别名绕过自复制/目标锁 | 同一数据库用新 Datasource、revision、hostname/IP 别名并发写同一表 | 不可变 PhysicalEndpointIdentity + 引擎真实标识符规范化 TargetNamespace；自复制与唯一锁只用物理表 hash/namespace | MySQL server_uuid、PostgreSQL system_identifier、别名/revision 并发负例 |
| TM-16 | 策略漂移 | 编辑 EndpointPolicy 同一 ID 后，历史 JobVersion 静默获得新 CIDR/egress 权限 | 不可变 EndpointPolicyRevision；Datasource/JobVersion 固定版本；守卫只读 current ACTIVE view 并校验 revision/hash，撤策/hash 变化立即清全部租约并切 base-deny；每阶段证据包含实际 policy/resolver/egress 版本 | 规则修改、current pointer 漂移、撤策、旧版本运行拒绝 |
| TM-17 | 平台外目标写入竞态 | 第三方客户端、触发器或 DBA 在 Worker 空表检查后、oracle 读完前执行 DML/DDL；平台锁无法阻止，瞬时后回滚或未报告写入也可能不可观测 | Operator/DBA 提交 `statement_version='1.0'`、有限 `valid_until` 的 `target_exclusivity_confirmation`；Execution 持久化 `ACTIVE/REVOKED/EXPIRED`；获知破坏时经专用接口报告/撤回并写 `TARGET_EXCLUSIVITY_REVOKED`；Worker/oracle 要求 ACTIVE、未撤回未过期且 snapshot finish≤valid_until；平台锁明确不冒充外部锁或完整侦测 | 声明版本/过期/撤回/时间窗不足、Operator/DBA 报告已知 DML/DDL/冻结破坏、未领取/已领取/VERIFYING 收敛与审计负例；明确不声称发现任意未报告写入 |
| TM-18 | MySQL TLS 身份校验降级 | 旧 Connector/J 把 `VERIFY_CA` 与 `VERIFY_FULL` 都渲染成 `verifyServerCertificate=true`，攻击者用受信 CA 签发但主机名不匹配的证书冒充目标 | 固定 Connector/J `9.7.0`/新驱动类；`VERIFY_CA→sslMode=VERIFY_CA`、`VERIFY_FULL→sslMode=VERIFY_IDENTITY`；禁用旧 TLS 参数；驱动 JAR/许可进入 Runtime manifest；证书链或 hostname 不匹配 fail closed | URL 契约负例、旧/重复驱动制品替换负例、真实 MySQL 正确/错误 CA 与正确/错误 FQDN 握手 |
| TM-19 | Windows 安装/升级制品被替换 | 下载镜像、`Setup.exe` 或 `launcher.exe` 被篡改；攻击者改用任意受信代码签名证书重签；签名失效；被降级到已知漏洞版本，或利用安装器默认 `/D`/`/NCRC`/`/S`、repair/临时卸载路径或 reparse point 绕过预期边界 | 执行 Setup 前从外部核对固定发布证书 DER SHA-256 与发布页文件 SHA-256；正式制品内部同时验证 Authenticode 信任链与唯一主签名证书 DER SHA-256；1–8 项严格排序轮换允许集写入清单 1.1，清单精确哈希绑定到已签名 Launcher，运行时无环境变量覆盖；Setup 安装前要求自身与 Launcher 实际签名者完全相同；时间戳、版本单调检查、固定镜像 digest、SBOM；固定每用户根并在 `.onInit` 拒绝 `/D`，`CRCCheck force` 拒绝 `/NCRC`，install/uninstall 静默状态以非零退出拒绝，候选核验与稳定 reparse 检查均在停止同版本前。repair 不允许 skip 且先解除受控只读属性；同版本 repair 的 stop 只启动已在临时目录完成签名/资源核验的候选 Launcher，绝不执行旧安装目录的 Launcher；卸载从注册表重新绑定固定根。稳定 reparse 防护只能降低 junction/symlink 攻击；hardlink 与同用户路径检查—使用 TOCTOU 仍未关闭，不能把 NSIS 属性检查表述为强路径完整性。CRC 只检测损坏，不能替代 Authenticode；内部自校验不声称能认证已执行且主动删除检查的恶意重打包 Setup；当前用户/管理员完全控制宿主仍是非目标 | 干净 Win11 VM 的正确签名；首次执行前外部验证；任意其他受信签名者、Setup/Launcher 不同签名者、空/缺失/重复/乱序/非法允许集、资源替换、过期/撤销签名和降级负例；`/D`、`/NCRC`、`/S`、稳定 root/resources/leaf reparse、无效候选同版本 repair、已验证候选 Launcher stop、只读资源写失败和临时 self-copy 卸载根负例；hardlink/TOCTOU 剩余风险或 future native helper/handle-relative 实施的真实 E4。当前仅 NSIS 源码 E1，非 Windows 安装验收 |
| TM-20 | 宿主端口意外暴露 | Compose 使用 `0.0.0.0`、API/DB/守卫端口映射、IPv6 或防火墙规则使 LAN 可达 | 只允许 Web `127.0.0.1:17860`；禁止 API/Worker/egress-guard/PostgreSQL 宿主映射；attestation/lease 只绑定共享 netns loopback；Launcher 启动后枚举实际监听和 Compose 映射，异常即停止 | `Get-NetTCPConnection`、局域网第二主机拒绝、IPv4/IPv6 监听证据 |
| TM-21 | Launcher/路径/DLL 劫持 | 当前目录 DLL、可写安装目录、PowerShell 拼接，或用户 Docker context/default-platform/proxy/registry auth/credential helper/Compose 覆盖让子进程偏离固定本机运行面；同 project label 的外来容器使 lifecycle/cleanup 触碰非产品对象；Docker CLI timeout 后遗留含 bind mount 的 helper | 签名 launcher、绝对规范路径、受限 ACL、无 `shell=True`/拼接、固定 Compose/镜像清单、不搜索当前目录；Launcher 发现 ambient `DOCKER_HOST`/`DOCKER_CONTEXT` 即拒绝，缺失时创建且每次回读 ACL 受限、字节精确 `{"auths":{}}` 的 Launcher-owned config，既有篡改/额外状态失败关闭；每个受控 Docker/Compose 子进程显式剥离 transport/TLS/认证/credential-helper/default-platform/custom-header/BuildKit、上/小写 proxy 与 Compose env-file/project/profile/行为/输出覆盖，只接收 Launcher 派生值、该 config 与已验证固定 local pipe。对任何既有 project 的 lifecycle、`up`、`down` 或 cleanup，逐一认证 immutable container ID、唯一预期 service、精确锁定 image、project/service label 与有状态卷 installation identity；未知、重复、镜像/挂载不符时失败关闭且不触碰容器，禁止 `--remove-orphans`。`up` 后安全检查失败只可对已认证完整产品栈不删卷地 `down`，清理失败保留双错误码；备份/恢复 helper timeout 或错误后只以已核验的 immutable container ID 和 role/opaque-ID 标签 `rm --force`，名称重用或标签/枚举/清理异常均失败关闭，不删未验证容器或 named volume | 标准用户 ACL、空格/Unicode/长路径、恶意 DLL/环境变量、ambient host/context/default-platform/proxy/BuildKit、config/credential helper/Compose 覆盖/pipe 篡改、启动后端口/netns/live/secret/lifecycle/ready 失败和 cleanup failure 的 Windows E4 负例；Docker CLI timeout/被终止、helper 非零/解析失败、同 project label 外来容器、伪造/重复 service、image/卷身份错配、部分产品栈与 named volume 保留实测 |
| TM-22 | 睡眠/重启后旧事实继续写 | Windows 睡眠、WSL VM 暂停、Docker 重启造成 lease 时钟跳跃、孤儿容器或旧 fence 写入 | 恢复先标记未就绪并对账 boot/container identity、lease 与 fence；旧工作停止后才开放新执行；单节点中断明确可见 | 睡眠/恢复、Docker stop/start、WSL shutdown、Windows reboot 故障注入 |
| TM-23 | 卸载、Docker 重置、首次初始化中断或磁盘故障导致数据丢失 | 卸载误删 named volumes/密钥/备份；先建卷后生成密钥时崩溃导致不可恢复；Docker 重置后静默创建空卷；卷部分丢失；磁盘不足时迁移或日志写入半完成；活动 pointer 旁边的无卷 LEGACY/root 或未知 generation/secret 残留被错误忽略 | 当前：程序/三卷分离；ACL 受控 FRESH journal 先固定随机 generation、installation identity、generation secret 目录和三卷名，完整 secret 后才创建同代际卷，最后以不可覆盖的单一 pointer 整组绑定 identity/secret/卷并清除 journal；进入 FRESH 后不使用 root legacy identity/secret/固定卷作为第二当前来源。FRESH/LEGACY 判别和每次 journal/pointer 恢复前后同时枚举全部 volume 名及产品角色标签：仅空集、完整 LEGACY 三固定卷或当前 generation 精确三卷可继续，额外随机/固定/带标签未绑定卷均在写入前失败关闭。journal、活动 pointer、pending pointer 仅以 `symlink_metadata=NotFound` 视为缺失；目录、链接/reparse point、悬空链接和元数据错误均在 ACL/`create_new` 前阻断。活动 pointer 还先以无副作用、no-reparse exact-set 判定 root/generation：FRESH/RESTORE 必须没有 root LEGACY marker/root `secrets/`，只能有自身 generation、`secrets/` 和十个已知 secret；未知 sibling、文件类型替换、链接/reparse 或枚举错误均停止。FRESH 写齐十项 secret 后、创建任一卷前再次验证该 exact set。LEGACY 不允许 generation 对象，且 `ensure_runtime_secrets` 必须先认证 root marker、十个 root secret 与三条固定卷，之后才可变更 runtime app-root/root `secrets/` ACL，并在 root DACL 后重验；缺少对象绝不生成替代值。Docker CLI/restore 是独立 app-root 门禁，不能误判为 generation 冲突，也不能把它可能更早的受控配置准备包装成“LEGACY 前没有任何 Launcher 文件副作用”。DATA/SECRETS 导出、双包认证 journal 与空 staging 已达到 E1；Unix 单元只证明源码失败关闭，不证明 Windows reparse/ACL/TOCTOU。FRESH 真实 Windows 验证、异机恢复、新空卷 `pg_restore`、证据重算、`RESTORE` 代际提交与覆盖升级仍是发布缺口 | 初始化各提交点断电/进程终止、容器存在、缺 secret、部分卷、错标签、Docker reset、随机/标签残留卷、root LEGACY/root secret/unknown generation/unknown secret sibling、journal/pointer/pending reparse/元数据 I/O 与 LEGACY preflight 无写入负例；发布前补安装→数据→卸载→重装、磁盘不足、真实 Windows 导出和异机恢复证据 |
| TM-24 | 出口租约伪造、未授权创建、重放或守卫死亡后残留 | 客户端自报 lease ID、token 被记录/重放；普通调用者复用 API/Worker 共享 netns 对 `POST /v1/leases` 申请 ACTIVE 策略内任意 IP+port；API/Worker 不在守卫 netns；守卫死亡后旧 allow 无限存活，或 nft 原子替换的无语义 runtime metadata 触发错误漂移 | lease ID 与 32-byte bearer 均由守卫生成；`POST /v1/leases` 必须恰好携带 Launcher 由 32 个 OS CSPRNG 原始字节生成的 64 字符小写十六进制 Docker-secret 能力，guard 在 body/策略/controller/nftables 前用常量时间比较；能力只挂载给 guard/API/Worker，缺失/重复/错误统一 `401 LEASE_CREATION_AUTH_INVALID` 且不得记录/回显/传给 Job 或 DataX 环境。它阻断不能读 secret 的普通同 netns 调用者，不是同 UID Worker/DataX RCE sandbox。token 仅首次响应且内存只存域分离摘要；create/renew 重读 ACTIVE view；逻辑 30 秒、5 秒续租、nft 元素最多 15 秒；ruleset hash 只排除内核重新分配的 `handle` 与 `expires` 倒计时，仍绑定 timeout、地址、端口、表达式、hook 和 policy；真实规则漂移锁存 base-deny；Launcher 实测三容器 netns 相等 | 缺失/错误/重复能力头在 body/策略读取前统一 401；secret mount target、响应/日志/Job/DataX 环境泄漏负例；普通 netns 调用者不得创建租约；有效 API/Worker 正例；错误 token、token 日志扫描、netns 不等、guard kill 15 秒、DB 失败、nft `handle`/expires 变化不误降级、timeout/规则变化和撤策故障注入；同 UID RCE 只记录为残余风险，不能宣称被此控制消除 |

| TM-26 | 资格自举、签名替代、ledger 越权或发布哈希循环 | 将测试注入/环境变量/自申报 JSON 作为生产资格；重放 QH nonce、篡改/删除 PAG，重用 PEA `grant_id`/`execution_id`、把 PEA 复制到不同 Execution、以 snapshot 错配绕过四检查点，或让 QH 进入普通包；让 QR 回写 Worker 镜像，或让 QR 与 Setup/manifest 互相绑定后仍宣称同一候选 | ADR-0011 固定 `P → QH → PAG → QR → F → PR` 的单向链；PEA 只是 PAG→一条私有 Execution 的内部边。0020/0021 拒绝 nonce 重放、grant 修改/删除/截断及非单调 grant lifecycle；0021 用无登录 owner/issuer/consumer 和最小 `SECURITY DEFINER` issue/revoke/read 函数禁止标准运行角色、issuer/consumer 直接 DML。0022 新增 append-only PEA，`grant_id`/`execution_id` 各自唯一，只保存 nonce SHA-256；issuer authorize 只对锁定的 pending `PHASE_A_HARNESS` Execution 和有效 PAG 原子写入，consumer read 只在 PAG `ACTIVE`、QH 时间窗和 Execution/JobVersion/revision/policy/namespace/P/runtime/harness/QH 全量 current-fact 相等时返回。普通 Worker 只领取 `STANDARD`。0023 新增无登录 private runner，且仅能调用复用全局 `TargetCopyLock` 与 `Execution` fence 的 reserve/claim/heartbeat/recovery/release/read `SECURITY DEFINER` 原语；它不 provision runner，也不接入 API/Worker/Compose/Launcher。**当前仍只是数据库基础约束**：标准 Settings/Compose/Launcher/API/Worker 没有 runner 角色凭据、QH/PAG/PEA override 或 adapter 接线，也没有私有创建/rerun、四检查点、harness 或 QR reader；普通路径继续 deny-all。future HQA 只能签短期 QH，RQA 才能签 QR；标准 Compose 必须拒绝 QH/PAG/PEA 资源，QR 必须是 detached 资源且不绑定包含自身的 F；受信 reader 对签名、purpose、有效期和 P/commit/image/runtime/JAR/依赖/许可证逐项失败关闭；公开发布还须 ADR-0010 provenance。标准 backup/diagnostics/restore 必须排除 ledger，恢复后的 protected issuer/consumer 还须以非恢复的 post-restore issuance epoch 拒绝旧 grant/PEA；保护 public `executions` trigger 的 mode guard 必须留在标准 dump，仍由无登录 ledger owner 持有并撤销普通调用者执行权 | 当前：parser/binding，及本轮 disposable real PostgreSQL 15 `scripts/test-postgres-e2.sh` 退出 `0`、PostgreSQL pytest `30 passed`：0021 upgrade/downgrade/re-upgrade、actual issuer/consumer function boundary、Python issuer → consumer preflight → revoke、预存角色失败关闭和 future-function `PUBLIC EXECUTE` 默认权负例，以及 0022 PEA authorization、普通路径拒绝、API/Worker runtime-role RLS、0023 无登录 private runner、全局 `TargetCopyLock` 互斥与 `Execution` fence 函数、schema exclusion/TOC/空库 `pg_restore` probe。它仅为数据库 E2，不是完整 restore/E3/E4。关闭前：QH/PEA/QR 篡改、未知 key/purpose、过期、raw nonce 持久化或读取、nonce/grant/PEA grant_id/execution_id/rerun 重放、append-only/lifecycle/派生有效性旁路、所有 payload/Execution/JobVersion/revision/policy/namespace 错配、标准 Compose 注入、资源替换、自引用、同版本不同候选、私有 role/function/issuer/runner 旁路、backup/diagnostic 泄露或 restore authority revival、self-hosted provenance 混淆和真实 Phase A/B 证据；当前 E3/E4/发布全部 BLOCKED |
| TM-27 | 数据源外部操作持锁造成控制面 DoS 与陈旧结果 | 获授权用户让允许端点缓慢响应，或高并发执行 datasource create/update probe、test、metadata、job validation；外部 DNS/JDBC/schema I/O 若持有 Organization/Project/Datasource/Job 锁，会阻塞取消、凭据 revoke、目标独占撤回；I/O 后变更 revision/secret/grant/policy 时旧结果又可能覆盖/泄露 | **候选源码/E1 与局部 PostgreSQL E2 已实施，未关闭：** ADR-0014 五入口 A/B/C。A 只短事务授权并绑定 immutable datasource/policy/secret/envelope/grant/job/transfer/namespace/runtime/AuthSession snapshot；已有凭据的 B 先以极短 barrier 锁定、复制、提交，随后无产品 DB 锁做 resolve/egress/解密/connector（创建使用候选请求凭据），受总 deadline；C 重新授权并比较全部 security binding，漂移统一 409 stale、无旧 metadata/evidence/audit/last-test 副作用。PUBLISHED/ARCHIVED Job 在外部 I/O 前拒绝。已有 datasource/job 仅在 A 验证后才进入单 API 进程非阻塞 admission（global=4、organization/datasource=1、TEST 60 秒），未知 UUID 不得污染 retained state；429 在外部 I/O/audit 前返回，deadline 503 不持久化 B 结果。隔离 PostgreSQL E2 已证明阻塞 B probe 不持有同一 Organization 行锁；完整并发矩阵与真实 E3 未验证，`ASR-013=IN_PROGRESS`，不得声称连接测试限速已关闭 | 关闭前：五入口 source/contract 回归；AuthSession/revision/secret/envelope/grant/policy/job/project/scope/namespace/runtime 漂移负例；429 无 connector/DNS/decrypt/audit；真实 PostgreSQL `pg_locks`/时间界限证明阻塞 connector 不持有 Organization lock，并发 cancel/revoke/update 成功；真实 MySQL/PostgreSQL E3 deadline、DNS/egress、分页和恢复 |

**TM-26 的 0022/0023 动态 read 与 lock/fence 边界。** PEA consumer 不得仅相信 append-only row：它必须重验
Project `ACTIVE`、Job `PUBLISHED`、source/target Datasource 与 EndpointPolicy 的 current/`ACTIVE` parent、
Organization/Project/physical identity/TargetNamespace 的 scope+engine、active TransferPolicy 的 revision/
physical scope/hash/row version、未撤回的目标独占及 engine→Reader/Writer 配对。普通 API、Worker、
Recovery/reconciler 和日志路径只处理 `STANDARD`，不能把 `PHASE_A_HARNESS` 作为可读、可写、可领取、
可对账或可展示对象。本轮真实 PostgreSQL E2 已验证该源代码/迁移控制；它不形成 private harness、E3 或 E4。
0022 还将这一边界延伸至 `datax_api/datax_worker/datax_egress_guard` 的直接 DB 连接：`executions` 和任何
execution/probe-linked attempt、lock、event、cancel、log、recovery、evidence、work-termination row 使用
parent-linked RLS，标准角色不能藉由子表发现或写入 private execution。issuer authorize 只将该 row 置为
`BLOCKED/PHASE_A_PRIVATE_WORKER_NOT_IMPLEMENTED`，不会授予 runnable 状态。RLS 已在本切片真实
PostgreSQL E2 中验证；它仍是 E1 控制，不能替代 private harness、E3 或 E4。0023 的无登录 private runner
仅可调用复用全局 `TargetCopyLock` 与 `Execution` fence 的 reserve/claim/heartbeat/recovery/release/read 数据库原语；
该原语是 E2 前置，不是 provisioned runner，也不接入 API/Worker/Compose/Launcher。
当前没有可运行的私有 Phase-A Worker/runner，任何试图经普通 Settings/Compose/API/maintenance 启动它的路径都是越权。
未来 runner 启用还必须完成并验证完整私有 lock/fence 生命周期、源静默/目标独占 confirmation、execution/fence 关联的
受保护 audit checkpoint、专用 credential/log/maintenance 边界、独立 protected backup/restore 设计和全部运行接线；否则保持硬禁用。

**TM-26 J0c-1 私有文件输入边界（E1，不是 trust completion）。** 当前
`datax_studio.qualification.private_harness_loader` 不接受 Settings、环境变量、HTTP 请求、普通
Compose 或 Launcher 作为 trust source；未来受保护基础设施必须显式传入 private filesystem root、
hash-pinned P/QH 相对文件、独立 P root 和预期 harness identity。读取对 root/descendant 同时做
`lstat`、路径 containment 与 descriptor-relative `O_NOFOLLOW`，拒绝符号链接、路径逃逸、目录/其他
非普通文件、超限文件和 hash/P/QH-binding/signature/time drift。输出仅有验证后的非秘密事实和文档
hash，不保存或序列化 raw QH/raw nonce；它不消费 nonce、不写 PAG/PEA、不创建/领取 Execution、
不 `Popen` 或启动 DataX；宿主缺少安全 descriptor-open primitive 时固定失败关闭。这个代码边界不能证明
该 root 的 OS ACL、账户、介质或 harness 可信，不能
代替 private source/override，也不改变普通 production deny-all；`test_private_harness_loader.py` 和
普通 no-E4 拒绝回归仅为 E1 负向证据，E3/E4/QR/发布仍 `BLOCKED`。

**TM-14/TM-26 Phase-A backup 与恢复边界。** 标准系统 backup、诊断包和 restore 输入必须
固定排除完整 `des_phase_a_qualification` schema；不得只依赖“包已加密”或“普通 API/Worker 无表权限”
来保留或转移 qualification authority。0022/0023 还使 private execution 的 metadata/target-lock/log 路径位于 public
`executions`/target-lock/log volume，因此当前 Launcher 在 `pg_dump` 前后（PostgreSQL 停止前）固定重验无
`PHASE_A_HARNESS` 行；存在或非 `t` 输出返回 `BACKUP_PHASE_A_PRIVATE_EXECUTION_PRESENT`，psql 完成但非零返回
`BACKUP_PHASE_A_PRIVATE_EXECUTION_CHECK_FAILED`，底层命令错误同样失败关闭。不得靠 schema/table/log 过滤继续生成普通包。受保护 Phase-A backup/restore 未实现。当前 dump 会恢复 `alembic_version=20260802_0023` 却排除该 schema，
所以真实 restore/bootstrap/start 必须失败关闭。恢复目标必须从无 Phase-A authority 的状态开始，未来
protected issuer/consumer 要生成并强制检查一个不随备份恢复的 issuance epoch，旧 QH/PAG/grant/PEA 一律
不能复活。候选 schema exclusion、TOC 与临时库 probe 最多是 E2；没有完整 `pg_restore`、bootstrap/
原子提交、实际 issuer/consumer 和干净 Windows 证据时，这一边界仍为 `BLOCKED`。

**Windows E4 证据语义（TM-13/TM-19/TM-25）。** 权威 profile 防止发布候选删减、替换或把一个
Windows 测试的断言借给另一个：它精确枚举 23 个 test/profile ID、25 个 requirement/test 对。未来
result catalog 必须与 profile SHA、精确 candidate/commit、environment manifest、Windows baseline、
harness version、执行时间及 RFC 8785 assertion hash 共同不可变绑定，并全量覆盖 profile；任何
`NOT_RUN`、缺失、额外或错绑结果都必须失败关闭。该 source/validator 控制只能检测 JSON 语义
伪造，不能认证运行它的机器、签名、Docker Desktop/WSL2、DataX 或安装行为；直到受保护 Windows
harness 产出真实结果并由 ADR-0010 的独立 attestor 聚合前，发布仍为 `BLOCKED`。

**TM-27 范围与审查补充。** 表中“五个入口”只指 Credential Service 的五个直接外部操作；
`POST /projects/{project_id}/transfer-policies` 与会重算范围的
`PATCH /transfer-policies/{transfer_policy_id}` 是同一 metadata lane 的双数据源复合调用。它们在
A 阶段释放产品数据库 Session 后，必须原子取得 source/target 两个 permit；两个嵌套
`list_columns` 复用同一 live lease 和同一 `OperationDeadline`。因此外层 `429` 发生在任一
DNS、connector、解密、metadata evidence 或 audit 之前，不能先完成源端 probe 再因目标端限流。

`0019` 已让 `DatasourceUsageGrant` 在 revoke/regrant 时递增代际；A/C 还检查 Organization、调用者
User 与 Project 的状态/row version。已完成的模板化路由幂等 replay 同时核验 durable resource 与
保存 response，跨 Project/Job/Execution 的同 key 重放必须 409。所有 egress attestation 错误保留
503 平台 code，deadline 优先于晚到错误。C 阶段会在关键数据库步骤前按剩余预算刷新 PostgreSQL
transaction-local `lock_timeout`/`statement_timeout`，并在提交前执行 `configure → flush → check`，使
已到期的 validation/evidence/audit 写入回滚。MySQL TCP 后握手、每条 catalog SQL 和 cleanup 也会按
剩余预算重新夹紧；但 PostgreSQL 的设置仍按单条语句计时，终端检查到 COMMIT 存在极小窗口，且同步
psycopg 网络黑洞的 read/fetch/rollback/close 没有已验证的强制中断。因此 30 秒配置不是端到端硬返回
保证，`ASR-013` 仍为发布阻塞。

**TM-12/TM-23 Windows 容量补充控制。** `%LOCALAPPDATA%` 的 40 GiB 水位只保护
Launcher 自身文件，不能证明 Docker Desktop VHD 或 named volume 余量。当前 `start` 与
`backup` 先确认五个 release-locked Linux/amd64 镜像已缓存；只有缺失时才由空的
Launcher-owned Docker config 按 immutable digest 拉取。预取后所有产品 `docker run` helper 和
`compose up` 都显式 `--pull=never`；缓存若被并发 Docker 操作删除，必须失败而不能在 admission
后重新下载。随后它们分别在 Compose `up` 和 backup staging 前，对已认证活动
`RuntimeGeneration` 的三个 `local`/无 options 卷运行带
opaque name/双标签的 Worker `statvfs` probe：固定只读 `/probe/*`、`network=none`、无 secret、
只读根、`0:0`、`cap_drop=ALL` 后仅加 `DAC_READ_SEARCH` 以进入 PostgreSQL `0700` 卷根、
资源上限与 `--pull=never`。错误、超时或输出无效时只能按重新认证 immutable ID 清理同名
probe 容器；任何 Docker/协议异常或任一卷少于 200 GiB 均失败关闭。该 capability 不提供写入、
网络或 secret，却可绕过普通文件读取及目录搜索权限；因此不能把它说成“仅 metadata”，也不是
卷内容保密隔离。固定 `-c` 脚本与锁定 Worker digest 是必要信任前提，受损的 probe image 仍可能
读取并经 stdout 尝试外带内容（严格协议会拒绝结果但不能把内核权限收回）。容量拒绝前受控初始化
或镜像缓存可能已存在，不能表述为“没有任何副作用”；Compose/业务数据库不会启动。它不证明运行中
增长、不同 VHD/临界容量或 Docker API cleanup TOCTOU 的真实行为；目前仅 E1，必须由签名 Windows
E4 的对应负例闭合。

## 5. 一次复制的强制安全序列

1. Admin 已批准不可变 EndpointPolicyRevision、两个 DatasourceRevision/
   PhysicalEndpointIdentity、用途授权，以及精确源/目标表列 `scope_hash` 的 TransferPolicy。
2. 源所有者对指定表和时间窗作出可审计的静默确认；Operator/DBA 提交
   `statement_version='1.0'`、有限 `valid_until` 的目标外部独占声明，承诺覆盖 Worker
   最后空表观察至 oracle 目标一致性读事务完成。两者都是外部运行前提，不是平台生成的
   数据库锁或快照；获知目标窗口破坏时必须调用撤回/报告接口。
3. API 在同一事务创建 `Execution(QUEUED)`、幂等事实与
   `TargetCopyLock=RESERVED`；已有同 TargetNamespace 未释放锁时拒绝第二个排队意图。
4. Worker 在同一领取事务取得 Execution fence，把 TargetNamespace 预留转为活动锁，并在任何连接前
   固定两端 policy revision、ACTIVE CredentialSecret/Envelope。
5. 提交后 Worker 解析两端并为每个 selected IP 向同 netns 守卫申请租约；守卫重读
   ACTIVE revision/hash 并只放 exact IP+port。Worker 保存解析、selected/peer IP、TTL、
   lease/ruleset/resolver/egress 证据，校验物理源/目标不同、Schema、scope、目标约束和
   `COUNT(*) = 0`。
6. Worker 先验证并清理私有 tmpfs 中可证明属于产品的过期敏感目录，失败时不领取；随后
   创建最小权限持久工作区和私有 tmpfs Attempt，把含密 Job 与未脱敏 Runtime 日志限定在
   tmpfs，保持 5 秒租约续租后启动 DataX。任一租约丢失或脏记录都使执行不能成为业务
   成功，退出时立即释放租约并清理敏感 Attempt。
7. DataX exit 0 后进入 `VERIFYING`；独立 oracle 比较源和目标规范化结果，并在目标端
   同一一致性读事务内计算行数和多重集摘要，保存快照标识与起止时间。
8. 只有 oracle `PASSED`、目标声明仍为 `ACTIVE`、未撤回未过期、
   `target_result.snapshot_finished_at <= valid_until` 且两类确认覆盖实际时间窗，才进入
   `SUCCEEDED`；领取后任何其他结果均保存 `data_effect` 并统一把目标锁转
   `RECOVERY_REQUIRED`，不以“未启动/可能没写”跳过。
9. 提交必要外部处置确认后创建独立 RecoveryProbe；无需清理时如实记录理由。只有其 ProbeAttempt/fence 产生
   `SUCCEEDED+EMPTY` 才关闭门禁。成功复制的非空 TargetNamespace 不允许再次追加。

## 6. 审计与密钥信任根

审计 `event_hash` 的 preimage 固定为：

```text
event_for_hash = deep_copy(event_json)
delete event_for_hash.integrity.event_hash
preimage =
  UTF8(
    "DXAUDITv1\n" ||
    organization_id_lowercase_uuid || "\n" ||
    sequence_base10_without_leading_zero || "\n" ||
    lowercase_previous_hash_or_64_zeroes || "\n"
  ) ||
  RFC8785(event_for_hash)
event_hash = SHA-256(preimage)
```

`event_for_hash.integrity.previous_hash` 必须与前像一致，末尾不追加 LF；包含
`integrity.event_hash` 的完整对象不能作为自己的哈希输入。

当前实现止于数据库内 `DXAUDITv1` 事件哈希链及连续性验证；它不能抵抗能够同时改写
事件和链头的数据库管理员。以下 checkpoint/keyring/WORM 设计是发布前必须实现并获得
真实证据的门禁，当前不得配置为“已启用”或用于解除 readiness/发布阻断。

目标锚定任务至少每日以及每 10,000 个事件（先到者）生成链头 checkpoint，由独立
Ed25519 审计锚定密钥签名，并写入数据库之外、审计账号不可改写的 WORM/对象保留存储。
锚点不可用时审计写入可继续最多 24 小时，但 readiness 标记 degraded；超过 24 小时
停止高风险管理和新执行。验证必须从最近可信锚点向前重放。

checkpoint 签名前像必须逐字节按以下公式生成，UUID/哈希为小写 ASCII，sequence 为无
前导零十进制，时间固定六位微秒 UTC；末字段后不追加 LF：

```text
preimage = UTF8(
  "DXAUDITCHECKPOINTv1\n" ||
  organization_id || "\n" ||
  through_sequence || "\n" ||
  chain_head_hash || "\n" ||
  previous_checkpoint_hash_or_64_zeroes || "\n" ||
  "SHA-256\n" ||
  "RFC8785-v1\n" ||
  checkpoint_created_at_as_YYYY-MM-DDTHH:MM:SS.ffffffZ || "\n" ||
  anchor_key_version
)
signature = Ed25519.Sign(private_key, preimage)
checkpoint_hash = SHA-256(
  UTF8("DXAUDITCHECKPOINTRECORDv1\n") || preimage || signature_64_raw_bytes
)
```

数据库只保存版本化 Ed25519 公钥 keyring 与指纹，签名私钥独立保管。常规轮换必须先把
旧/新 key 双签的 `DXAUDITKEYROTATIONv1` 声明写入 WORM，再切换
`ACTIVE/VERIFY_ONLY`；旧公钥保留到所有关联 checkpoint/保全到期。`COMPROMISED` key
立即停止高风险操作，并由离线信任根和双人流程恢复。首个公钥指纹固定在数据库外只读
genesis 声明；否则 DB 管理员可同时替换 checkpoint 与数据库内 keyring。

凭据使用每条 CredentialSecret 独立 DEK 的 AES-256-GCM 加密；数据 AAD 精确绑定
organization/project/datasource/secret ID/secret version/AAD schema/data algorithm，
明确不包含 KEK/Envelope 版本。KEK 包裹算法固定为 AES-256-KWP（RFC 5649），包裹结果
单独保存为版本化 CredentialSecretEnvelope。重包裹只新增 Envelope、切换
ACTIVE/SUPERSEDED，业务 ciphertext/nonce/AAD 不变。部署注入只读版本化 KEK keyring；
轮换、回滚、退役和销毁都双人审批，旧 KEK 只有在活动引用结束、全部备份过保留期且
恢复演练通过后才能销毁。Secret 的 `REVOKED/COMPROMISED` 紧急状态优先于既有租约并
触发引用工作的终止。

## 7. 发布门禁与剩余风险

以下任一项没有真实证据时，状态为 `BLOCKED`：

- `E2E-WIN-001`（`PRD-FR-WS-001`）与 `E2E-WIN-002`（`ACC-PRD-014`）在本次发布
  制品创建的干净 Windows 11 x64 VM 中均为 PASS；
- 干净 Windows 11 x64 VM 上已签名 Setup/Launcher 的信任链、同一固定证书 DER
  SHA-256、允许集正负例、安装、哈希、SBOM、升级/回滚与
  默认保留三个 `des-*` named volumes、配置和导出备份的卸载/重装；
- Docker Desktop 未安装/未启动、WSL2/虚拟化缺失、端口冲突、磁盘不足的明确阻断，
  且安装器没有静默安装 Docker 或代替用户接受许可；
- 仅 Web 绑定 `127.0.0.1:17860`，API/Worker/egress-guard/PostgreSQL 无宿主映射，
  LAN/IPv6 不可达；
- Windows 重启、睡眠/恢复、Docker Desktop 重启和 `wsl --shutdown` 后先对账再服务；
- 不可变 EndpointPolicyRevision、DNS rebinding-safe 解析、selected/peer IP 证据；
  exact-IP 租约创建（含唯一创建能力头的缺失/错误/重复负例）/续租/释放、同 CIDR 地址偏移拒绝、守卫/DB/规则失败最多 15 秒失效，
  以及默认拒绝 egress enforcement；
- PhysicalEndpointIdentity/TargetNamespace 别名与跨 revision 自复制/目标锁负例；
- API 原子 `QUEUED+RESERVED`、同目标不同幂等键并发与未领取取消释放预留负例；
- TransferPolicy 精确表列 scope 的越权/漂移负例；
- 真实 MySQL/PostgreSQL 的目标空表、外部独占声明版本/有限有效期/
  `ACTIVE|REVOKED|EXPIRED`、已知破坏的 Operator/DBA 撤回/报告与审计、目标端单一一致性
  快照及其结束时间不晚于 `valid_until`、任一脏记录、部分写入、领取后统一门禁、取消、
  LOST、独立 RecoveryProbe/fence 和 oracle E2E；
- Execution/Probe fence/lease 丢失、未领取取消和进程身份故障注入；
- 明文凭据全路径扫描、稳定 AEAD AAD、KEK/Envelope 轮换、secret 紧急撤销/旧备份恢复；
- LogGap 与 raw/redacted/stored/dropped 计数故障注入；
- `DXAUDITCHECKPOINTv1` 前像、公钥 keyring/双签轮换、外部锚点和篡改恢复；
- 200 GiB 组合容量公式、绿黄红 admission、队列 SLO及重启后跨项目公平性。

- ADR-0011 的 `P/QH/PAG/PEA/QR/F/PR` 绑定真实可验证：当前 parser、binding 与 nonce/grant/PEA
  ledger 只构成 E1，0023 的全局 lock/fence 数据库原语只构成受限 PostgreSQL E2 前置；0022 的 PEA
  issuer-authorize/consumer-read 与 0023 runner entrypoint 都不能替代 protected issuer/consumer/runner 调用链；
  QH/PAG/PEA 必须未泄露至普通路径且已清理，QR 必须由独立 RQA 为精确 P 签发，无 QH/PAG/PEA 的精确 F 必须完成 Phase B，最终候选根必须
  来自 hosted attestor；任何缺少 Windows/数据库/签名/OIDC 外部 TCB 的状态均为 BLOCKED。

保留风险：源静默与目标外部独占都依赖系统所有者的外部变更冻结流程。平台无法仅靠 JDBC
证明源扫描期间绝无写入，也无法靠 TargetCopyLock 阻止或完整发现第三方对目标执行的
DML/DDL。目标声明的版本、截止时间、状态、撤回报告和最终数据 oracle 只能形成
fail-closed 的责任与结果证据，不能证明任意瞬时、未报告或已回滚的外部写从未发生。
未获得任一确认、目标声明非 `ACTIVE`、目标快照完成晚于 `valid_until`，或需要在线
一致性快照/数据库强制外部排他的场景不属于 V1，必须拒绝执行。
