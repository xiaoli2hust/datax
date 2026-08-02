# 对抗式安全审查报告

| 项 | 值 |
|---|---|
| 审查日期 | 2026-08-02 |
| 审查范围 | Windows Launcher/Setup、Compose/egress-guard、API 登录准入与审计 readiness、数据源外部操作、Worker 租约客户端、GitHub Windows 签名链、Phase-A 私有 Execution 生命周期，以及其权威契约与验收追踪 |
| 方法 | 从攻击者可控制的环境变量、同 netns 调用、同名容器、安装器参数、Runner 工具路径和工作区污染出发；每项都要求失败关闭或明确外部阻塞 |
| 当前结论 | 已有源码修复仍只到 E1/E2；本轮补齐 0024 private create→PEA→global lock 的原子数据库边界、drain 串行化、失败关闭 downgrade、闭合 receipt 契约和跨语言 schema-head 同步。真实 DataX E3、Windows 实机、真实签名和发布仍 `BLOCKED` |

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

验证：Rust 格式检查、70 个 Launcher 库测试和 Clippy `-D warnings` 均通过。残余风险：未在真实 Docker Desktop/Windows 上测 timeout、ACL、重名竞争与容器清理，故仍不是 E4。

### ASR-003 — High — Windows 签名链可受 PATH、Cargo 覆盖与 Runner 污染影响

攻击路径：自托管 Runner 的 PATH shim、Cargo wrapper/flags/target/home 覆盖、工作区污染或工具替换可改变被签名二进制。

修复：签名 job 固定 `datax-release-signing` group 与精确 Windows labels；导入 PFX 前拒绝 dirty/untracked checkout、非固定盘/重解析工具路径和常见 Cargo 编译覆盖；`cargo.exe`、`rustc.exe`、`makensis.exe`、`signtool.exe` 均由显式路径提供，Cargo 强制使用显式 rustc，工具链执行后再次检查 tracked source。实现见 `.github/workflows/release.yml:L226-L236`、`L351-L480`、`L695-L842` 及三个 PowerShell release scripts。

验证：release workflow、Environment verifier 与 Setup 源码的 16 个定向测试通过，release YAML BaseLoader 解析通过。残余风险：绝对路径只消除 PATH 选择，不证明工具字节身份、父目录 ACL、默认 Cargo profile/config、链接器、TOCTOU、私钥不可导出性或 source-to-binary provenance；这些仍要求受控 Runner/HSM/远程签名和 E3/E4 证据。

### ASR-004 — Medium — NSIS 安装/repair/uninstall 固定根与交互边界

攻击路径：NSIS 默认 `/D` 可覆盖安装路径，`/NCRC` 可绕过 CRC，`/S` 可绕过交互确认；无效候选可能先停止旧服务；同版本 repair、临时 self-copy 卸载或重解析路径可能处理错误对象。

修复：固定当前用户安装根，在 `.onInit` 拒绝 `/D`，以 `CRCCheck force` 拒绝 `/NCRC`，以 NSIS `IfSilent` 让 install/uninstall 静默状态非零退出；先核验临时候选和稳定 reparse point 再停止同版本服务；repair 禁止 skip 并显式解除受控资源只读属性；卸载从 HKCU 安装记录重新绑定固定根。稳定 reparse 检查只降低 junction/symlink 风险，hardlink 与同用户 TOCTOU 仍见 ASR-008。

验证：安装器源码负向测试 5/5 通过。旧版源码曾由 hosted Windows E1 编译，但本轮 guards 尚未在 Windows 上重新编译或以签名 Setup 运行；CRC 仅检测损坏，不是 Authenticode 信任证明。

### ASR-005 — Medium — 安全控制与验收追踪出现闭包缺口

发现：新 secret 已加入运行面，但既有 Worker secret-closure 测试和两个 Worker settings fixture 最初没有同步。完整后端回归立即暴露该漂移。

修复：将能力 secret 纳入 exact Compose closure、Worker settings fixture、备份固定 secret 集合、威胁模型、部署/架构契约和机器验收 catalog；新增 `SEC-EGRESS-LEASE-001`，后续对抗式审查又把安装器、Compose、WSL、磁盘、本机登录准入、审计 readiness 和数据源外部操作边界测试纳入 catalog，当前为 81 个需求、107 个 requirement/test 对。

验证：本轮 68 个 acceptance 回归已通过；requirements catalog canonical check 已重算，catalog SHA-256 为 `e797409612c4c352a88d76167adfe4f3303ab09ec4924ecec1c24b1090220af4`。完整回归结果记录于本报告末尾；仍只代表 E1/E2。

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
个定向测试）；仅为 E1。残余风险：远端当前仍为 0 个 Environment、没有
`windows-candidate-signing` 的在线 preflight/审批/签名记录，且
`datax-release-signing` custom runner group 在当前 User-owned public repo 上需要所有权/ADR 决策；因此
本修复不能声明真实签名或 E4。补充对抗发现：GitHub 默认允许管理员 bypass protection rules；官方
REST Get Environment schema 和当前 GraphQL `Environment` 类型不公开 `can_admins_bypass`，所以
verifier/ID-hash 快照不能证明它已禁用。Release Owner 必须保存 Settings UI 中关闭该开关的记录；
迁入 Organization 后，还须保存 `environment.update_protection_rule` audit event 的
`can_admins_bypass=false` 与签名窗口无反向修改查询。没有这组外部证据，reviewer gate 不可视为独立。

### ASR-007 — High — Compose project label 可被外来容器伪造

攻击路径：Launcher 曾仅以 `com.docker.compose.project=datax-enterprise-studio` 认定现有栈，随后
对整个项目执行 lifecycle、`down --remove-orphans` 或启动失败清理。具有本机 Docker 控制权的
进程可用相同 project label 放入外来容器，使产品错误执行、停止或删除不属于本安装的容器。

修复：Launcher 现先枚举 project-labeled immutable ID，再严格 inspect 唯一预期 service、精确锁定
image、project/service label、活动 `RuntimeGeneration` 派生的 named-volume source/target 与
installation-id/role 标签；未知、重复、镜像/挂载/代际不符统一为
`COMPOSE_PROJECT_OWNERSHIP_UNVERIFIED`，不触碰已有容器。`--remove-orphans` 已移除；`exec` 与
启动后安全核验要求完整服务集，受认证部分集合只可用于恢复性 `up`/`down`。单元测试覆盖固定和
FRESH/RESTORE 风格随机卷名。

残余风险：这是源码 E1；真实 Windows E4 仍必须包含同 project label 外来容器、伪造/重复 service、
镜像/卷身份不符、部分受信栈、cleanup 不删除未知容器与 Docker API TOCTOU 的负例。

### ASR-008 — High — Setup/repair/uninstall 可沿重解析点写入或删除

攻击路径：NSIS 安装器此前只比较 `$INSTDIR` 字符串；固定根、`resources` 或卸载目标若是 junction/
symlink/reparse point，安装、repair 或删除会沿其重定向，甚至可能先停止现有服务再失败。

修复：NSIS 3.11 现于 install、repair 和 uninstall 的停止服务、写入或删除前，拒绝固定根、
`resources` 与既有目标文件的 stable reparse point；`IfSilent` 在 install/uninstall 入口以非零
退出拒绝静默模式。安装器静态回归覆盖该源码边界。它只能降低稳定重解析攻击；NSIS 的“检查后按
路径操作”仍有同用户 TOCTOU 上限，且不会检测 hardlink，不能写成强路径完整性保证。要完全关闭此类
路径替换，需由受信原生 helper 以 non-reparse/handle-relative 语义实际完成写入和删除，并经 ADR、
威胁模型和真实 E4 验收。

### ASR-009 — High — 远端发布治理未强制供应链与独立复核

当前线上快照显示：`Dependabot security updates=disabled`，Actions policy 为 `allowed_actions=all` 且
`sha_pinning_required=false`，required approving review count 为 0、未要求 CODEOWNERS review，新增
hosted Windows E1 也尚未列为 `main` 的 required check。源码 action SHA 固定并不能替代远端强制。

当前状态：`BLOCKED_EXTERNAL`。Repository Owner 必须在确定 Organization/签名信任边界后，启用
Dependabot security updates，配置受限 actions/SHA pinning 与安全敏感路径独立复核（或 Accepted ADR
记录等效控制），并决定是否将 hosted E1 设为 required check；保留实际配置和负向证据。没有这些
治理记录，不得把当前 CI 绿灯、12 个 required checks 或 PR 存在表述为发布供应链已闭合。

### ASR-010 — Medium — 安装目录磁盘水位不能证明 Docker 实际数据容量

攻击路径：Docker Desktop 的 VHD/named volumes 可以位于与 `%LOCALAPPDATA%` 不同的盘；若只看
Launcher 配置目录余量，迁移、日志、复制或备份可能在真正持久卷已满时半途失败。

修复：40 GiB host 检查现明确只保护 Launcher 自身配置/secret/本地备份元数据。`start` 与
`backup` 先确认五个锁定 Linux/amd64 镜像已缓存；只在缺失时由 Launcher-owned 空 Docker config
按 immutable digest 拉取。`start` 在当前 `RuntimeGeneration`/三卷身份认证后、Compose `up` 前，
`backup` 在 staging 前，均运行带 opaque name/双标签的 release-locked Worker 容量探针：三个
`local`/无 options 认证卷只读挂到固定 `/probe/*`，`network=none`、无 secret、只读根、`0:0`、
`cap_drop=ALL` 后仅加 `DAC_READ_SEARCH`、16 PID/64 MiB/0.25 CPU、`--pull=never`；只允许固定
行协议的 `statvfs` 输出，任一 Docker/协议异常或少于 200 GiB 均失败关闭。错误、超时或无效输出
只按重新认证 immutable ID 清理同名 probe 容器。容量失败前受控初始化或镜像缓存可能保留，但
Compose/业务数据库不会启动。

验证与残余风险：Rust 单元覆盖五镜像集合、固定参数/标签、随机活动卷名、local driver/options、
输出 schema/乱序/溢出和容量边界，属于 E1。尚未在 Windows Docker Desktop 上验证异盘 VHD、临界值、
运行中耗尽、PostgreSQL `0700` 权限、Docker CLI timeout、残留 probe 容器或 cleanup TOCTOU，因而
不是稳定容量或 E4 证据。

### ASR-011 — High — 登录入口可在认证前放大本机资源耗尽

攻击路径：`/auth/login` 虽只经 loopback 暴露，但不可信本机进程可高并发提交不存在邮箱。若每次
请求先建立数据库会话、取得组织锁、执行 Argon2id dummy verify 并写失败审计，会抽干 API/数据库
预算；按邮箱或 IP 分桶还会保存不必要的敏感输入并留下绕过、枚举面。

修复：在 `request_id → TrustedHost → Origin` 后、router 之前加入单 API 进程的全局 admission
guard：burst=5、5 次/分钟加一个非阻塞验证槽，不记录邮箱、密码、IP、User-Agent 或浏览器身份。
拒绝一律是 `429 AUTH_LOGIN_ADMISSION_LIMITED`、固定 `Retry-After: 60`、Problem JSON、匹配
request ID 和 `Cache-Control: no-store`，没有 Cookie/`WWW-Authenticate`。429 尚未进入认证决策，
因此不得建立 DB session、运行 Argon2、修改失败计数/锁定、创建 session 或写 AuditEvent；前端清空
密码且不自动重放。

验证：定向 API/admission 回归覆盖 429 短路、request header、非法 Host 不耗额度、验证槽释放和
已获准错误凭据原语义。该结果是 E1，真实 PostgreSQL/Windows 并发压力尚待执行。

残余风险：控制是单进程内存状态，API 重启会清空它；V1 因此固定一个 API/Uvicorn 进程，不允许
workers、API scale、额外 API 入口或旁路代理。多实例前必须先新增 ADR 定义共享、围栏的控制。

### ASR-012 — High — readiness 全量审计链重放可把健康检查变成拒绝服务器

攻击路径：公开 `/health/ready` 若每次都读取所有 `audit_events.event_json`、RFC8785 规范化并
重新计算链，审计越多，每次 health poll 越占用 CPU 和小型数据库连接池；仅缓存旧成功结果又会
掩盖新增 event、尾部漂移或历史篡改。

修复：迁移 `20260802_0018` 新增 `audit_chain_watermarks`。所有 AuditEvent writer 以固定锁序在
同一事务写 Event 与 head；迁移仅回填实际 head 并标记 `PENDING`。ready 正常路径只读取组织、
watermark 和索引 tail；完整重放最多每 60 秒、单次 30 秒，suffix 重放以 head/hash/epoch CAS
发布，FAILED sticky。缺 state、tail 漂移、过期证明、超时或竞争一律 `503/DOWN`；1 秒缓存与
nonblocking singleflight 不让并发 health 请求排队。

验证：SQLite migration/readiness 回归覆盖 PENDING 首次重放、常规路径不读取 `event_json`、篡改、
state 缺失、CAS 竞争、concurrent check 与 timeout 后 cadence 限制；2026-08-02 临时真实 PostgreSQL E2 已
验证当前 `0019→0017→head` 迁移回退/重升，以及隔离 schema 的 pending watermark replay 和
transaction-local statement-timeout 设置。它不启动产品 API/Worker health loop，也不做负载 timeout，
故真实 health poll、压力行为与 Windows E4 仍需单独证据。

残余风险：同库 watermark 可以检测普通应用路径的漂移，却不能阻止有数据库管理员权限的攻击者
同时改写 AuditEvent、水位线和触发器。外部 WORM/签名锚点仍是独立发布阻塞，不能被本修复替代。

## 开放发现

### ASR-013 — High — 数据源外部探测可造成控制面 DoS 或提交陈旧结果

**状态：IN_PROGRESS / 发布 BLOCKED；`FIXED_IN_SOURCE`（E1），局部 PostgreSQL E2 不等于真实
PostgreSQL/MySQL/DataX E3，且同步 psycopg 网络黑洞尚未证明 30 秒内可强制返回。**

攻击路径：获授权的 Admin 可反复触发数据源创建/更新的连接 probe 或显式连接测试；拥有精确
`SOURCE_USE`/`TARGET_USE` grant 的 Developer 也可读取 metadata。若五个入口——
`create_datasource()`、`update_datasource()` 的 `requires_probe`、`test_datasource()`、
`list_columns()`（Schema tables）和 `validate_job()` 的两端 Schema 读取——把 DNS、egress、密码
解密、JDBC/数据库连接和 Schema 读取留在 Organization/Project/Datasource/Job 锁内，慢的允许
端点可使取消、凭据 revoke、目标独占撤回和其他控制写入排队。B 阶段期间再撤销 session、修改
数据源/策略/凭据/授权/任务或目标命名空间，则旧结果还可能泄露或回写到不同的安全事实。

修复：`credentials/operation_boundary.py` 提供不可变 operation snapshot 与单调总 deadline；
`credentials/ingress.py` 提供单 API 进程内、非阻塞的 global=4、organization/datasource=1 和
TEST 60 秒 admission。五个入口均采用 A（短事务重新授权并冻结 AuthSession、数据源、凭据、
grant、Organization/调用者 User/Project 代际、Job/TransferPolicy/TargetNamespace/runtime binding）→ B（已有凭据先在极短 current-credential
barrier 中锁定、复制并提交；随后无产品数据库事务/锁的 DNS/egress、解密、connector；创建使用候选
请求凭据）→ C（短事务重新授权并逐项复核）边界。已有 datasource 先通过 A 身份/授权验证才进入
retained admission bucket，纯描述性/DISABLED PATCH 不取 permit；已完成创建 replay 是无外部 I/O 的
只读返回。429 在 resolver/connector/解密/audit/幂等写入之前返回，deadline 到期后仅在 C 复核仍有效时返回
`503 DATASOURCE_OPERATION_DEADLINE_EXCEEDED`，不持久化 B 结果。PUBLISHED/ARCHIVED Job 在
外部 I/O 前拒绝；校验 material 只在 C 事务原子写入当前 Job validation state/evidence/audit，
不创建或修改 `JobVersion`。`0019` 令 UsageGrant 的 revoke/regrant 单调换代；模板化路由的
idempotency replay 同时对 durable resource 与保存 response 重绑定，跨 User、Datasource secret、
Project/Job/Execution 重放返回 409。egress attestation 故障保留稳定 503 平台 code，只有明确可用性集合可人工重试，且在
共享预算已耗尽时 deadline 结果优先。

**本次对抗审查修订。** 上文“五个入口”仅指五个 Credential Service 直接入口；创建
TransferPolicy 及会重算 scope 的 PATCH 是同一 metadata lane 的双数据源复合调用。它们在 A 阶段
释放产品数据库 Session 后原子取得 source/target permit，两个嵌套 Schema probe 必须复用同一 live
lease 与同一 `OperationDeadline`；因此外层 `429` 不得先触发任一端 DNS、connector、解密、metadata
evidence 或 audit。任务校验 C 阶段还会在关键产品数据库步骤前按剩余预算刷新 transaction-local
`lock_timeout`/`statement_timeout`，并在提交前执行 `configure → flush → check`，以回滚已到期的
validation/evidence/audit 写入。这是逐语句的数据库侧约束；同步 psycopg 网络黑洞及终端检查到
COMMIT 的极小窗口仍不能证明端到端硬 30 秒返回，故 `ASR-013` 继续 `IN_PROGRESS/BLOCKED`。

验证：新增 admission、deadline、operation-boundary、Job validation closure 以及 API/契约回归。
覆盖 permit 释放、429 无 DNS/connector/decrypt/audit、deadline 剩余预算、AuthSession、Organization、
User、Project 在 B 期间漂移、跨资源 idempotency replay，以及 PUBLISHED/ARCHIVED Job 无外部 I/O。
MySQL TCP 后握手、每条 catalog SQL 与 cleanup 的预算重夹紧已有 L1 回归。2026-08-02 已运行
`scripts/test-postgres-e2.sh`：PostgreSQL-only 的受控阻塞 probe 在 B 阶段等待时，第二个会话以
`FOR UPDATE NOWAIT` 成功取得同一 Organization 行；CI 也已配置 `DATAX_CREDENTIAL_POSTGRES_TEST_URL`
执行。该局部锁证据是 E2；connector 仍为受控替身，尚未覆盖取消/撤回/revoke/更新全竞态，mock/SQLite
更不能替代真实 PostgreSQL 或 DataX E3。

尚未验证/关闭条件：在真实 PostgreSQL 用可控阻塞 connector 和 `pg_locks` 或时间界限证明 B
阶段不持有 Organization lock，且并发取消、目标独占撤回、secret revoke、datasource/job/policy
更新可完成；解锁后旧请求必须 stale 且没有陈旧副作用。随后仍需固定 Runtime 上真
MySQL/PostgreSQL E3 deadline、DNS/egress、metadata 分页和恢复证据。特别是 PostgreSQL transport
blackhole 必须用可验证的 client-side cancel/close 或隔离进程边界证明时限内收敛；`statement_timeout`
仅约束服务端 SQL，不能强制中断客户端 read/fetch/rollback/close。不能用 API 空闲事务 timeout、
SQLite、mock 或“登录已限速”代替这些证据。

### ASR-014 — High — private 创建可能在本机 stop/drain 后仍依据陈旧准入事实提交

攻击路径：Phase-A create 是 `SECURITY DEFINER` 数据库事务。若它先读取“服务可接受新任务”再读取业务
current facts，而 Launcher/Worker 同时把 `SystemControl.draining` 改为真，则二者可能都依据旧事实提交：
本机进入停止/备份流程后仍出现新的 protected Execution/target lock。

修复：0024 函数在任何业务事实读取前，以固定锁序对
`public.system_control(singleton_id=1)` 执行 `SELECT ... FOR UPDATE`，并在锁内拒绝 `draining=true`。
无登录 ledger owner 只获得 PostgreSQL 行锁必需的窄 `UPDATE(singleton_id)`；issuer、consumer、runner
和普通 runtime role 均没有该列或该表的直接更新权。实现见
`backend/migrations/versions/20260802_0024_phase_a_private_creation.py:L208-L232`、`L266-L292`、`L402-L415`。

验证：真实 PostgreSQL 15 两连接 E2 由 owner 持有同一行锁、issuer 记录自身 `pg_backend_pid()` 后调用
create；测试在 `pg_locks` 观察 issuer 的未授予锁，owner 提交 `draining=true` 后 issuer 必须返回 `P0001`，
且 Execution/PEA/lock/checkpoint 均为零残留。见
`backend/tests/test_phase_a_execution_authorization_postgres.py:L1590-L1747`。这是数据库 E2，未启动
Worker 或 DataX。

### ASR-015 — High — schema downgrade 可与 protected create 并发并删除仍有语义的私有状态

攻击路径：若 downgrade 先做无锁存在性检查，issuer 可在检查和 `DROP` 之间提交 create→PEA→lock，
使回退删除 checkpoint/entrypoint 后留下无法由旧模型安全解释的 public protected row。

修复：0024 downgrade 在检查前以 `ACCESS EXCLUSIVE` 同时锁定 public executions/attempts/target locks 和
private grant/PEA/checkpoint 表；任一 `PHASE_A_HARNESS`、PEA 或 checkpoint 存在即以 SQLSTATE `55000`
失败关闭。实现见
`backend/migrations/versions/20260802_0024_phase_a_private_creation.py:L780-L849`。这不是清理能力：
当前没有 protected disposition，标准 backup/restore 仍必须拒绝有任何 private Execution 的数据库。

验证：一次性 PostgreSQL E2 覆盖空库 downgrade/re-upgrade，并在持久 protected state 后验证 downgrade
明确拒绝；脚本见 `scripts/test-postgres-e2.sh:L270-L282`。

### ASR-016 — Medium — 私有 receipt 的机器契约曾不能由真实 adapter 完整产生

风险：若 Schema 只存在于文档、adapter 却返回另一套字段，未来 protected harness 可能在不暴露凭据的
前提下仍传递了无法验证、可漂移的状态包。

修复：adapter 现在显式投影 closed `phase-a-execution-lifecycle.v1` envelope，只允许最终
`LOCK_RESERVED`、固定 blocked execution/queue 状态和非秘密 UUID/timestamp；不使用通用 dataclass
序列化，也不在不确定提交结果时重试。实现见
`backend/src/datax_studio/qualification/execution_lifecycle.py:L49-L103`、`L124-L160`。
迁移还显式撤销 issuer/consumer/runner/runtime 对 checkpoint table 与 guard function 的直接权限，避免
未来默认 ACL 漂移；见 `20260802_0024_phase_a_private_creation.py:L208-L214`。

验证：`backend/tests/test_phase_a_execution_lifecycle.py` 用真实 adapter 产物通过 Draft 2020-12
Schema 校验并断言封闭字段集；静态 migration/contract tests 通过。该 receipt 不是公开 API 或启动权限。

### ASR-017 — Medium — Windows Launcher 的 backup helper schema head 可落后数据库迁移

风险：若 Launcher 仍要求 0023、后端 head 已为 0024，用户在数据库已迁移后会被错误地拒绝 backup；反过来若
放宽检查则可能以不匹配的 helper 导出。

修复：Launcher 的唯一 `SUPPORTED_MIGRATION_REVISION` 已与 Settings 和 Alembic head 同步为
`20260802_0024`；backup helper 仍要求精确匹配，任何差异使用
`BACKUP_MIGRATION_REVISION_UNSUPPORTED` 失败关闭。实现见
`desktop/windows/src/lib.rs:L34-L42`、`L6009-L6048`。

验证：`cargo test --locked --manifest-path desktop/windows/Cargo.toml` 为 89 passed。这是宿主 Rust 单元测试，
不是 Windows Docker backup、Setup 或 E4。

## 未关闭的发布阻塞

1. GitHub 当前 `environments` 数为 **0**，尚不存在受保护的 `windows-candidate-signing` Environment；源码的双阶段 ID/hash 流程只证明 E1 失败关闭，尚无该签名 Environment 的在线 preflight、审批或签名记录。无发布权限的 hosted Windows E1 已运行成功，但不能替代本项。即使未来 reviewer 规则可见，管理员 bypass 默认允许，且 REST/GraphQL verifier 无法读取 `can_admins_bypass`；UI/audit-log 禁用证据仍是独立阻塞项。
2. 当前 public repo owner type 为 **User**；GitHub custom runner group 是 Organization/Enterprise 管理边界，强制的 `datax-release-signing` group 因此是 `BLOCKED_DECISION`。首选迁入/转让到 Organization；否则必须先接受新的 ADR，不能删除 group 回退到任意 runner。
3. GitHub 当前 repository self-hosted runner 数为 **0**，不存在可承载 `datax-release-signing` group/labels 的 Windows 11 x64 Runner。
4. 本机没有 `pwsh`、NSIS 或 Windows 11 x64 + Docker Desktop/WSL2，无法执行 PowerShell runtime、真实 PFX 签名、Setup 安装/卸载、宿主端口或 Docker helper 清理验收。
5. 真实 MySQL 8/PostgreSQL 15 四方向 DataX、独立 oracle、恢复、睡眠/重启和 LAN 负例仍未达到 E3/E4。
6. 安装器对稳定 reparse point 的最低防护即使落地，也不能消除同用户检查—使用竞争；强路径完整性边界仍需受信 native helper 架构和 E4。
7. Compose 项目归属必须在源码中认证并在真实 Docker Desktop 上证明不会触碰同 project label 的外来容器；未完成前不得执行 `--remove-orphans` 或把标签当作所有权证明。
8. 远端 Dependabot security updates、Actions/SHA policy、独立复核和 hosted E1 required-check 策略尚未由 Repository Owner 配置并取证。
9. Docker 数据卷容量 probe 只有 E1；异盘 VHD、临界容量、运行中耗尽、Docker timeout/残留与实际
   backup/start 行为仍须在同一签名 Windows 候选上完成 E4。
10. 0024 的 issuer 在标准产品中仍为 NOLOGIN，且没有 API/Settings/Compose/Launcher 调用路径；这是刻意
    deny-all，而不是可交付的私有运行通道。以后若单独 provision protected issuer，必须先设计并验收
    disposition、private runner 四检查点、凭据/日志、独立 backup/restore 及真实 DataX E3；在此之前任何
    成功 create 仅能作为一次性 E2 数据库证据，不能用于持久产品数据库。

因此不得发布 `Setup.exe`、不得声称“Windows 已稳定运行”或“企业级已完成”。下一次外部验收必须先由仓库所有者作出 Organization 迁移或新 ADR 的签名信任决策，再配置受保护 Environment、独立 reviewer、受控干净 Windows Runner、工具 hash/ACL 取证与不可导出签名能力，并运行同一精确候选的 E3/E4。

## 本轮已执行的检查

| 检查 | 结果 | 证据等级 |
|---|---|---|
| `git diff --check` | 通过 | E1 |
| 后端完整测试 | 当前工作树 `pytest -q backend/tests` 退出 `0`；未配置真实 PostgreSQL URL 的项仍按条件跳过 | E1/E2 |
| acceptance 测试 | 68/68 通过（含 hosted Windows 预检、安装器静默/重解析静态边界和本地 E4 前置观察器负向边界） | E1 |
| `scripts/test-postgres-e2.sh` | disposable PostgreSQL migrations、角色边界、0024 atomic create/drain race/downgrade、审计、credential/auth 并发 E2 子集 `32 passed` | E2；不是 DataX E3 或 Windows E4 |
| Launcher Rust 库测试 | 89/89 通过 | E1 |
| Rust format + Clippy | 通过 | E1 |
| Ruff | 通过 | E1 |
| requirements catalog + release YAML parse | 通过 | E1 |

这些检查是可复现的源码证据，不是 Windows E4、真实签名或外部数据库 E3 证据。
