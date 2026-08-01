# DataX Enterprise Studio V1.2 威胁模型

> 状态：V1 发布门禁输入
>
> 更新日期：2026-07-31
> 适用范围：Windows 11 x64 本地工作站、单组织、多项目、单节点、安全的一次性离线全量复制

> 实现口径：表中的“V1 强制控制”是发布前必须满足的控制集合，不等于当前全部已实现。
> 当前已有 DATA/SECRETS 分离加密导出、双包认证 journal 与全新空 staging，恢复只达到
> E1；新空 PostgreSQL volume、真实 `pg_restore`、证据重算、卷/secret 原子提交和覆盖
> 升级保持关闭。数据库外审计 checkpoint/WORM、公钥 keyring、真实默认拒绝 egress 的
> Windows Docker Desktop/WSL2 实测闭环、真实 Windows 签名制品及 E4 验收仍缺失。
> egress-guard、journal/staging、安全工作流或本地单元/镜像扫描不能替代真实内核、完整
> 恢复或 Windows 证据。当前 Mac 只用于开发验证，最终证据必须来自另一台 Windows 11
> x64 目标机；未闭合门禁保持 `BLOCKED_NOT_IMPLEMENTED`、
> `BLOCKED_NOT_VERIFIED` 或 `NOT_RUN`。

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
| 数据源密码、DEK/KEK、JWT/审计签名私钥、refresh/idempotency HMAC keys、egress lease bearer token | Secret | 不回显、独立生成、信封加密或受限 Secret 文件、lease token 只返回一次并仅存内存摘要、分离备份、最小读权限 |
| 源/目标策略/连接修订、物理身份、表列 scope、日志 | Confidential | 项目授权、脱敏、保留限制、下载审计 |
| JobVersion、Execution、核验证据 | Integrity critical | 不可变版本、哈希、围栏、追加事件 |
| 审计事件；未来公钥 keyring 与外部锚点 | Integrity critical | 当前为精确事件前像/同库哈希链；双签轮换、外部锚定和双人恢复仍是发布门禁 |
| Runtime、插件与镜像 | Supply-chain critical | digest/SHA-256、SBOM、签名/来源验证 |
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
  细粒度状态权限主要由应用层执行，不能声称数据库已强制职责隔离。
- 外部 MySQL/PostgreSQL、DNS、镜像仓库和备份系统均跨越信任边界。
- Windows 11 宿主、当前登录用户、浏览器、`launcher.exe`、Docker Desktop/WSL2 与
  Linux 容器之间均是独立信任边界。Docker Desktop 管理权限等价于本机高权限，不授予
  Web/API/Worker 容器访问 Docker Socket、Windows 命名管道或宿主敏感目录。

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
| TM-10 | 审计篡改/换钥断链 | DB 管理员重写事件/锚点，或替换公钥后伪造 checkpoint | 当前：同库 `DXAUDITv1` 追加哈希链和连续性验证；发布缺口：`DXAUDITCHECKPOINTv1`、独立只读公钥 keyring、双签轮换、外部 WORM | 当前同库删除/重写测试；发布前补逐字节签名、轮换/妥协和外部重放演练 |
| TM-11 | 密钥丢失、错误轮换或紧急撤销不生效 | 只保留最新 KEK；已泄露 secret 仍被新连接使用 | 版本化 KEK/Envelope、公钥/指纹；旧 key 保留到备份窗口；secret ACTIVE/RETIRED/REVOKED/COMPROMISED；紧急终止事实 | 新旧 Envelope、旧备份、紧急撤销竞态、灾难恢复 |
| TM-12 | 资源耗尽/队列饥饿 | 日志保留组合超 200 GiB；长任务、单项目或取消请求被唯一 Worker 饿死 | 分档组合公式、60 GiB 日志预算、绿黄红 admission、持久项目 service cursor、reconciler 独立取消、队列 SLO | 存储计算/水位故障、重启 cursor、取消 SLO、跨项目压测 |
| TM-13 | 供应链漂移 | 镜像、JDK、DataX 或插件被替换 | 固定 digest/SHA-256、来源清单、只读挂载；PostgreSQL/egress-guard 固定 `15.18-alpine3.24`，API/Worker 最终层固定 Python 3.12.13 `slim-trixie`（Debian 13）。PR 配置 Gitleaks、hash-lock pip-audit、pnpm、Cargo OSV、四语言 CodeQL，以及真实 patched Worker 镜像 Syft+OSV 应用门禁；本地为 0 未处理项、6 个逐项 Logback 1.2.13 短期例外（到期 `2026-09-30`）。candidate release 从精确 commit archive 生成源码 SBOM，并为五镜像生成 SBOM/OSV/Grype 证据；Grype candidate 对可修复 High/Critical 阻断，无修复项进入 `review_required` 且候选仍 `BLOCKED`，promotion 默认阻断或仅接受逐项不超过 90 天例外。2026-08-01 线上快照：最新 PR 的 CI/安全/CodeQL 门禁通过，开放 CodeQL 告警为 0；`main` 经典分支保护严格要求 12 个检查、PR、分支最新、线性历史和会话解决，禁止强推/删除且管理员不可绕过；漏洞告警与 Dependabot security updates 已启用。单维护者阶段审批数仍为 0，且真实 release/OS/Windows 扫描未验证 | 工作流与本地 Worker policy 证据；源码 commit/SBOM 绑定；候选与 promotion 策略负例；线上必需检查、Grype DB/报告、Windows release 状态；启动自检、制品替换负例 |
| TM-14 | 备份越权 | DB 备份与 KEK 同处、DATA/SECRETS/key 未分离，或恢复环境暴露 Secret | 当前导出强制 `.dxdata/.dxkeys` 分包、不同恢复秘密、allowlist/秘密扫描和用户选择的分离路径；双包认证、双秘密认证 journal、全新空 staging 与限定清理已达到 E1。ADR-0008 固定只向无旧身份/容器/产品卷的干净目标恢复，以单一运行代际指针共同选择 installation-id、独立 secret 目录和三个随机卷；Schema、严格 Rust 校验与 Compose name 注入已有候选代码，但尚未接入。新空 PostgreSQL volume、真实 `pg_restore`、证据重算、代际原子提交、最小恢复人员、隔离环境、双人审批与恢复后销毁仍是发布缺口 | 导出 ACL/分包与 journal 篡改/错包/staging/代际指针负例；发布前完成真实 Windows 导出、卷提交和异机恢复演练 |
| TM-15 | 别名绕过自复制/目标锁 | 同一数据库用新 Datasource、revision、hostname/IP 别名并发写同一表 | 不可变 PhysicalEndpointIdentity + 引擎真实标识符规范化 TargetNamespace；自复制与唯一锁只用物理表 hash/namespace | MySQL server_uuid、PostgreSQL system_identifier、别名/revision 并发负例 |
| TM-16 | 策略漂移 | 编辑 EndpointPolicy 同一 ID 后，历史 JobVersion 静默获得新 CIDR/egress 权限 | 不可变 EndpointPolicyRevision；Datasource/JobVersion 固定版本；守卫只读 current ACTIVE view 并校验 revision/hash，撤策/hash 变化立即清全部租约并切 base-deny；每阶段证据包含实际 policy/resolver/egress 版本 | 规则修改、current pointer 漂移、撤策、旧版本运行拒绝 |
| TM-17 | 平台外目标写入竞态 | 第三方客户端、触发器或 DBA 在 Worker 空表检查后、oracle 读完前执行 DML/DDL；平台锁无法阻止，瞬时后回滚或未报告写入也可能不可观测 | Operator/DBA 提交 `statement_version='1.0'`、有限 `valid_until` 的 `target_exclusivity_confirmation`；Execution 持久化 `ACTIVE/REVOKED/EXPIRED`；获知破坏时经专用接口报告/撤回并写 `TARGET_EXCLUSIVITY_REVOKED`；Worker/oracle 要求 ACTIVE、未撤回未过期且 snapshot finish≤valid_until；平台锁明确不冒充外部锁或完整侦测 | 声明版本/过期/撤回/时间窗不足、Operator/DBA 报告已知 DML/DDL/冻结破坏、未领取/已领取/VERIFYING 收敛与审计负例；明确不声称发现任意未报告写入 |
| TM-18 | MySQL TLS 身份校验降级 | 旧 Connector/J 把 `VERIFY_CA` 与 `VERIFY_FULL` 都渲染成 `verifyServerCertificate=true`，攻击者用受信 CA 签发但主机名不匹配的证书冒充目标 | 固定 Connector/J `9.7.0`/新驱动类；`VERIFY_CA→sslMode=VERIFY_CA`、`VERIFY_FULL→sslMode=VERIFY_IDENTITY`；禁用旧 TLS 参数；驱动 JAR/许可进入 Runtime manifest；证书链或 hostname 不匹配 fail closed | URL 契约负例、旧/重复驱动制品替换负例、真实 MySQL 正确/错误 CA 与正确/错误 FQDN 握手 |
| TM-19 | Windows 安装/升级制品被替换 | 下载镜像、`Setup.exe` 或 `launcher.exe` 被篡改；攻击者改用任意受信代码签名证书重签；签名失效；被降级到已知漏洞版本 | 执行 Setup 前从外部核对固定发布证书 DER SHA-256 与发布页文件 SHA-256；正式制品内部同时验证 Authenticode 信任链与唯一主签名证书 DER SHA-256；1–8 项严格排序轮换允许集写入清单 1.1，清单精确哈希绑定到已签名 Launcher，运行时无环境变量覆盖；Setup 安装前要求自身与 Launcher 实际签名者完全相同；时间戳、版本单调检查、固定镜像 digest、SBOM；校验失败拒绝安装/启动。内部自校验不声称能认证已执行且主动删除检查的恶意重打包 Setup；当前用户/管理员完全控制宿主仍是非目标 | 干净 Win11 VM 的正确签名；首次执行前外部验证；任意其他受信签名者、Setup/Launcher 不同签名者、空/缺失/重复/乱序/非法允许集、资源替换、过期/撤销签名和降级负例 |
| TM-20 | 宿主端口意外暴露 | Compose 使用 `0.0.0.0`、API/DB/守卫端口映射、IPv6 或防火墙规则使 LAN 可达 | 只允许 Web `127.0.0.1:17860`；禁止 API/Worker/egress-guard/PostgreSQL 宿主映射；attestation/lease 只绑定共享 netns loopback；Launcher 启动后枚举实际监听和 Compose 映射，异常即停止 | `Get-NetTCPConnection`、局域网第二主机拒绝、IPv4/IPv6 监听证据 |
| TM-21 | Launcher/路径/DLL 劫持 | 当前目录 DLL、可写安装目录、PowerShell 拼接或环境变量让攻击者执行任意程序 | 签名 launcher、绝对规范路径、受限 ACL、无 `shell=True`/拼接、固定 Compose/镜像清单、不搜索当前目录、不继承危险环境 | 标准用户 ACL、空格/Unicode/长路径、恶意 DLL/环境变量负例 |
| TM-22 | 睡眠/重启后旧事实继续写 | Windows 睡眠、WSL VM 暂停、Docker 重启造成 lease 时钟跳跃、孤儿容器或旧 fence 写入 | 恢复先标记未就绪并对账 boot/container identity、lease 与 fence；旧工作停止后才开放新执行；单节点中断明确可见 | 睡眠/恢复、Docker stop/start、WSL shutdown、Windows reboot 故障注入 |
| TM-23 | 卸载、Docker 重置、首次初始化中断或磁盘故障导致数据丢失 | 卸载误删 named volumes/密钥/备份；先建卷后生成密钥时崩溃导致不可恢复；Docker 重置后静默创建空卷；卷部分丢失；磁盘不足时迁移或日志写入半完成 | 当前：程序/三卷分离；ACL 受控初始化日志；先完整 secret、后卷、最后提交 installation-id；仅在无产品/数据卷容器且日志/secret/卷标签一致时补齐；既有卷缺密钥或状态矛盾 fail closed，绝不自动删卷；DATA/SECRETS 导出、双包认证 journal 与空 staging 已达到 E1。ADR-0008 进一步要求干净目标与单一运行代际提交，候选校验代码已有但尚未接入；异机恢复、新空卷 `pg_restore`、证据重算、代际提交与覆盖升级仍是发布缺口 | 初始化各提交点断电/进程终止、容器存在、缺 secret、部分卷、错标签、Docker reset 负例；journal/staging/代际指针中断与篡改负例；发布前补安装→数据→卸载→重装、磁盘不足、真实 Windows 导出和异机恢复证据 |
| TM-24 | 出口租约伪造、重放或守卫死亡后残留 | 客户端自报 lease ID、token 被记录/重放、API/Worker 不在守卫 netns、守卫死亡后旧 allow 无限存活 | lease ID 与 32-byte bearer 均由守卫生成；token 仅首次响应且内存只存域分离摘要；create/renew 重读 ACTIVE view；逻辑 30 秒、5 秒续租、nft 元素最多 15 秒；规则漂移锁存 base-deny；Launcher 实测三容器 netns 相等 | 请求未知字段/客户端 ID、错误 token、token 日志扫描、netns 不等、guard kill 15 秒、DB 失败、nft 漂移与撤策故障注入 |

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
  exact-IP 租约创建/续租/释放、同 CIDR 地址偏移拒绝、守卫/DB/规则失败最多 15 秒失效，
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

保留风险：源静默与目标外部独占都依赖系统所有者的外部变更冻结流程。平台无法仅靠 JDBC
证明源扫描期间绝无写入，也无法靠 TargetCopyLock 阻止或完整发现第三方对目标执行的
DML/DDL。目标声明的版本、截止时间、状态、撤回报告和最终数据 oracle 只能形成
fail-closed 的责任与结果证据，不能证明任意瞬时、未报告或已回滚的外部写从未发生。
未获得任一确认、目标声明非 `ACTIVE`、目标快照完成晚于 `valid_until`，或需要在线
一致性快照/数据库强制外部排他的场景不属于 V1，必须拒绝执行。
