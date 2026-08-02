# ADR-0009：DataX 完整上游随包与认证能力分级

- 状态：Accepted
- 日期：2026-08-01
- 决策者：仓库所有者
- 关联：`docs/14_第一性原理问题台账与开发修复计划.md`、
  `docs/contracts/plugin-manifest.v2.schema.json`（v1 仅保留为历史契约）、
  `docs/contracts/upstream-plugin-inventory.v1.schema.json`、
  `runtime/upstream-plugin-inventory.v1.json`、`runtime/upstream.lock.json`

## 背景

仓库已经固定并保存 Alibaba DataX `datax_v202309` 的完整上游源码，但当前 Worker 镜像
只构建核心、Transformer、MySQL/PostgreSQL 和 stream 测试插件；产品 API 只把
MySQL 8/PostgreSQL 15 的四个 Reader/Writer manifest 声明为认证能力。

仓库所有者要求最终 Windows 交付覆盖 DataX 的全部功能。这里必须区分四件不同的事：

1. 上游源码存在；
2. 插件能在固定供应链中构建并进入镜像；
3. 平台能安全表达其参数、凭据、端点、日志和数据结果；
4. 插件已经连接真实外部系统、通过独立 oracle 和 Windows 交付验收。

如果把源码目录、JAR 存在或 DataX 理论支持直接显示为“稳定可用”，会违反本仓库的
“不能伪装”原则。另一方面，如果继续把完整上游误解为永远只允许四个插件，又无法形成
面向全部 DataX 能力的可扩展终局。

## 决策

### 1. Windows 交付形态不改变

- 用户最终获得签名 `Setup.exe`、签名 `launcher.exe`、桌面快捷方式和本机浏览器入口。
- DataX、JDK、API、Worker 和 PostgreSQL 继续运行在 Docker Desktop + WSL2 的固定
  Linux 容器中；不承诺纯原生单进程 EXE，也不静默安装或代接受 Docker 许可。
- 上游运行时和允许再分发的插件在发布镜像构建阶段离线固化；安装、启动和执行阶段不得
  从互联网下载插件或执行用户上传 JAR。

### 2. “完整 DataX”采用逐级可证明状态

每个上游 Reader、Writer 或 Transformer 都必须进入机器可读能力目录，并且只能沿以下
单向状态推进：

| 状态 | 含义 | 可否在普通用户 UI 中执行 |
|---|---|---|
| `SOURCE_PRESENT` | 固定上游源码和来源/许可证已登记 | 否 |
| `BUILD_VERIFIED` | 在固定 JDK/Maven/补丁和无网络安装阶段可重复构建 | 否 |
| `PACKAGED` | JAR、依赖、SBOM、许可证和 SHA-256 已进入固定 Worker 镜像 | 否 |
| `CONTRACTED` | 参数、秘密、端点策略、JobSpec、日志、取消和结果语义已有机器契约 | 否 |
| `E3_CERTIFIED` | 对受支持版本的真实外部系统完成成功/失败/取消和独立 oracle E3 | 否 |
| `WINDOWS_E4_CERTIFIED` | 已绑定同一不可变 Runtime payload 的精确最终 F（Setup/Launcher）在无 QH/PAG/PEA 的正常模式通过 Phase B Windows E4；受信 reader 才可据此派生插件状态 | 仅当同一 F 另有有效 PR 时可；E4 状态本身不可 |
| `BLOCKED` | 因许可、不可重现依赖、安全模型、外部环境或上游缺陷阻断 | 否，必须显示原因 |

状态必须由发布制品摘要和证据包派生，不能由前端常量、文件名或人工勾选直接提升。任何
插件版本、依赖、驱动、参数契约或安全策略变化都使受影响认证失效并要求重新取证。

`WINDOWS_E4_CERTIFIED` 不是 Phase A payload 资格，也不是 QH/QR 的别名。它只能从
ADR-0011 Phase B 对精确最终 F 的正常模式 Windows E4 证据派生，并必须同时绑定 F、P、
Setup/Launcher、插件和候选身份。该插件状态也不等于公开发布批准：受信 reader 必须另行
验证同一 F 的有效 PR（完整发布门禁和 hosted provenance）后，才可把
`ordinary_user_executable` 暴露给普通用户。Phase A QH 只产生私有 harness/payload
qualification，绝不写入 Plugin Manifest 或成为 E4 状态；在当前尚无受信 reader 时所有能力
继续失败关闭。

### 3. V1 认证边界保持不变，完整覆盖作为后续纵向计划

- V1 仍只认证 MySQL 8/PostgreSQL 15 四方向的一次性离线全量表复制。先修复当前 P0/P1、
  完成真实 E3 和 Windows E4，不能用横向增加插件掩盖核心链路不稳定。
- 完整上游源码和插件清单可以随工程候选推进，但未达到 `WINDOWS_E4_CERTIFIED`、或没有
  与其精确最终 F 绑定的有效 PR 的能力，不得出现在普通用户可执行选择器中，也不得计入
  “稳定支持”。
- 后续按插件族逐个纵向交付：关系数据库、文件/FTP、对象存储、数仓、NoSQL/搜索、云
  专有服务、Transformer。每个切片必须单独完成许可、安全、契约、真实依赖和回滚评审。
- 只有目标清单中所有可合法再分发、仍受上游支持且能满足平台安全不变量的模块均达到
  `WINDOWS_E4_CERTIFIED`，且精确最终包已完成 ADR-0011/0010 的公开晋级，才允许声明
  “完整 DataX 功能稳定可用”。被永久阻断的模块必须
  从这一声明中显式列出，不能用“基本全部”隐藏。

### 4. 不允许用“全功能”绕过安全边界

- 上游支持任意 SQL、`preSql`、`postSql`、脚本 Transformer 或自定义参数，不等于平台
  自动获得安全执行这些能力的许可。引入每一种高风险能力前必须新增 ADR、更新威胁模型、
  权限、审计、参数白名单、进程/网络/文件隔离和真实负向测试。
- 不提供用户上传插件、运行时下载、任意本机路径、宿主 shell 或未经 schema 的原生 JSON
  透传。
- 某个插件无法接入独立数据 oracle 时，必须为该数据模型定义等价的独立验证器；仅依赖
  DataX 退出码或自报数量不能成为认证证据。

### 5. 发布和机器契约要求

- 新增由上游 `pom.xml`、`plugin.json`、构建产物和许可清单共同生成的插件 inventory；
  手工清单只能作为审核输入，不能成为发布事实源。
- `plugin-manifest.v2` 已表达状态、上游模块/哈希、方向、依赖/许可状态、
  参数与敏感字段、网络/文件边界、oracle 类型、候选绑定、E3/E4 证据引用、
  有效期和阻断原因；公开契约不允许测试注入证据。
- Worker 启动证明实际镜像内插件集合及摘要与 release manifest 完全一致；多出、缺少或
  摘要不符都必须 fail closed。
- Setup/Launcher 只消费已经发布的固定镜像；不会因为本机存在额外 JAR 而扩展能力。
- 资格证据不得回写进被认证的 Worker 镜像或与最终 Setup/manifest 形成自引用哈希。
  受保护 harness 的短期资格、detached release qualification、最终安装包和公开发布
  晋级必须按 ADR-0011 分离；测试注入和自申报 JSON 不是其中任一对象。

### 6. 已落地的第一安全切片：只证明源码存在

`runtime/build_upstream_plugin_inventory.py` 已从锁定上游根 POM、模块 POM 与规范位置的
`plugin.json` 生成 `runtime/upstream-plugin-inventory.v1.json`，并由
`docs/contracts/upstream-plugin-inventory.v1.schema.json` 约束。当前固定上游扫描得到 72 个
Reader/Writer 模块（31 Reader、41 Writer），没有用手抄插件名代替发现过程。catalog 绑定
上游 tag、commit、tree、根 POM、各模块 POM 以及每个 `plugin.json` 的路径和 SHA-256；
`--check` 与负向测试拒绝丢失、重复、非法方向、篡改和非规范输出。

本切片只关闭 `SOURCE_PRESENT` inventory。所有 72 项均固定
`ordinary_user_executable=false`；四个 MySQL/PostgreSQL 业务插件和两个 stream 内部自检
插件只带候选分类。该分类不是 `BUILD_VERIFIED`、`PACKAGED`、`CONTRACTED`、E3 或 E4
证据，不能改变 V1 普通用户可执行边界。

72 项只覆盖根 POM 中的 Reader/Writer 模块。本切片尚未生成 Transformer、任务模板、
DataX 核心/配置以及任意 SQL、`preSql/postSql`、脚本转换等原生功能的机器 inventory；
因此不能把“72 个 Reader/Writer 已登记”表述为“DataX 全部功能已盘点”或“全功能已实现”。

### 7. 已落地的第二安全切片：E1 失败关闭

`GET /plugins` 已改为消费 v2 能力契约，Runtime 心跳只能把当前四个制品
提升到最多 `PACKAGED`。生产 `ControlService` 默认注入 deny-all 证据源；
普通 Execution API 创建、恢复 `rerun`、Worker 领取和 Worker 建立工作区/解密凭据前
四个检查点各复检一次。
UI 从目录渲染 Reader/Writer 并对非 E4 能力显示阻断原因。明确的内部测试
依赖注入可验证门禁正路，但不能通过公开 Schema 或 `/plugins` 冒充发布事实。

受信的生产发布证明读取器尚未实现，当前 `WINDOWS_E4_CERTIFIED=0`。ADR-0011 的
`release-payload.v1`、`harness-qualification.v1`、`phase-a-qualification-grant.v1` 与
`phase-a-execution-authorization.v1` Schema，失败关闭 P/QH parser、私有 payload/runtime/job binding 与
durable nonce/grant/PEA 账本已作为 E1 基础件进入源码；`20260802_0021/0022` 还把 private ledger 交给无登录
owner，并以无登录 issuer/consumer 的最小 `SECURITY DEFINER` 函数分离 atomic issue/revoke/current-grant
read 与 PEA issuer-authorize/consumer-read。0022 的 PEA 对 `grant_id`/`execution_id` 双唯一、仅保存 nonce SHA-256，
普通 API/Worker/Recovery/公开日志路径只走 `STANDARD`；`datax_api/datax_worker/datax_egress_guard` 的 direct DB access
还受 parent-linked RLS 限制，不能通过 execution descendants 读取/写入 private row。issuer authorize 后仍是
`BLOCKED/PHASE_A_PRIVATE_WORKER_NOT_IMPLEMENTED`，所以它没有普通 DataX start 能力。RLS/0022 已在本切片真实 PostgreSQL E2
中验证。仍没有受保护 harness
凭据配置、private Execution 创建/rerun、private override、QR schema/reader、真实 E3/E4 或最终
promotion validator，也不会改变公开 `plugin-manifest.v2`、普通用户状态或 production deny-all。
因此该切片仍只证明“不会把未取证能力当成已认证能力运行”，不证明四方向 DataX E3、
Windows E4 或全部 DataX 功能已完成。

## 后果

- 最终仍然是一套用户可从 Windows EXE 入口安装和启动的本地产品，同时保留 DataX 的
  Linux/JVM 运行环境，避免不可验证的原生 Windows 移植。
- “完整源码”“已打包”和“稳定支持”不再混为一谈；插件扩展可以持续进行而不会制造
  假能力。
- 完整覆盖需要大量真实外部系统、许可核查和 Windows 取证，不能仅在当前 Mac 或 CI 中
  完成。缺少外部系统时对应插件保持 `BLOCKED`，而不是回退到 Mock 成功。
- V1 的四插件主链路仍是第一优先级；只有其可靠性、恢复和发布证据闭环后才扩大认证面。
