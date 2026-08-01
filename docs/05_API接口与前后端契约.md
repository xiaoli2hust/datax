# DataX Enterprise Studio API 接口与前后端契约

> 文档状态：V1.2 Windows 本地工作站工程候选；Discovery Gate 未取证，试点/发布 `BLOCKED`
>
> API 版本：`v1`
>
> 规范文件：[`contracts/openapi.yaml`](./contracts/openapi.yaml)
> JobSpec：[`contracts/job-spec.v1.schema.json`](./contracts/job-spec.v1.schema.json)
> 独立核验：[`contracts/verification-oracle.v1.schema.json`](./contracts/verification-oracle.v1.schema.json)
> 验收清单：[`contracts/acceptance-manifest.v1.schema.json`](./contracts/acceptance-manifest.v1.schema.json)

> 当前实现边界：数据源、任务、执行/日志/恢复 HTTP 路由及前端正式 API 适配已有工程
> 候选代码；这只说明契约消费者/生产者存在，不表示真实数据库、固定 DataX、浏览器或
> Windows E3/E4 已验收。系统 DATA/SECRETS 导出由 Launcher/helper 承担，不进入业务
> OpenAPI；双包认证 journal 与全新空 staging 已达到 E1，但真实 `pg_restore`、证据
> 重算、卷/secret 原子提交、完整恢复和覆盖升级仍失败关闭。

## 1. 契约优先级

机器契约负责字段、类型、枚举和约束形状；PRD 负责产品结果与范围，ADR 负责不可变架构决策，本文负责 HTTP 交互语义。任何来源发生冲突都必须阻断实现并在同一变更中修复，不能让格式契约覆盖产品结果，也不能让自然语言绕过机器约束。

V1 API 只提供安全的一次性离线全量复制：操作员确认源端静默，Operator/DBA 提交有版本、
有限有效期的目标外部独占声明；API 创建 `QUEUED` 时原子预留同目标锁，Worker 领取后
实测目标表为空，DataX 只执行一次 insert-only 写入，随后由独立 oracle 核验。目标声明
是带报告义务的人工前提，不是平台技术锁或外部写入未发生的技术证明；平台无法检测全部
未报告或已经回滚的外部 DML/DDL。`TargetCopyLock` 只串行平台内工作。API 不暴露调度、
DAG、告警、AI、插件安装、任意 SQL、Transformer、自动清理或原始 DataX JSON 执行接口。

V1 是 Windows 11 x64 本地工作站产品。业务 API 只通过 Compose `web` 反向代理暴露在
`http://127.0.0.1:17860/api/v1`；`api`、`worker`、`postgres` 不映射任何 Windows
宿主端口。`Setup.exe`/`launcher.exe` 的安装、前置检查、Compose 生命周期、备份和诊断
不是业务 HTTP API，不能借本规范新增远程管理入口。全新空库的首次 Admin 由 launcher
GUI 经固定容器 `bootstrap-admin` helper 创建，临时密码只走子进程标准输入；不通过
浏览器/API，也不进入参数、环境、日志或持久配置。若所有组织级 Admin 均因登录失败被
锁定，只允许本机操作者通过容器内 `datax-studio-recover-admin` CLI 恢复一名已锁定
Admin；新临时密码同样只走标准输入。只要仍有一名有效 Admin，该 CLI 必须拒绝执行；
它不提供 HTTP 路由，也不能恢复已停用用户。

## 2. 通用约定

| 主题 | 约定 |
|---|---|
| Base URL | `http://127.0.0.1:17860/api/v1`；前端代码使用同源相对路径 `/api/v1` |
| 传输边界 | 仅 Windows 本机 loopback HTTP；不得绑定 `0.0.0.0`、`::`、LAN IP 或对外反向代理 |
| Host / Origin | Host 只允许 `127.0.0.1:17860`；有 Origin 的请求必须精确同源；默认不启用 CORS |
| 内容类型 | `application/json; charset=utf-8` |
| ID | UUID v4 字符串 |
| 时间 | UTC RFC 3339，例如 `2026-07-30T02:30:00Z` |
| 字段名 | `snake_case` |
| 未知字段 | 请求返回 `422 VALIDATION_ERROR` |
| 空值 | 可空字段显式为 `null`；更新请求中“缺失”与 `null` 含义不同 |
| Request ID | 客户端可传 `X-Request-Id`；服务端始终返回有效 UUID |
| 认证 | `Authorization: Bearer <access_token>` |
| 乐观锁 | 可变资源 PATCH 必须传 `If-Match: W/"<row_version>"` |
| 分页 | 不透明 cursor + `limit`；不提供不稳定 offset 分页 |
| 删除 | 数据源/任务使用软删除或归档；有历史引用不物理删除 |

前端不得依赖错误 message 做分支，必须使用稳定 `code`。不得解析 cursor、ETag、JWT 或服务端生成的日志 storage key 来推导业务状态。

`web` 是唯一有宿主端口的 Compose 服务，映射必须精确为
`127.0.0.1:17860:<container-port>`。`api` 只信任来自固定 `web` 服务身份的代理流量，
并拒绝客户端伪造的 `Forwarded`、`X-Forwarded-*`；`web` 必须覆盖而不是追加这些头。
直接访问容器 IP、Docker Desktop 转发的随机端口或 Windows LAN 地址均不属于支持契约。
数据库 JDBC TLS、服务器证书验证和网络出口策略不因浏览器使用 loopback HTTP 而放宽。

## 3. 认证与会话

### 3.1 Access token

- Access token 是短时效 JWT，仅通过 `Authorization` header 发送。
- 前端只保存在内存，不写 localStorage、sessionStorage、IndexedDB 或 URL。
- JWT 至少包含 `sub`、`org_id`、`session_id`、`iat`、`exp`、`jti`。
- 项目角色每次在服务端查询或从可立即失效的授权缓存读取，不能只信任长期 token 中的角色。
- 登录和 `/auth/me` 返回 `must_change_password`；该值为 true 时，除 refresh、logout、
  me、change-password 外的业务接口统一返回 `403 PASSWORD_CHANGE_REQUIRED`。

### 3.2 Refresh token

- 登录成功后由 `Set-Cookie` 写入 `des_refresh`。
- V1 固定 loopback HTTP，因此 Cookie 必须为
  `HttpOnly; SameSite=Strict; Path=/api/v1/auth`，且不得设置 `Domain`。HTTP 交付不能
  虚假声明浏览器会执行 `Secure`；后续若改为受信 loopback HTTPS，必须增加 `Secure`
  且继续只绑定 loopback。
- `POST /auth/refresh` 旋转 refresh token；旧 token 重放会撤销整个 token family。
- 前端收到 `401 AUTH_TOKEN_EXPIRED` 时最多自动 refresh 一次，再重放原 GET 或本身安全幂等的请求。
- 非幂等写请求只有在携带原 `Idempotency-Key` 时才可自动重放。

### 3.3 登录请求与响应

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "operator@example.com",
  "password": "<write-only-password>"
}
```

```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": "8a70a0eb-0f0d-4a26-a3e3-1b84ebbd92c4",
    "email": "operator@example.com",
    "display_name": "值班工程师",
    "must_change_password": false
  }
}
```

密码只允许出现在本机 loopback 请求体和服务端瞬时内存中，不得进入日志、Trace、错误或
审计。loopback 不是加密通道，V1 的安全边界是假定 Windows 登录会话与本机进程可信；
同机恶意进程仍是明确剩余风险，不能把 `127.0.0.1` 描述成 TLS。

## 4. RBAC

一个用户可拥有多个角色，权限取并集。组织级 Admin 可访问组织内全部项目；其他角色必须在项目作用域内授予。

| 能力 | Admin | Developer | Operator | Viewer |
|---|:---:|:---:|:---:|:---:|
| 创建、停用、解锁和重置用户密码 | ✓ |  |  |  |
| 创建/归档项目、管理成员 | ✓ |  |  |  |
| 查看项目和脱敏数据源 | ✓ | ✓ | ✓ | ✓ |
| 管理 EndpointPolicy、创建/更新/测试/启停数据源、轮换密码 | ✓ |  |  |  |
| 授予 `SOURCE_USE / TARGET_USE` | ✓ |  |  |  |
| 申请/审批/撤销 TransferPolicy | ✓ |  |  |  |
| 使用已授权数据源创建任务 | ✓ | ✓ |  |  |
| 创建/修改任务草稿 | ✓ | ✓ |  |  |
| 校验、预览、发布 JobVersion | ✓ | ✓ |  |  |
| 查看任务和历史版本 | ✓ | ✓ | ✓ | ✓ |
| 创建 Execution / 提交恢复 / 恢复后再次执行 | ✓ |  | ✓ |  |
| 取消 Execution | ✓ |  | ✓ |  |
| 查看 Execution 与日志 | ✓ | ✓ | ✓ | ✓ |
| 查看项目审计 | ✓ | ✓ | ✓ | ✓ |

隐藏按钮不是权限控制。Developer 即使能编辑任务，也不能创建外部端点或自行授予数据源使用权；发布和执行前均须重新校验当前成员的 SOURCE/TARGET 使用授权与 ACTIVE TransferPolicy。`SENSITIVE` 传输需要两名不同 Admin 批准，申请人不能自批。API 对资源存在性和权限同时校验；对无权访问的跨项目 UUID 返回 `404 NOT_FOUND`，避免泄露资源存在。

## 5. 分页与过滤

通用列表请求：

```http
GET /api/v1/projects/{project_id}/executions?state=FAILED&limit=50&cursor=<opaque>
```

通用响应：

```json
{
  "items": [],
  "next_cursor": "eyJ2IjoxLC4uLn0",
  "has_more": false
}
```

规则：

- `limit` 默认 50，范围 1..200；日志单独为 1..1000 行。
- 首次请求不传 cursor；后续原样传 `next_cursor`。
- cursor 绑定路由、项目、筛选条件、排序和授权主体；条件变化必须从第一页开始。
- 非法、过期或跨用户 cursor 返回 `400 CURSOR_INVALID`。
- 默认按 `created_at desc, id desc`；日志按 `sequence asc`；版本按 `version_no desc`。

## 6. 幂等与乐观锁

### 6.1 `Idempotency-Key`

以下操作强制携带 8..128 字符的 `Idempotency-Key`：

- 创建 Project、Datasource、SyncJob；
- 创建 User、解锁用户、重置用户密码；
- 发布 JobVersion；
- 创建 Execution 或恢复后再次执行（机器路径保留 `rerun`）；
- 请求取消 Execution。

同一用户、路由作用域和 key 在 24 小时内：

- 请求体哈希相同：返回首次状态码和响应，带 `Idempotency-Replayed: true`。
- 请求体哈希不同：返回 `409 IDEMPOTENCY_CONFLICT`。
- 请求仍处理中：返回 `409 IDEMPOTENCY_IN_PROGRESS`，可按 `Retry-After` 重试。

PostgreSQL 在读取或创建幂等记录前，必须对 `actor_id + scope + key` 的域分离摘要取得
事务级 advisory try-lock；未取得时立即返回稳定的 `IDEMPOTENCY_IN_PROGRESS`，不得等待
唯一键竞态或把任意 `IntegrityError` 误报成业务冲突。过期记录只能在该锁内删除并重建。
SQLite 仅用于单元测试，以同键进程内 try-lock 模拟相同的非阻塞语义。

连接测试、校验和预览不创建持久业务版本，不强制 Idempotency-Key，但每次仍产生审计。

### 6.2 `If-Match`

GET 单个 Project、Datasource、SyncJob 时返回 `ETag: W/"<row_version>"`。PATCH 必须回传；版本不符返回：

```json
{
  "type": "https://datax-enterprise-studio.local/problems/version-conflict",
  "title": "资源已被其他人修改",
  "status": 409,
  "code": "VERSION_CONFLICT",
  "detail": "请刷新后重新应用修改。",
  "instance": "/api/v1/jobs/...",
  "request_id": "682cf29a-98e0-4fb8-ab22-7460b9fbebf4",
  "retryable": false,
  "field_errors": []
}
```

## 7. 错误契约

错误使用 `application/problem+json`：

| 字段 | 类型 | 说明 |
|---|---|---|
| `type` | URI | 稳定问题类型 |
| `title` | string | 安全的人类可读标题 |
| `status` | integer | HTTP 状态 |
| `code` | string | 前端分支使用的稳定错误码 |
| `detail` | string/null | 已脱敏说明 |
| `instance` | string | 请求路径 |
| `request_id` | UUID | 关联日志 |
| `retryable` | boolean | 是否可在保持幂等语义下重试 |
| `field_errors` | array | 字段级错误，默认空数组 |
| `details` | object/null | 仅稳定、脱敏的结构化细节；容量拒绝只允许公开 `reason` 枚举 |

常用错误码：

| HTTP | code | 含义 |
|---:|---|---|
| 400 | `CURSOR_INVALID` | cursor 无效或条件不一致 |
| 400 | `IDEMPOTENCY_KEY_INVALID` | key 格式错误 |
| 401 | `AUTH_INVALID_CREDENTIALS` | 登录失败，不区分账号是否存在 |
| 401 | `AUTH_TOKEN_EXPIRED` | access token 到期 |
| 403 | `PASSWORD_CHANGE_REQUIRED` | 当前账号必须先修改临时密码 |
| 403 | `FORBIDDEN` | 已认证但无操作权限 |
| 404 | `NOT_FOUND` | 资源不存在或不可见 |
| 409 | `VERSION_CONFLICT` | ETag/row_version 冲突 |
| 409 | `IDEMPOTENCY_CONFLICT` | 同 key 不同请求 |
| 409 | `IDEMPOTENCY_IN_PROGRESS` | 同一 actor/scope/key 正在事务内处理；保留 key 并按 `Retry-After` 重试 |
| 409 | `JOB_NOT_PUBLISHED` | 无可执行版本 |
| 409 | `EXECUTION_NOT_CANCELABLE` | 当前状态不能取消 |
| 409 | `TARGET_ACTIVE_EXECUTION` | 同一 TargetNamespace 已有 `RESERVED/ACTIVE/RECOVERY_REQUIRED` 锁；不同幂等键请求在 API 事务内拒绝，不创建第二个 QUEUED |
| 409 | `TARGET_NOT_EMPTY` | Worker 实测目标表非空，拒绝启动 |
| 409 | `RECOVERY_NOT_VERIFIED` | 失败执行尚未提交如实处置确认或尚未通过平台空表复检 |
| 409 | `RECOVERY_GATE_NOT_APPLICABLE` | Execution 未被 Worker 领取即取消；不创建 Attempt/fence/gate，创建时已有的 `RESERVED` 锁已转为 `RELEASED`，不适用恢复路径 |
| 409 | `TRANSFER_POLICY_NOT_ACTIVE` | 源修订到目标修订的传输策略未激活或已撤销 |
| 410 | `LOG_EXPIRED` | 日志正文已按策略删除 |
| 422 | `VALIDATION_ERROR` | 通用请求校验失败 |
| 422 | `JOB_SPEC_INVALID` | JobSpec 结构或语义错误 |
| 422 | `SOURCE_QUIESCENCE_CONFIRMATION_REQUIRED` | 未确认源端将从运行前检查开始到独立 oracle 完成始终静默 |
| 422 | `TARGET_EXCLUSIVITY_CONFIRMATION_REQUIRED` | 未由 Operator/DBA 确认从 Worker 最后空表观察到 oracle 目标一致性读事务完成期间无平台外 DML/DDL |
| 422 | `TYPE_MAPPING_UNSUPPORTED` | 字段类型不兼容 |
| 422 | `SOURCE_TARGET_SAME_TABLE` | insert-only 源目标指向同一物理表 |
| 422 | `SCHEMA_DRIFT_DETECTED` | 运行前 Schema 与版本快照不同 |
| 502 | `DATASOURCE_CONNECTION_FAILED` | 数据库连接/认证失败 |
| 503 | `RUNTIME_UNAVAILABLE` | Worker/Runtime 未就绪 |
| 503 | `CAPACITY_ADMISSION_BLOCKED` | 普通新 Execution 未通过容量准入；`details.reason` 仅为 `QUEUE_LIMIT/BACKLOG_LIMIT/DISK_YELLOW/DISK_RED/LOG_BUDGET` |
| 503 | `SERVICE_UNAVAILABLE` | 关键依赖不可用 |

错误中不得回显密码、token、完整 JDBC URL、完整 DataX JSON、SQL、堆栈或本机路径。

## 8. 资源接口

以下是 V1 的规范资源面。完整字段和响应码见 OpenAPI。

### 8.1 Auth

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/auth/login` | 登录并创建 refresh session |
| POST | `/auth/refresh` | 旋转 refresh token |
| POST | `/auth/logout` | 幂等撤销 bearer/refresh 能精确证明的 session；凭证缺失、无效、过期或已撤销仍返回 204 并清 Cookie |
| GET | `/auth/me` | 当前用户、可见项目与角色 |
| POST | `/auth/change-password` | 校验旧密码并修改本人密码；撤销其他 session |

### 8.2 User

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/users` | Admin | 分页列出组织用户 |
| POST | `/users` | Admin | 创建用户并设置 write-only 临时密码 |
| GET | `/users/{user_id}` | Admin | 用户状态和角色摘要 |
| PATCH | `/users/{user_id}` | Admin | 启用/停用或修改显示名，需 If-Match |
| PUT | `/users/{user_id}/organization-roles` | Admin | 授予/撤销组织级 Admin；至少保留一名有效 Admin |
| POST | `/users/{user_id}/unlock` | Admin | 清零登录失败计数并解除锁定 |
| POST | `/users/{user_id}/reset-password` | Admin | 设置 write-only 临时密码、要求下次改密并撤销全部 session |

Admin 创建或重置密码时，临时密码只在本机同源 loopback HTTP 请求体中出现，响应不生成
或回显密码。V1 不宣称远程 TLS 服务；若未来开放远程入口，必须先以 ADR 和威胁模型引入
HTTPS。本人改密成功后保留当前 session、撤销其他 session；Admin 重置或停用用户时撤销
全部 session。所有成功、失败和拒绝结果均写审计。

### 8.3 Project

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/projects` | 已认证 | 仅返回可见项目 |
| POST | `/projects` | Admin | 创建项目 |
| GET | `/projects/{project_id}` | 项目成员 | 项目详情 |
| PATCH | `/projects/{project_id}` | Admin | 更新或归档，需 If-Match |
| GET | `/projects/{project_id}/members` | Admin | 成员和角色 |
| PUT | `/projects/{project_id}/members/{user_id}/roles` | Admin | 原子替换项目角色集合；空数组移除项目访问 |

成员响应必须同时返回稳定的 `organization_member_id` 和 `user.id`：角色替换路径使用
`user.id`，数据源用途授权路径使用 `organization_member_id`。前端不得猜测两者相同，
也不得从审计事件或其他项目枚举成员内部 ID。

### 8.4 Dashboard

`GET /projects/{project_id}/dashboard?from=<RFC3339>&to=<RFC3339>` 对所有项目成员开放。`from`、`to` 必填，按 Execution 的 `queued_at` 使用半开区间 `[from, to)`；`from < to` 且窗口最长 31 天。UI 默认传最近 24 小时，服务端不隐式替换时间范围。

固定口径：

- 任务计数以请求时点当前项目的 SyncJob 状态统计；`executable` 表示未归档且至少存在一个 JobVersion。
- Execution 状态计数只包含 `queued_at` 位于窗口内的执行，并返回 `process_state` 全部十个状态（含 `VERIFYING`），缺失状态为 0；同时展示 `data_effect` 与 `verification_state`，不得从进程状态猜测数据结果。
- “已核验复制成功率”固定为
  `count(process_state=SUCCEEDED AND verification_state=PASSED) /
  count(process_state IN [SUCCEEDED, FAILED, TIMED_OUT, LOST])`；取消不计，分母为 0 时
  `ratio=null`。因此 DataX 进程失败即使未进入核验也进入分母。
- 最近失败只取窗口内当前状态为 `FAILED/TIMED_OUT/LOST` 的最近 10 条。
- `unresolved_failure_count` 统计恢复门禁尚未 `VERIFIED` 的 `FAILED/TIMED_OUT/LOST`；恢复后再次执行成功不能反向抹去原执行的数据影响事实。
- `verified_records` 只累计 `process_state=SUCCEEDED` 且 `verification_state=PASSED` 的 oracle `target_row_count`，不累计 DataX 自报的未核验写入数。
- 响应同时返回 process、data effect、verification 三组计数；`drilldowns` 必须原样应用相同 project、from、to、process_states、data_effects、verification_states，不能自行改变口径。

所有卡片均可下钻到 `/projects/{project_id}/jobs` 或 `/projects/{project_id}/executions`。执行列表相应支持 `from`、`to`、重复 `state` 和 `unresolved_failure` 查询参数。

### 8.5 Plugin

`GET /plugins` 的 operationId 为 `listPluginCapabilities`，返回四个只读
`plugin-manifest.v2`。响应分开 `certification_state`、
`ordinary_user_executable`、`evidence` 和 `block_reasons`，并包含上游模块/哈希、
依赖许可状态、网络/文件范围和 oracle 契约。当前生产默认无受信
Windows E4 证据源，因此 Runtime 健康的四插件最多为 `PACKAGED`、
`ordinary_user_executable=false`。公开 Schema 不接受或返回测试注入证据。
没有 POST、上传、启用第三方插件或安装接口。

`POST /jobs/{job_id}/executions` 在创建 `QUEUED+RESERVED` 之前校验发布版本
绑定的 Reader/Writer Phase-B `WINDOWS_E4_CERTIFIED` 资格，以及两端一致的
`evidence.release_promotion_ref`；`POST /executions/{execution_id}/rerun` 在创建
新的恢复执行前做同一校验。Worker 在领取事务和建立工作区/解密凭据前各复检一次。
E4 已具备但缺少该引用时，能力目录必须保持
`ordinary_user_executable=false` 并给出 `RELEASE_PROMOTION_REQUIRED`。这四个检查点
遇到降级、哈希/候选不匹配、证据过期、依赖未盘点、许可未审查、发布晋级引用缺失/格式
无效或 Reader/Writer 引用不一致时，统一失败关闭为
`PLUGIN_WINDOWS_E4_CERTIFICATION_REQUIRED`。

当前候选中的 `release_promotion_ref` 仍是**不透明引用**：实现只校验其存在性、格式和
Reader/Writer 配对一致性，尚没有受信 reader，也没有带签名、可独立校验的候选根/最终
`F` 绑定。因此该字段存在本身不能证明“同一最终 `F` 的有效公开发布晋级（PR）”。生产
证据源仍默认 deny-all，未由此放开任何普通用户能力；后续受信发布纵向切片必须原子引入
结构化、签名的发布晋级契约及其 reader，并同步加强四个检查点和负向验收。

### 8.6 Datasource

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/projects/{project_id}/datasources` | 项目可读 | 分页列表，永不返回密码 |
| POST | `/projects/{project_id}/datasources` | Admin | 命中 ACTIVE EndpointPolicy 后创建首个不可变修订并加密密码 |
| GET | `/datasources/{datasource_id}` | 项目可读 | `DatasourceRedactedSummary`；不返回真实 host/port/database/schema/username |
| GET | `/datasources/{datasource_id}/admin-detail` | Admin | `DatasourceAdminDetail`；可读非秘密连接定位，仍不返回任何 secret |
| PATCH | `/datasources/{datasource_id}` | Admin | 连接字段变化创建新 DatasourceRevision；密码单独轮换，需 If-Match |
| DELETE | `/datasources/{datasource_id}` | Admin | 软删除；有活动引用时 409 |
| GET | `/datasources/{datasource_id}/revisions/{revision_id}` | Admin | 读取真实连接定位字段的不可变修订原始详情 |
| GET | `/datasources/{datasource_id}/credential-secrets` | Admin | 只读 `ACTIVE/RETIRED/REVOKED/COMPROMISED` 生命周期与 Envelope 摘要 |
| POST | `/datasources/{datasource_id}/credential-secrets/{version}/status` | Admin | 已先切换为另一枚 current secret 的历史 `ACTIVE→RETIRED/REVOKED/COMPROMISED`，`RETIRED→REVOKED/COMPROMISED`；直接退役 current secret 返回 `CREDENTIAL_STATUS_CONFLICT`。紧急终态同事务禁用 current 数据源并为受影响的已绑定与未领取工作建立持久终止事实；不可重新激活或降级 |
| POST | `/datasources/{datasource_id}/test` | Admin | 复检 EndpointPolicy、DNS 与出口规则后受限连接测试 |
| GET | `/datasources/{datasource_id}/schema/tables` | 有 `SOURCE_USE/TARGET_USE` | 游标读取表和列元数据 |

创建请求：

```json
{
  "name": "订单库",
  "description": "只读订单源",
  "endpoint_policy_id": "33333333-3333-4333-8333-333333333333",
  "engine": "MYSQL_8",
  "host": "mysql.internal.example",
  "port": 3306,
  "database_name": "sales",
  "default_schema": "sales",
  "username": "datax_reader",
  "password": "<write-only>",
  "ssl_mode": "VERIFY_FULL"
}
```

Admin 创建后的响应使用 `DatasourceAdminDetail`；项目可读的列表和普通详情固定使用最小披露的 `DatasourceRedactedSummary`。后者示例：

```json
{
  "id": "11111111-1111-4111-8111-111111111111",
  "project_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  "name": "订单库",
  "description": "只读订单源",
  "engine": "MYSQL_8",
  "endpoint_redacted": "REDACTED",
  "credential_configured": true,
  "current_revision_id": "11111111-1111-4111-8111-111111111112",
  "current_revision_no": 1,
  "credential_status": "READY",
  "last_test_status": "SUCCEEDED",
  "last_tested_at": "2026-07-30T02:31:00Z",
  "last_test_error_code": null,
  "status": "ACTIVE",
  "row_version": 1,
  "created_at": "2026-07-30T02:30:00Z",
  "updated_at": "2026-07-30T02:30:00Z"
}
```

`DatasourceAdminDetail` 把真实定位字段放在 `current_revision` 中，并固定引用
`endpoint_policy_revision_id` 与 `physical_endpoint_identity_id`；凭据仅以
`CredentialSecretSummary` 表达版本、状态和 ACTIVE Envelope 的非秘密元数据。即使是
Admin 响应，也禁止返回 password、ciphertext、nonce、encrypted DEK、KEK、完整 JDBC URL
或已注入的 DataX JSON。普通项目成员不能通过 revision 路由绕过最小披露。

PATCH 中不包含 `password` 表示不轮换；`password: null` 或空字符串返回 422，不能被解释为清空。

PATCH 可修改 `endpoint_policy_id / engine / host / port / database_name / default_schema /
username / ssl_mode`。这些字段合并当前修订形成候选配置；服务端必须先绑定所选
EndpointPolicy 的当前 ACTIVE 不可变修订，完成 DNS、精确出口、TLS/认证和引擎原生物理
身份探针。成功后才新增 `DatasourceRevision`、保存 TEST 连接证据并原子切换
`current_revision_id`；失败时整个事务回滚。未提交 `password` 时，探针按需解密并安全
复用当前 ACTIVE secret；提交新密码时先用新密码探针，成功后才新增 secret 并退役旧版本。
旧 DatasourceRevision 和历史 secret 永不被覆盖。`status=ACTIVE` 的恢复同样要求真实探针，
不能只改状态字段。

数据源列表按 `created_at desc, id desc` 使用签名 cursor；cursor 绑定调用用户、项目、
`engine` 筛选和排序。元数据列表按 `schema_name asc, table_name asc` 使用签名 cursor；
cursor 绑定调用用户、Datasource、当前 DatasourceRevision、`schema_name/table_name`
筛选和排序。游标被篡改、
跨用户/数据源复用或改变筛选条件时返回 `400 CURSOR_INVALID`，服务端不得忽略 cursor
重新返回第一页。

连接测试的网络/认证失败是一个可审计的测试结果，正常返回 200：

```json
{
  "status": "FAILED",
  "tested_at": "2026-07-30T02:31:00Z",
  "latency_ms": 2100,
  "server_version": null,
  "error_code": "DATABASE_AUTHENTICATION_FAILED",
  "message": "数据库拒绝了认证；请检查账号或密码。",
  "request_id": "3dd59a72-4fca-4a2f-9d6d-b016eeb60f5d"
}
```

Schema 响应中的列类型是数据库原生规范化字符串，不允许前端自行判定兼容性；兼容性以 Job validate 响应为准。元数据请求必须带 `usage=SOURCE_USE|TARGET_USE`；Developer 按精确用途授权，Admin 可按任一用途检查。分页 cursor 绑定该 usage，不能把 SOURCE_USE 的 cursor 改用于 TARGET_USE。

### 8.7 数据移动授权

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET/POST | `/endpoint-policies` | Admin | 列出/创建可变策略身份；创建首个不可变 EndpointPolicyRevision |
| GET/PATCH | `/endpoint-policies/{id}` | Admin | 查看、修改或停用策略；网络字段变化创建新 revision，需 If-Match |
| GET | `/endpoint-policies/{id}/revisions/{revision_id}` | Admin | 读取不可变 FQDN/IP、CIDR、端口、TLS、resolver 与 egress 策略 |
| GET | `/physical-endpoint-identities/{id}` | Admin | 读取不含原生标识明文的 PhysicalEndpointIdentity 证据摘要 |
| GET | `/target-namespaces/{id}` | Admin | 读取不可变 TargetNamespace 与 `physical_table_identity_hash` |
| GET | `/endpoint-connection-evidence/{id}` | Admin | 读取不可变 DNS、selected/peer IP 与 egress 连接证据；项目成员仅见证据 ID |
| GET | `/datasources/{id}/grants` | Admin | 查看数据源使用授权 |
| PUT | `/datasources/{id}/grants/{member_id}` | Admin | 原子替换 `SOURCE_USE/TARGET_USE` |
| GET/POST | `/projects/{id}/transfer-policies` | Admin | 列出/创建源修订到目标修订策略；完整物理端点、表列 scope 和审批信息不向普通项目成员返回 |
| POST | `/transfer-policies/{id}/submit` | Admin | 提交审批 |
| POST | `/transfer-policies/{id}/approvals` | 不同 Admin | STANDARD 一人批准，SENSITIVE 两名不同 Admin 批准 |

EndpointPolicy 创建和修改请求只提交主机、CIDR、端口、TLS 与 DNS TTL 等业务约束；
`resolver_policy_version` 和 `egress_policy_version` 由安装包中的受信服务端常量写入不可变
revision，客户端不得提交或覆盖。两个版本仍在 revision 响应中只读返回，供界面展示和
连接证据核对；实际出口是否有效必须再由同一网络命名空间内的新鲜 egress guard
attestation 证明，不能由版本字符串或环境变量自证。

创建/修改请求使用 `requested_scope`，两侧都必须提交
`catalog/database + schema + table + selection_mode + allowed_columns`。`ALL_COLUMNS` 也必须
先从当前元数据展开为显式 `allowed_columns` 后提交；UI 不发送 `*`、正则或“运行时全部列”。
服务端校验表属于所选 DatasourceRevision，解析 `PhysicalEndpointIdentity`，按引擎标识符
规则规范化、排序和去重后生成响应中的 `scope_json`；客户端不能自报 `scope_hash`。

规范化 `TransferPolicy.scope_json` 必须精确包含 source/target 的
`physical_endpoint_identity_id + catalog + schema + table + allowed_columns`，列数组必须
显式、排序、去重且不得使用 `*`；服务端按
`SHA-256("DXTRANSFERPOLICYv1\n" || RFC8785(scope_json))` 生成 `scope_hash`。
提交审批和每次审批请求都必须带 `expected_scope_hash`。修改 source/target revision、
`requested_scope` 或 classification 会原子清空旧审批、退回 DRAFT 并重算 hash；旧页面的
提交/审批请求返回冲突。STANDARD 需一名非申请人 Admin，SENSITIVE 需两名不同且均非申请人
Admin。

任务 validate、发布和执行前均检查：端点策略为 ACTIVE、操作者具有相应数据源用途授权、
源修订到目标修订存在当前 `scope_hash` 的 ACTIVE TransferPolicy，且 source/target 的每个
mapping 都是两侧精确 scope 的子集。越界一列也必须拒绝。每个
TEST/METADATA/PREFLIGHT/DATAX/ORACLE/RECOVERY_PROBE 连接都保存
`EndpointConnectionEvidence`，固定 EndpointPolicyRevision、全部解析 IP、selected/peer IP
与 egress 证据；不能只在创建数据源时验证一次。平台直接持有 socket 的阶段必须写
`peer_observation_status=OBSERVED` 且 `peer_ip=selected_ip`。独立 Java/JDBC DataX
阶段当前不能可靠回传实际 socket peer，只能在两端精确 IP 内核租约均生效、进程尚未启动
时写 `ENFORCED_NOT_OBSERVED + peer_ip=null`；这表示 selected IP 是唯一允许目的地址，
不表示已观测到 Java peer 或连接成功。API/UI/证据校验器不得把 selected_ip 填入 peer_ip
伪装观测结果。

在实现驱动级 selected-IP socket 固定并保留原 FQDN TLS 身份校验、或把 DataX 拆入不放行
control 子网的独立 netns 之前，执行前 preflight 对任一 `EXACT_FQDN` 返回稳定错误
`DATAX_ENDPOINT_PINNING_UNSUPPORTED`，对 `EXACT_IP + VERIFY_FULL` 返回
`DATAX_VERIFY_FULL_IP_UNCERTIFIED`；两者都必须在 DataX 进程创建前失败且
`verification_state=NOT_STARTED`。这是当前 fail-closed 实现限制，不改变产品目标契约。

### 8.8 复制任务（内部 `SyncJob`）、校验、预览和版本

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/projects/{project_id}/jobs` | 项目可读 | 分页任务列表 |
| POST | `/projects/{project_id}/jobs` | Admin/Developer | 创建任务和首个草稿 |
| GET | `/jobs/{job_id}` | 项目可读 | 当前草稿和发布信息 |
| PATCH | `/jobs/{job_id}` | Admin/Developer | 修改元数据/草稿，需 If-Match，状态回 DRAFT |
| POST | `/jobs/{job_id}/validate` | Admin/Developer | 校验当前已保存草稿 |
| POST | `/jobs/{job_id}/preview` | Admin/Developer | 生成不可执行、已脱敏 DataX JSON |
| GET | `/jobs/{job_id}/versions` | 项目可读 | 不可变版本列表 |
| POST | `/jobs/{job_id}/versions` | Admin/Developer | 发布当前 VALID 草稿 |
| GET | `/jobs/{job_id}/versions/{version_id}` | 项目可读 | 版本详情和快照哈希 |

创建/更新的 `draft_spec` 必须符合 JobSpec schema。保存只做结构和基本资源校验；完整数据库 Schema/类型校验由 validate 完成。

任务列表支持 `q`（任务名、源表名、目标表名）、`status`、`exclude_status`、
`has_published_version`、`reader_plugin`、`writer_plugin` 和
`latest_execution_state`。任务列表和版本历史均按服务端不透明 cursor 翻页；cursor
绑定项目、授权主体、筛选条件与排序，筛选变化后复用旧 cursor 必须返回
`400 CURSOR_INVALID`。前端不得只筛当前页后宣称结果完整。

任务摘要必须同时返回 `latest_published_reader_plugin` 与
`latest_published_writer_plugin`；运行按钮只能按这两个不可变 JobVersion 绑定值查询当前
认证目录，不能用发布后仍可修改的 `draft_spec` 代替已发布版本。

归档仍通过 `PATCH /jobs/{job_id}` 和 `If-Match` 完成。存在非终态 Execution 时返回
`409 JOB_ACTIVE_EXECUTION`；归档只改变可变 `SyncJob` 生命周期，不删除或覆盖任何
`JobVersion`。版本历史响应的 `published_by / published_at` 是只读发布事实，前端必须
展示且不能以当前登录人替换。

V1 的 `execution_policy.dirty_data_limit.record_count` 与 `percentage` 都固定为 `0`。UI 不提供正数阈值输入，API/Schema 拒绝任何非零值；DataX 报告任一脏行时 Execution 不得进入业务成功。正数容忍阈值只可在 POST-V1 经新 ADR、PRD、契约和测试后引入。

Validate 响应：

```json
{
  "valid": false,
  "draft_spec_hash": "b8f1c1b9d7d5565b195859f6d7b6a8a0b7df12de79c00ffbdad28f8e6b4b6998",
  "source_schema_hash": "1b77d8c4c06b9bde93a7eb0a7cd17e4daef68524918ed878b0de1e6744878dbb",
  "target_schema_hash": "45dd20af6408af35852481bcc39a256e9c1ea7401ff551ff7393fb1e19a6709e",
  "errors": [
    {
      "code": "TYPE_MAPPING_UNSUPPORTED",
      "path": "/mappings/1",
      "message": "PostgreSQL jsonb 不能直连映射到 MySQL varchar。"
    }
  ],
  "warnings": []
}
```

Preview 响应只用于展示：

```json
{
  "draft_spec_hash": "b8f1c1b9d7d5565b195859f6d7b6a8a0b7df12de79c00ffbdad28f8e6b4b6998",
  "redacted_datax_json": {
    "job": {
      "content": [
        {
          "reader": {
            "name": "mysqlreader",
            "parameter": {
              "username": "datax_***",
              "password": "${SECRET}"
            }
          }
        }
      ]
    }
  },
  "executable": false,
  "warnings": []
}
```

预览响应不得包含完整连接串、密码、Worker 路径或可直接提交给 Runtime 的 secret。

发布请求：

```json
{
  "expected_draft_spec_hash": "b8f1c1b9d7d5565b195859f6d7b6a8a0b7df12de79c00ffbdad28f8e6b4b6998"
}
```

若当前草稿不是 VALID、哈希变化、数据源被禁用或 Schema 已漂移，返回 409/422，不创建半成品版本。

### 8.9 Execution、取消、恢复和恢复后再次执行

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/projects/{project_id}/executions` | 所有项目成员 | 分页；执行编号/任务、三维状态、目标独占、任务/版本、触发人、时间和恢复来源筛选 |
| POST | `/jobs/{job_id}/executions` | Operator/Admin | 对明确 JobVersion 人工执行 |
| GET | `/executions/{execution_id}` | 所有项目成员 | 状态、摘要和失败信息 |
| POST | `/executions/{execution_id}/cancel` | Operator/Admin | 创建取消请求，不由 API 直接推进状态 |
| POST | `/executions/{execution_id}/target-exclusivity/revoke` | Operator/Admin | 撤回目标外部独占声明或报告已知窗口破坏；写不可变审计 |
| GET/POST | `/executions/{execution_id}/recovery` | Operator/Admin | 查看/提交处置确认（`remediation_confirmation`）；无需清理时如实记录理由；POST 创建独立 RecoveryProbe 事实 |
| GET | `/recovery-probes/{recovery_probe_id}` | 项目可读 | 查看独立 probe 的队列、fence、空表结果与安全连接证据摘要 |
| POST | `/executions/{execution_id}/rerun` | Operator/Admin | 机器路径保留 `rerun`；用户动作是“恢复后再次执行”，绑定 VERIFIED gate 并创建新 Execution |
| GET | `/executions/{execution_id}/logs` | 所有项目成员 | 游标读取脱敏日志 |
| GET | `/executions/{execution_id}/logs/download` | 所有项目成员 | 服务端生成并审计脱敏文本下载 |

执行列表支持 `q`、可重复的 `process_state / data_effect /
verification_state / target_exclusivity_status`、`job_id`、
`job_version_id`、`requested_by`、半开区间 `from / to`、`is_rerun` 和
`unresolved_failure`。cursor 必须绑定上述全部筛选、项目、授权主体与
`queued_at DESC, id DESC` 排序；筛选或主体不一致时 fail closed 为
`CURSOR_INVALID`。列表和详情同时返回 `requested_by`，并始终并列返回
`process_state / data_effect / verification_state`。

执行请求：

```http
POST /api/v1/jobs/6f499e28-b9a1-4cc7-af55-e347014816a4/executions
Idempotency-Key: 01J43MRE4Q3W8FNF4PMY90M4W4

{
  "job_version_id": "b64006fc-5a22-4e48-a0bd-f9cb1440031f",
  "source_quiescence_confirmation": {
    "confirmed": true,
    "confirmed_at": "2026-07-30T02:39:30Z",
    "note": "已暂停源表写入，保持至核验结束"
  },
  "target_exclusivity_confirmation": {
    "statement_version": "1.0",
    "confirmed": true,
    "confirmed_at": "2026-07-30T02:39:35Z",
    "valid_until": "2026-07-30T06:39:35Z",
    "responsible_party": "DBA",
    "note": "已冻结目标表平台外 DML/DDL，保持至目标核验快照事务完成"
  }
}
```

返回 `202 Accepted`：

```json
{
  "id": "19bda447-c18e-4bca-bd45-11aed51eb33c",
  "project_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  "job_id": "6f499e28-b9a1-4cc7-af55-e347014816a4",
  "job_version_id": "b64006fc-5a22-4e48-a0bd-f9cb1440031f",
  "rerun_of_execution_id": null,
  "trigger_type": "MANUAL",
  "process_state": "QUEUED",
  "data_effect": "NONE",
  "verification_state": "NOT_STARTED",
  "target_exclusivity_confirmation": {
    "statement_version": "1.0",
    "confirmed": true,
    "confirmed_at": "2026-07-30T02:39:35Z",
    "valid_until": "2026-07-30T06:39:35Z",
    "responsible_party": "DBA",
    "note": "已冻结目标表平台外 DML/DDL，保持至目标核验快照事务完成"
  },
  "target_exclusivity_status": "ACTIVE",
  "target_exclusivity_revoked_at": null,
  "target_exclusivity_revocation_reason": null,
  "source_datasource_revision_id": "11111111-1111-4111-8111-111111111112",
  "target_datasource_revision_id": "22222222-2222-4222-8222-222222222223",
  "source_endpoint_policy_revision_id": "11111111-1111-4111-8111-111111111113",
  "target_endpoint_policy_revision_id": "22222222-2222-4222-8222-222222222224",
  "target_namespace_id": "55555555-5555-4555-8555-555555555555",
  "target_copy_lock": {
    "target_namespace_id": "55555555-5555-4555-8555-555555555555",
    "state": "RESERVED",
    "reserved_at": "2026-07-30T02:40:00Z",
    "activated_at": null,
    "released_at": null,
    "fence_epoch": null
  },
  "source_secret_version": null,
  "target_secret_version": null,
  "source_secret_envelope_id": null,
  "target_secret_envelope_id": null,
  "source_connection_evidence_id": null,
  "target_connection_evidence_id": null,
  "capacity_profile": "LARGE",
  "service_reservation_seconds": 3600,
  "queue_eligibility_state": "ELIGIBLE",
  "queue_block_reason": null,
  "queue_state_changed_at": "2026-07-30T02:40:00Z",
  "eligible_wait_milliseconds": 0,
  "log_incomplete": false,
  "log_raw_received_bytes": 0,
  "log_redacted_received_bytes": 0,
  "log_stored_bytes": 0,
  "log_dropped_bytes": 0,
  "resolved_config_hash": null,
  "runtime_snapshot": null,
  "verification_summary": null,
  "queued_at": "2026-07-30T02:40:00Z",
  "started_at": null,
  "finished_at": null,
  "exit_code": null,
  "failure_code": null,
  "failure_message": null,
  "summary_parse_status": "PENDING",
  "run_summary": null
}
```

`TargetExclusivityConfirmation` 必须同时包含
`statement_version="1.0" / confirmed_at / valid_until / responsible_party`，且
`valid_until > confirmed_at`。Execution 对外状态为 `ACTIVE / REVOKED / EXPIRED`：
`ACTIVE` 时 `revoked_at/reason` 均为 null；`REVOKED` 时二者必填；`EXPIRED` 时
`revoked_at=null` 且 reason 固定为 `VALIDITY_WINDOW_EXPIRED`。终态 Execution 保留作出
结论时的状态，不因查询时墙上时钟已经越过有效期而改写历史。

Operator/DBA 知悉冻结被撤回或窗口内发生平台外 DML/DDL 时必须报告：

```http
POST /api/v1/executions/19bda447-c18e-4bca-bd45-11aed51eb33c/target-exclusivity/revoke
Idempotency-Key: 01J43MRF4Q3W8FNF4PMY90M4W5

{
  "statement_version": "1.0",
  "responsible_party": "DBA",
  "reason": "EXTERNAL_DML_DDL_REPORTED",
  "reported_at": "2026-07-30T03:15:00Z",
  "note": "发现维护账号在窗口内执行过目标表 DDL"
}
```

`reason` 仅允许 `OPERATOR_REVOKED`、`DBA_REVOKED`、
`EXTERNAL_DML_DDL_REPORTED` 或 `CHANGE_FREEZE_BROKEN`。`responsible_party` 必须与原
Execution 固化的确认责任类型一致，服务端以原值为准。API 原子保存
`REVOKED`、`revoked_at/reason`、`TARGET_EXCLUSIVITY_REVOKED` 审计和独立
`WorkTerminationRequest`，但不直接写三组执行状态：未领取执行由 reconciler 取消并释放
`RESERVED`；已领取执行由 Worker 终止并进入恢复门禁；`VERIFYING` 中的报告使 oracle
形成 `INCONCLUSIVE/TARGET_EXCLUSIVITY_BROKEN`。安全终止原因优先于并发人工取消。该 API
不能把数据库提交与 OS `Popen` 或阻塞 JDBC 变成原子动作；Worker 只在有界控制点停止，无法
及时返回时保守收敛为 `LOST`。终态请求返回 409。

API 创建 Execution 的事务必须同时写 `QUEUED` 与
`TargetCopyLock(state=RESERVED)`；`TargetNamespace` 部分唯一索引覆盖
`RESERVED/ACTIVE/RECOVERY_REQUIRED`。同目标第二个不同 `Idempotency-Key` 请求在 API
返回 `409 TARGET_ACTIVE_EXECUTION`，不得创建多个同目标 QUEUED 再等待 Worker 失败；同一
幂等键只重放原 Execution。Worker 领取事务原子执行 `RESERVED→ACTIVE`，并创建 Attempt、
单调 fence 与运行快照。

取消请求返回 `202` 和 CancelRequest。对于未领取的 `QUEUED + PENDING` 请求，reconciler
直接收敛为 `CANCELED/NONE/NOT_STARTED`，把 RESERVED 锁更新为 `RELEASED`，且不创建
Attempt/fence 或 RecoveryGate；已经领取的执行才由 Worker 写入 `CANCEL_REQUESTED`、
终止进程树并把锁转为 `RECOVERY_REQUIRED`。前端应先展示“取消请求已提交”，不能立即显示“已取消”，也不能仅看到
`CANCELED` 就开放 recovery：必须以服务端是否存在 RecoveryGate 为准。

状态必须拆分展示：

- `process_state`：`QUEUED / STARTING / RUNNING / VERIFYING / SUCCEEDED / FAILED / TIMED_OUT / CANCEL_REQUESTED / CANCELED / LOST`。
- `data_effect`：`NONE / POSSIBLE / CONFIRMED / UNKNOWN`。其中 `CONFIRMED` 只表示目标影响已测得，测得值可以是 0 行；它不表示发生了非零写入，也不表示内容正确。空源成功仍是 `SUCCEEDED/CONFIRMED/PASSED`。
- `verification_state`：`NOT_STARTED / VERIFYING / PASSED / FAILED / INCONCLUSIVE`。Oracle 从未启动时始终为 `NOT_STARTED`，即使 DataX 已异常退出；只有 oracle 已启动却因静默破坏、排他前提破坏、锁丢失或读取失败而无法形成数据结论时才是 `INCONCLUSIVE`。

DataX 退出码 0 后 `process_state` 只能进入 `VERIFYING`；在 oracle 真正启动前
`verification_state` 仍为 `NOT_STARTED`，启动后才为 `VERIFYING`。独立 `oracle-v1`
数据比对通过、目标声明状态仍为 `ACTIVE`、`revoked_at/reason` 为空、目标一致性快照
`finished_at <= valid_until` 且脏行数为 0 后，才进入
`SUCCEEDED + CONFIRMED + PASSED`。`REVOKED / EXPIRED` 或快照越过截止时间时不得
`PASSED`。Oracle 得出差异时为 `FAILED`，已启动但无法形成结论时为 `INCONCLUSIVE`；
两者都使 `process_state=FAILED`。不得把 DataX 写入统计冒充核验结果。

领取是单个 PostgreSQL 事务：事务提交前任一失败必须整体回滚，Execution 仍是未领取的
`QUEUED`，原 API 预留保持 `TargetCopyLock=RESERVED`，不存在 Attempt、fence 或已固定
secret/Envelope。领取事务一旦
提交，除唯一 `SUCCEEDED/CONFIRMED/PASSED` 外的任何终态都不得回到 `QUEUED`、不得复用
Attempt 或自动重新入队，统一进入恢复门禁。

已领取执行的失败、超时、取消、丢失或核验失败可能已产生部分写入。Operator 先通过
recovery 接口提交 `remediation_confirmation`，字段固定为
`action/cleanup_performed/reason/confirmed_at`。需要清理时如实记录实际动作；确认无需清理时
使用 `NO_CLEANUP_REQUIRED + cleanup_performed=false` 并写明理由，不能被强制虚假声称已
清理。API 只创建独立
`RecoveryProbe(QUEUED)`，Worker 使用 probe 自身的 Attempt、lease 和单调 fence 在目标锁
下实测为空。只有 `SUCCEEDED + EMPTY` 才能把 RecoveryGate 原子写为 `VERIFIED`。机器
`rerun` 请求随后才能携带该 gate ID。未领取即取消的 Execution 没有 gate，不走 recovery
或 `rerun`。恢复后再次执行不复用原 Execution ID、不解析“最新版本”，而是绑定原
JobVersion；新执行启动前仍需重新提交源静默确认，以及声明版本为 `1.0`、具备新
`valid_until` 的目标排他确认，复检目标为空并取得同一 TargetNamespace 活动锁。目标排他
确认、接受 actor/时间和摘要固化在 Execution 运行快照，并产生
`TARGET_EXCLUSIVITY_CONFIRMED` 审计事件。领取事务提交后、真实 preflight 尚未完成的
`STARTING` Execution 可返回 `runtime_snapshot=null`；这不表示未领取，调用方必须结合
Attempt 和目标锁的 `activated_at/fence_epoch` 判断。当前 fenced Attempt 完成 preflight
后才一次性写入只读 `runtime_snapshot`，其中至少包含以下目标声明片段（完整对象还包含
Runtime、插件、revision、policy、secret envelope、目标空表证据与 fence）：

```json
{
  "target_exclusivity_confirmed_by": "33333333-3333-4333-8333-333333333333",
  "target_exclusivity_responsible_party": "DBA",
  "target_exclusivity_accepted_at": "2026-07-30T02:40:10Z",
  "target_exclusivity_statement_version": "1.0",
  "target_exclusivity_valid_until": "2026-07-30T06:39:35Z",
  "target_exclusivity_confirmation_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}
```

完整运行快照写入后不可变；`RUNNING` 及之后状态必须已有完整快照。后续撤回/过期由
Execution 生命周期字段和追加式审计表达。Oracle 的
`target_result` 必须记录单一一致性读事务的 `snapshot_id` 及开始/结束边界；多时点查询
拼接不得通过。

Execution 对外返回源/目标 `DatasourceRevision`、EndpointPolicyRevision、
TargetNamespace、CredentialSecret/Envelope 的非秘密版本身份、连接证据 ID、
TransferPolicy `scope_hash`、容量档位/eligible 等待、日志四计数、`resolved_config_hash`
和不含连接串/密钥的 `runtime_snapshot`，使历史结果可以追踪；完整已注入 DataX 配置永不返回或持久化。普通新 Execution 若触发容量门禁，返回
`503 CAPACITY_ADMISSION_BLOCKED`，安全 `details.reason` 仅允许
`QUEUE_LIMIT/BACKLOG_LIMIT/DISK_YELLOW/DISK_RED/LOG_BUDGET`。

### 8.10 日志游标

请求：

```http
GET /api/v1/executions/19bda447-c18e-4bca-bd45-11aed51eb33c/logs?limit=200&cursor=<opaque>
```

响应：

```json
{
  "items": [
    {
      "sequence": 1042,
      "timestamp": "2026-07-30T02:41:03.120Z",
      "stream": "STDOUT",
      "level": "INFO",
      "message": "任务平均流量: 12.4MB/s",
      "line_truncated": false,
      "raw_received_bytes": 31,
      "redacted_received_bytes": 31,
      "stored_bytes": 31,
      "dropped_bytes": 0
    }
  ],
  "next_cursor": "eyJleGVjdXRpb25faWQiOiIuLi4iLCJuZXh0X3NlcXVlbmNlIjoxMDQzfQ",
  "eof": false,
  "redaction_rules_version": "1.0",
  "truncated": false,
  "incomplete": false,
  "raw_received_bytes": 8192,
  "redacted_received_bytes": 8192,
  "stored_bytes": 8192,
  "reason": "NONE",
  "dropped_bytes": 0,
  "first_truncated_sequence": null,
  "gap_count": 0,
  "gaps": [],
  "expires_at": "2026-08-29T02:40:00Z"
}
```

规则：

- `sequence` 在单 Execution 内单调递增且不重复。
- 相同 cursor 重放返回相同边界，不跳行。
- `eof=true` 仅表示当前已无更多日志；Execution 未终态时可继续用 `next_cursor` 轮询。
- 日志默认保留 30 天；正文到期返回 `410 LOG_EXPIRED`，Execution 摘要仍可查看。
- V1 使用 HTTP cursor 轮询，不提供旧提纲中的 WebSocket `/logs/{id}`。
- V1 关键词搜索仅搜索浏览器已通过 cursor 加载的脱敏内容，不承诺服务端全文检索；UI 必须显示当前搜索覆盖范围。
- 页面和下载都只能称为“脱敏后的原序日志”，不能称为未脱敏原始日志。
- 每行、每个 LogChunk、每个 LogGap 与 Execution 汇总都分别累计
  `raw_received_bytes`（脱敏前只计数）、`redacted_received_bytes`（脱敏后截断前）、
  `stored_bytes` 和 `dropped_bytes`；独立 validator 强制
  `dropped_bytes = redacted_received_bytes - stored_bytes`。raw 与 redacted 可因占位符
  长度变化而不同，不能用差值推断秘密长度。
- 任一日志缺失、不连续、截断、解码/脱敏/存储失败或 fence 丢失都必须返回显式
  `LogGap`，并使 `incomplete=true`；`eof=true` 不能暗示日志完整。
- `truncated=true` 时必须同时返回四类字节计数、`dropped_bytes` 和
  `reason=EXECUTION_LIMIT|LINE_LIMIT|RING_EVICTION`；这些字节未持久化，cursor 与下载均
  不能恢复，UI 必须持续显示不完整标识。
- 下载由服务端从已持久化的脱敏 LogChunk 重新组装 UTF-8 文本，响应为 `text/plain`
  attachment，并返回脱敏规则版本、SHA-256、`X-Log-Incomplete`、四类字节计数、
  `X-Log-Gap-Count` 与相同截断元数据。
- V1 单次下载上限为 100 MiB（已持久化脱敏内容的未压缩大小）；超过时返回 `413 LOG_EXPORT_TOO_LARGE`，不能把响应上限与采集阶段日志截断混为一谈。
- 下载成功、失败和拒绝均写 `EXECUTION_LOG_EXPORTED` 审计；到期日志返回 `410 LOG_EXPIRED`。

### 8.11 Audit

`GET /projects/{project_id}/audit-events` 支持 `action`、`outcome`、`actor_id`、`from`、`to` 和 cursor。响应事件符合 `audit-event.v1.schema.json`。

所有项目成员均可读取已授权项目的审计。`GET /audit-events` 仅供组织级 Admin 跨项目筛选。审计默认保留 730 天。前端不得显示或导出 `event_hash` 之外的密钥材料，不提供编辑/删除接口。

### 8.12 Health

两个路由只用于 Windows launcher 和本机页面，经
`http://127.0.0.1:17860/api/v1` 同源入口访问；无认证不等于允许 LAN/公网访问。Docker
Desktop、WSL2、虚拟化、Compose 版本、端口和宿主 ACL 属于 launcher 启动前检查，不伪装
成 backend 自己能够证明的组件状态。

| 方法 | 路径 | 认证 | 含义 |
|---|---|---|---|
| GET | `/health/live` | 否（loopback-only） | 经 `web` 反向代理的 backend 进程可响应 |
| GET | `/health/ready` | 否（loopback-only） | 管理平面关键门及 dispatcher、Worker/固定 Linux Runtime、独立 oracle、egress 等能力状态 |

Health 响应不得暴露 Windows 用户名、`%LOCALAPPDATA%` 绝对路径、主机/容器地址、数据库
DSN、密码、容器环境变量、Docker secret 路径或堆栈。管理平面关键门失败返回
`503/DOWN`；管理平面可用但执行能力被阻断返回 `200/DEGRADED`，此时 launcher 可打开
浏览器用于配置和诊断，但页面与执行 API 必须明确阻断新任务，不能显示“任务可运行”。
容器仅为 running 或 live=200 不能替代 readiness。

launcher 的“停止服务”不通过新增远程 HTTP 端点实现。它只能调用安装包内固定、签名且
参数不可由用户扩展的 Compose/容器 lifecycle helper：先让 Worker 停止新领取，等待活动
Attempt 结束后再 graceful stop。仍有活动工作时默认拒绝直接停止；明确强制停止后，下次
启动必须由 Worker/reconciler 将无法证明连续受控的 Attempt 收敛为 `LOST` 并保留恢复
门禁。

## 9. 前端状态处理

- 分别按 `process_state / data_effect / verification_state` 渲染，不从日志文本或 DataX exit code 猜测数据成功。
- SyncJob 编辑后立即按响应切换为 DRAFT；只有 validate 响应成功后显示 VALID。
- 发布成功后展示新 version_no，不覆盖旧版本。
- Execution 在 `CANCEL_REQUESTED` 前可能已存在待处理 CancelRequest；分别展示。只有服务端返回 RecoveryGate 时才展示恢复入口，不能仅按 `CANCELED` 状态推断。
- `VERIFYING` 不显示成功；`LOST` 不自动重跑；用户发起恢复后再次执行前必须通过恢复门禁并产生新记录。
- 401 只自动 refresh 一次；403 展示无权限；404 不推断资源属于其他项目。
- 409 VERSION_CONFLICT 先保留用户本地编辑，再刷新并提示人工合并。
- 422 使用 `field_errors[].path` 定位表单；未知 path 展示在页面级错误区。
- 日志断线后使用最后一个服务端 cursor 续传，不能用本地行号拼 cursor。

## 10. API 兼容与弃用

- `/api/v1` 内新增可选响应字段是向后兼容；删除字段、改变枚举或语义不是。
- 请求对象默认拒绝未知字段，新增请求字段必须可选或发布新契约版本。
- JobSpec、Plugin Manifest、AuditEvent 分别维护自身 `schema_version`。
- 已发布 JobVersion 永远按原 JobSpec schema 读取；不在后台静默升级。
- 弃用至少保留一个发布周期，并在 OpenAPI 标记 `deprecated` 和替代路径。

## 11. 契约验收

1. OpenAPI 3.1 可解析，所有 `$ref` 可解析到存在的本地 schema。
2. 示例 JobSpec 可通过 JSON Schema，且五项传输策略固定为 `OPERATOR_QUIESCED / EMPTY_AND_VERIFIABLE / INSERT_ONLY_ONCE / REJECT_NONEMPTY_TARGET / MANUAL_REMEDIATE`；加入任意 SQL、未知插件或未知字段会失败。
3. 所有列表接口都有稳定排序、cursor、limit 和跨授权主体校验。
4. 所有强制幂等接口覆盖首次、重放、处理中和冲突测试。
5. 所有 PATCH 覆盖正确 ETag、缺失 If-Match 和版本冲突测试。
6. 四类角色和多角色并集均有允许/拒绝 API 测试。
7. 项目可读 Datasource 响应只符合 `DatasourceRedactedSummary`，真实
   host/port/database/schema/username 只允许 AdminDetail 与 Admin-only revision 路由；
   所有响应、错误、日志和审计均没有密码或密钥材料。
8. EndpointPolicyRevision、PhysicalEndpointIdentity、TargetNamespace、TransferPolicy
   精确 scope、CredentialSecret 生命周期、RecoveryProbe、LogGap 与四类日志计数均有
   正反契约测试。
9. Execution 创建原子写入 QUEUED+RESERVED、同目标不同幂等键 API 冲突、Worker 原子
   `RESERVED→ACTIVE+Attempt+fence`、未领取取消释放预留、源静默确认、有版本/有限期的
   目标排他确认、`ACTIVE/REVOKED/EXPIRED` 与撤回/报告接口、空表证据、三类状态、
   `RUNNING→VERIFYING→SUCCEEDED`、取消、恢复门禁、恢复后再次执行、容量拒绝、日志
   缺口/截断/续传/到期和 LOST 均有契约测试。
10. 独立核验产物通过 `verification-oracle.v1.schema.json`：`artifact_sha256` 必填；
    oracle 未启动时没有伪造产物且状态为 `NOT_STARTED`，`INCONCLUSIVE` 只用于已启动但无法
    形成结论并且必有原因；读取尚未形成的单侧结果/差异字段可为 null，禁止填充伪造的 0/hash。
    `PASSED` 固定源静默/目标锁/目标排他窗口为 true、声明状态为 `ACTIVE`、
    `revoked_at` 为 null、`target_result.snapshot_finished_at <= valid_until`、脏行数与差异为
    0、`row_count_equal/multiset_sha256_equal=true`。目标结果还必须来自一个有明确 ID 和
    时间边界的一致性读事务；独立语义 validator 另行强制源/目标字段实际相等、确认窗口覆盖
    最后空表观察至快照完成，以及制品哈希重算。该证据不被解释为能够检测所有未报告或
    已经回滚的外部 DML/DDL。
11. 候选版本证据通过 `acceptance-manifest.v1.schema.json`。独立 CI validator 用
    `requirements_catalog_sha256` 固定需求目录，把 V1-MUST 需求集合与 manifest entries
    做集合比对，并验证 coverage 计数、`catalog_exact_match`、缺失 ID 和重复“需求 ID +
    测试 ID”对；PASS 时两个缺口数组必须为空且 `catalog_exact_match=true`。
12. API 实现生成的审计事件通过 AuditEvent schema，日志和审计不包含 secret。
13. OpenAPI server 只声明 `http://127.0.0.1:17860/api/v1`；
    Compose/宿主监听测试证明只有 `web` 映射该 loopback 端口，`api`、`worker`、
    `postgres` 没有宿主端口。
14. 非允许 Host、跨 Origin、CORS 预检、伪造 Forwarded 头和从 LAN IP 访问均被拒绝；
    health 响应不泄露 Windows 路径、容器地址、DSN 或 secret。
15. launcher 只在 ready=200 后打开浏览器；Docker/WSL2 缺失、端口冲突、named volume/
    Runtime 不就绪时显示失败；首次 Admin 只经 launcher GUI/标准输入的固定 helper 创建；
    强制停止后的已领取工作收敛为 `LOST` 而不是自动续跑。
