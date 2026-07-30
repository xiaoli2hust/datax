# DataX Enterprise Studio API 接口与前后端契约

> 文档状态：V1 实施基线
>
> API 版本：`v1`
>
> 规范文件：[`contracts/openapi.yaml`](./contracts/openapi.yaml)
> JobSpec：[`contracts/job-spec.v1.schema.json`](./contracts/job-spec.v1.schema.json)

## 1. 契约优先级

`contracts/openapi.yaml` 和三个 JSON Schema 是机器可校验的权威格式。本文解释交互语义、权限、错误和前端处理方式；若示例与机器契约冲突，先修复两者再编码，不能静默选择其中一个。

V1 API 只提供离线批同步的人工操作，不暴露调度、DAG、告警、AI、插件安装、任意 SQL、Transformer 或原始 DataX JSON 执行接口。

## 2. 通用约定

| 主题 | 约定 |
|---|---|
| Base URL | `/api/v1` |
| 协议 | 生产 HTTPS；本地可由同源 reverse proxy 提供 HTTP |
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

## 3. 认证与会话

### 3.1 Access token

- Access token 是短时效 JWT，仅通过 `Authorization` header 发送。
- 前端只保存在内存，不写 localStorage、sessionStorage、IndexedDB 或 URL。
- JWT 至少包含 `sub`、`org_id`、`session_id`、`iat`、`exp`、`jti`。
- 项目角色每次在服务端查询或从可立即失效的授权缓存读取，不能只信任长期 token 中的角色。

### 3.2 Refresh token

- 登录成功后由 `Set-Cookie` 写入 `des_refresh`。
- Cookie 必须为 `HttpOnly; Secure; SameSite=Lax; Path=/api/v1/auth`。
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
    "display_name": "值班工程师"
  }
}
```

密码只允许出现在 TLS 请求体的瞬时内存中，不得进入日志、Trace、错误或审计。

## 4. RBAC

一个用户可拥有多个角色，权限取并集。组织级 Admin 可访问组织内全部项目；其他角色必须在项目作用域内授予。

| 能力 | Admin | Developer | Operator | Viewer |
|---|:---:|:---:|:---:|:---:|
| 创建、停用、解锁和重置用户密码 | ✓ |  |  |  |
| 创建/归档项目、管理成员 | ✓ |  |  |  |
| 查看项目和脱敏数据源 | ✓ | ✓ | ✓ | ✓ |
| 创建/更新/测试数据源、轮换密码 | ✓ | ✓ |  |  |
| 创建/修改任务草稿 | ✓ | ✓ |  |  |
| 校验、预览、发布 JobVersion | ✓ | ✓ |  |  |
| 查看任务和历史版本 | ✓ | ✓ | ✓ | ✓ |
| 创建 Execution / 人工重跑 | ✓ |  | ✓ |  |
| 取消 Execution | ✓ |  | ✓ |  |
| 查看 Execution 与日志 | ✓ | ✓ | ✓ | ✓ |
| 查看项目审计 | ✓ | ✓ | ✓ | ✓ |

隐藏按钮不是权限控制。API 对资源存在性和权限同时校验；对无权访问的跨项目 UUID 返回 `404 NOT_FOUND`，避免泄露资源存在。

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
- 创建 Execution 或人工重跑；
- 请求取消 Execution。

同一用户、路由作用域和 key 在 24 小时内：

- 请求体哈希相同：返回首次状态码和响应，带 `Idempotency-Replayed: true`。
- 请求体哈希不同：返回 `409 IDEMPOTENCY_CONFLICT`。
- 请求仍处理中：返回 `409 IDEMPOTENCY_IN_PROGRESS`，可按 `Retry-After` 重试。

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

常用错误码：

| HTTP | code | 含义 |
|---:|---|---|
| 400 | `CURSOR_INVALID` | cursor 无效或条件不一致 |
| 400 | `IDEMPOTENCY_KEY_INVALID` | key 格式错误 |
| 401 | `AUTH_INVALID_CREDENTIALS` | 登录失败，不区分账号是否存在 |
| 401 | `AUTH_TOKEN_EXPIRED` | access token 到期 |
| 403 | `FORBIDDEN` | 已认证但无操作权限 |
| 404 | `NOT_FOUND` | 资源不存在或不可见 |
| 409 | `VERSION_CONFLICT` | ETag/row_version 冲突 |
| 409 | `IDEMPOTENCY_CONFLICT` | 同 key 不同请求 |
| 409 | `JOB_NOT_PUBLISHED` | 无可执行版本 |
| 409 | `EXECUTION_NOT_CANCELABLE` | 当前状态不能取消 |
| 410 | `LOG_EXPIRED` | 日志正文已按策略删除 |
| 422 | `VALIDATION_ERROR` | 通用请求校验失败 |
| 422 | `JOB_SPEC_INVALID` | JobSpec 结构或语义错误 |
| 422 | `TYPE_MAPPING_UNSUPPORTED` | 字段类型不兼容 |
| 422 | `SOURCE_TARGET_SAME_TABLE` | insert-only 源目标指向同一物理表 |
| 422 | `SCHEMA_DRIFT_DETECTED` | 运行前 Schema 与版本快照不同 |
| 502 | `DATASOURCE_CONNECTION_FAILED` | 数据库连接/认证失败 |
| 503 | `RUNTIME_UNAVAILABLE` | Worker/Runtime 未就绪 |
| 503 | `SERVICE_UNAVAILABLE` | 关键依赖不可用 |

错误中不得回显密码、token、完整 JDBC URL、完整 DataX JSON、SQL、堆栈或本机路径。

## 8. 资源接口

以下是 V1 的规范资源面。完整字段和响应码见 OpenAPI。

### 8.1 Auth

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/auth/login` | 登录并创建 refresh session |
| POST | `/auth/refresh` | 旋转 refresh token |
| POST | `/auth/logout` | 撤销当前 session |
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

Admin 创建或重置密码时，临时密码只在 TLS 请求体中出现，响应不生成或回显密码。本人改密成功后保留当前 session、撤销其他 session；Admin 重置或停用用户时撤销全部 session。所有成功、失败和拒绝结果均写审计。

### 8.3 Project

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/projects` | 已认证 | 仅返回可见项目 |
| POST | `/projects` | Admin | 创建项目 |
| GET | `/projects/{project_id}` | 项目成员 | 项目详情 |
| PATCH | `/projects/{project_id}` | Admin | 更新或归档，需 If-Match |
| GET | `/projects/{project_id}/members` | Admin | 成员和角色 |
| PUT | `/projects/{project_id}/members/{user_id}/roles` | Admin | 原子替换项目角色集合；空数组移除项目访问 |

### 8.4 Dashboard

`GET /projects/{project_id}/dashboard?from=<RFC3339>&to=<RFC3339>` 对所有项目成员开放。`from`、`to` 必填，按 Execution 的 `queued_at` 使用半开区间 `[from, to)`；`from < to` 且窗口最长 31 天。UI 默认传最近 24 小时，服务端不隐式替换时间范围。

固定口径：

- 任务计数以请求时点当前项目的 SyncJob 状态统计；`executable` 表示未归档且至少存在一个 JobVersion。
- Execution 状态计数只包含 `queued_at` 位于窗口内的执行，并返回全部九个状态，缺失状态为 0。
- 成功率分子为 `SUCCEEDED`；分母为 `SUCCEEDED + FAILED + TIMED_OUT + LOST`。分母为 0 时 `ratio=null`。
- 最近失败只取窗口内当前状态为 `FAILED/TIMED_OUT/LOST` 的最近 10 条。
- `unresolved_failure_count` 统计尚无成功人工重跑的失败、超时或丢失执行。
- 响应 `drilldowns` 返回结构化列表筛选；前端必须原样应用相同 project、from、to、states，不能自行改变口径。

所有卡片均可下钻到 `/projects/{project_id}/jobs` 或 `/projects/{project_id}/executions`。执行列表相应支持 `from`、`to`、重复 `state` 和 `unresolved_failure` 查询参数。

### 8.5 Plugin

`GET /plugins` 返回四个只读认证 manifest：MySQL Reader/Writer、PostgreSQL Reader/Writer。没有 POST、上传、启用第三方插件或安装接口。

### 8.6 Datasource

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/projects/{project_id}/datasources` | 项目可读 | 分页列表，永不返回密码 |
| POST | `/projects/{project_id}/datasources` | Admin/Developer | 创建并加密密码 |
| GET | `/datasources/{datasource_id}` | 项目可读 | 脱敏详情 |
| PATCH | `/datasources/{datasource_id}` | Admin/Developer | 更新/轮换密码，需 If-Match |
| DELETE | `/datasources/{datasource_id}` | Admin/Developer | 软删除；有活动引用时 409 |
| POST | `/datasources/{datasource_id}/test` | Admin/Developer | 受限连接测试 |
| GET | `/datasources/{datasource_id}/schema/tables` | Admin/Developer | 游标读取表和列元数据 |

创建请求：

```json
{
  "name": "订单库",
  "description": "只读订单源",
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

响应：

```json
{
  "id": "11111111-1111-4111-8111-111111111111",
  "project_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  "name": "订单库",
  "description": "只读订单源",
  "engine": "MYSQL_8",
  "host": "mysql.internal.example",
  "port": 3306,
  "database_name": "sales",
  "default_schema": "sales",
  "username": "datax_reader",
  "ssl_mode": "VERIFY_FULL",
  "credential_configured": true,
  "status": "ACTIVE",
  "row_version": 1,
  "created_at": "2026-07-30T02:30:00Z",
  "updated_at": "2026-07-30T02:30:00Z"
}
```

PATCH 中不包含 `password` 表示不轮换；`password: null` 或空字符串返回 422，不能被解释为清空。

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

Schema 响应中的列类型是数据库原生规范化字符串，不允许前端自行判定兼容性；兼容性以 Job validate 响应为准。

### 8.7 SyncJob、校验、预览和版本

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

脏数据比例在 UI 可按百分数输入，提交 JobSpec 前必须转换为 `0..1`，并四舍五入到最多 6 位小数；服务端按同一规范化规则计算 `draft_spec_hash`，避免等价值因浮点表示不同产生不同版本哈希。

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

### 8.8 Execution、取消和重跑

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/projects/{project_id}/executions` | 所有项目成员 | 分页与状态筛选 |
| POST | `/jobs/{job_id}/executions` | Operator/Admin | 对明确 JobVersion 人工执行 |
| GET | `/executions/{execution_id}` | 所有项目成员 | 状态、摘要和失败信息 |
| POST | `/executions/{execution_id}/cancel` | Operator/Admin | 创建取消请求，不由 API 直接推进状态 |
| POST | `/executions/{execution_id}/rerun` | Operator/Admin | 创建引用相同 JobVersion 的新 Execution |
| GET | `/executions/{execution_id}/logs` | 所有项目成员 | 游标读取脱敏日志 |
| GET | `/executions/{execution_id}/logs/download` | 所有项目成员 | 服务端生成并审计脱敏文本下载 |

执行请求：

```http
POST /api/v1/jobs/6f499e28-b9a1-4cc7-af55-e347014816a4/executions
Idempotency-Key: 01J43MRE4Q3W8FNF4PMY90M4W4

{
  "job_version_id": "b64006fc-5a22-4e48-a0bd-f9cb1440031f"
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
  "state": "QUEUED",
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

取消请求返回 `202` 和 CancelRequest；Execution 可能仍显示原状态，直到 Worker 写入 `CANCEL_REQUESTED`。前端应展示“取消请求已提交”，不能立即显示“已取消”。

人工重跑不复用原 Execution ID，不重新解析“最新版本”，而是绑定原 Execution 的同一 JobVersion。由于 V1 为 insert-only，UI 和 API 响应必须提示可能产生重复记录。

### 8.9 日志游标

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
      "message": "任务平均流量: 12.4MB/s"
    }
  ],
  "next_cursor": "eyJleGVjdXRpb25faWQiOiIuLi4iLCJuZXh0X3NlcXVlbmNlIjoxMDQzfQ",
  "eof": false,
  "redaction_rules_version": "1.0",
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
- 下载由服务端从全部脱敏 LogChunk 重新组装 UTF-8 文本，响应为 `text/plain` attachment，并返回脱敏规则版本与 SHA-256。
- V1 单次下载上限为 100 MiB（脱敏后未压缩大小）；超过时返回 `413 LOG_EXPORT_TOO_LARGE`，不得静默截断，用户仍可通过 cursor 分页查看。
- 下载成功、失败和拒绝均写 `EXECUTION_LOG_EXPORTED` 审计；到期日志返回 `410 LOG_EXPIRED`。

### 8.10 Audit

`GET /projects/{project_id}/audit-events` 支持 `action`、`outcome`、`actor_id`、`from`、`to` 和 cursor。响应事件符合 `audit-event.v1.schema.json`。

所有项目成员均可读取已授权项目的审计。`GET /audit-events` 仅供组织级 Admin 跨项目筛选。审计默认保留 730 天。前端不得显示或导出 `event_hash` 之外的密钥材料，不提供编辑/删除接口。

### 8.11 Health

| 方法 | 路径 | 认证 | 含义 |
|---|---|---|---|
| GET | `/health/live` | 否 | 进程可响应 |
| GET | `/health/ready` | 否 | PostgreSQL、Redis、日志卷、dispatcher、Worker/Runtime 就绪 |

Health 响应不得暴露主机地址、密码、容器环境变量或堆栈。ready 失败返回 503 和组件级安全状态码。

## 9. 前端状态处理

- 按 API 状态枚举渲染，不从日志文本猜测成功或失败。
- SyncJob 编辑后立即按响应切换为 DRAFT；只有 validate 响应成功后显示 VALID。
- 发布成功后展示新 version_no，不覆盖旧版本。
- Execution 在 `CANCEL_REQUESTED` 前可能已存在待处理 CancelRequest；分别展示。
- `LOST` 不自动显示重试成功；人工重跑是新记录。
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
2. 示例 JobSpec 可通过 JSON Schema；加入任意 SQL、未知插件或未知字段会失败。
3. 所有列表接口都有稳定排序、cursor、limit 和跨授权主体校验。
4. 所有强制幂等接口覆盖首次、重放、处理中和冲突测试。
5. 所有 PATCH 覆盖正确 ETag、缺失 If-Match 和版本冲突测试。
6. 四类角色和多角色并集均有允许/拒绝 API 测试。
7. Datasource 的创建、更新、测试、Schema、错误和审计中没有密码回显。
8. Execution 创建、取消、worker 延迟确认、日志续传、日志到期和 LOST 状态均有契约测试。
9. API 实现生成的审计事件通过 AuditEvent schema，日志和审计不包含 secret。
