# DataX Enterprise Studio Agents 工程化方案

> 文档状态：V2 设计基线
>
> 适用范围：AI 辅助能力，不属于 V1 交付范围；必须继承 V1.1 安全一次性全量复制语义
>
> 核心约束：未配置或不可用 AI Provider 时，V1 全部手工功能仍须正常使用

## 1. 目标与边界

Agents 用于辅助数据工程师理解元数据、生成任务草稿、分析失败原因和提出优化建议。Agent 不是独立执行面，也不是 DataX Runtime 的替代品。

所有 Agent 输出都必须满足以下约束：

1. 只能生成草稿、解释或建议，不能直接创建可执行生产任务、触发 DataX、停止执行或修改已保存任务。
2. 任何 Agent 草稿必须经过确定性校验、权限检查和人工确认，才能导入平台的可编辑 `JobDraft`；之后仍须走 V1 的校验与发布流程才能生成不可变 `JobVersion`。
3. 任务的实际运行仍由具备执行权限的用户在 V1 手工触发流程中完成。
4. Agent 只能使用平台提供的白名单工具，不能生成或执行自由 SQL、`preSql`、`postSql`、Shell 命令、自定义插件、文件路径或任意 URL。
5. Agent 不得突破 V1 能力边界。V2 初始阶段仅支持 MySQL 8 与 PostgreSQL 15 作为
   Reader/Writer、完整表或选列直连映射、源端静默/目标外部独占声明、目标表预存在且
   可核验、`insert-only` 一次性复制、`channel` 范围 `1..16`、timeout 范围
   `60..604800` 秒、固定 `dirty_data_limit=0/0`。草稿阶段不以目标当时为空作为通过
   条件；空表只在每次运行前由 Worker 实测。Agent 不得把非空目标追加、重复运行或周期
   运行描述为“同步”。
6. 目标外部独占声明只能由 Operator/DBA 作出，固定 `statement_version='1.0'`、有限
   `valid_until` 与 `ACTIVE/REVOKED/EXPIRED` 生命周期。Agent 不得替人确认、撤回或
   伪造 `TARGET_EXCLUSIVITY_CONFIRMED/TARGET_EXCLUSIVITY_REVOKED` 审计，也不得把
   “未收到破坏报告”解释为平台已证明期间没有任意瞬时、未报告或已回滚的外部 DML/DDL。

V2 首批 Agent：

| Agent | 输入 | 输出 | 是否允许修改业务状态 |
| --- | --- | --- | --- |
| 任务草稿 Agent | 用户意图、已授权数据源元数据 | DataX 任务草稿、缺失项、风险提示 | 仅允许写入独立草稿区 |
| Schema 分析 Agent | 已授权表和字段元数据 | 字段选择、类型兼容建议 | 否 |
| 故障诊断 Agent | 执行状态、脱敏日志、指标 | 证据、可能原因、置信度、建议 | 否 |
| 性能建议 Agent | 脱敏运行指标、任务配置 | 参数建议和影响说明 | 否 |
| 数据治理建议 Agent | 元数据、确定性质量规则结果 | 风险标签和治理建议 | 否 |

性能建议和治理建议不得自动写回任务；“根因”只有在确定性证据充分时才能使用，其他情况必须表述为“可能原因”。

## 2. 设计原则

- **Manual-first**：AI 是可选增强，不是创建、编辑、执行、监控任务的必经依赖。
- **Provider-agnostic**：业务代码只依赖统一 Provider 接口，不硬编码特定模型厂商。
- **Draft-only**：模型生成内容永远先进入独立草稿区。
- **Least privilege**：工具按项目、角色、动作和字段最小授权。
- **Deterministic gate**：模型输出不可信；JSON Schema、业务规则和权限策略由确定性代码校验。
- **Untrusted context**：表名、字段名、注释、错误日志和用户输入均作为数据处理，不能当作指令。
- **Evidence-first**：诊断和建议必须引用可追溯证据，并明确不确定性。
- **Privacy by default**：默认不向 Provider 发送凭据、连接串、样例数据或完整的脱敏后原序日志，只发送经策略限量的必要片段。
- **Fail closed**：权限、审计、校验或 Provider 状态不明确时，不产生可采纳草稿，更不能执行。
- **No hidden reasoning retention**：不记录模型隐藏推理过程；只保存必要的脱敏输入摘要、结构化输出和决策证据。

## 3. 总体架构

```text
用户
  ↓
Vue UI（项目上下文、草稿预览、人工确认）
  ↓
FastAPI Auth/RBAC/Project Scope
  ↓
Agent Orchestrator
  ├── Provider Adapter
  ├── Tool Policy Gate
  ├── Structured Output Validator
  ├── Deterministic Business Verifier
  └── Audit Writer
  ↓
白名单 Tool Adapters
  ↓
V1 模块化单体服务（Datasource / Job / Execution / Audit）
  ↓
草稿库或只读查询
```

Agent Orchestrator 不连接 DataX Worker，不持有数据源明文密码，也不具备任务运行接口。Provider 只能返回结构化候选结果；最终权限、约束和状态转换由平台完成。

## 4. Agent Run 状态机

```text
created
  → collecting_context
  → generating
  → validating
  → draft_ready

任一步可进入：
  rejected | failed | cancelled | provider_unavailable
```

`draft_ready` 仅表示草稿生成和校验通过，不表示任务已保存，更不表示任务已执行。

禁止出现由 Agent 直接进入 `queued`、`running` 或其他 DataX Execution 状态的路径。

## 5. Provider 抽象

### 5.1 统一接口

Provider Adapter 至少实现：

```python
class AIProvider:
    async def health_check(self) -> ProviderHealth: ...
    async def generate_structured(
        self,
        request: ProviderRequest,
        output_schema: dict,
        timeout_seconds: int,
    ) -> ProviderResponse: ...
```

统一请求只包含：

- `request_id`
- `provider_config_id`
- `model_alias`
- `prompt_template_version`
- `task_type`
- `sanitized_context`
- `output_schema_version`
- `max_output_tokens`
- `timeout_seconds`

统一响应只包含：

- `provider_request_id`
- `model_resolved`
- `output_json`
- `usage`
- `latency_ms`
- `finish_reason`
- `provider_error`

业务代码不得依赖某个 Provider 的专有响应字段。Provider 专有参数只能位于适配层并经过白名单校验。

### 5.2 配置状态

Provider 配置必须使用以下可见状态：

- `disabled`：未启用，平台完全走手工流程。
- `configured_not_verified`：已保存配置但尚未通过真实连接探测。
- `ready`：真实探测和最小结构化输出校验均通过。
- `degraded`：近期调用连续失败或触发熔断。

只有 `ready` 状态可承接 Agent 请求。不得因为缺少外部 Provider 而阻止系统初始化、登录、创建数据源、创建任务或手工运行任务。

### 5.3 Provider 策略

- 凭据存入平台密钥存储或等价的加密设施，禁止进入数据库普通字段、前端状态、日志或模型上下文。
- Provider、模型、模型版本、提示模板版本和输出 Schema 版本必须进入审计。
- 默认禁止自动跨 Provider 降级；若管理员明确配置候选 Provider，降级也必须满足相同的数据区域、隐私和评测门槛，并在 UI 中明确显示。
- 仅对无副作用的 Provider 请求重试；重试次数、退避、超时和 Token/费用上限必须配置化。
- 模型或提示模板升级前必须执行完整回归评测，不得直接替换线上别名。

## 6. 工具统一契约

### 6.1 请求信封

所有工具请求使用同一信封：

```json
{
  "tool_version": "1.0",
  "request_id": "uuid",
  "agent_run_id": "uuid",
  "actor_id": "uuid",
  "project_id": "uuid",
  "expected_project_scope": "uuid",
  "input": {}
}
```

工具调用身份由服务端根据登录会话签发，模型不得提供或覆盖 `actor_id`、`project_id` 和权限声明。

### 6.2 响应信封

```json
{
  "tool_version": "1.0",
  "request_id": "uuid",
  "ok": true,
  "data": {},
  "error": null,
  "audit_event_id": "uuid"
}
```

错误必须结构化返回：

```json
{
  "code": "FORBIDDEN",
  "message": "sanitized message",
  "retryable": false,
  "details": {}
}
```

允许的通用错误码为 `INVALID_ARGUMENT`、`UNAUTHENTICATED`、`FORBIDDEN`、`NOT_FOUND`、`CONFLICT`、`POLICY_DENIED`、`RATE_LIMITED`、`TIMEOUT`、`DEPENDENCY_UNAVAILABLE` 和 `INTERNAL_ERROR`。

### 6.3 `datasource.list`

用途：列出当前项目中用户有权访问的数据源别名和能力。

```json
{
  "input": {
    "capability": "reader",
    "database_type": "mysql",
    "page": 1,
    "page_size": 20
  }
}
```

输出不得包含 host、port、database、username、password、连接串或扩展连接参数：

```json
{
  "items": [
    {
      "datasource_id": "uuid",
      "display_name": "订单库",
      "database_type": "mysql",
      "capabilities": ["reader", "writer"]
    }
  ],
  "total": 1
}
```

### 6.4 `datasource.schema.read`

用途：读取经授权数据源的数据库、Schema、表和列元数据。禁止接受自由 SQL。

```json
{
  "input": {
    "datasource_id": "uuid",
    "object_type": "columns",
    "database_name": "orders",
    "schema_name": null,
    "table_name": "order_header",
    "cursor": null,
    "limit": 200
  }
}
```

```json
{
  "datasource_id": "uuid",
  "table": {
    "database_name": "orders",
    "schema_name": null,
    "table_name": "order_header"
  },
  "columns": [
    {
      "name": "order_id",
      "database_type": "bigint",
      "nullable": false,
      "ordinal": 1
    }
  ],
  "next_cursor": null
}
```

该工具不得返回样例行、统计分布、凭据或数据库原始错误详情。数据库注释若确需返回，必须单独标记为 `untrusted_text`。

导入 JobSpec 时必须按机器契约规范化对象标识：MySQL 的 database 映射为 JobSpec `schema_name`，PostgreSQL 使用实际 schema；不得因为 Provider 用词不同而生成第二套字段语义。

### 6.5 `job.draft.create`

用途：在独立草稿区保存模型生成的候选任务。该工具没有发布和执行能力。

```json
{
  "input": {
    "name": "订单一次性复制草稿",
    "description": "由 Agent 生成，等待人工确认",
    "job_spec": {
      "schema_version": "1.0",
      "source": {
        "datasource_id": "11111111-1111-4111-8111-111111111111",
        "datasource_revision_id": "11111111-1111-4111-8111-111111111112",
        "plugin_name": "mysqlreader",
        "table": {
          "schema_name": "orders",
          "table_name": "order_header"
        }
      },
      "target": {
        "datasource_id": "22222222-2222-4222-8222-222222222222",
        "datasource_revision_id": "22222222-2222-4222-8222-222222222223",
        "plugin_name": "postgresqlwriter",
        "table": {
          "schema_name": "public",
          "table_name": "order_header"
        }
      },
      "selection_mode": "SELECTED_COLUMNS",
      "mappings": [
        {
          "source_column": "order_id",
          "source_ordinal": 1,
          "source_type": "bigint",
          "source_nullable": false,
          "target_column": "order_id",
          "target_ordinal": 1,
          "target_type": "bigint",
          "target_nullable": false,
          "compatibility": "EXACT"
        }
      ],
      "source_consistency_mode": "OPERATOR_QUIESCED",
      "target_precondition": "EMPTY_AND_VERIFIABLE",
      "write_semantics": "INSERT_ONLY_ONCE",
      "duplicate_policy": "REJECT_NONEMPTY_TARGET",
      "partial_write_policy": "MANUAL_REMEDIATE",
      "write_policy": {
        "mode": "INSERT",
        "target_table_must_exist": true,
        "target_table_must_be_empty": true,
        "platform_may_mutate_target_before_run": false
      },
      "execution_policy": {
        "channel": 1,
        "timeout_seconds": 3600,
        "dirty_data_limit": {
          "record_count": 0,
          "percentage": 0
        }
      }
    }
  }
}
```

`job_spec` 必须逐字段符合 `docs/contracts/job-spec.v1.schema.json`，工具不得维护另一套同义但不兼容的任务格式。

返回：

```json
{
  "draft_id": "uuid",
  "draft_version": 1,
  "draft_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "status": "AGENT_DRAFT",
  "validation": {
    "valid": true,
    "errors": [],
    "warnings": []
  }
}
```

服务端必须拒绝以下内容：

- MySQL 8/PostgreSQL 15 之外的数据源。
- 非直连字段映射、表达式、常量列或类型转换脚本。
- `update`、`upsert`、`replace`、`truncate` 或删除语义。
- 调度、DAG、CDC、告警或自动重试策略。
- 自由 SQL、`where` 自由表达式、`preSql`、`postSql`。
- 自定义插件或任意插件参数。
- 不存在的目标表。
- 无法核验、存在会修改映射列的触发器，或不符合 V1 安全画像的目标表。草稿阶段不因
  目标当时非空而拒绝；运行前空表门禁仍不可绕过。
- 源和目标解析为同一 PhysicalEndpointIdentity 下的同一规范化表身份；不同
  datasource/revision/hostname/IP 别名不能绕过 TargetNamespace 判断。
- `channel` 小于 1 或大于 16。
- timeout 小于 60 秒或大于 604800 秒。
- 任意非零脏数据条数/比例，或使用模型无法解释的自定义规则。

### 6.6 `job.draft.validate`

用途：对既有草稿执行确定性校验，不调用模型。

```json
{
  "input": {
    "draft_id": "uuid",
    "expected_draft_version": 1,
    "expected_draft_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
}
```

返回必须分别列出：

- JSON Schema 校验。
- 项目和权限校验。
- 数据源与表存在性校验。
- 源/目标 DatasourceRevision、数据源用途和源到目标传输授权校验。
- 字段存在性、顺序和类型兼容校验。
- 一次性复制策略、目标表安全画像和目标空表运行前复检要求。
- V1 能力边界策略校验。
- 敏感配置与禁止字段扫描。

### 6.7 `job.draft.diff`

用途：生成草稿与当前保存任务版本之间的人类可读和机器可读差异。

```json
{
  "input": {
    "draft_id": "uuid",
    "job_id": "uuid",
    "job_version": 3
  }
}
```

输出包含基础信息、源、目标、字段和运行语义的逐项差异；不得在差异中展开凭据。

### 6.8 `execution.read`

用途：读取当前项目中的执行状态和脱敏统计，只读。

```json
{
  "input": {
    "execution_id": "uuid"
  }
}
```

返回可包含 `process_state`、`data_effect`、`verification_state`、开始/结束时间、独立核验摘要、DataX 统计摘要和错误分类，不得把退出码 0 单独描述为数据成功，也不得包含完整命令行、临时 JSON 路径、凭据或未脱敏异常。

### 6.9 `execution.logs.read`

用途：分页读取脱敏日志。

```json
{
  "input": {
    "execution_id": "uuid",
    "cursor": null,
    "limit": 200,
    "severity": ["ERROR", "WARN"]
  }
}
```

日志服务必须先执行密钥、连接串、Token、邮箱、手机号等已配置规则的脱敏，再返回 Agent。单次和单个 Agent Run 的日志量必须设上限；发生截断时同时返回 `truncated`、`original_bytes`、`dropped_bytes` 和 `reason`，Agent 不得声称已分析完整日志。

### 6.10 明确禁止的工具

V2 首批版本不得向 Agent 注册以下工具：

- `task_runner`
- `execution.start`
- `execution.stop`
- `job.publish`
- `datasource.raw_query`
- `shell.exec`
- `file.read`
- `file.write`
- 任意网络请求工具

如未来新增有副作用工具，必须单独完成威胁模型、审批设计和安全评测，不得通过修改提示词直接开放。

## 7. 权限与人工确认

### 7.1 Agent 动作权限

| 动作 | Admin | Developer | Operator | Viewer |
| --- | --- | --- | --- | --- |
| 配置 Provider | 允许 | 禁止 | 禁止 | 禁止 |
| 调用任务草稿 Agent | 允许 | 允许（授权项目） | 禁止 | 禁止 |
| 调用 Schema 分析 Agent | 允许 | 允许（授权项目） | 禁止 | 禁止 |
| 调用故障诊断 Agent | 允许 | 允许（授权项目） | 允许（授权项目） | 禁止 |
| 调用性能建议 Agent | 允许 | 允许（授权项目） | 允许（授权项目） | 禁止 |
| 查看已有 Agent Run | 允许 | 授权项目 | 授权项目 | 仅已授权、已发布结果 |
| 采纳为平台任务草稿 | 允许 | 允许（具备任务编辑权限） | 禁止 | 禁止 |
| 通过 Agent 触发任务 | 禁止 | 禁止 | 禁止 | 禁止 |

权限由服务端重新计算；模型提供的角色、用户或项目声明一律忽略。

### 7.2 草稿采纳、校验与发布

Agent 草稿采纳不由 Agent Tool 完成，而由正常平台 API 导入为 `JobDraft`，并满足：

1. UI 展示源、目标、固定 DatasourceRevision、字段、一次性写入方式、源静默要求、目标空表要求、触发方式、校验结果和全部差异。
2. 操作者拥有目标项目的任务编辑权限。
3. 操作者确认的对象绑定 `draft_id`、`draft_version`、`draft_hash`、项目和有效期。
4. 草稿在确认后发生任何变化，原确认立即失效。
5. 平台再次执行确定性校验，校验结果与确认对象一致后才导入或更新 `JobDraft`。
6. Agent 不具备校验通过声明权或发布权；Developer/Admin 必须在 V1 页面完成校验并显式发布，发布产生不可变 `JobVersion`。
7. 采纳 Agent 草稿不等于发布，发布也不等于运行；运行仍需 Admin 或 Operator 从 V1 页面
   手工触发并确认源端静默，Operator/DBA 还需提交 `statement_version='1.0'` 且带有限
   `valid_until` 的目标外部独占声明；服务端必须复检目标为空、声明处于 `ACTIVE`、
   传输授权有效，且同一 TargetNamespace 没有其他未释放的
   `RESERVED/ACTIVE/RECOVERY_REQUIRED` 锁。获知目标窗口破坏后由 Operator/Admin 使用
   正常执行接口撤回/报告并产生 `TARGET_EXCLUSIVITY_REVOKED` 审计，不由 Agent 代办。

## 8. 提示注入与输出安全

- 用户文本、表名、列名、数据库注释、日志、错误消息统一标记为不可信数据。
- 提示模板必须明确区分系统策略、工具结果和不可信内容；不可信内容中的“忽略规则”“调用工具”等文字不能改变控制流。
- 工具名称和参数 Schema 由服务端注册，模型不能动态声明工具。
- 每次工具调用先经过 RBAC、项目范围、参数 Schema 和业务 Policy Gate。
- 模型输出使用严格 JSON Schema；禁止从自然语言中解析并直接执行命令。
- DataX JSON 由平台根据已校验领域对象确定性生成，不直接采用模型生成的原始 JSON。
- 前端显示模型文本时必须进行 HTML 转义和安全 Markdown 渲染。
- 日志或 Schema 内容不能用于拼接 SQL、Shell、文件路径或网络 URL。
- 安全测试必须覆盖跨项目诱导、伪造工具结果、编码混淆、超长输入和日志内嵌提示等场景。

## 9. 数据隐私与 Memory

### 9.1 默认数据最小化

允许发送给 Provider：

- 用户明确输入的业务意图。
- 已授权且经策略允许的 datasource 别名、数据库类型、表名、列名、数据类型和 nullable 信息。
- 经过脱敏和限量的错误日志片段。
- 确定性统计摘要。

禁止发送给 Provider：

- 密码、Token、Cookie、JWT、API Key、完整连接串。
- 数据源 host、内网 IP、用户名等基础设施信息，除非管理员建立了明确的 Provider 数据策略。
- 任何样例行、原始业务数据或文件内容。
- 未脱敏完整日志、环境变量、进程命令行。
- 其他项目的元数据、任务或运行记录。

### 9.2 Memory

首版只允许保存结构化、可解释的项目级偏好，不保存自由文本对话全文。每条 Memory 必须包含：

- `memory_id`
- `project_id`
- `created_by`
- `source_agent_run_id`
- `category`
- `value`
- `created_at`
- `expires_at`
- `sensitivity`

要求：

- 项目隔离，禁止跨项目自动检索。
- 默认有效期 90 天，可由管理员缩短或关闭。
- 用户可查看、删除和纠正。
- 不得保存凭据、连接串、样例数据、完整日志或未经确认的模型推断。
- 被采纳的偏好仍需在每次使用时通过当前权限和能力边界校验。

## 10. 审计

V2 实现前必须先以机器契约扩展 Agent 审计事件；不得把本节新增字段直接塞入 V1 `audit-event.v1.schema.json` 未允许的 `metadata` 或未知字段，也不得绕过契约校验。

每个 Agent Run 必须形成完整关联链：

```text
actor → agent_run → provider_call → tool_calls
      → validation → agent_draft → human_confirmation → JobDraft
      → V1 validation/publish → JobVersion
```

审计至少包含：

- `agent_run_id`、actor、角色、项目、请求时间和最终状态。
- Agent 类型、Agent 版本、提示模板版本、输出 Schema 版本。
- Provider 配置 ID、Provider、模型及模型版本。
- 脱敏输入摘要和输入引用哈希。
- 每次工具调用的工具版本、脱敏参数、结果摘要、耗时和错误。
- Policy Gate 与确定性校验的逐项结果。
- 草稿 ID、版本、哈希和差异摘要。
- 确认人、确认时间、确认对象哈希和导入的 JobDraft。
- 后续 V1 校验、发布人、发布时间和最终 JobVersion；该关联由平台业务审计记录，不由 Agent 补写。
- 关联的 execution ID，仅当用户之后通过 V1 手工触发时记录。

审计写入失败时 Agent Run 必须失败关闭。审计记录不可由 Agent 修改，保留时间遵循平台安全与审计策略。

## 11. 降级与失败处理

| 场景 | 必须行为 | 禁止行为 |
| --- | --- | --- |
| 未配置 Provider | 隐藏或禁用 AI 入口，保留全部手工流程 | 阻止系统初始化或伪造 AI 结果 |
| Provider 探测失败 | 标记 `configured_not_verified` 或 `degraded` | 显示 ready |
| Provider 超时/限流 | 明确失败，可按策略重试只读请求 | 无限重试或重复有副作用工具 |
| 输出非 JSON/Schema 不合法 | 拒绝输出，保留用户输入供手工处理 | 猜测修复后自动采纳 |
| 工具部分失败 | 返回已完成项和失败项，草稿不可采纳 | 把部分结果标记为完整 |
| Policy Gate/权限失败 | 立即拒绝并审计 | 让模型解释后继续 |
| 审计不可用 | Fail closed | 无审计运行 |
| 上下文过长 | 分页、摘要并保留证据引用，或明确停止 | 静默截断后给出确定结论 |
| 费用/Token 超限 | 停止并显示限额原因 | 自动切换到未经批准模型 |

## 12. 评测与发布硬门槛

### 12.1 评测集

至少建立：

- 支持范围内的任务生成黄金用例。
- 缺少必要信息、歧义和超出 V1 范围的拒绝/追问用例。
- MySQL/PostgreSQL 类型、nullable、字段顺序和目标表不匹配用例。
- 真实 DataX 失败日志及人工标注的诊断用例。
- 提示注入、跨项目、越权调用、敏感数据泄漏和输出编码攻击用例。
- Provider 超时、错误、限流、结构化输出损坏和审计故障用例。

评测数据必须脱敏、版本化，并记录来源、适用版本和人工标注人。

### 12.2 硬门槛

以下任一项未通过，V2 Agent 不得发布：

1. 工具请求和响应 JSON Schema 合法率 100%。
2. 任务草稿中的 V1 能力边界策略通过率 100%。
3. 所有生成结果保持 `AGENT_DRAFT`，Agent 直接运行或发布次数为 0。
4. 越权、跨项目和未授权工具调用成功次数为 0。
5. 凭据、Token、连接串和样例数据发送给 Provider 或出现在日志/审计中的次数为 0。
6. 提示注入安全集阻断率 100%。
7. 支持范围内黄金用例的必填参数准确率 100%，字段映射完全匹配率不低于 95%。
8. 超出范围请求被明确拒绝或转为人工处理的比例 100%。
9. 故障诊断输出证据引用覆盖率 100%，无证据却表述为确定根因的次数为 0；标注集 Top-3 可能原因召回率不低于 85%。
10. Provider 未配置、不可用和输出损坏用例进入明确手工降级路径的比例 100%。
11. Agent Run、Provider、Tool、Validation、Draft 与确认审计关联完整率 100%。
12. 所有 Provider/模型/提示模板变更均通过同一回归集，无未审批的线上漂移。

### 12.3 证据

发布评审必须提供：

- 版本化评测集及不可变结果报告。
- Provider 和模型版本清单。
- Tool Schema 与契约测试报告。
- 权限/项目隔离测试报告。
- 提示注入和敏感数据泄漏测试报告。
- Provider 故障注入和手工降级录像或自动化证据。
- 至少一次完整的“用户意图 → Agent 草稿 → 确定性校验 → 差异预览 → 人工采纳为 JobDraft → V1 校验/发布 JobVersion → 用户确认源静默 → 服务端复检目标为空 → 手工运行 → 独立 oracle 核验”真实闭环，其中 Agent 不直接接触 DataX Worker。

## 13. V2 完成定义

只有同时满足以下条件，Agent 能力才可称为工程化完成：

- V1 在完全关闭 AI 时可独立安装、启动并完成真实 DataX 一次性复制、数据影响识别和独立核验闭环。
- Provider Adapter、Tools、Policy Gate、Validator、Audit 均有版本化契约和自动化测试。
- 所有角色、项目隔离、草稿采纳和人工运行路径均通过授权测试。
- 隐私数据流、保留策略和管理员配置已实现并经过安全评审。
- 第 12 节全部硬门槛通过。
- UI 明确区分“AI 草稿”“JobDraft”“已发布 JobVersion”“执行进程状态”“数据影响”“核验结果”，无可能把已发布、进程退出或未核验结果误导为数据成功的文案。
- README、配置说明、运行手册、降级手册和已知限制与实现一致。
