# 机器可校验契约

本目录中的文件优先于自然语言示例：

- `openapi.yaml`：HTTP API。
- `job-spec.v1.schema.json`：平台任务契约。
- `plugin-manifest.v1.schema.json`：认证插件能力与参数 UI 契约。
- `audit-event.v1.schema.json`：审计事件最小结构。

实现阶段 CI 必须完成：

1. 文件可解析。
2. JSON Schema 通过对应 Meta Schema 校验。
3. OpenAPI 示例和引用有效。
4. 前后端生成类型与契约一致。
5. 破坏性变更提升版本并提供迁移说明。

不得直接修改生成代码来绕过契约。
