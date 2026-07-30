# GitHub 工程规范与开源规划

| 项 | 决策 |
|---|---|
| 仓库 | `xiaoli2hust/datax` |
| 默认分支 | `main` |
| 开发模式 | 受保护主干 + 短期分支 + Pull Request |
| 发布单位 | 可复现的源码标签、镜像摘要、迁移版本、Runtime manifest |
| 当前许可证 | 仓库所有者尚未选择；公开源码前必须完成 |

## 1. 仓库目标

仓库同时承载：

- 权威产品和工程文档。
- 前端、API、Worker 与部署代码。
- 机器可校验的 API、JobSpec、Plugin、Audit、Verification Oracle 和 Acceptance Manifest 契约。
- 自动测试、迁移、构建、SBOM 和发布证据。

不承载：

- 生产密钥、连接串、业务数据或运行日志。
- 未经校验的 DataX 二进制和插件 JAR。
- 模型密钥或 Provider 响应样本中的敏感数据。
- 无来源、无许可证或无摘要的大型制品。

## 2. 目标目录

```text
.
├── .github/
│   ├── ISSUE_TEMPLATE/
│   ├── workflows/
│   └── PULL_REQUEST_TEMPLATE.md
├── frontend/
│   └── src/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── auth/
│   │   ├── audit/
│   │   ├── datasources/
│   │   ├── jobs/
│   │   ├── executions/
│   │   └── workers/
│   ├── migrations/
│   └── tests/
├── docker/
├── tests/
│   ├── contracts/
│   └── e2e/
├── docs/
│   ├── adr/
│   ├── contracts/
│   └── security/
├── AGENTS.md
├── CONTRIBUTING.md
├── SECURITY.md
└── README.md
```

DataX Runtime 由构建脚本获取或从受控制品库下载，按 manifest 校验，不直接提交到 Git。

## 3. 分支规则

- `main`：始终可构建；禁止日常直接推送。
- `feature/<slug>`：用户能力。
- `fix/<slug>`：缺陷。
- `docs/<slug>`：纯文档或契约。
- `security/<slug>`：私密协作后公开的安全修复。
- `agent/<slug>`：编码 Agent 发起的受审查变更。

不维护长期 `develop` 分支，减少双主干漂移。分支应短命，合并后删除。

空仓库的首次文档基线可以作为 bootstrap 提交建立 `main`；从下一次变更起执行 PR 规则。

## 4. 提交与 PR

提交信息使用简短动词，例如：

- `建立 V1 文档基线`
- `实现数据源连接测试`
- `修复执行取消后的孤儿进程`

每个 PR 必须包含：

- 变更目的和关联需求/Issue。
- 用户或运维影响。
- 架构、数据迁移、权限和兼容性影响。
- 已执行检查与结果。
- 真实外部链路是否验证。
- 未验证项、风险和回滚方式。
- 文档、契约和追踪矩阵是否同步。
- PRD、ADR、数据模型与机器契约在各自关注点上是否一致；任何冲突必须列为阻塞项。
- 需求优先级、唯一测试 ID、oracle、证据路径和结果是否进入 `acceptance-manifest.v1`。

禁止把无关格式化、依赖升级和功能改动塞入同一 PR。

## 5. 主分支保护

仓库管理员应在首次代码 PR 前启用：

- 必须通过 PR 合并，至少 1 名审批人。
- 代码所有者路径需要对应审批。
- 所有必需 CI 状态通过。
- 分支必须与 `main` 保持最新。
- 禁止 force push 和删除 `main`。
- 合并后自动删除分支。
- 安全敏感目录建议 2 名审批人。

建议使用 squash merge；PR 标题成为主干提交摘要。

## 6. CI 门禁

### 文档阶段

- Markdown 格式和内部链接。
- OpenAPI 语法与示例校验。
- JSON Schema 解析、Meta Schema 和示例校验。
- ADR 状态、威胁模型、逐条需求追踪和无错位引用检查。
- JobSpec、OpenAPI、数据枚举和验收 manifest 的跨契约一致性检查。
- Secret/高熵字符串扫描。

### 工程阶段

- 前端格式化、lint、类型检查、单元测试和构建。
- 后端格式化、lint、类型检查、单元和 API 集成测试。
- Alembic 从空库升级、前后版本兼容与恢复测试。
- Docker 镜像构建、健康检查、非 root 和制品摘要检查。
- 真实 DataX E2E 由隔离测试环境执行；必须包含源静默确认、空目标复检、目标外部独占
  `statement_version='1.0'`/`valid_until`/`ACTIVE|REVOKED|EXPIRED` 生命周期、已知窗口破坏的
  Operator/DBA 撤回或报告与 `TARGET_EXCLUSIVITY_REVOKED` 审计、独立 oracle、部分写入、
  并发同目标、Worker fencing 和恢复后再次执行。Oracle `PASSED` 必须要求声明未撤回、
  未过期且目标快照结束不晚于 `valid_until`；测试不得声称平台能自动发现任意瞬时、未报告
  或已回滚的平台外 DML/DDL。没有真实凭据时明确为未运行，不能替换成 Mock 绿灯。
- SAST、依赖漏洞、SBOM、许可证和容器扫描。

高风险 CI 所需密钥只使用受保护环境和最小权限短期凭据，不向 Fork PR 暴露。

## 7. Issue 规范

功能 Issue 至少包含：

- 背景和用户价值。
- 关联需求 ID。
- 输入、输出和非目标。
- 正常/失败/权限/并发路径。
- 数据、API、UI、迁移和安全影响。
- 可执行验收标准，包括唯一测试 ID、oracle、证据等级和证据路径。

Bug Issue 应包含版本、环境、复现步骤、预期/实际、脱敏日志和影响；不得粘贴密码、连接串或业务数据。

## 8. 版本与发布

采用语义版本：

- `0.x`：企业试点，可能有受控破坏性变更。
- `1.0.0`：完成生产认证门禁后。

发布候选必须固定：

- Git commit 和标签。
- 前端/API/Worker 镜像 digest。
- 数据库迁移 head。
- DataX 版本、Runtime 包 SHA-256、每个插件 JAR SHA-256。
- OpenAPI/JobSpec/Plugin Manifest 版本。
- Verification Oracle、Acceptance Manifest 和外部审计锚点格式版本。
- SBOM、许可证清单和已知漏洞豁免。
- 升级、回滚和数据备份说明。

禁止使用可漂移的 `latest` 作为生产部署依据。

## 9. 上游与依赖治理

每个第三方组件记录：

- 名称、来源、版本/commit。
- 直接或传递依赖。
- 许可证与 NOTICE 义务。
- 下载地址和摘要。
- 漏洞状态、维护状态和替代方案。

DataX 上游代码采用 Apache License；如果分发其二进制或修改版本，必须保留相应 LICENSE/NOTICE 并单独记录修改。插件许可证和数据库驱动许可要逐项检查，不能用上游总体许可代替。

## 10. 本仓库许可证决策

仓库公开不等于自动授予开源许可。在所有者明确选择前：

- 不添加推测性的 `LICENSE`。
- README 明确当前无额外许可授予。
- 允许公开阅读，但不得对再分发或商业使用作承诺。
- 首次公开源码发布前，由所有者在 Apache-2.0、其他许可证或闭源策略中做出明确决定。

## 11. 安全响应

安全报告遵循根目录 `SECURITY.md`。仓库管理员应启用 GitHub Private Vulnerability Reporting；含密钥、利用细节或客户数据的问题不得建立公开 Issue。

## 12. 开源路线

1. **文档基线**：公开范围、架构和贡献规则。
2. **可复现试点**：发布无生产数据的完整源码、Compose 和测试。
3. **供应链透明**：发布 SBOM、Runtime manifest、许可证清单。
4. **社区扩展**：在插件安全模型成熟后开放插件 SDK。
5. **生态治理**：只有签名、审计、兼容和撤回机制齐全后才建设插件市场。
