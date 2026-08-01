# 安全政策

## 支持范围

当前仓库处于 V1.2 文档与开发阶段，尚未声明任何生产支持版本。V1.2 唯一计划支持的终端交付环境是 **Windows 11 x64 本地工作站**：

- 用户通过已签名的 `Setup.exe` 安装，通过已签名的 `launcher.exe` 启动和停止产品。
- Docker Desktop、WSL2、CPU 虚拟化是明确前置条件；安装器不得静默安装、启用、接受许可证或改变组织策略。
- DataX、JDK、API、Worker 和 PostgreSQL 均在固定摘要的 Linux 容器内运行，不在 Windows 宿主直接执行 `datax.py`。
- 默认入口固定为 `http://127.0.0.1:17860`。仅 Web 容器可映射 `127.0.0.1:17860`；API、Worker、PostgreSQL 和 DataX Runtime 不得映射宿主端口。
- Windows Defender Firewall 规则不得开放 LAN/WAN；产品不得把 `0.0.0.0`、`::`、`localhost` 名称解析结果或随机端口作为发布默认值。
- 卸载默认只删除程序、快捷方式和注册项，保留三个 `des-*` named volumes、配置、导出
  备份与审计；清除数据必须是独立、明确确认且可审计的动作。

macOS/Linux 上的源码开发、容器构建或测试结果不能证明 Windows 安装、启动、睡眠恢复、卸载和本机安全边界。未来发布时将在本文件列出仍接收安全修复的版本。

## 报告漏洞

不要在公开 Issue 中提交密钥、连接串、客户数据、可直接利用的细节或未脱敏日志。

首选 GitHub 的 Private Vulnerability Reporting。若仓库尚未启用该能力，请通过你与仓库所有者已有的可信私密渠道联系，并只提供最小必要信息；不要把漏洞细节公开。仓库管理员应在首次代码发布前启用私密漏洞报告。

报告建议包含：

- 受影响版本或 commit。
- 影响范围和前置条件。
- 最小复现步骤。
- 期望与实际行为。
- 已做脱敏的证据。
- 可能的缓解建议。

请勿在未经授权的系统、生产数据源或第三方环境中测试。

## 高优先级问题

- 数据源凭据、JWT/主密钥或业务数据泄露。
- 跨项目/角色越权。
- 未授权端点、数据源用途或源到目标方向造成的数据外传。
- 任意 SQL、命令注入、路径穿越、SSRF 或 DNS 重绑定绕过网络出口策略。
- Worker 逃逸、失租后继续写状态/目标、宿主访问或未授权插件执行。
- 目标非空绕过、部分写入后绕过恢复门禁再次执行、独立核验绕过或三维执行状态伪造。
- 目标外部独占声明版本/有效期/`ACTIVE|REVOKED|EXPIRED` 校验绕过、撤回/破坏报告丢失、
  `TARGET_EXCLUSIVITY_REVOKED` 审计缺失，或把平台锁/未收到报告错误宣称为已证明期间没有
  任意平台外 DML/DDL。
- 凭据 KEK keyring 轮换/恢复失败、审计链重写或外部签名锚点失效。
- 脱敏后的原序日志泄密、静默截断或截断证据伪造。
- Agent 越权调用工具或敏感数据外发。
- `Setup.exe` / `launcher.exe` 签名无效、发布哈希不匹配、安装路径劫持、DLL 搜索顺序劫持、升级包降级或供应链制品替换。
- Launcher 绕过 Docker/WSL2/虚拟化检查、把宿主 Docker Socket 暴露给业务容器、使用浮动镜像或在 Windows 宿主直接运行 DataX/JDK。
- Web 端口绑定到非 loopback、API/Worker/PostgreSQL 被映射到宿主、Windows 防火墙入站放行或浏览器之外的远程访问。
- 睡眠/休眠、Docker Desktop 重启、WSL2 重启或 Windows 重启后旧进程/租约/围栏继续写状态或目标。
- 卸载、升级或回滚误删 Docker named volumes（`des-postgres-data`、
  `des-log-data`、`des-workspace-data`）、导出备份、密钥或审计锚点。

## 响应原则

仓库维护者应确认收到、评估严重性、对照 `docs/security/THREAT_MODEL.md` 更新威胁与控制、隔离敏感证据、制定修复与回滚，并在安全发布后公开不含利用细节的说明。任何临时缓解都必须有负责人、有效范围和到期日；涉及 Windows 安装/签名、产品承诺、权限、执行围栏、密钥或网络边界时必须同步更新 ADR、机器契约、测试和需求追踪。Windows 发布验收必须在干净 Windows 11 x64 VM 上重新完成，不能以非 Windows 构建或既有安装覆盖。
