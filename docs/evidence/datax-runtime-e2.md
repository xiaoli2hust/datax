# DataX Runtime E2 直接诊断记录（不是产品 E3/E4）

## 结论与证据边界

2026-08-02 已通过 `scripts/test-datax-runtime-e2.sh` 运行一次完整的直接 Runtime E2
诊断。它证明固定 DataX Runtime 在隔离的临时 MySQL 8/PostgreSQL 15 fixture 之间可完成
本记录所列的真实复制及独立数据核验；它**不**证明产品 API、队列、产品 Worker、权限、
发布制品或 Windows 安装路径可用。

**当前脚本修订说明**：已在 2026-08-02 使用当前 hardened harness 重新构建
`datax-enterprise-studio-worker:runtime-e2` 并完整运行。脚本以创建时返回的 Docker ID（及
runtime-E2 label）清理资源，只读挂载 runner 脚本，并在创建 fixture 前校验 image 内
runtime-manifest；报告为 `status=PASSED`、`runtime.manifest=PASSED`、`runtime_code=RUNTIME_OK`、
`oracle_code=ORACLE_OK`，八个 case 均通过。运行后没有同前缀的容器、网络或命名卷。它仍然只是
直接 Runtime E2，不能成为产品 E3/E4。

机器可读运行结果的固定边界如下：

- `suite`: `DATAX_RUNTIME_E2_DIRECT`
- `evidence_boundary`: `NOT_PRODUCT_E3_OR_E4`
- `product_components_started`: `[]`
- 每个 fixture 数据集：10,000 行

此诊断由操作者显式传入已构建好的 Worker 镜像；脚本不会自动构建、拉取或选择镜像。执行时
创建唯一命名的内部 Docker 网络、四个临时数据库容器和一个显式命名的临时 Worker 容器。
数据库目录为 tmpfs，无宿主端口和命名卷；随机 fixture 凭据只在临时容器环境变量中存在，
不写入报告、日志或仓库。Worker 只读取单个 bind-mounted runner 脚本；平台/独立 oracle
代码均从所提供的 Worker image 加载，整个开发仓库不会被挂入。cleanup 使用创建时返回的
不可变 Docker ID 并复核 runtime-E2 label，名称重用时拒绝删除替代对象。创建 fixture 前
runner 还校验 image 内 runtime manifest、固定 JDK、DataX Runtime、四个插件、驱动与 oracle；
失败时不形成通过证据。

## 2026-08-02 当前 hardened revision 实际运行

固定 Job JSON 的根对象已包含：

```json
{"common":{"column":{"timeZone":"UTC"}}}
```

使用真实 DataX v202309、`mysqlreader`、`mysqlwriter`、`postgresqlreader`、
`postgresqlwriter` 与 `runtime/oracle/verification_oracle.py` 的独立 oracle，所有下列
作业均为 DataX 返回码 `0`、未超时、源/目标各 10,000 行、multiset SHA-256 一致、
`missing_row_count=0`、`unexpected_row_count=0`：

| 方向 | 全列（`ALL_COLUMNS`） | 选列（`SELECTED_COLUMNS`） |
| --- | --- | --- |
| MySQL 8 → MySQL 8 | 通过 | 通过 |
| MySQL 8 → PostgreSQL 15 | 通过 | 通过 |
| PostgreSQL 15 → MySQL 8 | 通过 | 通过 |
| PostgreSQL 15 → PostgreSQL 15 | 通过 | 通过 |

全列 fixture 含固定/变长/Unicode/空/NULL 文本、`TINYINT(1)`/Boolean、`DATE`、
`TIME(6)`、`TIMESTAMP(6)`、`DECIMAL(18,4)` 与 32 字节二进制列。因此关键的
MySQL 8 → PostgreSQL 15 全列核验实际覆盖 `timestamp_value`；该列没有被 oracle 做时间
偏移补偿，摘要一致说明此前发现的 8 小时偏移在此受控诊断中已消失。

正常完成后，使用下列只读检查确认没有同此前缀匹配的临时容器、网络或命名卷：

```bash
docker ps -a --filter 'name=^/datax-runtime-e2-'
docker network ls --filter 'name=^datax-runtime-e2-'
docker volume ls --filter 'name=^datax-runtime-e2-'
```

另做过一次运行中 `INT` 检查：runner 以脱敏的
`RUNTIME_E2_INTERRUPTED` 状态结束，shell trap 删除显式命名的 Worker、四个 fixture 与网络；
随后上述三项检查同样没有匹配资源。该中断检查不是通过的复制证据，也不替代产品取消/恢复
验收。

## 发现的问题、根因与最小修复

修复前，隔离的全列 MySQL 8 → PostgreSQL 15 实际 DataX 进程曾返回 `0`，但独立 oracle
发现 10,000 条缺失和 10,000 条意外记录。抽样显示源端 `2024-01-01 00:01` 被写成目标端
`2024-01-01 08:01`。这不是 oracle 的时间转换问题：固定上游源码
`third_party/alibaba-datax/core/src/main/conf/core.json` 与 `ColumnCast` 默认
`common.column.timeZone=GMT+8`，且该作业级配置会优先于仅有的 JVM
`-Duser.timezone=UTC`。

最小修复是由 `backend/src/datax_studio/worker/job_builder.py` 在每个受控 Job JSON 根对象
显式固定 `common.column.timeZone=UTC`，并由单元测试和上述真实全列 MySQL→PostgreSQL
运行共同验证。未修改上游 DataX 源码，也未在 oracle 中增加时间戳补偿。

同一诊断还发现 PyMySQL 会将确认为 `TINYINT(1)` 的 Boolean 表示为 `int`、将确认为
`TIME`/`TIME(6)` 的值表示为 `timedelta`。`oracle_database.py` 仅在 MySQL、精确原生类型、
精确逻辑类型和无损取值范围同时满足时将其桥接为 oracle 所需的 `bool`/`datetime.time`；
其他整数、其他原生类型、字符串、负 TIME 或大于等于 24 小时的 TIME 均保持拒绝。该桥接
不处理时间戳。

## 可重复命令

```bash
docker build -f backend/Dockerfile.worker -t datax-enterprise-studio-worker:runtime-e2 .
./scripts/test-datax-runtime-e2.sh \
  --worker-image datax-enterprise-studio-worker:runtime-e2
```

脚本为每个 DataX 作业强制设置 1–900 秒的超时上限（默认 180 秒）。输出只包含作业方向、
范围、返回码、超时布尔值、原始输出字节计数与 oracle 汇总；不会输出完整 DataX 日志、
密码或连接串。

## 明确未覆盖项

此记录及脚本存在都**不能**用于声称 E3、E4、发布就绪或 Windows 安装验收。仍未被本诊断
覆盖且需要独立证据的项目包括：

- 产品 API 创建执行、PostgreSQL 事实队列、产品 Worker 领取/围栏/重启对账；
- `DenyAllPluginCertificationSource` 以外的私有 Phase-A 认证执行、四个检查点与证据固化；
- EndpointPolicy、DNS 重绑定防护、真实 TLS CA/主机名正反例和证书轮换；
- 目标独占声明/撤回、目标锁、审计、凭据生命周期、取消和部分写入人工处置；
- Docker Desktop + WSL2 前置检查、Windows 11 x64 的 `Setup.exe` 安装/卸载、桌面快捷方式、
  本机恢复和浏览器入口；
- 真实产品 Compose 网络边界、权限越权和发布签名/制品验收。

任何后续 E3/E4 报告必须单独启动相应产品组件、引用对应的机器可读验收清单和真实外部证据；
不得把本 Runtime E2 结果提升为产品级结论。
