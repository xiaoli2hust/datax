# 固定 DataX Runtime

Windows 产品在 Docker Desktop + WSL2 的 Linux Worker 容器内运行 DataX，不在 Windows
宿主直接启动 Java/DataX 进程。

构建输入：

- 上游源码：`third_party/alibaba-datax/`
- 来源锁：`upstream.lock.json`
- 逐文件哈希清单：`upstream-files.sha256`
- Reader/Writer 源码 inventory：`upstream-plugin-inventory.v1.json`
- inventory 生成器：`build_upstream_plugin_inventory.py`
- 最小构建补丁：`patches/0001-reproducible-safe-runtime.patch`
- 只读运行配置：`config/`
- 独立数据核验算法：`oracle/verification_oracle.py`
- 再分发许可与告知：`third_party/licenses/`、上游 `license.txt` 和 `NOTICE`

`backend/Dockerfile.worker` 只构建四个认证业务插件
`mysqlreader/mysqlwriter/postgresqlreader/postgresqlwriter`，另带
`streamreader/streamwriter` 作为内部启动自检插件。内部自检插件不进入用户任务白名单。
构建会先校验哈希清单自身、全部 1,346 个上游文件、文件数和无符号链接条件，再应用固定
补丁；不匹配时立即失败。

`upstream-plugin-inventory.v1.json` 不是手写支持列表。生成器从固定根 `pom.xml` 的模块、
各模块 `pom.xml` 的 `artifactId` 和规范位置的 `plugin.json` 扫描生成，并把上游 tag、
commit、tree、根 POM、模块 POM 以及每个 `plugin.json` 的相对路径和 SHA-256 绑定在
规范化 JSON 中。当前锁定源码扫描结果为 72 项（31 Reader、41 Writer）；四个 V1 业务
插件仅标记 `V1_BUSINESS` 候选，两个 stream 插件仅标记 `INTERNAL_SMOKE` 候选。所有条目
都固定为 `SOURCE_PRESENT` 和 `ordinary_user_executable=false`，inventory 不从源码目录、
Dockerfile 或候选名称推断 `BUILD_VERIFIED/PACKAGED/CONTRACTED/E3/E4`。

这里的 72 项严格只表示根 POM 中名称以 `reader`/`writer` 结尾且具有规范位置
`plugin.json` 的模块。Transformer、`plugin_job_template.json` 参数语义、DataX 核心/模板、
任意 SQL、`preSql/postSql`、脚本转换及其他原生功能不在本切片的 inventory 内；“72 个
Reader/Writer 源码条目”绝不等于“DataX 全部功能已盘点、已打包或可稳定执行”。

重建与校验命令：

```bash
python runtime/build_upstream_plugin_inventory.py
python runtime/build_upstream_plugin_inventory.py --check
python -m unittest runtime.test_upstream_plugin_inventory -v
```

`--check` 会拒绝缺失/重复插件、非法 Reader/Writer 方向、锁后源码篡改、catalog 篡改和
非规范 JSON。JSON Schema 位于
`docs/contracts/upstream-plugin-inventory.v1.schema.json`；schema 有效性和跨字段不变量都在
测试中复核。

构建补丁把上游 MySQL Connector/J `5.1.47` 固定升级到 `9.7.0`，构建阶段还校验官方
Maven 制品 SHA-256 `0353648e…43eb44`，并把 DataX 的驱动类名改为
`com.mysql.cj.jdbc.Driver`。JDBC 模板只使用 Connector/J 的明确 `sslMode`：
平台 `VERIFY_CA` 对应 `VERIFY_CA`，`VERIFY_FULL` 对应带主机名身份校验的
`VERIFY_IDENTITY`；不得再用只能表达证书链校验、不能表达主机名校验的旧
`useSSL/requireSSL/verifyServerCertificate` 参数。驱动以 GPLv2 + Universal FOSS
Exception 1.0 提供，其原始完整许可文件随 Runtime 一起分发。

镜像构建结束时生成 `/opt/datax/runtime-manifest.json`，固定源码身份、JDK、DataX
运行目录、插件、两份 Connector/J `9.7.0` JAR、第三方许可、内部自检和 oracle 制品
哈希。Worker 启动时先重新校验这些制品并执行固定 stream 自检；驱动版本/路径或摘要不符
时失败关闭，不接收业务执行。

当前证据只证明隔离 Maven 构建、Python 契约测试和内部 stream 自检；四种真实数据库复制
方向，以及 MySQL 正确 CA、错误 CA、正确主机名和错误主机名的 TLS 握手，仍必须在干净
Windows 11 x64 验收环境中运行，不能用 URL 字符串断言或内部自检替代。

## 可重复的直接 Runtime E2 诊断（不是产品 E3/E4）

为发现和复现固定 Runtime 与数据库类型互操作问题，可由操作者显式提供已经构建好的
Worker 镜像运行：

```bash
docker build -f backend/Dockerfile.worker -t datax-enterprise-studio-worker:runtime-e2 .
./scripts/test-datax-runtime-e2.sh \
  --worker-image datax-enterprise-studio-worker:runtime-e2
```

脚本绝不会自动构建、拉取或选择 Worker 镜像。它创建一个名称唯一的内部 Docker 网络，启动
四个临时 MySQL 8/PostgreSQL 15 fixture（均无宿主端口、无命名卷、数据库目录为 tmpfs），
并在受限且只读的容器中直接调用固定 DataX Runtime。每个 DataX 作业都有上限（默认
180 秒，可在 1–900 秒内显式调整），其输出只以截断字节数和状态进入报告；原始 DataX
日志、密码和连接串不输出。正常退出、失败、`HUP`、`INT` 或 `TERM` 都会精确清理临时
Worker、fixture 与网络，并拒绝残留同前缀的命名卷。

临时 Worker 只读 bind mount 单个 runner 脚本；`datax_studio` 与 oracle 均从所提供的
Worker image 本身加载，不会把整个开发仓库挂入带有 fixture 凭据的容器。清理始终以启动时
返回的不可变 Docker ID（并复核 runtime-E2 label）为目标，名称重用时不删除替代对象。
在创建任何 fixture 前，runner 还会校验 image 内 `/opt/datax/runtime-manifest.json`、固定
JDK、DataX Runtime、四个插件、驱动与 oracle；校验失败不会生成通过证据。

该诊断会用真实 DataX 和独立 oracle 对四个方向（MySQL→MySQL、MySQL→PostgreSQL、
PostgreSQL→MySQL、PostgreSQL→PostgreSQL）的全列与选列复制进行核验。它不启动产品
Compose、API、PostgreSQL 事实库、队列或产品 Worker 服务，因此**不能**作为产品 E3、
Windows E4、TLS、授权、插件认证、目标独占、审计或发布验收。已记录的运行时证据、已修复
问题和未覆盖项见 [直接 Runtime E2 证据](../docs/evidence/datax-runtime-e2.md)。
