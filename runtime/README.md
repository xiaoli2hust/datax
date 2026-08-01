# 固定 DataX Runtime

Windows 产品在 Docker Desktop + WSL2 的 Linux Worker 容器内运行 DataX，不在 Windows
宿主直接启动 Java/DataX 进程。

构建输入：

- 上游源码：`third_party/alibaba-datax/`
- 来源锁：`upstream.lock.json`
- 逐文件哈希清单：`upstream-files.sha256`
- 最小构建补丁：`patches/0001-reproducible-safe-runtime.patch`
- 只读运行配置：`config/`
- 独立数据核验算法：`oracle/verification_oracle.py`
- 再分发许可与告知：`third_party/licenses/`、上游 `license.txt` 和 `NOTICE`

`backend/Dockerfile.worker` 只构建四个认证业务插件
`mysqlreader/mysqlwriter/postgresqlreader/postgresqlwriter`，另带
`streamreader/streamwriter` 作为内部启动自检插件。内部自检插件不进入用户任务白名单。
构建会先校验哈希清单自身、全部 1,346 个上游文件、文件数和无符号链接条件，再应用固定
补丁；不匹配时立即失败。

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
