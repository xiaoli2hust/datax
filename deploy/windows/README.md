# Windows 本地运行编排

本目录是 Windows 11 x64 本地工作站版的 Compose 入口。最终用户不直接执行这里的命令；
`launcher.exe` 负责前置检查、生成本地 secret、启动服务、等待
`/api/v1/health/ready` 返回 `200`，然后打开 `http://127.0.0.1:17860`。只达到
`live=200` 或容器处于 running 状态不能显示“服务已就绪”。
当前仓库所在 Mac 只用于开发验证；最终 Compose 必须运行并验收在另一台 Windows 11
x64 电脑的 Docker Desktop + WSL2 中。

仓库已提供 `backend/Dockerfile.worker`：它从锁定的上游源码、JDK 与插件集合构建
Linux/amd64 DataX Runtime，并在镜像内生成
`/opt/datax/runtime-manifest.json`。开发环境已经完成过容器构建与固定 stream smoke；
这不等于发布镜像已经签名或在 Windows 实机验收。缺少 manifest、摘要不符或 smoke
失败时，`/api/v1/health/ready` 必须返回 `503`，这是诚实阻断状态。

当前镜像基线固定为：PostgreSQL 服务和 `egress-guard` 使用固定摘要的 PostgreSQL
`15.18-alpine3.24`；API 与 Worker 的最终 Python 运行层使用固定摘要的 Python 3.12.13
`slim-trixie`（Debian 13）。发布环境仍只接受 `repository@sha256`。

PostgreSQL、脱敏日志和无秘密、受限的 oracle 产物只落在三个固定 Docker named volumes：
`des-postgres-data`、`des-log-data`、`des-workspace-data`。DataX Runtime 属于不可变发布
镜像，不使用空 named volume 覆盖镜像目录。Launcher 为每次安装生成独立
`installation-id`，并要求三个卷同时存在且分别携带匹配的安装标识和 role 标签；Docker
重置、部分卷丢失、标签不符或旧卷缺少安装标识都会阻断启动，不能自动用空卷覆盖旧状态。
首次初始化使用 ACL 受控的 `initialization-incomplete` 日志：全部 secret 先完整落盘并
通过域分离/密钥对校验，随后才创建卷，最后提交 `installation-id`。断电重试只允许补齐
该受控阶段，并同时要求没有任何产品/数据卷容器、已存在卷标签匹配且卷出现前 secret
已经完整；任何矛盾都阻断，绝不自动删除可能含数据的卷。

明文 DataX Job JSON、DataX 进程工作目录、未脱敏 Runtime 日志和性能临时文件不进入上述 named volume，而只
进入 Worker 的 `/tmp/datax-studio-sensitive` tmpfs。敏感根目录/Attempt 目录为 `0700`，
文件以 `0600`、`O_EXCL|O_NOFOLLOW` 原子创建；Worker 启动及每轮领取前只清理带固定产品
标记和规范 Execution/Attempt UUID 的过期目录。出现未知条目、标记不符或清理失败时停止
新领取，不把未知文件当作产品残留删除。Worker 同时固定 2 GiB 内存、2 CPU、256 PID 和
`nofile=4096/8192` 上限；tmpfs 上限为 256 MiB，耗尽时执行失败关闭。

Launcher 生成的 `credential-kek-v1.key` 是独立 32-byte OS CSPRNG 原始密钥，不能与
refresh-token/idempotency HMAC key 复用；Compose 只读挂载给 API 和 Worker。Launcher
另行生成与 PostgreSQL 管理密码不同的
`egress_guard_database_password.txt`，仅迁移任务和 `egress-guard` 可读取。

数据库 owner 凭据只提供给受控迁移；API 使用 `datax_api`，Worker 使用
`datax_worker`，两者密码相互独立，且都无 DDL、TEMP 和对象所有权。当前迁移仍向这两个
运行角色授予相同的全表 DML 与序列权限，细粒度“API 只创建初始记录、Worker 推进运行态”
主要由应用层边界执行；在数据库层收紧前，不得声称角色权限已经阻止 API 越权更新执行状态。

`egress-guard` 是唯一拥有 `NET_ADMIN` 的容器；API/Worker 通过
`network_mode: service:egress-guard` 共享它的 Linux 网络命名空间，二者仍
`cap_drop: [ALL]`。基础 nftables 策略默认拒绝，只长期允许 Docker DNS、loopback 控制
端点和 Compose `control` 子网。ACTIVE EndpointPolicy 的 CIDR×port 只作为 selected-IP
租约准入条件；外部 allow rule 必须是守卫生成的精确 `/32` 或 `/128` + TCP port，
落入运行时 `control` 子网的 selected IP 即使被策略 CIDR 覆盖也拒绝发放租约，
逻辑租约 30 秒、建议 5 秒续租，内核元素最多 15 秒。接口与失败关闭规则见
[`../../docs/contracts/egress-guard.v1.md`](../../docs/contracts/egress-guard.v1.md)。

发布安装包必须携带由发布流水线生成并签名覆盖的镜像环境文件；其中五个镜像值都必须
是 `repository@sha256:<64 hex>`。Launcher 在启动前重新校验格式、允许的仓库名与安装
资源哈希，不能接受 tag 或用户自定义镜像。

候选生成前，发布流水线还会使用全新、固定空 `auths` 的临时 `DOCKER_CONFIG`，在不继承
任何 registry 凭据的条件下逐项拉取这五个 digest，并生成
`anonymous-image-pulls.json`。任一镜像不是公开可匿名读取时，候选包构建必须停止；
Launcher 不因此增加 GHCR/Docker Hub 登录或凭据保存能力。

候选发布的源码 SBOM 只从 release context 绑定的精确 Git commit archive 生成；源码和
PostgreSQL/API/egress-guard/Worker/Web 五个固定 digest 镜像分别生成 SPDX SBOM。
OSV 应用策略与 Grype distro 策略属于候选证据门禁，但当前真实 GitHub release、Grype
OS 状态及 Windows release runner 尚无在线验证结果。

当前 Launcher 已有候选备份导出路径：在受控停机后，将 `.dxdata` 与 `.dxkeys` 分别写入
用户选择的两个不同本地目录，并使用两把不同密钥加密；DATA 包只含 PostgreSQL
custom-format 逻辑 dump、脱敏日志和固定发布元数据，SECRETS 包含本机基础设施 secret。
内部 helper 已能完整认证/配对双包，以两把恢复秘密认证 journal，并只解包到全新空
staging；成功仍返回 `RESTORE_STAGED_COMMIT_BLOCKED`，只达到 E1。新空 PostgreSQL
volume、真实 `pg_restore`、数据库/审计链/日志/密钥证据重算、卷/secret/
installation-id 原子提交和升级路径仍未实现，必须失败关闭。该候选尚未经过真实
Windows 11 备份/完整恢复验收，具体边界见
[`../../docs/contracts/system-backup.v1.md`](../../docs/contracts/system-backup.v1.md)。

开发者可以在明确设置 `DES_SECRET_DIR` 后，显式叠加仅供开发的 build override：

```powershell
docker compose `
  --env-file deploy/windows/images.dev.env `
  -f deploy/windows/compose.yaml `
  -f deploy/windows/compose.dev.yaml `
  build
docker compose `
  --env-file deploy/windows/images.dev.env `
  -f deploy/windows/compose.yaml `
  -f deploy/windows/compose.dev.yaml `
  up -d
```

`images.dev.env` 中的应用 tag 不是发布证据，不得放入安装器。

不得把本地 macOS/Linux 构建成功称为 Windows 安装验收。发布必须在干净 Windows 11 VM
验证 WSL2、Docker Desktop、安装器、签名、睡眠/恢复、备份和真实 DataX 四方向链路。
