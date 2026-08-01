# egress-guard V1 内部契约

本契约只用于 Windows 本地 Compose 内部的 API、Worker、迁移任务与
`egress-guard`。它不是宿主或产品公网 API。唯一监听地址为共享 Linux 网络命名空间内的
`127.0.0.1:17990`，不得发布 `ports`、绑定 LAN 地址或经 `web` 反向代理。

## 1. 数据库只读接口

迁移创建登录角色 `datax_egress_guard` 和安全屏障视图
`des_egress_guard_active_rules_v1`。该角色只有数据库 `CONNECT`、`public` schema
`USAGE` 和该视图 `SELECT`，没有基础表、写入、DDL、继承、建库、建角色或复制权限。

视图每行必须包含且只包含：

| 字段 | 语义 |
|---|---|
| `revision_id` | 当前 `ACTIVE` EndpointPolicy 的不可变 revision UUID |
| `policy_hash` | revision 的 64 位小写 SHA-256 |
| `resolver_policy_version` | 固定 `des-system-dns-v1` |
| `egress_policy_version` | 固定 `des-nftables-egress-v1` |
| `allowed_cidrs` | 1–64 个规范、排序、无重复 CIDR |
| `allowed_ports` | 1–32 个排序、无重复 TCP 端口 |

数据库密码是独立 32-byte OS CSPRNG 的 64 位小写 hex 文件
`/run/secrets/egress_guard_database_password`。迁移只通过
`DES_EGRESS_GUARD_DATABASE_PASSWORD_FILE` 读取它；API/Worker 不得挂载或继承该变量。
守卫只在私有 tmpfs 生成 mode `0600` 的 `PGPASSFILE`，退出时删除，不输出密码。

策略集合哈希必须与后端逐字节一致：

```text
ordered = [{"revision_id": id, "policy_hash": hash}, ...]  # 按 revision_id 排序
payload = JSON(ordered, sort_keys=true, separators=(",", ":"), ensure_ascii=false)
policy_set_hash = SHA-256(UTF8("DXEGRESSPOLICYSETv1\n") || UTF8(payload))
```

## 2. 证明接口

`GET /v1/attestation` 返回
[`egress-guard-attestation.v1.schema.json`](./egress-guard-attestation.v1.schema.json)。
API/Worker 必须拒绝未知字段、非 `VERIFIED`、超过 15 秒、未来超过 2 秒、版本不符、
策略集合哈希不匹配，或 `network_namespace_id` 不等于自身 `/proc/self/ns/net` 的响应。

`policies` 证明当前 ACTIVE revision 已进入租约准入集合，不表示整个 CIDR 已被内核
放行。`ruleset_hash` 是 nftables readback 去除运行时 `expires` 倒计时和内核分配
`handle` 后的结构哈希；`handle` 会在同一规则集的原子替换中重新分配，不代表许可语义。
守卫失联、证明过期、数据库读取/形状/版本失败、nft apply/readback 失败或规则漂移时，
消费者必须失败关闭。规则漂移会锁存到守卫重启，不能靠下一次轮询自动恢复授权。

## 3. selected-IP 租约

CIDR 只用于准入校验。内核外部规则只允许租约中的规范 IP 字面量
`/32` 或 `/128` 与单个 TCP 端口，禁止把策略 CIDR 直接写成 allow rule。这样即使 JDBC
使用 FQDN 并发生第二次 DNS 解析，解析到其他地址的连接也会被内核拒绝；连接可能安全
失败，但不能回退为 CIDR 全放行。

### 创建

`POST /v1/leases`，`Content-Type` 必须精确为 `application/json`，禁止
`Transfer-Encoding`，body 上限 4 KiB。请求符合
[`egress-guard-lease.v1.schema.json`](./egress-guard-lease.v1.schema.json) 的
`createRequest`。守卫重新读取当前 ACTIVE 视图并独立验证
`revision_id + policy_hash + selected_ip + port`；即使策略 CIDR 包含 Compose
`control` 子网，落入运行时 `control` 子网的 `selected_ip` 也必须拒绝，不能把内部
PostgreSQL 或其他控制面容器包装成外部数据源租约。客户端不能提交 lease ID 或 token。

成功返回 `201`/`createResponse`。`lease_id` 和 32-byte 随机 bearer token 均由守卫
生成；token 只在本次响应出现，守卫仅在内存保存其域分离 SHA-256，禁止日志、数据库、
attestation 或错误响应记录 token。

### 续租与释放

- `PUT /v1/leases/{lease_id}`：空 body，唯一 `Authorization: Bearer <token>`；
  成功返回 `200`/`renewResponse`，不再次返回 token。
- `DELETE /v1/leases/{lease_id}`：相同鉴权与空 body；成功返回 `204` 空响应。

逻辑租约每次创建/续租为 30 秒，客户端应每 5 秒续租；nft 元素每次最多存活 15 秒。
守卫死亡时，即使逻辑租约尚未到期，外部 allow 最迟 15 秒自动消失。租约到期、释放、
策略撤回、policy hash 改变、数据库失败或规则漂移后不得继续复用。

错误响应只有 `{"code":"..."}`：

| HTTP | code | 处理 |
|---|---|---|
| 400 | `LEASE_REQUEST_INVALID` | 请求形状、编码、IP 或端口无效 |
| 401 | `LEASE_AUTH_INVALID` | bearer 缺失、格式错误或不匹配 |
| 404 | `LEASE_NOT_FOUND` | 路径或租约不存在 |
| 409 | `LEASE_POLICY_NOT_ACTIVE` | 请求不在当前 ACTIVE revision 的 CIDR×port 内，或 selected IP 落入运行时 `control` 子网 |
| 429 | `LEASE_LIMIT_REACHED` | 活动租约达到固定上限 |
| 503 | 其他守卫/策略/nft 错误 | 一律视为没有出口授权，不重试真实数据库连接 |

## 4. Compose 与能力边界

- 只有 `egress-guard` 获得 `NET_ADMIN`，且先 `cap_drop: [ALL]`；API、Worker、迁移任务
  都不得获得新增 capability。
- API/Worker 使用 `network_mode: service:egress-guard`，必须与 attestation 中的 netns
  完全一致；Launcher 启动后再次读取三个容器的 `/proc/self/ns/net`。
- 基础规则默认 `policy drop`，只长期允许 Docker DNS、完整 `lo` 回环接口（使 API/guard
  的请求与随机回包端口均可达）和 Compose `control` 子网；`lo` 不是 LAN/WAN 路由，不能
  放宽外部出口。外部数据库仅来自 selected-IP 租约。
- 规则以单个 nft batch 原子替换并 readback；ACTIVE view 每 5 秒刷新。撤策、数据库失败
  或漂移立即清空全部租约并安装 base-deny。
- `web` 通过 `egress-guard:8000` 访问共享 netns 内 API；只有 Web 映射
  `127.0.0.1:17860`。

这些代码、Schema 和单元测试不是 Windows 实机证据。必须在干净 Windows 11 x64 +
Docker Desktop/WSL2 上验证 nftables 语法/能力、守卫死亡 15 秒失效、FQDN 二次解析偏移、
同 CIDR 不同 IP 拒绝、并发续租、睡眠/恢复和真实 MySQL/PostgreSQL 四方向链路；未完成
前保持 `NOT_RUN/BLOCKED`。
