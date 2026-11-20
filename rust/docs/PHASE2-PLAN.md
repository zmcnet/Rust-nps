# 第二阶段计划：完美替代老版 NPS

目标：让 Rust-nps 在功能上完整覆盖 ehang-io/nps 0.26.10，成为可无缝替换的实现。

## 一、原版能力全清单（从源码逐项确认，非估算）

### 已实现 ✅

| 能力 | 状态 |
| --- | --- |
| TCP 隧道（`mode=tcp`） | 真实 npc 验证 24/24 |
| 配置文件注册隧道（`conf` + `NEW_TASK`） | 真实 npc `-config` 验证通过 |
| 多路复用 mux | 4 并发流 6 MB 逐字节一致 |
| vkey 认证 | 通过 |
| 断线重连 | 通过 |
| 隧道运行时启停 | 端口真实释放 |
| 网页查看状态 + 启停 | 浏览器 8/8 |
| 双向流量统计 | 精确对账 |

### 未实现 ❌（按优先级排序）

| # | 能力 | 原版实现 | 复杂度 | 用户影响 |
| --- | --- | --- | --- | --- |
| 1 | **UDP 隧道**（`mode=udp`） | `server/proxy/udp.go`，`addrMap` 按来源地址映射子流 | 中 | 高（DNS、游戏、语音） |
| 2 | **HTTP 域名代理**（`mode=httpProxy` + `Host`） | `server/proxy/http.go`，按 `Host` 头路由 | 中 | 高（最常用场景之一） |
| 3 | **HTTPS 域名代理**（`https_proxy_port`） | `server/proxy/https.go`，SNI 路由 + 默认证书 | 中高 | 高 |
| 4 | **SOCKS5**（`mode=socks5`） | `server/proxy/socks5.go`，含 UDP ASSOCIATE | 中 | 中 |
| 5 | **加密 + 压缩**（`crypt` / `compress`） | `lib/crypt/tls.go` 自签 TLS；`lib/conn` snappy | 中 | 中（安全相关） |
| 6 | **限速 + 流量上限**（`rate_limit` / `flow_limit`） | `lib/rate` 令牌桶 | 低 | 中 |
| 7 | **健康检查**（`health_check_*`） | `client/health.go` + `sheap` | 中 | 中（多目标故障转移） |
| 8 | **多目标负载均衡** | `Target.GetRandomTarget()` 轮询 | 低 | 中 |
| 9 | **文件服务**（`mode=file`） | `client/local.go` 的 `http.FileServer` | 低 | 低 |
| 10 | **P2P 打洞**（`mode=p2p`） | `server/proxy/p2p.go` + UDP 信令 | 高 | 低（NAT 环境成功率低） |
| 11 | **多用户 + 权限** | `web/controllers/login.go`、`client.go` | 中高 | 低（自部署单用户为主） |
| 12 | **流量持久化**（`flow_store_interval`） | `server/server.go` 定时落盘 | 低 | 低 |
| 13 | **IP 访问限制**（`ip_limit`） | `bridge` 的 Register 表 | 低 | 低 |
| 14 | **Basic Auth / 多账号**（`multi_account`） | SOCKS5/HTTP 认证 | 低 | 低 |
| 15 | **客户端 KCP 传输** | `kcp-go` | 中 | 低（弱网） |
| 16 | **Web 端 CRUD**（增删改客户端/隧道/域名） | `web/controllers/index.go` | 中 | 中（当前只能改 JSON） |

## 二、分阶段路线

### 阶段 2.1：补齐传输协议（最高优先）

**目标**：覆盖绝大多数实际使用场景。

1. **UDP 隧道**
   - 服务端：`UdpTunnel` 按 `(来源IP:端口)` 维护子流映射，空闲超时回收
   - 协议：`Link.ConnType = "udp"`，子流内传原始 UDP 载荷
   - 客户端：`rnpc` 侧拨号 UDP 目标，双向转发
   - 验证：真实 npc 的 `mode=udp` 对接，DNS 查询 + 大包
2. **HTTP 域名代理**
   - 服务端：`Host` 模型（`Host`/`Location`/`Scheme`/`Target`），按 `Host` 头 + 路径前缀路由
   - 复用现有 mux：`Link.ConnType = "http"`，子流内传完整 HTTP 请求/响应
   - 支持 WebSocket 升级（`hijack`）
3. **HTTPS 域名代理**
   - SNI 解析（`ClientHello` 嗅探），按域名选证书或透传到客户端
   - 默认自签证书 + 用户自定义证书路径
4. **SOCKS5**
   - CONNECT / BIND / UDP ASSOCIATE
   - 用户名密码认证（对应 `multi_account`）

**验收标准**：每一项都用真实 Go `npc` 对接验证，并写入 `tools/interop/`。

### 阶段 2.2：安全与流控

5. **加密 + 压缩**
   - 对齐原版：`crypt=true` 走自签 TLS 包装子流；`compress=true` 走 snappy
   - 必须与真实 npc 互通（原版用 `InsecureSkipVerify`）
6. **限速**（令牌桶，按客户端/隧道）
7. **流量上限**（`flow_limit`，超限断开）
8. **IP 访问限制**（`ip_limit`，按注册 IP 白名单）

### 阶段 2.3：可用性

9. **健康检查 + 多目标故障转移**
10. **多目标轮询负载均衡**
11. **文件服务**
12. **流量持久化**（可选，落 JSON 或 SQLite）

### 阶段 2.4：管理面

13. **Web 端完整 CRUD**
    - 新增/编辑/删除客户端与隧道
    - 域名代理配置
    - 配置持久化到 JSON 文件
14. **多用户 + 登录**
15. **P2P 打洞**（最后做，收益最低）

## 三、明确不做的事

| 项 | 原因 |
| --- | --- |
| KCP 传输 | 弱网优化，可与后续新协议一起做；老 npc 兼容层不引入 |
| 原版 Web UI 复刻 | 当前自研界面更简洁；只补功能不抄样式 |
| 数据库（MySQL/Postgres） | 自部署场景用 JSON 文件足够；原版也支持 JSON |
| 与原版完全相同的 API 路径 | 无必要；保持当前 `/api/*` 设计 |

## 四、执行原则

1. **每项都用真实原版客户端验证**，不接受"单测通过"作为完成标准
2. **不破坏已通过的 24/24**，每次改动后回归
3. **协议层改动集中在 `nps-legacy`**，新能力优先在新模块实现
4. **诚实标注未验证项**

## 五、当前技术债（需在阶段 2 内偿还）

| 项 | 说明 |
| --- | --- |
| 无连接速率限制 | 桥端口可被暴力尝试 vkey，无失败计数与封禁 |
| 注册隧道不持久化 | 重启即失效 |
| 无长时间运行测试 | 无 24h soak，内存/句柄泄漏未知 |
| 无公网跨 NAT 验证 | 仅本机回环 |
| 架构矩阵未做 | 17 个目标只有 x86_64 验证过 |

## 六、建议执行顺序

```
2.1 UDP → HTTP → HTTPS → SOCKS5     （功能覆盖，用户可感知）
2.2 加密压缩 → 限速 → 流量上限      （安全与资源控制）
2.3 健康检查 → 负载均衡 → 文件服务   （可用性）
2.4 Web CRUD → 多用户               （管理面）
2.5 P2P                             （最低优先）
```

先做 2.1，因为它是"能否替代原版"的决定性分水岭——UDP 和 HTTP 域名代理是原版用户最常用的两个功能。
