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
3. **HTTPS 域名代理 + 证书管理**（详见下节）
4. **SOCKS5**
   - CONNECT / BIND / UDP ASSOCIATE
   - 用户名密码认证（对应 `multi_account`）

**验收标准**：每一项都用真实 Go `npc` 对接验证，并写入 `tools/interop/`。

## 2.3 HTTPS 与证书管理（详细设计）

### 定位

`rnps` 内置 80/443 监听，自己完成 TLS 终结与证书生命周期管理。
**目标不是做 Caddy**，只覆盖内网穿透场景真正需要的部分：

- 用户已经有公网 IP 和域名（内网穿透的前提）
- 需要把 `app.example.com` 直接指到家中的服务
- 不想额外装 nginx/caddy 再配一遍反代

**不做**：HTTP/2 推送、OCSP stapling 集群、多节点证书同步、WAF、缓存、gzip 预处理、
复杂 rewrite 规则。这些交给专业的反代去做。

### 三种证书来源

| 模式 | 场景 | 实现 |
| --- | --- | --- |
| `acme` | 有公网 IP + 域名已解析 | `rustls-acme` 自动申请与续期 |
| `upload` | 企业 CA / 已有证书 / 内网自签 | 面板上传 PEM，热加载 |
| `self-signed` | 测试、内网 | 启动时生成，浏览器告警属预期 |

### 三种 ACME 挑战

| 挑战 | 要求 | 用途 |
| --- | --- | --- |
| `http-01` | 80 端口公网可达 | 默认，最通用 |
| `tls-alpn-01` | 443 端口可达 | 80 被封时 |
| `dns-01` | DNS API 凭据 | 泛域名 `*.example.com` |

DNS-01 首期支持 Cloudflare（API Token）与阿里云 DNS（AccessKey），
其它厂商留扩展点，不硬编码。

### 数据模型

```jsonc
{
  "web_listen": { "http": "0.0.0.0:80", "https": "0.0.0.0:443" },
  "acme": {
    "provider": "letsencrypt",       // letsencrypt | letsencrypt-staging | zerossl | custom
    "directory_url": null,           // provider=custom 时必填
    "email": "admin@example.com",
    "challenge": "http-01",
    "dns_provider": null,            // cloudflare | aliyun
    "dns_credentials_env": "CF_DNS_API_TOKEN"
  },
  "sites": [
    {
      "id": 1,
      "domain": "app.example.com",
      "client_id": 1,
      "target": "127.0.0.1:3000",
      "routes": [                     // 可选，按路径前缀分流
        { "prefix": "/api", "target": "127.0.0.1:8080" }
      ],
      "tls": {
        "mode": "acme",
        "force_https": true,
        "hsts": false
      },
      "websocket": true,
      "enabled": true
    }
  ]
}
```

证书私钥**不写进配置文件**，单独存放：

```
<data_dir>/certs/<domain>/
├─ cert.pem        叶子证书 + 中间证书链
├─ key.pem         私钥（权限 0600，绝不入日志）
└─ meta.json       签发者 / 到期时间 / 签发方式 / 上次续期结果
```

### 核心实现点

1. **SNI 路由**：实现 `rustls::server::ResolvesServerCert`，按 SNI 查表；
   未匹配域名直接拒绝握手（不返回默认证书，避免信息泄漏）。
2. **证书热加载**：`ArcSwap<CertifiedKey>` 原子替换，续期不重启、不断连。
3. **ACME 挑战服务**：80 端口上优先匹配 `/.well-known/acme-challenge/<token>`，
   其余请求 301 到 HTTPS（`force_https` 时）。
4. **TLS-ALPN-01**：在 443 的 ALPN 协商中同时宣告 `acme-tls/1` 与 `http/1.1`。
5. **HTTP 转发**：解析请求行 + 头，按 `Host` 查 site，选 `routes` 前缀，
   通过 mux 子流把**原始 HTTP 字节**转发给客户端，由客户端连目标。
   这样客户端侧可以是任意语言/框架，不要求它会终止 HTTP。
6. **WebSocket**：识别 `Upgrade: websocket`，之后转为双向字节流（不再解析 HTTP）。
7. **续期**：到期前 30 天自动续；失败按 1h/6h/24h 退避重试并记录到 `meta.json`；
   面板显示剩余天数与最近一次失败原因。
8. **私钥保护**：只在内存解密；`Debug` 一律 `<redacted>`；任何错误信息不含路径以外的敏感内容。

### 面板新增

```
站点管理
├─ 站点列表：域名 / 客户端 / 目标 / 证书状态 / 到期天数 / 启用
├─ 新增站点：域名、选客户端、填目标、选 TLS 模式
├─ 路径分流：前缀 → 目标（可多条）
├─ 一键申请证书（显示 ACME 进度：下单 → 验证 → 签发 → 部署）
└─ 实时检测：DNS 解析是否正确、80/443 是否可达、握手是否成功

证书管理
├─ 证书列表：域名 / 签发者 / 到期 / 自动续期开关
├─ 上传证书：粘贴 PEM 或上传文件，即时解析校验（含链完整性）
├─ 手动续期 / 吊销
└─ 私钥指纹展示（不显示私钥本身）
```

### 安全约束（必须有）

1. 80/443 默认**不监听**，需显式配置 `web_listen` 才开启。
2. 私钥文件权限 0600，且不随配置导出。
3. ACME 账户密钥单独存放，同样 0600。
4. 拒绝为未在 `sites` 中声明的域名签发证书（防滥用）。
5. 面板上的证书操作需要管理令牌，且**不能**通过 API 读取私钥。
6. `force_https` 默认开启；HSTS 默认关闭（避免用户误锁自己）。

### 验收标准

| 项 | 验证方式 |
| --- | --- |
| 证书上传与热加载 | 上传自签证书 → `openssl s_client` 握手成功 → 换证书 → 不重启即生效 |
| HTTP 转发 | 真实 `npc` 接本地 Web 服务，`curl -H "Host: x"` 内容正确 |
| WebSocket | `websocat` 或浏览器实测双向消息 |
| ACME 申请 | 用 Pebble（Let's Encrypt 官方测试 CA）在本地跑完整流程 |
| 续期逻辑 | 伪造临近到期证书，验证自动续期触发 |
| SNI 拒绝 | 未声明域名握手失败，不返回任何证书 |

> ACME 真实签发需要公网域名，开发阶段用 **Pebble** 做本地 ACME 服务器验证全流程，
> 不依赖真实 Let's Encrypt 配额。


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
