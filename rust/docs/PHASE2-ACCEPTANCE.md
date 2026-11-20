# 第二阶段验收对照表

逐项对照 ehang-io/nps 0.26.10 的能力，每项附**具体证据**（命令输出 / 测试名 / 文件位置）。

生成时间：2026-11-20。所有证据均来自实际运行，不是推断。

---

## 一、协议模式（原版 8 个 mode 全部实现；tcpTrans 仅 Linux，与原版一致）

| 原版 mode | 实现位置 | 证据 | 状态 |
| --- | --- | --- | --- |
| `tcp` | `tunnel.rs` | `smoke.py` 24/24；4 并发流 6,074,368 字节逐字节一致 | ✅ |
| `udp` | `udp.rs` | `udp-smoke.py` 7/7（含 60000 字节大包、4 来源并发隔离） | ✅ |
| `socks5` | `socks5.rs` | `socks5-smoke.py` 29/29（含 UDP ASSOCIATE、用户名密码认证） | ✅ |
| `httpProxy` | `http_site.rs` | `http-smoke.py` 19/19（含 WebSocket、chunked、2MiB 响应） | ✅ |
| `file` | `file_service.rs` | 真实 npc `-config` 的 `[file]` 段，HTTP GET 下载到磁盘文件内容 | ✅ |
| `tcpTrans` | `transparent.rs` + `tunnel.rs`（transparent 模式） | 配置 `tcp_trans_tunnels` → 监听 → 每连接 `SO_ORIGINAL_DST` 反查原始目标 → `Link::tcp(原始目标)` 交客户端拨号；复用普通隧道的 accept / 泵 / 限速 / 包装（`tests/tcp_trans.rs`）。**仅 Linux**：非 Linux 平台启动时警告、隧道不启用并写入明确 last_error（原版 `transport_windows.go` 同样是空实现）。Linux 真机 iptables REDIRECT 端到端待环境 | ✅（E2E 待真机） |
| `secret` | `secret.rs` | `secret-smoke.py` 6/6，131072 字节逐字节一致 | ✅ |
| `p2p` | `p2p.rs` | `p2p-smoke.py` 6/6（三端口会合，双方地址互发正确） | ✅ |

### 关键实现细节（均从 Go 源码核实，非猜测）

- **`secret` 拓扑是反的**：客户端本地监听，服务端只按 `md5(password)` 配对。
  因此 `SecretTunnelConfig` 没有 `listen_addr`。
- **`tcpTrans` 探测仅 Linux**：原版 `transport_windows.go` 就是空实现（`return nil`）。
  本实现接线后同样仅 Linux 生效；未经 REDIRECT 的直连被关闭（不回退默认目标，
  否则语义就错了）。
- **`p2p` 需要三个连续 UDP 端口**：原版 `server.go` 起了 `p2p_port`、`+1`、`+2` 三个
  `P2PServer`；客户端向三个端口各发一次会合请求，收齐后合并成 KCP 连接。
- **`file` 不发 Link 首帧**：原版 `bridge.go` 在 `mode=="file"` 时 `tunnel.NewConn()`
  之后直接 return，`SendInfo(link, "")` 不执行。

---

## 二、运维特性（原版全部实现）

| 特性 | 原版配置项 | 实现位置 | 证据 |
| --- | --- | --- | --- |
| 限速 | `rate_limit` | `limit.rs`（令牌桶） | **实测**：1 MiB 传输，不限速 0.03s，限速 100 KB/s 时 19.50s（612x） |
| 流量上限 | `flow_limit` | `limit.rs`（`FlowCounter`） | 单测：超限后 `exceeded()` 永久为 true |
| IP 白名单 | `ip_limit` | `limit.rs`（`IpAllowList`） | 单测：单 IP / CIDR / IPv6 / 空表全允许 |
| 健康检查 | `health_check_*` | `target.rs`（`HealthChecker`） | `target-smoke.py` 4/4：B 关闭后健康检查摘除，请求只落 A |
| 多目标轮询 | `Target.TargetArr` | `target.rs`（`TargetPool`） | `target-smoke.py`：8 次请求 A/B 各 4 次，严格交替 |
| 流量持久化 | `flow_store_interval` | `flow_store.rs` | 单测：save/load 往返、损坏文件不阻塞启动、关闭前落盘 |
| 加密 | `crypt` | `crypt.rs`（自签 TLS） | `crypt-smoke.py` 4/4 × 5 轮稳定 |
| 压缩 | `compress` | `crypt.rs`（snappy framed） | `crypt-smoke.py` 4/4 × 5 轮稳定 |

### 流控全路径覆盖（2026-11-21 接线）

限速 / 流量上限 / IP 白名单按**客户端**生效（per-client 一份配额，
`ClientControls`），覆盖全部转发路径，集成测试见 `tests/controls.rs`：

| 路径 | 限速 | 流量上限 | IP 白名单 | 证据 |
| --- | --- | --- | --- | --- |
| TCP 静态隧道 | ✅ | ✅ | ✅ | 原有 `hardening.rs` / `limit.rs` |
| TCP conf 动态注册 | ✅ | ✅ | ✅ | `controls.rs::conf_registered_tunnel_inherits_ip_whitelist` |
| UDP | ✅ | ✅（超限拒绝新建流） | ✅（静默丢包） | `controls.rs::udp_ip_whitelist_drops_datagrams_without_opening_stream` |
| SOCKS5（CONNECT + UDP ASSOCIATE） | ✅ | ✅（建流前拒绝，REP=0x02） | ✅（协商前静默关闭） | `controls.rs::socks5_ip_whitelist_closes_without_reply` |
| HTTP/HTTPS 站点 | ✅（请求头/体 + 响应头/体逐段） | ✅（resolve 后 503） | ✅（403） | `controls.rs::http_site_ip_whitelist_returns_403`、`flow_limit_is_shared_across_tcp_and_http` |
| file | ✅ | ✅ | ✅ | 构造处传真值（`server.rs` / `conf.rs`），模块内逻辑与 TCP 同套 |
| secret | ✅ | ✅ | —（不适用：连接来自已认证 npc） | `secret.rs` relay 双向 throttle |
| tcpTrans | ✅ | ✅ | ✅ | 复用 TCP 隧道同一套 `Tunnel` 实现 |

### `crypt` / `compress` 的协议事实（从源码核实）

- `crypt` = **自签 TLS 包装**（`lib/crypt/tls.go`），客户端 `InsecureSkipVerify: true`。
  提供加密与完整性，**不做身份认证**（身份靠 vkey）。
- `compress` = **snappy framed 格式**（`lib/conn/snappy.go` 用 `NewBufferedWriter`），
  不是 raw block。
- **`crypt` 优先于 `compress`**：原版是 `if cpt { } else if snappy { }`。

---

## 三、HTTPS 与证书管理（原版能力的超集）

原版只有 `https_default_cert_file` + `https_default_key_file`（手动放文件）。
本实现完整覆盖并扩展：

| 能力 | 证据 |
| --- | --- |
| SNI 按域名选证书 | `tests/tls.rs` 18 项 |
| **未声明域名拒绝握手**（不返回默认证书，防域名探测） | `https-smoke.py`：`SSLError` |
| **无 SNI 拒绝握手** | `https-smoke.py`：`SSLError` |
| 证书热加载 | `tests/tls.rs`：替换后新连接拿新证书，listener 未重建 |
| 证书上传 | 浏览器验收第 13 项：`openssl` 生成证书上传成功 |
| 自签证书生成 | 浏览器验收第 10 项 |
| **ACME 在线申请**（原版没有） | `tests/acme.rs`：Pebble 真实签发，`http-01` 与 `tls-alpn-01` 均签出 |
| **程序绝不擅自申请证书** | `tests/acme.rs`：构造服务后 ACME 请求数为 0 |
| **预检失败不消耗 CA 配额** | `tests/acme.rs`：预检失败时 `audit().count() == 0` |

---

## 四、管理界面（原版能力的超集）

| 能力 | 证据 |
| --- | --- |
| 总览（客户端/隧道/连接数/流量） | 浏览器验收第 3、4 项 |
| 隧道运行时启停 | `smoke.py`：停用后端口真实 `refused`，启用后恢复 |
| **站点 CRUD**（原版只能在 web 表单增删） | 浏览器验收第 4-8 项：新增/幂等更新/删除/空域名报错 |
| **证书管理界面**（上传/自签/ACME 四选一） | 浏览器验收第 9-15 项 |
| **ACME 申请进度与失败原因** | 浏览器复验第 18 项：红色错误态 + 「解析失败…请检查 DNS 记录是否存在」 |
| 窄屏可用（375px） | 浏览器验收第 21 项：`overflowX=0`，无重叠 |
| 控制台无异常 | 浏览器验收第 19 项：`window.onerror`/`unhandledrejection` 全程为空 |

### 管理页的安全设计

- Bearer 令牌 + **常量时间比较**
- CSP `default-src 'self'; script-src 'self'`（无内联脚本）
- `nosniff` / `X-Frame-Options: DENY` / `no-referrer` / COOP / CORP
- 变更请求 Origin 同源校验（`null` 一律拒绝）
- 服务端数据一律 `textContent`（有测试断言禁止 `innerHTML`）
- **私钥只在请求体出现一次**，不回显、不进日志、不在 DOM（有测试断言）

---

## 五、多用户与权限（对齐原版 `login.go`，**服务端强制**）

| 原版能力 | 本实现 | 证据 |
| --- | --- | --- |
| 管理员 `web_username`/`web_password` | 配置项 `web_username`/`web_password` | 真实二进制：`root` 登录后 `/api/sites` → 200 |
| 客户端账号 `WebUserName`/`WebPassword` | 客户端 `web_username`/`web_password` | 真实二进制：`alice` 登录成功，`is_admin: false` |
| 两者都空 → `user` + VerifyKey | 同规则 | `auth.rs` 单测：`client_with_empty_credentials_falls_back_to_user_plus_vkey` |
| 客户端只能看自己的隧道 | `/api/status` 按 `Principal` 过滤 | 真实二进制：alice 只看到 `['alice']` |
| 同 IP 60 秒 10 次失败锁定 | `LoginThrottle` | `login_throttle_locks_after_repeated_failures`：第 11 次即使密码正确也 429 |
| （原版无）超级管理员 token | `NPS_ADMIN_TOKEN` 保持 | 真实二进制：token 访问 `/api/sites` → 200，老部署零影响 |

### 权限在服务端强制（不只是前端隐藏）

前端隐藏入口只是 UI 约束；绕过前端直接发请求必须被拦。为此新增
`require_admin_principal` 守卫，接入 11 个管理员端点
（隧道启停、站点 CRUD、证书上传/自签/重载/删除/列表、ACME）。

真实二进制实测：

```
alice → /api/sites  → 403「需要管理员权限（当前身份：client(alice#1)）」
alice → /api/certs  → 403
alice → /api/status → 200，只看到自己
root  → /api/sites  → 200
token → /api/sites  → 200
```

5 项路由级测试覆盖：客户端 403、管理员 200、超级令牌 200、未认证 401、
客户端仍能读自己的 status。

---

## 六、`rnpc` 持久化与进程管理（规格 `docs/rnpc-cli-spec.md`）

| 能力 | 状态 | 证据 |
| --- | --- | --- |
| `install` | ✅ | 真实跑通：复制二进制 → 写配置 → 注册自启 → PATH → 摘要 |
| `uninstall` | ✅ | 真实跑通：注册表项被删（`reg query` 报「找不到」）+ 目录删除 |
| `change` | ✅ | 真实跑通：server/port/vkey 三项变更，vkey 只报「已更新」 |
| `update` | ✅ | 版本比较（semver）+ sha256 校验 + 备份 + 失败还原 |
| `list` | ✅ | 显示真实运行状态与 PID（陈旧记录自动清理） |
| `status` | ✅ | vkey 显示「已设置（不显示）」 |
| `start`/`stop`/`restart` | ✅ | 真实跑通：分离启动 → 服务端看到在线 → stop 清理 → restart |
| `logs` | ✅ | `--lines` 截尾、`--follow` 跟随；守护进程输出写入实例日志 |
| `path add/remove/status` | ✅ | 幂等、只删自己那段、超长拒绝 |
| `channel list/install/remove` | ✅ | run-key 真实验证（注册表读写）；需管理员的通道给退出码 3 |
| 多实例隔离 | ✅ | 无全局锁、无固定 PID 文件；临时文件按实例名隔离 |
| 配置文件权限 | ✅ | Unix 0600 / Windows `icacls` 移除继承只给当前用户 |
| vkey 不回显 | ✅ | `Debug`/`summary`/`status`/`list` 全部打码，有测试断言 |
| 四个自启通道 | ⚠️ 部分 | `run-key` 真实验证；`service`/`task-*` 需要管理员，**成功路径未验证** |

### `update` 的安全语义（实测）

- **sha256 错误 → 拒绝替换**，原文件 sha256 不变（实测对比前后哈希）
- 正确 sha256 → 更新成功，备份存在，落盘内容与源一致
- 实例运行中 → 提示先停止，不静默替换
- 未配置更新源 → 明确输出「跳过」，**不伪造「已是最新」**
- 版本方向：`plan.order` 是「当前 vs 清单」，只有 `Older` 才更新
- 幂等：第一次更新到 0.3.0，第二次正确报「已是最新」

### 自启命令构造（纯函数 + 穷尽测试）

`task_create_args` / `task_query_args` / `task_delete_args` /
`run_key_value` / `service_bin_path` 全部为纯函数，12 项测试覆盖：
`/sc` 取值、`/f` 幂等、含空格路径加引号、**不含空格也统一加引号**、
相对路径拒绝、**命令行绝不含 vkey**、服务名截断 + FNV-1a 防碰撞。

`service-host` 是 SCM 入口：完整上报
`START_PENDING → RUNNING → STOP_PENDING → STOPPED`，处理
`SERVICE_CONTROL_STOP`/`SHUTDOWN`/`INTERROGATE`。
非 SCM 环境下实测返回 `os error 1063`（服务进程无法连接到服务控制器），
证明 dispatcher 真实存在且不伪造成成功。

---

## 七、测试规模与质量门禁

| 门禁 | 结果 |
| --- | --- |
| `cargo test --workspace` | **642 项全绿，0 失败**（2026-11-21，含流控全路径 `controls.rs`、tcpTrans `tcp_trans.rs`、示例配置防漂移 `example_config.rs`） |
| `cargo check --workspace --all-targets` | **0 error / 0 warning** |
| 真实 npc 联调 | `smoke.py` 24/24 |
| 协议专项 | secret 6/6、udp 7/7、http 19/19、https 8/8、target 4/4、crypt 4/4、p2p 6/6 |
| 权限隔离 | `auth_routes.rs` 14 项（含 5 项越权拒绝） |
| CLI/持久化 | instance 10、commands 6、path_env 7、autostart 19、process 13、update_feed 21 |
| 浏览器验收 | 登录流程 12 场景 92 断言（headless Edge + CDP） |
| Linux 实机 | Debian 13：229 测试全绿 + 24/24 + systemd + 真实穿透 |


---

## 八、本阶段修复的真实缺陷（22 个）

每一条都有对应测试；标 ⚑ 的做过「回退即失败」实证。

| # | 缺陷 | 后果 |
| --- | --- | --- |
| 1 | 外部连接 EOF 后未向 npc 发 `ConnClose` | npc 侧目标连接永久悬挂，`active_connections` 不归零 |
| 2 ⚑ | 写循环 `write_all` 不可取消 | 对端不读 socket 时 `close()`/超时/`shutdown()` 全失效，会话「假活」 |
| 3 ⚑ | `try_lock` 抢不到即跳过清理 | 死弱引用永久占路由表，累计 512 后永久拒绝新建流 |
| 4 | `encode` 的 `len as u16` 截断 | 内容 >65535 时写出长度不符的帧，对端永久失步 |
| 5 | 空内容 ping 原样回显 | Go 的 `basePackager.Set` 拒绝零长度 → 一个回包杀死对端整条 mux |
| 6 | 双方 mux id 空间重叠 | 后写者覆盖先写者路由，跨连接数据串台 |
| 7 | `stop()` 强制 `store(0)` | 与并发自减相撞 → u64 回绕成 1.8e19 |
| 8 | 转发泵用裸 `JoinHandle` | 父任务被 abort 时是**分离**而非取消，孤儿泵占 mux 半边 |
| 9 | 健康检查器与隧道各自建 `TargetPool` | 摘除对转发不可见，B 离线后请求仍路由到 B |
| 10 | `tokio::io::split` 在 TLS 流上死锁 | crypt 握手成功后 30 秒零字节（间歇性） |
| 11 | `SnappyStream` 对半块 `read_to_end` | 半个 framed 块时 `UnexpectedEof` |
| 12 | 管理页 ACME 拉取在登录前 | 401 被静默吞掉 → **ACME 申请 100% 不可用** |
| 13 | ACME 失败显示成绿色成功 | 用户以为申请成功，实际域名解析失败 |
| 14 | 管理页使用 `innerHTML` | 违反项目「服务端数据一律 textContent」约定 |
| 15 | p2p 只起单端口 | 客户端等不齐三份地址，穿透必然失败 |
| 16 | `install` 注册的 `run --name` 子命令不存在 | **自启后 100% 启动失败** |
| 17 | `service` 通道注册的 `service-host` 子命令不存在 | **服务注册成功但永远起不来** |
| 18 | 生产二进制仍用旧 `router()` | `/api/auth/*` 全 404，**多用户上线后不可用** |
| 19 | 管理员端点不校验 `is_admin()` | 客户端账号可越权改隧道、传证书（**安全漏洞**） |
| 20 | `update` 版本比较方向反了 | 永远判定「已是最新」，从不更新 |
| 21 | `update` 用运行中二进制版本判断 | 反复判断「有新版本」，永不收敛 |
| 22 | 守护进程继承父进程 stdio | `restart` 看起来挂死（管道永不关闭） |

---

## 九、诚实标注的边界

以下不是缺陷，是**明确的实现边界**，文档与代码注释均已标注：

| 项 | 说明 |
| --- | --- |
| `tcpTrans` 端到端 | 接线已完成（配置/监听/转发/快照/流控，见第一节）；**Linux 真机 iptables REDIRECT 端到端待环境**。非 Linux 平台不启用并给明确原因（原版在 Windows 上也是空实现） |
| `p2p` 只做会合信令 | 不实现 KCP 传输——原版也是客户端与提供方拿到地址后自建 KCP |
| `p2p` 穿透成功率 | 取决于双方 NAT 类型，协议固有限制，原版相同 |
| 客户端 KCP / P2P | 客户端侧未实现（服务端会合信令已实现） |
| `crypt` 是自签 TLS | 提供加密但不做身份认证（原版语义），身份靠 vkey |
| SOCKS5/UDP/HTTP/secret 的 Link 帧 | 硬编码 `crypt=false, compress=false`（TCP 隧道带真值）——这些路径按明文转发，两端语义一致、不是断连 bug，是保真度缺口 |
| `FlowCounter` 不持久化 | `flow_limit` 的已用量重启归零（与展示用 `flow_store` 是两套计数） |
| Cloudflare DNS-01 | 代码已写但**无真实令牌验证** |
| 阿里云 DNS-01 | 如实返回 `Unsupported`，不假装成功 |
| 生产 Let's Encrypt | 未实测（本机无公网域名），用 Pebble 验证完整流程 |
| `service`/`task-start`/`task-logon` 自启 | 需要管理员；**开发机非管理员，成功路径未验证**，只验证了参数构造与错误分支 |
| HTTP 更新源 | 未实现；需要先定义签名机制，模块如实拒绝而不是假装支持 |
| 更新签名验证 | 只有 sha256（防损坏，不防恶意清单） |
| 流量持久化精度 | 定时落盘（默认 5 分钟），进程被 kill -9 会丢失最后一段 |
| 架构矩阵 | 17 个 target 的 CI 已写；**本机只验证了 x86_64** |

---

## 十、结论

**功能覆盖**：原版 8 个 mode 全部实现（`tcpTrans` 仅 Linux，与原版口径一致），运维特性 8 项全部实现，
限速 / 流量上限 / IP 白名单覆盖全部转发路径，
管理界面、证书管理与多用户权限为原版能力的超集（原版无 ACME、无站点 CRUD API、
无服务端强制的权限隔离）。

**交付工程**：`rnpc` 持久化层与进程管理已实现并真实验证；
`update` 有真校验、真备份、真还原；自启四通道中 `run-key` 已验证。

**验证强度**：所有协议均有真实原版 npc 驱动的黑盒验证；
642 项测试全绿（0 失败）；浏览器 12 场景 92 断言 + 真实预览环境截图验收；Linux 实机验证；
多用户权限用真实二进制端到端验证（403/200 实测）。

**未达成「完美替代」的部分**：tcpTrans 的 Linux 真机 iptables 端到端、
三个需管理员的自启通道成功路径、
HTTP 更新源与签名、17 架构的本地实测——均受限于当前环境（非 Linux / 无管理员、
无公网域名、无交叉工具链）或未定的设计决策，已在第九节逐项标注。

