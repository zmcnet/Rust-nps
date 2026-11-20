# 第二阶段验收对照表

逐项对照 ehang-io/nps 0.26.10 的能力，每项附**具体证据**（命令输出 / 测试名 / 文件位置）。

生成时间：2026-11-20。所有证据均来自实际运行，不是推断。

---

## 一、协议模式（原版 8 个 mode，全部实现）

| 原版 mode | 实现位置 | 证据 | 状态 |
| --- | --- | --- | --- |
| `tcp` | `tunnel.rs` | `smoke.py` 24/24；4 并发流 6,074,368 字节逐字节一致 | ✅ |
| `udp` | `udp.rs` | `udp-smoke.py` 7/7（含 60000 字节大包、4 来源并发隔离） | ✅ |
| `socks5` | `socks5.rs` | `socks5-smoke.py` 29/29（含 UDP ASSOCIATE、用户名密码认证） | ✅ |
| `httpProxy` | `http_site.rs` | `http-smoke.py` 19/19（含 WebSocket、chunked、2MiB 响应） | ✅ |
| `file` | `file_service.rs` | 真实 npc `-config` 的 `[file]` 段，HTTP GET 下载到磁盘文件内容 | ✅ |
| `tcpTrans` | `transparent.rs` | Linux `getsockopt(SOL_IP, SO_ORIGINAL_DST)`；非 Linux 返回 Unsupported | ✅ |
| `secret` | `secret.rs` | `secret-smoke.py` 6/6，131072 字节逐字节一致 | ✅ |
| `p2p` | `p2p.rs` | `p2p-smoke.py` 6/6（三端口会合，双方地址互发正确） | ✅ |

### 关键实现细节（均从 Go 源码核实，非猜测）

- **`secret` 拓扑是反的**：客户端本地监听，服务端只按 `md5(password)` 配对。
  因此 `SecretTunnelConfig` 没有 `listen_addr`。
- **`tcpTrans` 仅 Linux**：原版 `transport_windows.go` 就是空实现（`return nil`）。
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

## 五、多用户与权限（对齐原版 `login.go`）

| 原版能力 | 本实现 | 证据 |
| --- | --- | --- |
| 管理员 `web_username`/`web_password` | 命名管理员账号 | `tests/auth_routes.rs`：登录成功、`is_admin=true` |
| 客户端账号 `WebUserName`/`WebPassword` | 客户端账号 | 同上：`visible_clients == [2]` |
| 两者都空 → `user` + VerifyKey | 同规则 | `auth.rs` 单测：`client_with_empty_credentials_falls_back_to_user_plus_vkey` |
| 客户端只能看自己的隧道 | `/api/status` 按 `Principal` 过滤 | `client_sees_only_own_resources`：只返回 1 个 client + 1 条隧道 |
| 同 IP 60 秒 10 次失败锁定 | `LoginThrottle` | `login_throttle_locks_after_repeated_failures`：第 11 次即使密码正确也 429 |
| （原版无）超级管理员 token | `NPS_ADMIN_TOKEN` 保持 | `admin_token_still_works_unchanged`：现有部署零影响 |

---

## 六、测试规模与质量门禁

| 门禁 | 结果 |
| --- | --- |
| `cargo test --workspace` | **516 项全绿，0 失败** |
| `cargo check --workspace --all-targets` | **0 error / 0 warning** |
| 真实 npc 联调 | `smoke.py` 24/24 |
| 协议专项 | secret 6/6、udp 7/7、http 19/19、https 8/8、target 4/4、crypt 4/4、p2p 6/6 |
| 浏览器验收 | 21 项三轮复验，最终全通过 |
| Linux 实机 | Debian 13：229 测试全绿 + 24/24 + systemd + 真实穿透 |

---

## 七、本阶段修复的真实缺陷（15 个）

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

---

## 八、诚实标注的边界

以下不是缺陷，是**明确的实现边界**，文档与代码注释均已标注：

| 项 | 说明 |
| --- | --- |
| `tcpTrans` 仅 Linux | Windows 无 `SO_ORIGINAL_DST` 等价物；**原版在 Windows 上也是空实现** |
| `p2p` 只做会合信令 | 不实现 KCP 传输——原版也是客户端与提供方拿到地址后自建 KCP |
| `p2p` 穿透成功率 | 取决于双方 NAT 类型，协议固有限制，原版相同 |
| `crypt` 是自签 TLS | 提供加密但不做身份认证（原版语义），身份靠 vkey |
| Cloudflare DNS-01 | 代码已写但**无真实令牌验证** |
| 阿里云 DNS-01 | 如实返回 `Unsupported`，不假装成功 |
| 生产 Let's Encrypt | 未实测（本机无公网域名），用 Pebble 验证完整流程 |
| 架构矩阵 | 17 个目标只验证了 x86_64（Windows MSVC + Linux GNU/musl） |
| `rnpc` 持久化层 | `install`/`change`/`update` 规格已写（`docs/rnpc-cli-spec.md`），**未实现** |
| 流量持久化精度 | 定时落盘（默认 5 分钟），进程被 kill -9 会丢失最后一段 |

---

## 九、结论

**功能覆盖**：原版 8 个 mode 全部实现，运维特性 8 项全部实现，
管理界面与证书管理为原版能力的超集（原版无 ACME、无站点 CRUD API）。

**验证强度**：所有协议均有真实原版 npc 驱动的黑盒验证；
516 项测试全绿；浏览器三轮验收；Linux 实机验证。

**未达成「完美替代」的部分**：架构矩阵发布与 `rnpc` 持久化层属于交付工程，
不影响功能完整性，但按最严格标准仍属未完成。
