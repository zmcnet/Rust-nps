# Rust-nps

用 Rust 重写的 NPS 兼容内网穿透内核。**服务端 `rnps` + 客户端 `rnpc`，单文件、内嵌管理页、无需安装运行库。**

面向大量各自独立部署的个人与小团队：一台 NAS、一台软路由、一台小 VPS，就能把自己的服务接回家。

> 原版 8 个协议模式已在服务端实现（`tcpTrans` 仅有探测层），与老版 NPS 0.26.10 的桥协议线上兼容，并用**真实原版 Go 客户端**做黑盒验收。逐项证据见 [rust/docs/PHASE2-ACCEPTANCE.md](rust/docs/PHASE2-ACCEPTANCE.md)。

## 它现在能做什么

| 能力 | 状态 |
| --- | --- |
| TCP 隧道转发 | 真实原版 npc 黑盒验收 24/24，4 并发流逐字节一致 |
| UDP 隧道 | udp-smoke 7/7（60 KB 大包跨 mux 分片、多来源隔离） |
| HTTP / HTTPS 域名代理 | http-smoke 19/19、https-smoke 8/8（SNI 选证书、热加载、WebSocket） |
| SOCKS5 | socks5-smoke 29/29（CONNECT + UDP ASSOCIATE + 用户名密码认证） |
| 文件服务 | 真实 npc `[file]` 段下载验证 |
| secret 隧道（客户端本地监听） | secret-smoke 6/6 |
| P2P 三端口会合信令 | p2p-smoke 6/6（KCP 传输属客户端侧，未实现） |
| 加密（自签 TLS）/ 压缩（snappy） | crypt-smoke 4/4 × 5 轮稳定 |
| 限速 / 流量上限 / 健康检查摘除 / 多目标轮询 | rate-limit-smoke 3/3、target-smoke 4/4 |
| 多用户登录 + 服务端强制权限隔离 | 客户端账号访问管理员端点一律 403（真实二进制实测） |
| vkey 认证 / 断线重连 / 隧道运行时启停 | 停用后端口真实释放，启用后恢复 |
| 内嵌网页管理 | 客户端/隧道/连接数/双向流量、隧道启停、站点与证书 CRUD、ACME 进度 |
| 配置文件注册隧道 | 客户端上报，服务端自动建监听（task: tcp/udp/file + host） |
| rnpc 客户端 | 实例持久化（install/change/update/list/status/…）、四自启通道、本地更新源 |

**明确的边界**（详见验收表第九节）：`tcpTrans` 透明代理未接入转发路径；KCP 传输与 P2P 客户端侧未实现；客户端 `crypt`/`compress=true` 只告警并按未加密上报；限速/流量上限/IP 白名单目前只作用于 TCP 隧道；HTTP 更新源与更新签名未实现；生产 Let's Encrypt 未实测（Pebble 端到端已过）。

## 快速开始

```powershell
# 构建
cd rust
cargo build --release --workspace

# 启动服务端（管理令牌至少 24 字节）
$env:NPS_ADMIN_TOKEN = <32 字节随机值>
.\target\release\rnps.exe --config nps.json
```

```powershell
# 客户端连接
.\target\release\rnpc.exe -s <服务端地址> -p 8024 -vkey <密钥>
```

打开 `http://127.0.0.1:8080` 进入管理页。

## 文档

- [rust/docs/PHASE2-ACCEPTANCE.md](rust/docs/PHASE2-ACCEPTANCE.md) — 逐项验收对照表（当前状态的权威依据）
- [rust/README.md](rust/README.md) — 完整构建、配置、验证说明与兼容边界
- [rust/docs/rnpc-cli-spec.md](rust/docs/rnpc-cli-spec.md) — `rnpc` 命令行与持久化规范
- [rust/packaging/](rust/packaging/) — systemd / Docker / 安装脚本
- [tools/interop/README.md](tools/interop/README.md) — 与原版客户端的黑盒联调方法

## 验证方式

不靠自说自话。`tools/interop/smoke.py` 用**真实原版 Go 客户端**做黑盒验收，检查认证、大流量多连接、重连、隧道启停、端口释放、密钥泄漏与计数归零：

```powershell
python -I tools\interop\smoke.py --server-bin rust\target\debug\rnps.exe --npc-bin tools\interop\bin\npc.exe
```

当前结果：**24/24 通过**。工作区 `cargo test --workspace` 617 项全绿。

## 许可

[MIT](LICENSE)。协议行为参考了 [ehang-io/nps](https://github.com/ehang-io/nps)（GPL-3.0），其源码不在本仓库内，详见 [NOTICE](NOTICE)。

## 致谢

这个项目站在 [**ehang-io/nps**](https://github.com/ehang-io/nps) 肩上。

NPS 用 Go 写就。在一个内网穿透工具普遍难以上手的年代，它把「一个服务端 + 一个客户端 + 内嵌网页管理」这条路走通了，让大量没有运维团队的个人和小团队也能给自己的 NAS、软路由、家里的电脑开一条回家的路。它长期维护、文档完整、默认配置就能跑起来——这些看起来朴素的东西，恰恰是最难的。

Rust-nps 的协议层，每一个字节、mux 的窗口算法、握手的先后次序，都是从 NPS 的实际行为里逐项对照出来的。没有那份可读、可查、可验证的 Go 源码，这项工作无从谈起。

向 NPS 的作者和所有贡献者致谢。
