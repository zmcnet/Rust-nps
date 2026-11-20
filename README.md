# Rust-nps

用 Rust 重写的 NPS 兼容内网穿透内核。**服务端 `rnps` + 客户端 `rnpc`，单文件、内嵌管理页、无需安装运行库。**

面向大量各自独立部署的个人与小团队：一台 NAS、一台软路由、一台小 VPS，就能把自己的服务接回家。

> 当前是 **TCP 兼容预览版**。它与老版 NPS 的桥协议线上兼容，但还不是原版的全功能替代品。

## 它现在能做什么

| 能力 | 状态 |
| --- | --- |
| TCP 隧道转发 | 已用真实原版 Go npc 验证 |
| 多路复用（一条连接承载多条隧道流） | 4 并发流 6 MB 逐字节一致 |
| vkey 认证 | 错误 vkey 被拒，客户端保持离线 |
| 断线重连 | 客户端重启后自动恢复 |
| 隧道运行时启停 | 停用后端口真实释放，启用后恢复 |
| 内嵌网页管理 | 客户端/隧道/连接数/双向流量，可逐行启停 |
| 配置文件注册隧道 | 客户端上报，服务端自动建监听 |

**尚未实现**：UDP、HTTP 域名代理、SOCKS5、KCP、P2P、文件服务、加密、压缩。

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

- [rust/README.md](rust/README.md) — 完整构建、配置、验证说明与兼容边界
- [rust/docs/rnpc-cli-spec.md](rust/docs/rnpc-cli-spec.md) — `rnpc` 命令行与持久化规范
- [rust/packaging/](rust/packaging/) — systemd / Docker / 安装脚本
- [tools/interop/README.md](tools/interop/README.md) — 与原版客户端的黑盒联调方法

## 验证方式

不靠自说自话。`tools/interop/smoke.py` 用**真实原版 Go 客户端**做黑盒验收，检查认证、大流量多连接、重连、隧道启停、端口释放、密钥泄漏与计数归零：

```powershell
python -I tools\interop\smoke.py --server-bin rust\target\debug\rnps.exe --npc-bin tools\interop\bin\npc.exe
```

当前结果：**24/24 通过**。工作区 `cargo test --workspace` 全部通过。

## 许可

[MIT](LICENSE)。协议行为参考了 [ehang-io/nps](https://github.com/ehang-io/nps)（GPL-3.0），其源码不在本仓库内，详见 [NOTICE](NOTICE)。

## 致谢

这个项目站在 [**ehang-io/nps**](https://github.com/ehang-io/nps) 肩上。

NPS 用 Go 写就。在一个内网穿透工具普遍难以上手的年代，它把「一个服务端 + 一个客户端 + 内嵌网页管理」这条路走通了，让大量没有运维团队的个人和小团队也能给自己的 NAS、软路由、家里的电脑开一条回家的路。它长期维护、文档完整、默认配置就能跑起来——这些看起来朴素的东西，恰恰是最难的。

Rust-nps 的协议层，每一个字节、mux 的窗口算法、握手的先后次序，都是从 NPS 的实际行为里逐项对照出来的。没有那份可读、可查、可验证的 Go 源码，这项工作无从谈起。

向 NPS 的作者和所有贡献者致谢。
