# Rust-nps

延续 NPS 的自部署体验和可视化管理，用 Rust 逐步替换内核。面向个人和小团队：一个服务端程序，内嵌网页管理端，使用自己的 VPS、NAS 或内网设备。

当前状态：**原版 8 个协议模式已在服务端全部实现（`tcpTrans` 仅 Linux，与原版一致），与真实原版 Go npc 0.26.10 / nps 0.26.10 双向完成端到端联调验证**。逐项证据见 [docs/PHASE2-ACCEPTANCE.md](docs/PHASE2-ACCEPTANCE.md)。

已用真实客户端实测通过的项（`../tools/interop/smoke.py`，24/24）：

- 握手与 vkey 校验；错误 vkey 被拒且客户端保持离线
- 4 条并发隧道流、合计 6,074,368 字节逐字节一致
- 客户端断开后状态转为离线，重启后自动重连并恢复传输
- 网页/API 停用隧道后监听端口真实释放（连接被拒），重新启用后恢复服务
- 全部 127 次管理 API 响应中不含 vkey、md5(vkey) 或管理令牌
- 传输结束后活动连接计数归零，字节计数与实际业务字节一致
- 所有子进程与套接字在测试结束后清理干净

## 能力范围

- 原版 8 个 mode：tcp / udp / socks5 / httpProxy（域名代理）/ file / secret / p2p（`p2pm` 邀请 + 三端口会合，双真实 npc 打洞直连端到端验证）/ tcpTrans（透明代理，**仅 Linux**：目标由 `SO_ORIGINAL_DST` 反查，需 iptables REDIRECT 指入；原版 Windows 同样是空实现）。逐项证据见 [docs/PHASE2-ACCEPTANCE.md](docs/PHASE2-ACCEPTANCE.md)。
- JSON 配置定义客户端与 tcp / udp / http 站点 / socks5 / secret / file 隧道；老 npc 也可用 `-config` 动态注册 task（tcp/udp/file）与 host 站点。
- 网页管理：客户端/隧道/连接数/流量总览、隧道启停、站点 CRUD、证书上传/自签/ACME；多用户登录（管理员账号 + 客户端账号 + 超级令牌），权限在服务端强制，不只是前端隐藏。
- 管理 API 使用独立管理令牌。客户端 vkey 和管理令牌分别设置。
- 网页资源编入二进制，运行时不需要 Node、CDN 或独立静态目录。
- 客户端 `rnpc`：直接参数、配置文件或 `--name` 实例模式；install/change/update/list/status 等持久化命令与自启通道见 [docs/rnpc-cli-spec.md](docs/rnpc-cli-spec.md)。

已知边界：网页启停仅改变当前进程状态，重启后按配置恢复；conf 动态注册的隧道不持久化；TCP 流量累计每 5 分钟落盘（`flow_store_interval`），进程被 kill -9 会丢最后一段；流量上限（`flow_limit`）的已用量不落盘，重启后重新从零计数。限速 / 流量上限 / IP 白名单按客户端生效，覆盖全部转发路径（TCP / conf 注册 / UDP / SOCKS5 / HTTP(S) 站点 / file / secret）；SOCKS5 / UDP / HTTP / secret 子流的 Link 帧未携带客户端 crypt/compress 标志，这些路径按明文转发。

## 构建

当前开发基线为 Rust 1.100。源码位于此目录，原版参考仓库保留在 `../resources/nps`。

Linux/macOS，以及已配置好 MSVC 或 MinGW 的 Windows：

```sh
cargo build --workspace
cargo test --workspace
```

本机开发环境使用 **MSVC 工具链**（`stable-x86_64-pc-windows-msvc`，Visual Studio 2022 Build Tools + Windows SDK），直接用上面的 `cargo` 命令即可，无需额外环境变量。

`scripts/cargo.ps1` 是**历史遗留，不要用**（交接文档 26.2）：当年为绕过 Windows GNU 目标的一个坑——Rust 自带 self-contained 链接器里的 `dlltool.exe` 在部分机器上无法执行（`CreateProcess` 失败），而 `cargo check` 不触发链接、会"假通过"——脚本会接入外部 MinGW-w64（`NPS_MINGW_BIN` 或自动发现的 w64devkit）并关闭 `-C link-self-contained`。现在 MSVC 工具链下 `cargo build` / `cargo test` 直接可用，不需要它；只有将来再用 GNU 目标且 `dlltool` 报错时才考虑启用。

下载依赖需要代理时，按本地 Clash 的实际端口设置：

```powershell
$env:CARGO_HTTP_PROXY = 'http://127.0.0.1:7897'
```

调试二进制为 `target/debug/rnps.exe`（Linux/macOS 为 `rnps`）。它可以与配置文件放在一起运行，不需要另放网页资源。

## 本机快速开始

下面的 PowerShell 示例生成随机管理令牌和客户端 vkey，写入一条测试隧道。目标 `127.0.0.1:9000` 需要在 npc 所在机器上已有服务。

```powershell
function New-NpsSecret {
    $bytes = New-Object byte[] 32
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($bytes) } finally { $random.Dispose() }
    [Convert]::ToBase64String($bytes)
}

$env:NPS_ADMIN_TOKEN = New-NpsSecret
$clientKey = New-NpsSecret
$config = @{
    bridge_addr = '127.0.0.1:8024'
    web_addr = '127.0.0.1:8080'
    clients = @(@{ id = 1; name = 'my-device'; vkey = $clientKey })
    tunnels = @(@{
        id = 1
        name = 'local-service'
        client_id = 1
        listen_addr = '127.0.0.1:8081'
        target_addr = '127.0.0.1:9000'
        enabled = $true
    })
}
$json = $config | ConvertTo-Json -Depth 5
$utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText((Join-Path $PWD 'nps.local.json'), $json, $utf8)

# 在启动前，把这两个值保存到自己的密码管理器。
$env:NPS_ADMIN_TOKEN
$clientKey

.\target\debug\rnps.exe --config .\nps.local.json
```

另一个终端使用相同 vkey 启动原版 npc：

```powershell
.\npc.exe -server=127.0.0.1:8024 -vkey='<刚才生成的 clientKey>' -type=tcp

# 或使用本仓库客户端 rnpc（默认即 tcp 类型）：
.\target\debug\rnpc.exe -s 127.0.0.1:8024 -vkey '<刚才生成的 clientKey>'
```

打开 [本机管理端](http://127.0.0.1:8080)，输入刚才的管理令牌。登录信息只保留在当前浏览器会话中；退出会清除它。

访问 `127.0.0.1:8081`，流量会经 Rust 服务端和 npc 到达 npc 机器上的 `127.0.0.1:9000`。跨机器部署时，将 `bridge_addr` 改为服务端对外可达的监听地址，将 npc 的 `-server` 改为该服务器地址；`target_addr` 仍指 npc 所在网络中的目标。按实际访问范围设置隧道监听地址。

默认示例只监听回环地址。需要远程访问管理端时，应通过自己的 HTTPS 反向代理或 SSH 隧道访问；当前程序直接提供 HTTP。原版桥协议也没有现代传输认证，兼容模式不应当作新的安全传输方案。

空配置可从 `nps.example.json` 开始。程序要求管理令牌至少 24 字节，不提供默认账号或密码。Ctrl+C 关闭服务和连接。

## 管理 API

请求头：`Authorization: Bearer <NPS_ADMIN_TOKEN>`（或登录会话返回的 Bearer 令牌）。

| 方法与路径 | 作用 | 权限 |
| --- | --- | --- |
| `GET /api/status` | 客户端、隧道及流量快照，不返回任何密钥 | 登录即可见；客户端账号只看到自己 |
| `GET /api/listeners` | 各监听面的连接统计 | 登录即可见 |
| `GET /api/whoami` | 当前身份与是否管理员 | 登录即可见 |
| `POST /api/tunnels/{id}/state` | 请求体 `{"enabled": true/false}`，启用或停用隧道 | 管理员 |
| `GET/POST /api/sites`、`DELETE /api/sites/{domain}` | 站点查询 / 增改 / 删除 | 管理员 |
| `GET /api/certs`、`POST /api/certs/upload`、`POST /api/certs/self-signed`、`POST /api/certs/reload`、`DELETE /api/certs/{domain}` | 证书管理 | 管理员 |
| `GET /api/acme`、`POST /api/certs/acme-request` | ACME 状态与申请（程序绝不擅自申请） | 管理员 |
| `POST /api/auth/login`、`POST /api/auth/logout` | 用户名密码登录 / 登出 | 公开 / 登录 |

管理员端点在服务端强制校验（`require_admin_principal`），客户端账号一律 403。

## 验证

Rust 测试之外，`../tools/interop/smoke.py` 用真实原版 npc 进行黑盒联调。它会启动临时回环测试服务，检查认证、大数据流、多连接、重连与隧道启停，然后清理子进程。

```powershell
python -I ..\tools\interop\smoke.py --server-bin .\target\debug\rnps.exe --npc-bin ..\tools\interop\bin\npc.exe
```

是否通过以脚本实际退出码和报告为准。Go 客户端构建说明见 `../tools/interop/README.md`。

脚本支持 `--preview-seconds <秒>`：联调成功后保留同一套真实 npc / rnps / 回环目标环境，供人工在浏览器里验收管理页；环境信息写入该次运行的 `logs/run-<时间戳>/ui-session.json`。

### 当前测试规模

`cargo test --workspace` 共 **617 项**通过，0 失败（2026-11-20）：`nps-legacy` 69（协议字节样例、mux 多流双向 1 MiB、超窗、慢流不阻塞、关闭唤醒、桥生命周期，以及对抗性加固：不可取消写、路由泄漏、长度截断、零长 ping、id 串台）、`nps-proto` 4、`nps-server`（单元 + 12 个集成测试文件：转发端到端、UDP、SOCKS5、HTTP 站点、conf 注册、加固、边界、target、limit、tls、acme、file）、`nps-web`（路由 + 权限隔离）、`nps-client`（autostart / process / update_feed）。分项计数见 [docs/PHASE2-ACCEPTANCE.md §7](docs/PHASE2-ACCEPTANCE.md)。

### 第一阶段（mux / 桥）加固修掉的真实缺陷

这些不是理论风险，每一条都有对应测试，其中两条做了"回退即失败"的实证。
第二阶段累计修复的 22 个缺陷（含权限绕过安全漏洞）见
[docs/PHASE2-ACCEPTANCE.md §8](docs/PHASE2-ACCEPTANCE.md)：

| 缺陷 | 后果 |
| --- | --- |
| 外部连接 EOF 后未向 npc 发 `ConnClose` | npc 侧目标连接永久悬挂，`active_connections` 永不归零 |
| `stop()` 强制 `store(0)` 与并发自减相撞 | 计数回绕成 1.8e19，管理端显示错误数据且无法恢复 |
| 转发泵用裸 `JoinHandle` | 父任务被 abort 时是**分离**而非取消，孤儿泵继续占用 mux 半边 |
| 写循环 `write_all` 不可取消 | 对端不读 socket 时 `close()`/超时/`shutdown()` 全部失效，会话"假活" |
| `try_lock` 抢不到即跳过清理 | 死弱引用永久占住路由表，累计 512 后该会话永久拒绝新建流 |
| `encode` 的 `len as u16` 截断 | 内容 >65535 时写出长度与实际不符的帧，对端从此永久失步 |
| 空内容 ping 原样回显 | Go 的 `basePackager.Set` 拒绝零长度，一个回包即可杀死对端整条 mux |
| 双方 mux id 空间重叠 | 后写者覆盖先写者路由，跨连接数据串台 |

### Windows 说明

默认使用 MSVC 工具链，`cargo build` / `cargo test` 直接可用，无需额外环境变量。`scripts/cargo.ps1` 是历史遗留，日常不要用——只有 Windows GNU 目标再次出现 `dlltool` 链接错误时才考虑启用（见上文构建一节）。

## 代码结构

`nps-proto` 定义兼容数据结构；`nps-legacy` 实现旧桥协议和 mux；`nps-server` 管理连接与转发；`nps-web` 提供内嵌界面；`nps-app` 提供 `rnps` 服务端入口；`nps-client` 提供 `rnpc` 客户端。旧协议集中在 `nps-legacy` 中，便于后续引入新协议并逐步移除它。

Linux 部署产物在 [packaging/](packaging/)：systemd 单元、环境变量示例、Dockerfile、安装脚本和部署说明。systemd + `install.sh` 已在 Debian 13 实机验证（安装、真实穿透、内存占用 1.7 MB，见 [LINUX-VERIFY.md](LINUX-VERIFY.md)）；Dockerfile 尚未真实构建过。

## 许可

MIT，见 [LICENSE](LICENSE)。

## 致谢

本项目的诞生离不开 [**ehang-io/nps**](https://github.com/ehang-io/nps)。

NPS 用 Go 写就，在一个内网穿透工具普遍难以上手的年代，它把「一个服务端 + 一个客户端 + 内嵌网页管理」这条路走通了，让大量没有运维团队的个人和小团队也能给自己的 NAS、软路由、家里的电脑开一条回家的路。它长期维护、文档完整、默认配置就能跑起来——这些看起来朴素的东西，恰恰是最难的。

Rust-nps 是站在它肩上的重写：协议层的每一个字节、mux 的窗口算法、握手的先后次序，都是从 NPS 的实际行为里逐项对照出来的。没有那份可读、可查、可验证的 Go 源码，这项工作无从谈起。

向 NPS 的作者和所有贡献者致谢。

> 本仓库不包含 ehang-io/nps 的任何源代码。原版 Go 源码仅作为协议参考保存在构建树之外，不会编译进发布的二进制。
