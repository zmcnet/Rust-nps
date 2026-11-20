# Rust-nps

延续 NPS 的自部署体验和可视化管理，用 Rust 逐步替换内核。面向个人和小团队：一个服务端程序，内嵌网页管理端，使用自己的 VPS、NAS 或内网设备。

当前状态：**TCP 兼容预览版，已与真实原版 Go npc 0.26.10 完成端到端联调验证**。它还不是原版 NPS 的全功能替代品。

已用真实客户端实测通过的项（`../tools/interop/smoke.py`，24/24）：

- 握手与 vkey 校验；错误 vkey 被拒且客户端保持离线
- 4 条并发隧道流、合计 6,074,368 字节逐字节一致
- 客户端断开后状态转为离线，重启后自动重连并恢复传输
- 网页/API 停用隧道后监听端口真实释放（连接被拒），重新启用后恢复服务
- 全部 127 次管理 API 响应中不含 vkey、md5(vkey) 或管理令牌
- 传输结束后活动连接计数归零，字节计数与实际业务字节一致
- 所有子进程与套接字在测试结束后清理干净

## 预览版范围

- 使用 JSON 文件定义客户端与 TCP 隧道。
- 原版 npc 以 `-type=tcp` 连接桥端口；过渡期保留原协议。
- 网页查看客户端状态、隧道状态、活动连接和累计流量，启用或停用隧道。
- 管理 API 使用独立管理令牌。客户端 vkey 和管理令牌分别设置。
- 网页资源编入二进制，运行时不需要 Node、CDN 或独立静态目录。

UDP、HTTP 域名代理、SOCKS5、KCP、P2P、文件服务、配置文件动态注册、原版 JSON 数据迁移、Rust 原生客户端暂未实现。旧 npc 使用命令行连接，任务由服务端配置；不支持旧版 npc.conf 的 `WORK_CONFIG` 注册流程。加密、压缩及本地代理选项尚未开放。

网页启停仅改变当前进程状态，重启后按配置恢复。累计流量也会在重启时清零。

## 构建

当前开发基线为 Rust 1.100。源码位于此目录，原版参考仓库保留在 `../resources/nps`。

Linux/macOS，以及已配置好 MSVC 或 MinGW 的 Windows：

```sh
cargo build --workspace
cargo test --workspace
```

本机开发环境使用 **MSVC 工具链**（`stable-x86_64-pc-windows-msvc`，Visual Studio 2022 Build Tools + Windows SDK），直接用上面的 `cargo` 命令即可，无需额外环境变量。

项目脚本 `scripts/cargo.ps1` 只用于 GNU 目标兜底：它会检测 host 是否为 `*windows-gnu`，是则接入完整 MinGW-w64（`gcc.exe` / `as.exe` / `dlltool.exe`）并关闭 `-C link-self-contained`；MSVC 目标下不做任何改动。若要使用 GNU 目标：
```powershell
$env:NPS_MINGW_BIN = 'D:\Tools\w64devkit\bin'   # 可选；脚本也会自动探测
.\scripts\cargo.ps1 build --workspace
```

Windows GNU 目标有一个必须知道的坑：Rust 自带 self-contained 链接器里的 `dlltool.exe` 在部分机器上无法执行（`CreateProcess` 失败）。`cargo check` 不触发链接，所以会"假通过"，只有 `build`/`test` 才暴露。这就是脚本要接外部 MinGW 的原因。

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
```

打开 [本机管理端](http://127.0.0.1:8080)，输入刚才的管理令牌。登录信息只保留在当前浏览器会话中；退出会清除它。

访问 `127.0.0.1:8081`，流量会经 Rust 服务端和 npc 到达 npc 机器上的 `127.0.0.1:9000`。跨机器部署时，将 `bridge_addr` 改为服务端对外可达的监听地址，将 npc 的 `-server` 改为该服务器地址；`target_addr` 仍指 npc 所在网络中的目标。按实际访问范围设置隧道监听地址。

默认示例只监听回环地址。需要远程访问管理端时，应通过自己的 HTTPS 反向代理或 SSH 隧道访问；当前程序直接提供 HTTP。原版桥协议也没有现代传输认证，兼容模式不应当作新的安全传输方案。

空配置可从 `nps.example.json` 开始。程序要求管理令牌至少 24 字节，不提供默认账号或密码。Ctrl+C 关闭服务和连接。

## 管理 API

请求头：`Authorization: Bearer <NPS_ADMIN_TOKEN>`。

| 方法与路径 | 作用 |
| --- | --- |
| `GET /api/status` | 返回客户端、隧道及流量快照，不返回任何密钥 |
| `POST /api/tunnels/{id}/state` | 请求体 `{"enabled": true}` 或 `{"enabled": false}`，启用或停用隧道 |

## 验证

Rust 测试之外，`../tools/interop/smoke.py` 用真实原版 npc 进行黑盒联调。它会启动临时回环测试服务，检查认证、大数据流、多连接、重连与隧道启停，然后清理子进程。

```powershell
python -I ..\tools\interop\smoke.py --server-bin .\target\debug\rnps.exe --npc-bin ..\tools\interop\bin\npc.exe
```

是否通过以脚本实际退出码和报告为准。Go 客户端构建说明见 `../tools/interop/README.md`。

脚本支持 `--preview-seconds <秒>`：联调成功后保留同一套真实 npc / rnps / 回环目标环境，供人工在浏览器里验收管理页；环境信息写入该次运行的 `logs/run-<时间戳>/ui-session.json`。

### 当前测试规模

`cargo test --workspace` 共 143 项通过：`nps-legacy` 69（协议字节样例、mux 多流双向 1 MiB、超窗、慢流不阻塞、关闭唤醒、桥生命周期，以及对抗性加固：不可取消写、路由泄漏、长度截断、零长 ping、id 串台）、`nps-proto` 4、`nps-server` 16 单元 + 边界 7 + 转发端到端 2 + 加固 17、`nps-web` 28。

### 加固过程中修掉的真实缺陷

这些不是理论风险，每一条都有对应测试，其中两条做了"回退即失败"的实证：

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

默认使用 MSVC 工具链，`cargo build` / `cargo test` 直接可用，无需额外环境变量。若改用 GNU 目标，需要完整 MinGW-w64（`gcc.exe` / `as.exe` / `dlltool.exe`）：Rust 自带的自包含链接器里那个 `dlltool.exe` 在部分机器上无法执行，而 `cargo check` 不触发链接、会"假通过"，只有 `build`/`test` 才暴露。`scripts/cargo.ps1` 只在 host 为 `*windows-gnu` 时接管，接入 `NPS_MINGW_BIN` 或自动发现的 w64devkit，并关闭 `-C link-self-contained`。

## 代码结构

`nps-proto` 定义兼容数据结构；`nps-legacy` 实现旧桥协议和 mux；`nps-server` 管理连接与转发；`nps-web` 提供内嵌界面；`nps-app` 提供 `rnps` 服务端入口；`nps-client` 提供 `rnpc` 客户端。旧协议集中在 `nps-legacy` 中，便于后续引入新协议并逐步移除它。

Linux 部署产物在 [packaging/](packaging/)：systemd 单元、环境变量示例、Dockerfile、安装脚本和部署说明。**这些文件尚未在真实 Linux/systemd/Docker 上验证过**，使用前请自行核对。

## 许可

MIT，见 [LICENSE](LICENSE)。

## 致谢

本项目的诞生离不开 [**ehang-io/nps**](https://github.com/ehang-io/nps)。

NPS 用 Go 写就，在一个内网穿透工具普遍难以上手的年代，它把「一个服务端 + 一个客户端 + 内嵌网页管理」这条路走通了，让大量没有运维团队的个人和小团队也能给自己的 NAS、软路由、家里的电脑开一条回家的路。它长期维护、文档完整、默认配置就能跑起来——这些看起来朴素的东西，恰恰是最难的。

Rust-nps 是站在它肩上的重写：协议层的每一个字节、mux 的窗口算法、握手的先后次序，都是从 NPS 的实际行为里逐项对照出来的。没有那份可读、可查、可验证的 Go 源码，这项工作无从谈起。

向 NPS 的作者和所有贡献者致谢。

> 本仓库不包含 ehang-io/nps 的任何源代码。原版 Go 源码仅作为协议参考保存在构建树之外，不会编译进发布的二进制。
