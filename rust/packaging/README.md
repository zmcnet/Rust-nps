# rnps 部署产物（Linux）

面向自部署小用户：单机 NAS、小 VPS、软路由。这里的文件只覆盖「把 `rnps`
装到一台 Linux 机器上并让它由 systemd 托管」这一条路径。

## 先说清楚能力边界

服务端已覆盖原版 NPS 0.26.10 的全部协议模式（逐项证据见
[../docs/PHASE2-ACCEPTANCE.md](../docs/PHASE2-ACCEPTANCE.md)）：

| 项目 | 状态 |
| --- | --- |
| TCP / UDP / SOCKS5 / HTTP(S) 域名代理 / 文件 / secret / p2p 会合 | 支持，各有真实 npc 专项联调 |
| 加密（自签 TLS）、压缩（snappy） | 支持 |
| 限速、流量上限、IP 白名单、健康检查、多目标轮询 | 支持（**目前只作用于 TCP 隧道**） |
| tcpTrans 透明代理 | 仅探测层（仅 Linux），**未接入转发路径** |
| KCP 传输、P2P 客户端侧 | 未实现 |
| 网页启停、流量统计、连接计数 | 支持；启停只在内存，TCP 流量每 5 分钟落盘 |
| 状态持久化 | 重启后按 `nps.json` 的 `enabled` 恢复；conf 动态注册的隧道重启即失效 |

## 目录内容

| 文件 | 用途 |
| --- | --- |
| `rnps.service` | systemd 单元（`User=nps`，严格沙箱） |
| `rnps.env.example` | `NPS_ADMIN_TOKEN` 与 `RUST_LOG` 模板 |
| `nps.json.example` | 空配置模板（JSON **不能写注释**） |
| `Dockerfile` | 多阶段构建，非 root 运行（**未在本机验证**） |
| `install.sh` | Linux 安装脚本（创建用户、装二进制、生成令牌、装 systemd） |
| `README.md` | 本文件 |

## 一、二进制与安装

需要先构建 Linux 版 `rnps`（在 `rust/` 目录）：

```sh
cargo build --release -p nps-app --bin rnps
# 产物：target/release/rnps
```

把 `rnps` 与 `packaging/` 下的文件一起拷到目标机器（同一目录），然后：

```sh
sudo ./install.sh ./rnps
```

脚本会：

1. 创建系统组与系统用户 `nps`（`--no-create-home`，`nologin`，无同名组时先建组）；
2. 装二进制到 `/usr/local/bin/rnps`（`0755 root:root`），安装前用 `--version` 试跑一次；
3. 建 `/etc/nps`；
4. 首次安装时用 `openssl rand -base64 32`（缺失则 `/dev/urandom` 兜底）生成管理令牌
   写入 `/etc/nps/nps.env`（`0600 root:root`）；**已有非空令牌则原样保留**；
5. 安装 `/etc/systemd/system/rnps.service`，`daemon-reload` + `enable` + `restart`，
   启动失败时打印 `journalctl` 尾部并退出非零。

脚本是 `set -euo pipefail`。**已在 Debian 13 实机执行验证**（安装、启用、
真实穿透一次通过；过程中修复了 PATH 缺 `/usr/sbin` 与脚本执行位两个问题，
见 [../LINUX-VERIFY.md](../LINUX-VERIFY.md)）；其它发行版的行为见文末「未验证项」。

已有 `/etc/nps/nps.json` 和已有非空令牌的 `/etc/nps/nps.env` 都不会被覆盖
（配置文件的属主/权限会被校正为 `0640 root:nps`，环境文件为 `0600 root:root`）。

## 二、配置 `nps.json`

JSON 不支持注释，所以字段说明放在这里。先用下面的命令生成一个真实 vkey，
把输出整串替换到示例的 `vkey` 字段（**示例文字不是密钥，原样使用等于公开密钥**）：

```sh
openssl rand -base64 32
```

最小可用配置：

```json
{
  "bridge_addr": "0.0.0.0:8024",
  "web_addr": "127.0.0.1:8080",
  "clients": [
    { "id": 1, "name": "home-nas", "vkey": "替换成上面命令的输出" }
  ],
  "tunnels": [
    {
      "id": 1,
      "name": "ssh",
      "client_id": 1,
      "listen_addr": "0.0.0.0:6000",
      "target_addr": "127.0.0.1:22",
      "enabled": true
    }
  ]
}
```

| 字段 | 含义 |
| --- | --- |
| `bridge_addr` | 原版 npc 接入的桥地址。默认 `127.0.0.1:8024`；跨机器必须改成对外可达的地址 |
| `web_addr` | 管理端 HTTP 监听地址，默认 `127.0.0.1:8080` |
| `clients[].id` | 正整数，隧道通过 `client_id` 引用 |
| `clients[].name` | 展示用名称，不能为空 |
| `clients[].vkey` | 客户端认证密钥。必须显式配置，不能为空、不能是 `123`/`123456`/`password`/`vkey`，且不能与其它客户端重复 |
| `web_username` / `web_password` | 管理员账号（两者都非空才生效）。管理令牌只走环境变量 `NPS_ADMIN_TOKEN`，**不写进这个文件** |
| `clients[].web_username` / `web_password` | 客户端账号（登录管理页只能看自己的隧道）；两者都空时回退 `user` + vkey（对齐原版 `login.go`） |
| `tunnels[].id` | 正整数，唯一 |
| `tunnels[].listen_addr` | 服务端对外监听地址（外部入口） |
| `tunnels[].target_addr` | **npc 所在网络**里的目标地址，如 `127.0.0.1:22` |
| `tunnels[].target_addrs[]` | 多目标顺序轮询（优先于 `target_addr`），可配 `health_check` 自动摘除 |
| `tunnels[].enabled` | 随服务启动是否监听；默认 `true`。网页启停不改这个值 |
| `udp_tunnels[]` | UDP 隧道，字段同 `tunnels[]`（另有 `idle_timeout_secs`、`max_sessions`） |
| `http_sites[]` | HTTP(S) 域名站点：`domain` / `target_addr` / `routes[]` 前缀分流 / `websocket` / `tls_mode`（`off`/`upload`/`self-signed`/`acme`） |
| `http_listen_addr` / `https_listen_addr` | 域名代理监听地址（默认都不监听；配了 `http_sites` 至少要配一个） |
| `socks5_listeners[]` | SOCKS5 服务：`listen_addr` + 可选 `users[]`（RFC 1929 用户名密码） |
| `secret_tunnels[]` | secret 隧道：无 `listen_addr`，服务端按 `password` 的 md5 配对，密码须唯一 |
| `file_tunnels[]` | 文件服务隧道（数据面走独立 file 通道） |
| `conf_register` | 允许老 npc 用 `-config` 动态注册 task（tcp/udp/file）与 host 站点；默认 `false`；注册结果只存内存 |
| `ip_limit[]` | 来源 IP 白名单（单 IP / CIDR / IPv6；**目前只在 TCP 隧道路径强制**） |
| `cert_dir` | TLS 证书目录，默认 `<配置目录>/certs` |
| `acme` | ACME 设置（provider / challenge / auto_renew 等）；**程序绝不擅自申请证书** |
| `data_dir` | 流量持久化等数据目录 |
| `flow_store_interval` | TCP 流量落盘间隔（分钟），默认 5 |

完整字段与校验规则以 [../crates/nps-server/src/config.rs](../crates/nps-server/src/config.rs) 为准。非 TCP 模式常用片段（示例值不是密钥，原样使用等于公开）：

```json
{
  "udp_tunnels": [
    { "id": 1, "name": "dns", "client_id": 1,
      "listen_addr": "0.0.0.0:53", "target_addr": "127.0.0.1:53" }
  ],
  "http_listen_addr": "0.0.0.0:8081",
  "http_sites": [
    { "id": 1, "name": "home", "client_id": 1,
      "domain": "home.example.com", "target_addr": "127.0.0.1:80", "websocket": true }
  ],
  "socks5_listeners": [
    { "id": 1, "name": "socks", "client_id": 1,
      "listen_addr": "0.0.0.0:1080",
      "users": [{ "username": "alice", "password": "替换成真实密码" }] }
  ]
}
```

生成 vkey：

```sh
openssl rand -base64 32
```

每个客户端一个，互不相同。vkey 明文只出现在这个配置文件里，桥内部只比对
md5；管理端快照和日志都不会返回 vkey。

> 注意：`vkey` 是必填项，且不能是 `123`/`123456`/`password`/`vkey` 这类默认值，
> 也不能与其它客户端重复——服务端启动时会校验并拒绝。

`clients[].id` 与 `tunnels[].id` 必须唯一；`listen_addr` 不能被两条启用的隧道
同时占用（启动时会校验并拒绝）。

## 三、环境文件 `nps.env`

```sh
sudo install -m 0600 -o root -g root rnps.env.example /etc/nps/nps.env
sudo editor /etc/nps/nps.env
```

必须填 `NPS_ADMIN_TOKEN`，**至少 24 字节随机值**，程序启动时校验，短了直接退出。
不要用任何默认值/示例值——管理 API 的全部防护就是这个令牌。

`RUST_LOG` 默认 `info`；排查问题可临时设成
`nps_server=debug,nps_legacy=debug`。

## 四、启动与验证

```sh
sudo systemctl enable --now rnps.service
sudo systemctl status rnps.service
```

TCP 隧道用原版 npc 或本仓库 rnpc 接入（其余协议模式见能力边界表；npc 的
`-config` 动态注册需 `conf_register: true`）：

```sh
./npc -server=<服务器IP>:8024 -vkey='<该客户端的 vkey>' -type=tcp
# 或：./rnpc -s <服务器IP>:8024 -vkey '<该客户端的 vkey>'
```

验证管理 API（令牌从 0600 的环境文件读，不写进 shell 历史）：

```sh
TOKEN=$(sudo grep '^NPS_ADMIN_TOKEN=' /etc/nps/nps.env | cut -d= -f2-)
curl -s -H "Authorization: Bearer ${TOKEN}" http://127.0.0.1:8080/api/status | jq .
```

期望看到 `clients[].online` 在 npc 连上后变 `true`。

启用/停用一条隧道：

```sh
curl -s -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"enabled":false}' \
  http://127.0.0.1:8080/api/tunnels/1/state
```

停用会关闭监听端口并断开这条隧道当前的转发连接。这个状态只在内存里，
重启后按 `nps.json` 的 `enabled` 恢复。

端到端验证（本机，不依赖 npc）：起一个临时监听，从隧道入口写入，确认能通：

```sh
# 终端 1：npc 侧目标（假设隧道 target_addr 指向 127.0.0.1:9000）
nc -l 9000

# 终端 2：通过隧道入口访问
printf 'hello\n' | nc 127.0.0.1 6000
```

## 五、HTTPS（必须自己处理）

管理端是**明文 HTTP**，程序本身不提供 TLS。要远程访问管理界面，必须：

- 用 nginx/caddy 做 HTTPS 反向代理，只把 `/` 转给 `127.0.0.1:8080`，或
- 走 SSH 隧道：`ssh -L 8080:127.0.0.1:8080 user@server`

不要把 `web_addr` 直接改成 `0.0.0.0` 暴露到公网：Bearer 令牌会明文过网。
桥端口同理——原版桥协议没有现代传输认证，兼容模式不应作为新的安全传输方案使用。

## 六、Docker

```sh
cd rust
docker build -f packaging/Dockerfile -t rnps:local .
docker run -d --name rnps \
  -e NPS_ADMIN_TOKEN="$(openssl rand -base64 32)" \
  -p 8024:8024 -p 8080:8080 \
  -v /etc/nps/nps.json:/etc/nps/nps.json:ro \
  rnps:local
```

容器内默认读 `/etc/nps/nps.json`；配置里的监听地址若要被宿主机访问，必须写成
`0.0.0.0`（默认 `127.0.0.1` 只在容器内可达）。

容器以 uid/gid `10001` 运行，确认挂载进去的 `nps.json` 对它可读（例如宿主机上
`chmod 0644`，或 `chown 10001:10001`）。`NPS_ADMIN_TOKEN` 通过 `-e` 或
`--env-file` 传入，不要写进镜像。

构建上下文是 `rust/` 整个目录；`target/` 不会被 `COPY` 进镜像，但仍会作为
构建上下文上传，建议本地先 `cargo clean`，或在仓库根放一个 `.dockerignore`。

**未在本机验证（本机没有 Docker）**：Dockerfile 的镜像标签、构建步骤与
`--version` 冒烟检查都未经真实构建。

## 七、排错

```sh
journalctl -u rnps.service -n 100 --no-pager
```

| 现象 | 常见原因 |
| --- | --- |
| 启动即退出，日志提到 `NPS_ADMIN_TOKEN` | 令牌未设置或短于 24 字节 |
| 日志「隧道 N 无法监听 …」 | 端口被占用，或改了 `listen_addr` 但没 `systemctl restart` |
| 快照 `clients[].online` 一直是 false | npc 没连上桥端口，或 vkey 不匹配（vkey 错误时握手会直接拒绝） |
| 管理端 401 | `Authorization: Bearer` 令牌不对；注意别把 `NPS_ADMIN_TOKEN=` 前缀带进去 |
| 端口起了但连不通 | 隧道 `client_id` 指向的客户端离线；`target_addr` 是 npc 侧地址，不是服务器本地地址 |

## 八、卸载

```sh
sudo systemctl disable --now rnps.service
sudo rm -f /etc/systemd/system/rnps.service
sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/rnps
sudo rm -rf /etc/nps
sudo userdel nps
```

`/etc/nps/nps.env` 里有管理令牌，删除前确认已不再需要。

## 九、未验证项

以下内容在本机（Windows，无 Docker / 无 systemd）无法验证，请在目标机确认：

1. systemd 路径（`rnps.service` + `install.sh`）**已在 Debian 13 实机验证**
   （systemd 257：`systemd-analyze verify` 无告警、真实穿透、内存 1.7 MB，
   见 [../LINUX-VERIFY.md](../LINUX-VERIFY.md)）；其它发行版与 systemd 版本的
   差异（含 `ReadWritePaths=` / `CapabilityBoundingSet=` 空赋值语义）仍请自行核对。
2. `Dockerfile` 未构建过；`rust:1.100-slim` 与 `debian:bookworm-slim` 标签、
   构建出的 glibc 是否与运行镜像兼容，均未实测（`--version` 冒烟步骤未执行）。
3. 本 README 中的 `curl` 示例依赖服务实际运行，未在本机（Windows 开发机）跑通。
4. 各发行版（Debian/Ubuntu 之外的 NAS 系统）的用户名/组名策略差异未覆盖；
   非 systemd 系统（OpenWrt 等）需要自己写 init 脚本。
5. `openssl rand -base64 32` 的输出含 `/` `+` `=`，放进 JSON 与 shell 都安全，
   但若用户把它拼进 URL 查询串需要先做 URL 编码——示例未覆盖该用法。