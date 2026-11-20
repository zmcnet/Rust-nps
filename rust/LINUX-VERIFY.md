# Linux 实机验证报告

在真实 Linux 主机上完成的验证，不是交叉编译或推测。环境与结果如下。

## 验证环境

| 项 | 值 |
| --- | --- |
| 发行版 | Debian GNU/Linux 13 (trixie) |
| 内核 | 6.8.0-149-generic |
| 架构 | x86_64 |
| CPU / 内存 | 20 核 / 15.9 GiB |
| Rust | 1.100.0（rustup 安装） |
| Go | 1.23.4（编译原版 npc 用） |
| systemd | 257（PID 1 就是 systemd，非容器伪装） |

## 1. 构建与测试

```
cargo build --release --workspace   → 成功，1m 05s
cargo test --workspace              → 229 passed, 0 failed
```

各 crate 明细：`nps-client` 67、`nps-legacy` 69、`nps-proto` 4、`nps-server` 22、
`boundaries` 7、`conf_registration` 13、`e2e_forwarding` 2、`hardening` 17、`nps-web` 28。

与 Windows 结果一致，说明代码没有平台特定缺陷。

## 2. 与原版 Go 客户端的黑盒联调

用 Go 1.23.4 编译的原版 `npc`（`Version 0.26.10` / `Core 0.26.0`）连接 Rust `rnps`：

```
==== 24/24 checks passed ====
RESULT: OK (real Go npc <-> Rust rnps interop verified)
```

含 4 条并发流合计 6,074,368 字节逐字节一致、断线重连、隧道启停、
端口真实释放、管理 API 零密钥泄漏、连接计数归零。

> 原版仓库 `cmd/npc` 同时含 `npc.go` 与 `sdk.go`（后者是 c-shared 入口），
> 直接 `go build ./cmd/npc` 会报 `main redeclared`。需指定 `./cmd/npc/npc.go`。

## 3. systemd 部署（首次实机验证）

之前 `packaging/` 下的文件只在 Windows 上做过语法检查。本次在 Debian 13 上真实验证：

```bash
sudo ./rust/packaging/install.sh ~/Rust-nps/rust/target/release/rnps
```

**发现并修复两个真实缺陷**：

1. **`install.sh` 在 git 里没有执行位**（`100644`，因在 Windows 上创建）。
   `sudo ./install.sh` 直接报 `command not found`。已改为 `100755`。
2. **`useradd` / `groupadd` 找不到**。Debian 上它们在 `/usr/sbin`，而 sudo 的
   `secure_path` 不含该目录。已在脚本开头显式补 `PATH`。

修复后安装完整成功：

```
==> 创建系统组 nps
==> 创建系统用户 nps
==> 安装二进制到 /usr/local/bin/rnps
==> 生成默认配置 /etc/nps/nps.json
==> 生成随机管理令牌（32 字节）
==> 令牌已写入 /etc/nps/nps.env（0600）
==> 安装 systemd 单元 /etc/systemd/system/rnps.service
Created symlink .../multi-user.target.wants/rnps.service
```

服务真实运行：

```
● rnps.service - Rust-nps TCP tunnel server (rnps)
     Loaded: loaded (/etc/systemd/system/rnps.service; enabled)
     Active: active (running)
   Main PID: 10565 (rnps)
      Tasks: 21
     Memory: 1.7M (peak: 3.8M)
        CPU: 52ms
```

**内存占用 1.7 MB**——这是面向 NAS / 软路由的关键指标。

`systemd-analyze verify rnps.service` 在安装前只报「二进制不存在」，
安装后无任何告警，说明单元文件语法与安全加固选项（`ProtectSystem=strict`、
`PrivateTmp`、`NoNewPrivileges`、`CapabilityBoundingSet=`、`ReadWritePaths=` 等）均被接受。

## 4. 管理 API 与真实穿透

```
无令牌  → 401
带令牌  → {"bridge_addr":"127.0.0.1:8024","clients":[],"tunnels":[]}
管理页  → 200
```

配置一条真实隧道后启动原版 npc：

```json
{"clients":[{"id":1,"name":"live","vkey":"..."}],
 "tunnels":[{"id":1,"name":"live-tcp","client_id":1,
             "listen_addr":"127.0.0.1:18081",
             "target_addr":"127.0.0.1:19000","enabled":true}]}
```

`/api/status` 显示客户端上线：

```json
{"id":1,"name":"live","online":true,"version":"0.26.10"}
```

传输 3 MiB 随机数据：

```
sent 3145728 recv 3145728
sha_sent 13e5b1d3a4feed28c0bd003b
sha_recv 13e5b1d3a4feed28c0bd003b
MATCH
```

传输后统计精确对账：

```
active: 0  to_client: 3145728  from_client: 3145728
```

## 5. 静态链接（解决老发行版兼容）

```
rustup target add x86_64-unknown-linux-musl
cargo build --release -p nps-app --bin rnps --target x86_64-unknown-linux-musl
```

结果：

```
-rwxrwxr-x 3.0M  target/x86_64-unknown-linux-musl/release/rnps
ldd → statically linked
```

**3.0 MB，完全静态。** musl 静态二进制不依赖 glibc 版本，
因此可在 RHEL 6、Debian 9 等老发行版上直接运行——这是覆盖老 Linux 的正确方案，
与 Windows 侧「静态 CRT」思路一致。

> 默认的 `x86_64-unknown-linux-gnu` 构建依赖宿主 glibc 版本，
> 在更老的发行版上会报 `GLIBC_2.xx not found`。发布产物应使用 musl target。

## 6. 未验证项

- 未在 RHEL 6 / Debian 9 等老发行版上实际运行 musl 产物（仅确认静态链接属性）。
- 未验证 ARM / MIPS / RISC-V / LoongArch 等交叉编译目标。
- 未验证 Docker 镜像构建（远端无 Docker）。
- 未在真实公网跨 NAT 场景验证。
