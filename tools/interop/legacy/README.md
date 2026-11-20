# 老系统客户端（Windows 7 / Server 2008 R2）

本目录存放为**老 Windows** 编译的原版 NPS Go 客户端。

## 为什么需要它

Rust 版客户端 `rnpc` 与 Rust 版服务端 `rnps` 的最低系统要求都是 **Windows 10**。
这不是本项目的选择，而是 Rust 标准库自身的下限（详见 `../../rust/WINDOWS-COMPAT.md`）。

但在 Windows 7 / Server 2008 R2 上仍然可以完整使用 Rust-nps 的**服务端**——只要客户端换用这里的老版本 Go 客户端。协议完全兼容，功能一致。

## 文件

| 文件 | 说明 |
| --- | --- |
| `npc-win7.exe` | 原版 Go 客户端，用 **Go 1.20.14** 编译 |

## 实测数据

| 项 | 值 |
| --- | --- |
| 版本 | `Version: 0.26.10` / `Core version: 0.26.0` |
| PE `MinOS` / `Subsystem` | **6.1**（Windows 7 / Server 2008 R2） |
| 导入 DLL | **仅 `kernel32.dll`** |
| 大小 | 16 MB |
| sha256 | `89e73ae8474e5c1e018ff8dc09e0b67a192b89649b3803db254932c887b4dff4` |
| 与 Rust `rnps` 联调 | **24/24 通过**（与新版客户端结果一致） |

对比：用当前 Go 1.27 编译的同类产物 `MinOS=10.0`，在 Win7 上无法启动。所以系统下限由**编译用的 Go 版本**决定：

| Go 版本 | 最低 Windows |
| --- | --- |
| ≤ 1.20 | Windows 7 / Server 2008 R2 |
| ≥ 1.21 | Windows 10 / Server 2016 |

## 关于 Server 2008（非 R2）

Server 2008（NT 6.0，Vista 内核）需要更老的 Go：

| 目标 | 所需 Go | 说明 |
| --- | --- | --- |
| Server 2008 R2 (6.1) | Go 1.20 | 本目录已提供 |
| Server 2008 (6.0) | Go ≤ 1.10 | 需另行编译，且 `go.mod` 声明的 `go 1.15` 会被拒，需临时放宽 |

Go 1.20 的 `MinOS` 是 6.1，因此在 6.0 上仍会拒绝加载。

## 如何重新编译

本目录的二进制由以下命令产生（在 `resources/nps` 内执行，不修改任何源码）：

```bash
# 1. 取 Go 1.20.14
curl -LO https://go.dev/dl/go1.20.14.windows-amd64.zip
unzip go1.20.14.windows-amd64.zip

# 2. 编译（GOTOOLCHAIN=local 防止自动升级到新版 Go）
cd resources/nps
GOTOOLCHAIN=local /path/to/go1.20/bin/go build -mod=readonly -o npc-win7.exe ./cmd/npc
```

`GOTOOLCHAIN=local` 很关键：否则新版 Go 会按 `go.mod` 自动拉取更高版本工具链，
产物又会变回 `MinOS=10.0`。

## 使用方式

与新版客户端完全相同：

```bat
npc-win7.exe -server=<服务端地址>:8024 -vkey=<密钥> -type=tcp
```

或配置文件模式（需要服务端开启 `conf_register`）：

```bat
npc-win7.exe -config=npc.conf
```

## 安全提示

这是**原版** NPS 客户端，其桥协议本身没有现代传输认证与加密。
在不可信网络上使用时，请自行通过 TLS 隧道或可信内网承载。

## 未验证项

- 未在真实的 Windows 7 / Server 2008 R2 机器上启动验证。上述结论基于 PE 头的
  `MinOS` 字段与导入表静态分析，以及与本机 Rust 服务端的 24/24 联调。
  若需 100% 确认，应在目标系统实际运行一次。
- Server 2008（非 R2）的产物未构建。
- 32 位（x86）老系统客户端未构建。
