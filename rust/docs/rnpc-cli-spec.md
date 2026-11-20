# rnpc 命令规格（Windows 持久化与服务管理）

本文是 `rnpc` 客户端的命令行与持久化行为规范。实现必须以本文为准；本文未写明之处，
实现前应先补进本文，而不是在代码里发明行为。

## 设计目标

1. **单文件**：一个 `rnpc.exe`，静态 CRT，不依赖 VC++ 运行库或任何第三方 DLL。
2. **两种使用形态并存**：
   - 临时会话：`rnpc run -s host -p port`，退出即结束，不写任何持久化状态。
   - 持久实例：`rnpc install ...`，写入配置 + 注册自启，可长期驻留。
3. **一台机器可跑任意多个实例**，互不干扰，无全局单例锁。
4. **自启多通道**：按当前权限自动选择可用的最强通道，并如实告知用户实际效果。

## 选项别名

以下写法完全等价，任何组合都必须解析为同一结果：

| 语义 | 等价写法 |
| --- | --- |
| 服务端主机 | `-s` · `-server` · `--server` |
| 服务端端口 | `-p` · `-port` · `--port` |

- `-s 10.0.0.1 -p 8024` 与 `-server=10.0.0.1:8024` 等价。
- `-s` 给主机、`-p` 给端口是推荐形式；`-server` 也可直接给 `host:port`。
- 同时给 `host:port` 和 `-p` 且两者端口不一致 → 报错，不静默取其一。
- `-p` 缺省 **8024**。
- IPv6 主机（`::1`、`2001:db8::1`）必须与 `-p` 正确组合；输出地址时用 `[v6]:port` 形式。

## 命令总表

| 命令 | 作用 | 写持久化 | 需管理员 |
| --- | --- | --- | --- |
| `rnpc run` | 前台运行，不持久化（默认子命令） | 否 | 否 |
| `rnpc install` | 创建/更新实例：写配置 + 注册自启 + 注册 PATH | 是 | 视通道 |
| `rnpc uninstall` | 移除自启、按需移除 PATH 与配置 | 是 | 视通道 |
| `rnpc change` | 只改实例配置（可选重启），不动自启与 PATH | 是 | 否 |
| `rnpc update` | 检查新版本二进制 + 同步服务端配置 + 重启 | 是 | 视通道 |
| `rnpc list` | 列出所有实例及状态 | 否 | 否 |
| `rnpc status` | 单实例详情 | 否 | 否 |
| `rnpc start` / `stop` / `restart` | 控制已安装实例 | 否 | 视通道 |
| `rnpc logs` | 查看实例日志（`--lines`、`--follow`） | 否 | 否 |
| `rnpc path add\|remove\|status` | 手动管理 PATH 注册 | 是 | 否 |
| `rnpc channel list\|install\|remove` | 手动管理自启通道 | 是 | 视通道 |
| `rnpc doctor` | 环境自检 | 否 | 否 |
| `rnpc version` / `rnpc help` | 版本 / 帮助 | 否 | 否 |

未知子命令：退出码 `2`，并提示 `rnpc help`。**不得**把未知子命令当成运行参数。

## 实例模型

- 实例由 `--name` 标识，缺省 `default`。
- 合法实例名：`[a-z0-9]([a-z0-9_-]{0,30}[a-z0-9])?`。保留名：`all`、`rnpc`。
- 实例之间**完全隔离**：配置、日志、PID、自启项各一份。
- 同一实例重复 `install` 是幂等的（覆盖配置，不重复注册自启项）。
- 不同实例可指向同一服务端，也可指向不同服务端。

## 文件布局

全部位于当前用户目录，避免写系统目录（LTSC/受限环境友好）：

```
%LOCALAPPDATA%\rnpc\
├─ bin\rnpc.exe                       安装的二进制（install 时复制自身）
├─ bin\npc.exe                        （可选）兼容别名，指向同一文件
├─ instances\<name>\config.json       实例配置（含 vkey，权限收紧）
├─ instances\<name>\instance.json     元数据：通道、PID、安装时间、二进制版本
└─ logs\<name>.log                    日志（可轮转，单文件上限 10 MiB，保留 3 份）
```

`config.json` 必须只允许当前用户读取。写入用「临时文件 + 原子改名」，避免半写状态。

## 配置内容

```jsonc
{
  "server": "10.0.0.1",          // 主机
  "port": 8024,                   // 端口
  "vkey": "…",                    // 可空：由服务端下发
  "tunnels": [ /* 注册隧道；见下 */ ],
  "auto_reconnect": true,
  "log_level": "info"
}
```

- **不得**在日志、错误信息、`list`/`status` 输出中回显 vkey。
- `status` 对 vkey 只显示是否已设置。

## 自启通道

四个通道，按能力与权限选择：

| 通道 | 需要管理员 | 触发时机 | 说明 |
| --- | --- | --- | --- |
| `service` | 是 | 开机即启，无需登录 | Windows 服务，名为 `rnpc-<name>` |
| `task-start` | 是 | 开机即启 | 计划任务 `rnpc-<name>`，`/sc onstart` |
| `task-logon` | 视策略 | 用户登录 | 计划任务 `/sc onlogon` |
| `run-key` | 否 | 用户登录 | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |

**选择策略**（`--channel auto`，默认）：

1. 管理员身份 → 优先 `service`；服务安装失败则降级 `task-start`，再降级 `run-key`。
2. 非管理员 → 直接 `run-key`。
3. 显式指定通道但无权限 → **报错退出**（退出码 `3`），不静默降级。
4. 每次安装后，实际生效的通道与触发时机必须打印给用户，例如：
   `已注册自启：注册表 Run 键（用户登录后启动；开机即启需要管理员权限）`

**服务通道实现要点**

- 服务二进制路径必须是**绝对路径**（服务的工作目录是 `System32`）。
- 服务以 `rnpc service-host --name <name>` 形式被 SCM 拉起；该子命令只供 SCM 调用，
  在 `help` 中标注「内部使用」。
- 必须正确上报 `SERVICE_START_PENDING` → `SERVICE_RUNNING` → `SERVICE_STOP_PENDING` →
  `SERVICE_STOPPED`，否则 SCM 会判定超时（默认 30s）。
- 必须处理 `SERVICE_CONTROL_STOP` / `SERVICE_CONTROL_SHUTDOWN`。
- 服务名长度受限，`<name>` 需截断到安全长度并保持唯一。

**Run 键实现要点**

- 值名 `rnpc-<name>`，值为 `"<绝对路径>" run --name <name>`（路径含空格必须加引号）。
- 重装时覆盖同名值，不产生重复项。
- 卸载时只删自己写的那一项，绝不批量清理。

## PATH 注册

- 默认 `install` 时把 `%LOCALAPPDATA%\rnpc\bin` 加入 **用户级** PATH（`HKCU\Environment`），
  不碰系统级 PATH。
- 幂等：已存在则跳过；比较时忽略大小写与末尾反斜杠。
- 修改后用 `WM_SETTINGCHANGE` 广播，尽量让新开的终端立即生效；
  对当前已开的终端不生效属预期，需在输出中说明「新开终端后生效」。
- `uninstall` 时**只移除自己加的那一段**；若发现该目录已被其他条目引用则保留并提示。
- PATH 总长度接近上限（用户级约 32767）时必须拒绝写入并给出明确错误，不得截断。

## install 语义

```
rnpc install [-s HOST] [-p PORT] [-vkey KEY] [-config FILE]
             [--name NAME] [--channel auto|service|task-start|task-logon|run-key|none]
             [--no-autostart] [--no-path] [--npc-alias]
```

步骤（任一步失败都要回滚已完成的部分，不留半安装状态）：

1. 校验参数与实例名。
2. 若 `--config` 给了配置文件，读取并合并；命令行参数优先。
3. 复制自身到 `%LOCALAPPDATA%\rnpc\bin\rnpc.exe`（若已在目标位置则跳过）。
4. 写实例配置（原子写）。
5. 注册自启通道（`--no-autostart` 则跳过）。
6. 注册 PATH（`--no-path` 则跳过）。
7. `--npc-alias` 时在同目录建 `npc.exe` 硬链接（失败则复制并提示占用额外空间）。
8. 打印摘要：实例名、服务端、自启通道与触发时机、PATH 是否生效、配置路径。

## change 语义

```
rnpc change [-s HOST] [-p PORT] [-vkey KEY] [-config FILE] [--name NAME] [--restart]
```

- 只改 `config.json`，**不**触碰自启通道与 PATH。
- 实例不存在时报错（退出码 `4`），提示先 `install`。
- 默认不重启；`--restart` 时按当前通道重启实例。
- 打印「哪些字段变了」，但**不回显 vkey**（只显示「vkey 已更新」）。

## update 语义

```
rnpc update [--name NAME] [-s HOST] [-p PORT] [--check-only] [--force]
```

两件事都做：

1. **二进制更新**：从更新源检查新版本。
   - 更新源通过配置项 `update_feed`（URL 或本地目录）指定；未配置则跳过并明确提示
     「未配置更新源，跳过二进制更新」。
   - 有新版：下载 → 校验（若提供 sha256）→ 原子替换 `bin\rnpc.exe` → 备份旧版为
     `rnpc.exe.bak` → 重启实例。
   - 替换正在运行的 exe 在 Windows 上会失败：必须先停实例，替换后再启动；
     若失败要还原备份，不能让实例停留在「已停止」。
   - `--check-only` 只检查不更新。
2. **配置同步**：若给了 `-s`/`-p`，按 `change` 的规则更新配置。

**当前阶段说明**：更新源与签名机制尚未提供。实现时应把「检查更新」做成真实可用的
本地目录/HTTP 拉取，未配置时诚实跳过；**不得**伪造「已是最新」的成功结果。

## 多实例约束

- 允许同一实例名? 不允许。同名视为同一实例，`install` 幂等覆盖。
- 不同实例可同时运行，互不干扰。
- **禁止**使用全局锁文件、固定 PID 文件、固定临时文件名；一切按实例名隔离。
- 日志按实例分文件，避免交叉写入。
- `list` 必须能显示每个实例的：名称、服务端、通道、运行状态、PID（未知显示 `-`）。

## 退出码

| 码 | 含义 |
| --- | --- |
| 0 | 成功 |
| 1 | 运行时失败（连接断开等） |
| 2 | 参数/子命令非法 |
| 3 | 权限不足（指定的通道需要管理员） |
| 4 | 实例不存在 / 未安装 |
| 5 | 不支持的连接类型 |
| 6 | 协议错误 |
| 7 | 配置冲突（实例名非法、重复安装冲突等） |

## 安全约束

1. 任何输出（stdout/stderr/日志/`list`/`status`/`doctor`）都不得包含 vkey 明文或 md5。
2. 配置文件创建时权限收紧为仅当前用户可读。
3. 自启项的值必须是带引号的绝对路径，防止路径中空格导致解析错位。
4. `uninstall` 只能删除自己创建的注册表项/计划任务/服务/路径片段；
   删除前应校验目标确实由本程序创建（值内容包含 `rnpc` 与实例名）。
5. `--npc-alias` 创建硬链接前若目标已存在且不是自己创建的，**必须报错**，不覆盖。

## 与现有代码的接口

- 连接逻辑复用 `nps_client::client::run(RunConfig, shutdown)`。
- 服务通道需要一个可被 SCM 调用的入口；它与前台运行共享同一套连接逻辑，只换生命周期驱动。
- 持久化层不得依赖 `nps-server` / `nps-legacy` 的内部实现细节。

## 未验证项（必须在实现报告中标注）

- 服务通道、计划任务通道需要管理员权限；开发机当前为非管理员，
  这些通道**无法在本机验证**，只能验证「无权限时给出明确错误」。
- `WM_SETTINGCHANGE` 广播对已打开终端无效，属系统行为，不算缺陷。
