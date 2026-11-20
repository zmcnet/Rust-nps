//! 命令行解析：兼容原版 npc 的短横线选项，同时接受 GNU 风格长选项。
//!
//! 原版 npc 使用 Go `flag` 包；这里同时接受 `-x` / `--x` / `-x=y` / `-x y` 形式。
//!
//! ## 支持的启动形式
//! 1. 直连（显式 host:port）：`rnpc -server 127.0.0.1:8024 -vkey <key>`
//! 2. 主机 + 端口分离：`rnpc -s 10.0.0.1 -p 8024`（等价于上一种写法）
//! 3. 配置文件：`rnpc -config npc.json`
//!
//! 选项别名（全部等价）：`-s` ≡ `-server` ≡ `--server`，`-p` ≡ `-port` ≡ `--port`。
//! `-server` 已带端口时**不允许**再给 `-p`（明确报错，不静默择一）；
//! `-server` 不带端口时端口取 `-p`，缺省 `8024`（与原版 nps 桥端口一致）。

use std::ffi::OsString;
use std::path::PathBuf;

/// 正常退出（Ctrl+C 优雅关闭）。
pub const EXIT_OK: u8 = 0;
/// 参数或配置非法 / 子命令尚未实现。
pub const EXIT_CONFIG: u8 = 2;
/// 首次连接服务端失败（不可达 / 超时 / 被拒绝）。
pub const EXIT_UNREACHABLE: u8 = 3;
/// 服务端明确拒绝了 vkey。
pub const EXIT_VKEY_REJECTED: u8 = 4;
/// `-type` 为本阶段不支持的传输类型。
pub const EXIT_UNSUPPORTED: u8 = 5;
/// 握手或协议帧非法（版本不匹配、连接类型 flag 异常等）。
pub const EXIT_PROTOCOL: u8 = 6;
/// 服务端拒绝了注册流程（未开启 public_vkey / 注册被关闭）。
pub const EXIT_REGISTER_DENIED: u8 = 7;
/// 配置文件不可读 / 超限 / 语法错误。
pub const EXIT_CONFIG_FILE: u8 = 8;

/// `-p` 的缺省值，与原版 nps `bridge_port` 默认值一致。
pub const DEFAULT_BRIDGE_PORT: u16 = 8024;

pub const HELP: &str = "\
Rust-nps 客户端 rnpc

用法:
  rnpc run -server <host:port> -vkey <密钥> [-type tcp] [-log_level <级别>]
  rnpc run -s <host> -p <端口> [-vkey <密钥>] [-type tcp]
  rnpc run -config <配置文件> [-log_level <级别>]
  rnpc -server <host:port> -vkey <密钥>            # 省略 run 等价于 run
  rnpc help
  rnpc version
  rnpc --help
  rnpc --version

选项:
  -s, -server    服务端桥接地址。可写成 host:port，也可只给主机（端口由 -p 决定）
  -p, -port      服务端桥接端口，缺省 8024；与 -server 自带的端口互斥
  -vkey          客户端认证密钥；日志与错误信息中不会回显。
                 直连模式下省略时走注册流程，由服务端分配密钥
  -config        JSON 配置文件路径（结构对齐原版 npc.conf）
  -type          连接类型，本阶段只支持 tcp（默认 tcp）
  -log_level     日志级别：trace|debug|info|warn|error 或 0~7（默认 info）
                 RUST_LOG 环境变量优先于 -log_level

子命令:
  run            运行客户端（默认；未指定子命令时按 run 处理）
  help / version 显示帮助 / 版本
  install / uninstall / update / change / list / status / start / stop
                 已识别但尚未实现（退出码 2）

退出码:
  0  正常退出（Ctrl+C）
  2  参数非法 / 子命令尚未实现
  3  首次连接服务端失败（不可达 / 超时 / 连接被拒）
  4  服务端拒绝 vkey（或注册后服务端仍不认密钥）
  5  -type 本阶段不支持
  6  握手或协议帧非法
  7  服务端拒绝注册流程
  8  配置文件不可读 / 超过 1 MiB / JSON 语法错误

说明:
  本阶段只建立 TCP 隧道；UDP、SOCKS5、HTTP 域名代理、KCP、P2P、
  加密、压缩暂未实现。配置文件中的非 tcp 隧道会明确提示「暂不支持」并跳过。
  Ctrl+C 会关闭全部子流并退出。
";

/// 传输类型。本阶段只支持 TCP 桥接。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnType {
    Tcp,
}

impl ConnType {
    pub fn parse(input: &str) -> Result<Self, CliError> {
        match input.trim().to_ascii_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            other => Err(CliError::UnsupportedType(other.to_owned())),
        }
    }
}

/// 启动目标。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// 直连桥端口。`vkey` 为 `None` 时走注册流程。
    Direct { server: String, vkey: Option<String> },
    /// 读取 JSON 配置文件后再决定连接参数。
    ConfigFile { path: PathBuf },
    /// 按已安装实例名运行（`install` 注册的自启项用的就是这条路径）。
    ///
    /// 配置从 `<data_root>/instances/<name>/config.json` 读取；
    /// 这是 `rnpc run --name <name>` 的实现基础。
    Instance { name: String },
}

/// 解析后的运行配置。`Debug` 手写以隐藏 vkey。
#[derive(Clone, PartialEq, Eq)]
pub struct RunConfig {
    pub target: Target,
    pub conn_type: ConnType,
    /// 已归一化的 tracing 过滤级别。
    pub log_level: String,
}

impl std::fmt::Debug for RunConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("RunConfig");
        match &self.target {
            Target::Direct { server, vkey } => {
                debug
                    .field("server", server)
                    .field("vkey", &if vkey.is_some() { "<redacted>" } else { "<none>" });
            }
            Target::ConfigFile { path } => {
                debug.field("config", path);
            }
            Target::Instance { name } => {
                debug.field("instance", name);
            }
        }
        debug
            .field("conn_type", &self.conn_type)
            .field("log_level", &self.log_level)
            .finish()
    }
}

impl RunConfig {
    /// 用于日志的服务端标识（不含密钥）。
    pub fn server_label(&self) -> String {
        match &self.target {
            Target::Direct { server, .. } => server.clone(),
            Target::ConfigFile { path } => format!("config:{}", path.display()),
            Target::Instance { name } => format!("instance:{name}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Run(RunConfig),
    Help,
    Version,
    /// `install`
    Install(InstallArgs),
    /// `uninstall`
    Uninstall { name: String, keep_config: bool },
    /// `change`
    Change(ChangeArgs),
    /// `update`
    Update(UpdateArgs),
    /// `list`
    List,
    /// `status`
    Status { name: String },
    /// `doctor`
    Doctor,
    /// `logs`
    Logs {
        name: String,
        lines: usize,
        follow: bool,
    },
    /// `channel list|install|remove`
    Channel {
        action: ChannelAction,
        name: String,
        channel: Option<String>,
    },
    /// `path add|remove|status`
    Path { action: PathAction },
    /// 扩展预留：已识别但本阶段不实现的子命令。
    UnsupportedSubcommand(String),
    /// 扩展预留：无法识别的子命令。
    UnknownSubcommand(String),
}

/// `install` 的参数
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallArgs {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub vkey: Option<String>,
    pub channel: String,
    pub no_autostart: bool,
    pub no_path: bool,
    pub npc_alias: bool,
}

/// `change` 的参数
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeArgs {
    pub name: String,
    pub server: Option<String>,
    pub port: Option<u16>,
    pub vkey: Option<String>,
    pub restart: bool,
}

/// `update` 的参数
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateArgs {
    pub name: String,
    pub feed: Option<String>,
    pub check_only: bool,
}

/// `channel` 子命令动作
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelAction {
    List,
    Install,
    Remove,
}

/// `path` 子命令动作
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathAction {
    Add,
    Remove,
    Status,
}

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("参数不是合法 UTF-8")]
    NonUtf8,
    #[error("未知选项 {0}")]
    UnknownOption(String),
    #[error("选项 {0} 缺少值")]
    MissingValue(String),
    #[error("缺少必需选项 {0}")]
    MissingOption(&'static str),
    #[error(
        "server 地址非法：需要 host、host:port 或 [IPv6]:port；主机不能为空，端口必须是 1~65535"
    )]
    InvalidServer,
    #[error("-server 已包含端口，不能再同时给 -p（请只保留一种写法）")]
    ConflictingPort,
    #[error("-p 非法：端口必须是 1~65535 的十进制整数")]
    InvalidPort,
    #[error("-config 与 -server/-p/-vkey/-type 不能同时使用，连接参数请写在配置文件里")]
    ConfigConflictsWithDirect,
    #[error("vkey 不能为空，且不能包含控制字符")]
    InvalidVkey,
    #[error("暂不支持 -type={0}，本阶段只支持 tcp")]
    UnsupportedType(String),
    #[error("日志级别非法；支持 trace|debug|info|warn|error 或 0~7")]
    InvalidLogLevel,
    #[error("无法解析参数：{0}")]
    InvalidArgument(&'static str),
}

impl CliError {
    pub fn exit_code(&self) -> u8 {
        match self {
            CliError::UnsupportedType(_) => EXIT_UNSUPPORTED,
            _ => EXIT_CONFIG,
        }
    }
}

/// 已知但尚未实现的子命令。
pub const RESERVED_SUBCOMMANDS: &[&str] = &[
    "install",
    "uninstall",
    "update",
    "change",
    "list",
    "status",
    "start",
    "stop",
];

/// 解析参数（不含 argv[0]）。
pub fn parse_args(args: impl IntoIterator<Item = OsString>) -> Result<Command, CliError> {
    let mut args: Vec<OsString> = args.into_iter().collect();
    let mut subcommand: Option<String> = None;

    // 第一个不以 `-` 开头的参数视为子命令（而不是像旧版直接报错）。
    if let Some(first) = args.first() {
        if let Some(text) = first.to_str() {
            if !text.is_empty() && !text.starts_with('-') {
                subcommand = Some(text.to_owned());
                args.remove(0);
            }
        }
    }

    match subcommand.as_deref() {
        Some("run") => {}
        Some("help") => return Ok(Command::Help),
        Some("version") => return Ok(Command::Version),
        Some("install") => return parse_install(args),
        Some("uninstall") => return parse_uninstall(args),
        Some("change") => return parse_change(args),
        Some("update") => return parse_update(args),
        Some("list") => return Ok(Command::List),
        Some("status") => return parse_status(args),
        Some("doctor") => return Ok(Command::Doctor),
        Some("path") => return parse_path(args),
        Some("logs") => return parse_logs(args),
        Some("channel") => return parse_channel(args),
        Some(name) if RESERVED_SUBCOMMANDS.contains(&name) => {
            return Ok(Command::UnsupportedSubcommand(name.to_owned()));
        }
        Some(name) => return Ok(Command::UnknownSubcommand(name.to_owned())),
        None => {}
    }

    let mut server: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut vkey: Option<String> = None;
    let mut config_path: Option<PathBuf> = None;
    let mut conn_type: Option<ConnType> = None;
    let mut log_level = "info".to_owned();
    let mut instance_name: Option<String> = None;

    let mut iter = args.into_iter();
    while let Some(raw) = iter.next() {
        let argument = raw.to_str().ok_or(CliError::NonUtf8)?;

        // 原版 npc 的 `-version` 以及常见 `--version` 都接受。
        if matches!(argument, "-h" | "--help" | "-help") {
            return Ok(Command::Help);
        }
        if matches!(argument, "-version" | "--version" | "-V" | "-v") {
            return Ok(Command::Version);
        }
        if argument == "--" {
            // GNU 参数终止符：本阶段没有位置参数，直接跳过。
            continue;
        }
        if !argument.starts_with('-') {
            // 不回显参数内容：误把密钥作为位置参数传入时也不能写进日志。
            return Err(CliError::InvalidArgument(
                "只接受以 - 或 -- 开头的选项；子命令请放在最前面",
            ));
        }

        let (name, inline_value) = match argument.split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (argument, None),
        };
        let name = name.trim_start_matches('-');
        if name.is_empty() {
            return Err(CliError::InvalidArgument("选项名不能为空"));
        }

        let value = match inline_value {
            Some(value) => value,
            None => {
                let next = iter
                    .next()
                    .ok_or_else(|| CliError::MissingValue(format!("-{name}")))?;
                next.into_string().map_err(|_| CliError::NonUtf8)?
            }
        };

        match name {
            // -s ≡ -server ≡ --server
            "s" | "server" => server = Some(value),
            // -p ≡ -port ≡ --port
            "p" | "port" => port = Some(parse_port(&value)?),
            "vkey" => vkey = Some(value),
            "config" => config_path = Some(PathBuf::from(value)),
            "type" => conn_type = Some(ConnType::parse(&value)?),
            "log_level" | "log-level" => log_level = normalize_log_level(&value)?,
            "name" => instance_name = Some(value),
            other => return Err(CliError::UnknownOption(format!("-{other}"))),
        }
    }

    let conn_type = conn_type.unwrap_or(ConnType::Tcp);

    // ---- 实例模式（自启项使用的路径）----
    if let Some(name) = instance_name {
        if server.is_some() || port.is_some() || vkey.is_some() || config_path.is_some() {
            return Err(CliError::ConfigConflictsWithDirect);
        }
        return Ok(Command::Run(RunConfig {
            target: Target::Instance { name },
            conn_type,
            log_level,
        }));
    }

    // ---- 配置文件模式 ----
    if let Some(path) = config_path {
        if server.is_some() || port.is_some() || vkey.is_some() {
            return Err(CliError::ConfigConflictsWithDirect);
        }
        if path.as_os_str().is_empty() {
            return Err(CliError::MissingValue("-config".to_owned()));
        }
        return Ok(Command::Run(RunConfig {
            target: Target::ConfigFile { path },
            conn_type,
            log_level,
        }));
    }

    // ---- 直连模式 ----
    let server = server
        .filter(|value| !value.trim().is_empty())
        .ok_or(CliError::MissingOption("-server"))?;
    let (has_port, normalized) = normalize_server(&server, port)?;

    // `-p` 只在 server 未自带端口时生效，否则明确报错（不静默择一）。
    if has_port && port.is_some() {
        return Err(CliError::ConflictingPort);
    }

    let vkey = match vkey {
        Some(value) => Some(normalize_vkey(value)?),
        None => None,
    };

    Ok(Command::Run(RunConfig {
        target: Target::Direct {
            server: normalized,
            vkey,
        },
        conn_type,
        log_level,
    }))
}

/// 从参数列表里取一个通用选项值（支持 `-k v` 与 `-k=v` 与 `--k=v`）
fn take_value(
    iter: &mut std::vec::IntoIter<OsString>,
    name: &str,
    inline: Option<String>,
) -> Result<String, CliError> {
    match inline {
        Some(v) => Ok(v),
        None => {
            let next = iter
                .next()
                .ok_or_else(|| CliError::MissingValue(format!("-{name}")))?;
            next.into_string().map_err(|_| CliError::NonUtf8)
        }
    }
}

/// 统一的选项扫描：把 `-k v` / `-k=v` 拆成 (name, Option<inline_value>)
fn next_option(
    iter: &mut std::vec::IntoIter<OsString>,
) -> Result<Option<(String, Option<String>)>, CliError> {
    let Some(raw) = iter.next() else {
        return Ok(None);
    };
    let argument = raw.to_str().ok_or(CliError::NonUtf8)?.to_owned();
    if !argument.starts_with('-') {
        return Err(CliError::InvalidArgument(
            "子命令选项必须以 - 或 -- 开头",
        ));
    }
    let (name, inline) = match argument.split_once('=') {
        Some((n, v)) => (n.to_owned(), Some(v.to_owned())),
        None => (argument, None),
    };
    let name = name.trim_start_matches('-').to_owned();
    if name.is_empty() {
        return Err(CliError::InvalidArgument("选项名不能为空"));
    }
    Ok(Some((name, inline)))
}

fn parse_install(args: Vec<OsString>) -> Result<Command, CliError> {
    let mut name = "default".to_owned();
    let mut server: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut vkey: Option<String> = None;
    let mut channel = "auto".to_owned();
    let mut no_autostart = false;
    let mut no_path = false;
    let mut npc_alias = false;

    let mut iter = args.into_iter();
    while let Some((opt, inline)) = next_option(&mut iter)? {
        match opt.as_str() {
            "s" | "server" => server = Some(take_value(&mut iter, &opt, inline)?),
            "p" | "port" => port = Some(parse_port(&take_value(&mut iter, &opt, inline)?)?),
            "vkey" => vkey = Some(normalize_vkey(take_value(&mut iter, &opt, inline)?)?),
            "name" => name = take_value(&mut iter, &opt, inline)?,
            "channel" => channel = take_value(&mut iter, &opt, inline)?,
            "no-autostart" => no_autostart = true,
            "no-path" => no_path = true,
            "npc-alias" => npc_alias = true,
            other => return Err(CliError::UnknownOption(format!("-{other}"))),
        }
    }

    let server = server
        .filter(|v| !v.trim().is_empty())
        .ok_or(CliError::MissingOption("-server"))?;
    let (has_port, host) = normalize_server(&server, port)?;
    if has_port && port.is_some() {
        return Err(CliError::ConflictingPort);
    }
    let port = port.unwrap_or(8024);
    // host 可能是 "host:port" 形式，需要拆开
    let (host_only, final_port) = split_host_port(&host).unwrap_or((host.clone(), port));

    Ok(Command::Install(InstallArgs {
        name,
        server: host_only,
        port: final_port,
        vkey,
        channel,
        no_autostart,
        no_path,
        npc_alias,
    }))
}

/// 把 `host:port` 拆成 (host, port)；无端口返回 None
fn split_host_port(addr: &str) -> Option<(String, u16)> {
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        let port = rest.strip_prefix(':')?.parse().ok()?;
        return Some((host.to_owned(), port));
    }
    let (host, port) = addr.rsplit_once(':')?;
    if host.contains(':') {
        return None; // 裸 IPv6
    }
    Some((host.to_owned(), port.parse().ok()?))
}

fn parse_uninstall(args: Vec<OsString>) -> Result<Command, CliError> {
    let mut name = "default".to_owned();
    let mut keep_config = false;
    let mut iter = args.into_iter();
    while let Some((opt, inline)) = next_option(&mut iter)? {
        match opt.as_str() {
            "name" => name = take_value(&mut iter, &opt, inline)?,
            "keep-config" => keep_config = true,
            other => return Err(CliError::UnknownOption(format!("-{other}"))),
        }
    }
    Ok(Command::Uninstall { name, keep_config })
}

fn parse_change(args: Vec<OsString>) -> Result<Command, CliError> {
    let mut name = "default".to_owned();
    let mut server = None;
    let mut port = None;
    let mut vkey = None;
    let mut restart = false;
    let mut iter = args.into_iter();
    while let Some((opt, inline)) = next_option(&mut iter)? {
        match opt.as_str() {
            "s" | "server" => server = Some(take_value(&mut iter, &opt, inline)?),
            "p" | "port" => port = Some(parse_port(&take_value(&mut iter, &opt, inline)?)?),
            "vkey" => vkey = Some(normalize_vkey(take_value(&mut iter, &opt, inline)?)?),
            "name" => name = take_value(&mut iter, &opt, inline)?,
            "restart" => restart = true,
            other => return Err(CliError::UnknownOption(format!("-{other}"))),
        }
    }
    Ok(Command::Change(ChangeArgs {
        name,
        server,
        port,
        vkey,
        restart,
    }))
}

fn parse_update(args: Vec<OsString>) -> Result<Command, CliError> {
    let mut name = "default".to_owned();
    let mut feed = None;
    let mut check_only = false;
    let mut iter = args.into_iter();
    while let Some((opt, inline)) = next_option(&mut iter)? {
        match opt.as_str() {
            "name" => name = take_value(&mut iter, &opt, inline)?,
            "feed" => feed = Some(take_value(&mut iter, &opt, inline)?),
            "check-only" => check_only = true,
            other => return Err(CliError::UnknownOption(format!("-{other}"))),
        }
    }
    Ok(Command::Update(UpdateArgs {
        name,
        feed,
        check_only,
    }))
}

fn parse_logs(args: Vec<OsString>) -> Result<Command, CliError> {
    let mut name = "default".to_owned();
    let mut lines = 50usize;
    let mut follow = false;
    let mut iter = args.into_iter();
    while let Some((opt, inline)) = next_option(&mut iter)? {
        match opt.as_str() {
            "name" => name = take_value(&mut iter, &opt, inline)?,
            "lines" | "n" => {
                let raw = take_value(&mut iter, &opt, inline)?;
                lines = raw
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| CliError::InvalidArgument("--lines 必须是正整数"))?;
            }
            "follow" | "f" => follow = true,
            other => return Err(CliError::UnknownOption(format!("-{other}"))),
        }
    }
    Ok(Command::Logs {
        name,
        lines,
        follow,
    })
}

fn parse_channel(args: Vec<OsString>) -> Result<Command, CliError> {
    let mut iter = args.into_iter();
    let Some(raw) = iter.next() else {
        return Err(CliError::MissingOption("channel list|install|remove"));
    };
    let action = match raw.to_str().ok_or(CliError::NonUtf8)? {
        "list" => ChannelAction::List,
        "install" => ChannelAction::Install,
        "remove" => ChannelAction::Remove,
        _ => {
            return Err(CliError::InvalidArgument(
                "channel 只支持 list / install / remove",
            ))
        }
    };
    let mut name = "default".to_owned();
    let mut channel = None;
    while let Some((opt, inline)) = next_option(&mut iter)? {
        match opt.as_str() {
            "name" => name = take_value(&mut iter, &opt, inline)?,
            "channel" => channel = Some(take_value(&mut iter, &opt, inline)?),
            other => return Err(CliError::UnknownOption(format!("-{other}"))),
        }
    }
    Ok(Command::Channel {
        action,
        name,
        channel,
    })
}

fn parse_status(args: Vec<OsString>) -> Result<Command, CliError> {
    let mut name = "default".to_owned();
    let mut iter = args.into_iter();
    while let Some((opt, inline)) = next_option(&mut iter)? {
        match opt.as_str() {
            "name" => name = take_value(&mut iter, &opt, inline)?,
            other => return Err(CliError::UnknownOption(format!("-{other}"))),
        }
    }
    Ok(Command::Status { name })
}

fn parse_path(args: Vec<OsString>) -> Result<Command, CliError> {
    let mut iter = args.into_iter();
    let Some(raw) = iter.next() else {
        return Err(CliError::MissingOption("path add|remove|status"));
    };
    let action = match raw.to_str().ok_or(CliError::NonUtf8)? {
        "add" => PathAction::Add,
        "remove" => PathAction::Remove,
        "status" => PathAction::Status,
        _ => {
            return Err(CliError::InvalidArgument(
                "path 只支持 add / remove / status",
            ))
        }
    };
    Ok(Command::Path { action })
}


fn parse_port(value: &str) -> Result<u16, CliError> {
    match value.trim().parse::<u16>() {
        Ok(0) | Err(_) => Err(CliError::InvalidPort),
        Ok(port) => Ok(port),
    }
}

fn normalize_vkey(value: String) -> Result<String, CliError> {
    if value.is_empty() || value.len() > 1024 || value.bytes().any(|b| b.is_ascii_control()) {
        return Err(CliError::InvalidVkey);
    }
    Ok(value)
}

/// 归一化 `-server`。返回 `(是否已显式带端口, 归一化后的地址)`。
///
/// 规则：
/// - `[v6]:port` / `host:port` → 已带端口，原样（去空白）返回
/// - `host` / `v6`（含多个冒号且能解析为 IPv6） → 不带端口，端口取 `-p` 或 8024
/// - 其它形态（空主机、端口非数字/为 0、冒号多于一个但不是 IPv6）→ 报错
pub fn normalize_server(server: &str, port: Option<u16>) -> Result<(bool, String), CliError> {
    let value = server.trim();
    if value.is_empty() || value.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return Err(CliError::InvalidServer);
    }

    // 形如 [IPv6]:port 或 [IPv6]
    if let Some(rest) = value.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            return Err(CliError::InvalidServer);
        };
        if host.is_empty() {
            return Err(CliError::InvalidServer);
        }
        if tail.is_empty() {
            let port = port.unwrap_or(DEFAULT_BRIDGE_PORT);
            return Ok((false, format!("[{host}]:{port}")));
        }
        let Some(raw_port) = tail.strip_prefix(':') else {
            return Err(CliError::InvalidServer);
        };
        let _ = parse_port(raw_port)?;
        return Ok((true, format!("[{host}]:{raw_port}")));
    }

    let colons = value.matches(':').count();
    if colons == 0 {
        let port = port.unwrap_or(DEFAULT_BRIDGE_PORT);
        return Ok((false, format!("{value}:{port}")));
    }
    if colons == 1 {
        let Some((host, raw_port)) = value.rsplit_once(':') else {
            return Err(CliError::InvalidServer);
        };
        if host.is_empty() {
            return Err(CliError::InvalidServer);
        }
        let _ = parse_port(raw_port)?;
        return Ok((true, value.to_owned()));
    }

    // 冒号多于一个：裸 IPv6（不带端口）。不是合法 IPv6 就报错。
    if value.parse::<std::net::Ipv6Addr>().is_err() {
        return Err(CliError::InvalidServer);
    }
    let port = port.unwrap_or(DEFAULT_BRIDGE_PORT);
    Ok((false, format!("[{value}]:{port}")))
}

/// 接受 tracing 级别名，也接受原版 npc 的 0~7 数字级别。
pub fn normalize_log_level(input: &str) -> Result<String, CliError> {
    let value = input.trim();
    if let Ok(number) = value.parse::<u8>() {
        let level = match number {
            0..=3 => "error",
            4 => "warn",
            5..=6 => "info",
            _ => "debug",
        };
        return Ok(level.to_owned());
    }
    match value.to_ascii_lowercase().as_str() {
        "trace" => Ok("trace".to_owned()),
        "debug" => Ok("debug".to_owned()),
        "info" => Ok("info".to_owned()),
        "warn" | "warning" => Ok("warn".to_owned()),
        "error" => Ok("error".to_owned()),
        _ => Err(CliError::InvalidLogLevel),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Command, CliError> {
        parse_args(args.iter().map(OsString::from))
    }

    fn run(args: &[&str]) -> RunConfig {
        match parse(args).expect("参数应解析成功") {
            Command::Run(config) => config,
            other => panic!("期望 Run，实际 {other:?}"),
        }
    }

    fn direct(args: &[&str]) -> (String, Option<String>) {
        match run(args).target {
            Target::Direct { server, vkey } => (server, vkey),
            other => panic!("期望 Direct，实际 {other:?}"),
        }
    }

    // ---- 选项别名 ----

    #[test]
    fn server_aliases_are_all_equivalent() {
        let canonical = direct(&["-server=10.0.0.1:8024", "-vkey=k"]).0;
        for args in [
            vec!["-s=10.0.0.1:8024", "-vkey=k"],
            vec!["-server", "10.0.0.1:8024", "-vkey", "k"],
            vec!["--server", "10.0.0.1:8024", "--vkey", "k"],
            vec!["-s", "10.0.0.1:8024", "-vkey=k"],
        ] {
            assert_eq!(direct(&args).0, canonical, "args={args:?}");
        }
    }

    #[test]
    fn port_aliases_are_all_equivalent() {
        let canonical = direct(&["-server=10.0.0.1:8024", "-vkey=k"]).0;
        for args in [
            vec!["-s=10.0.0.1", "-p=8024", "-vkey=k"],
            vec!["-server=10.0.0.1", "-port=8024", "-vkey=k"],
            vec!["--server", "10.0.0.1", "--port", "8024", "--vkey", "k"],
            vec!["-s", "10.0.0.1", "-p", "8024", "-vkey=k"],
            vec!["-server", "10.0.0.1", "-port", "8024", "-vkey=k"],
            vec!["-server=10.0.0.1:8024", "-vkey=k"],
        ] {
            assert_eq!(direct(&args).0, canonical, "args={args:?}");
        }
    }

    // ---- 模式 1：host:port ----

    #[test]
    fn parses_short_and_long_forms() {
        let config = run(&["-server=127.0.0.1:8024", "-vkey=secret", "-type=tcp"]);
        assert_eq!(
            config.target,
            Target::Direct {
                server: "127.0.0.1:8024".into(),
                vkey: Some("secret".into())
            }
        );
        assert_eq!(config.conn_type, ConnType::Tcp);
        assert_eq!(config.log_level, "info");

        let config = run(&[
            "--server",
            "example.com:9000",
            "--vkey",
            "another",
            "--type",
            "TCP",
            "--log_level=debug",
        ]);
        assert_eq!(config.conn_type, ConnType::Tcp);
        assert_eq!(config.log_level, "debug");
    }

    // ---- 模式 2：-server 主机 + -p 端口 ----

    #[test]
    fn host_and_port_is_equivalent_to_host_colon_port() {
        let (combined, _) = direct(&["-server=10.0.0.1:8024", "-vkey=k"]);
        let (split, _) = direct(&["-server=10.0.0.1", "-p=8024", "-vkey=k"]);
        let (spaced, _) = direct(&["--server", "10.0.0.1", "--p", "8024", "--vkey", "k"]);
        assert_eq!(combined, "10.0.0.1:8024");
        assert_eq!(split, combined);
        assert_eq!(spaced, combined);
    }

    #[test]
    fn host_without_port_defaults_to_8024() {
        assert_eq!(direct(&["-server=10.0.0.1", "-vkey=k"]).0, "10.0.0.1:8024");
        assert_eq!(direct(&["-server=localhost", "-vkey=k"]).0, "localhost:8024");
        assert_eq!(
            direct(&["-server=10.0.0.1", "-p=9999", "-vkey=k"]).0,
            "10.0.0.1:9999"
        );
    }

    #[test]
    fn host_port_and_p_together_is_an_explicit_error() {
        for args in [
            vec!["-server=10.0.0.1:8024", "-p=8024", "-vkey=k"],
            vec!["-s=10.0.0.1:9000", "-port=8024", "-vkey=k"],
            vec!["-server=[::1]:8024", "-p=8024", "-vkey=k"],
        ] {
            let error = parse(&args).expect_err("必须报冲突错误");
            assert!(matches!(error, CliError::ConflictingPort), "args={args:?}");
            assert_eq!(error.exit_code(), EXIT_CONFIG);
            assert!(error.to_string().contains("-p"));
        }
    }

    #[test]
    fn ipv6_hosts_work_with_separate_port() {
        assert_eq!(
            direct(&["-server=::1", "-p=8024", "-vkey=k"]).0,
            "[::1]:8024"
        );
        assert_eq!(
            direct(&["-server=2001:db8::1", "-p=8024", "-vkey=k"]).0,
            "[2001:db8::1]:8024"
        );
        assert_eq!(direct(&["-s=[::1]", "-p=9000", "-vkey=k"]).0, "[::1]:9000");
        assert_eq!(direct(&["-server=::1", "-vkey=k"]).0, "[::1]:8024");
        assert_eq!(direct(&["-server=[::1]:8024", "-vkey=k"]).0, "[::1]:8024");
    }

    #[test]
    fn invalid_hosts_are_rejected() {
        for server in [
            "",
            " ",
            "127.0.0.1:0",
            "127.0.0.1:x",
            ":8024",
            "127.0.0.1:8024:1",
            "[::1",
            "[::1]x8024",
            "1.2.3.4:70000",
        ] {
            let error =
                parse(&[&format!("-server={server}"), "-vkey=k"]).expect_err("应拒绝非法地址");
            assert_eq!(error.exit_code(), EXIT_CONFIG, "server={server}");
        }
    }

    #[test]
    fn invalid_port_values_are_rejected() {
        for port in ["0", "abc", "-1", "70000"] {
            let error = parse(&["-server=10.0.0.1", &format!("-p={port}"), "-vkey=k"])
                .expect_err("应拒绝非法端口");
            assert!(matches!(error, CliError::InvalidPort), "port={port}");
            assert_eq!(error.exit_code(), EXIT_CONFIG);
        }
    }

    #[test]
    fn p_without_server_is_missing_server() {
        let error = parse(&["-p=8024", "-vkey=k"]).expect_err("缺少 server");
        assert!(matches!(error, CliError::MissingOption("-server")));
    }

    // ---- vkey 可省略（注册流程） ----

    #[test]
    fn vkey_is_optional_in_direct_mode() {
        let (server, vkey) = direct(&["-server=10.0.0.1", "-p=8024"]);
        assert_eq!(server, "10.0.0.1:8024");
        assert_eq!(vkey, None);
    }

    #[test]
    fn empty_vkey_is_rejected_without_echo() {
        let error = parse(&["-server=127.0.0.1:8024", "-vkey="]).unwrap_err();
        assert_eq!(error.exit_code(), EXIT_CONFIG);
        assert!(!error.to_string().contains("vkey="));
    }

    // ---- 模式 3：配置文件 ----

    #[test]
    fn config_mode_parses_both_forms() {
        for argument in ["-config=npc.json", "--config=npc.json"] {
            let config = run(&[argument]);
            assert_eq!(
                config.target,
                Target::ConfigFile {
                    path: PathBuf::from("npc.json")
                }
            );
        }
        assert_eq!(
            run(&["-config", "npc.json", "-log_level=debug"]).log_level,
            "debug"
        );
    }

    #[test]
    fn config_mode_rejects_mixed_direct_options() {
        for args in [
            vec!["-config=npc.json", "-server=127.0.0.1:8024"],
            vec!["-config=npc.json", "-p=8024"],
            vec!["-config=npc.json", "-vkey=k"],
        ] {
            let error = parse(&args).expect_err("必须报冲突");
            assert!(
                matches!(error, CliError::ConfigConflictsWithDirect),
                "args={args:?}"
            );
            assert_eq!(error.exit_code(), EXIT_CONFIG);
        }
    }

    // ---- 子命令（扩展预留） ----

    #[test]
    fn run_subcommand_is_the_default_behaviour() {
        let implicit = run(&["-server=127.0.0.1:8024", "-vkey=k"]);
        let explicit = run(&["run", "-server=127.0.0.1:8024", "-vkey=k"]);
        assert_eq!(implicit.target, explicit.target);
    }

    #[test]
    fn help_and_version_subcommands() {
        assert_eq!(parse(&["help"]).unwrap(), Command::Help);
        assert_eq!(parse(&["version"]).unwrap(), Command::Version);
        assert_eq!(parse(&["help", "-server=x"]).unwrap(), Command::Help);
    }

    #[test]
    fn reserved_subcommands_are_recognized_not_silently_run() {
        // 已实现的子命令必须解析成具体变体，绝不能当成运行参数
        assert!(matches!(
            parse(&["install", "-server=127.0.0.1:8024"]).unwrap(),
            Command::Install(_)
        ));
        assert!(matches!(parse(&["list"]).unwrap(), Command::List));
        assert!(matches!(parse(&["doctor"]).unwrap(), Command::Doctor));
        assert!(matches!(
            parse(&["status", "--name", "web"]).unwrap(),
            Command::Status { .. }
        ));
        assert!(matches!(
            parse(&["uninstall", "--name", "web"]).unwrap(),
            Command::Uninstall { .. }
        ));
        assert!(matches!(
            parse(&["change", "-s", "1.2.3.4"]).unwrap(),
            Command::Change(_)
        ));
        assert!(matches!(
            parse(&["update", "--check-only"]).unwrap(),
            Command::Update(_)
        ));
        assert!(matches!(
            parse(&["path", "status"]).unwrap(),
            Command::Path { .. }
        ));

        // 仍未实现的子命令保持 UnsupportedSubcommand
        for name in ["start", "stop"] {
            assert_eq!(
                parse(&[name]).unwrap(),
                Command::UnsupportedSubcommand((*name).to_owned()),
                "subcommand={name}"
            );
        }
    }

    #[test]
    fn install_parses_aliases_and_defaults() {
        // -s + -p 拆分形式
        match parse(&["install", "-s", "10.0.0.1", "-p", "9000", "--name", "web"]).unwrap() {
            Command::Install(a) => {
                assert_eq!(a.server, "10.0.0.1");
                assert_eq!(a.port, 9000);
                assert_eq!(a.name, "web");
                assert_eq!(a.channel, "auto");
            }
            other => panic!("期望 Install，实际 {other:?}"),
        }
        // host:port 合并形式
        match parse(&["install", "-server=10.0.0.1:9001"]).unwrap() {
            Command::Install(a) => {
                assert_eq!(a.server, "10.0.0.1");
                assert_eq!(a.port, 9001);
                assert_eq!(a.name, "default");
            }
            other => panic!("期望 Install，实际 {other:?}"),
        }
        // 缺省端口 8024
        match parse(&["install", "-s", "h"]).unwrap() {
            Command::Install(a) => assert_eq!(a.port, 8024),
            other => panic!("期望 Install，实际 {other:?}"),
        }
        // 冲突：host:port 又给 -p
        assert!(parse(&["install", "-server=1.2.3.4:9000", "-p", "9001"]).is_err());
        // 开关
        match parse(&["install", "-s", "h", "--no-autostart", "--no-path", "--npc-alias"])
            .unwrap()
        {
            Command::Install(a) => {
                assert!(a.no_autostart && a.no_path && a.npc_alias);
            }
            other => panic!("期望 Install，实际 {other:?}"),
        }
    }

    #[test]
    fn unknown_subcommand_is_distinct() {
        assert_eq!(
            parse(&["bogus"]).unwrap(),
            Command::UnknownSubcommand("bogus".into())
        );
    }

    // ---- 通用 ----

    #[test]
    fn help_and_version_take_effect_immediately() {
        assert_eq!(parse(&["--help"]).unwrap(), Command::Help);
        assert_eq!(parse(&["-h"]).unwrap(), Command::Help);
        assert_eq!(parse(&["-version"]).unwrap(), Command::Version);
        assert_eq!(parse(&["--version"]).unwrap(), Command::Version);
    }

    #[test]
    fn missing_required_options_exit_config() {
        let error = parse(&[]).unwrap_err();
        assert_eq!(error.exit_code(), EXIT_CONFIG);
        assert!(error.to_string().contains("-server"));

        let error = parse(&["-server=127.0.0.1:8024", "-vkey"]).unwrap_err();
        assert!(matches!(error, CliError::MissingValue(_)));
    }

    #[test]
    fn unsupported_type_is_distinct_exit_code() {
        let error = parse(&["-server=127.0.0.1:8024", "-vkey=k", "-type=udp"]).unwrap_err();
        assert!(matches!(error, CliError::UnsupportedType(_)));
        assert_eq!(error.exit_code(), EXIT_UNSUPPORTED);
        assert!(error.to_string().contains("暂不支持"));
    }

    #[test]
    fn secrets_never_appear_in_debug_or_errors() {
        let config = run(&["-server=127.0.0.1:8024", "-vkey=super-secret-value"]);
        assert!(!format!("{config:?}").contains("super-secret-value"));
        let error =
            parse(&["-server=127.0.0.1:8024", "-vkey=super-secret-value", "-type=x"]).unwrap_err();
        assert!(!error.to_string().contains("super-secret-value"));
    }

    #[test]
    fn unknown_options_do_not_echo_values() {
        let error =
            parse(&["-server=127.0.0.1:8024", "-vkey=secret", "--bogus=secret"]).unwrap_err();
        assert!(matches!(error, CliError::UnknownOption(_)));
        assert!(!error.to_string().contains("secret"));
    }

    #[test]
    fn numeric_log_levels_map_to_tracing_levels() {
        assert_eq!(normalize_log_level("0").unwrap(), "error");
        assert_eq!(normalize_log_level("3").unwrap(), "error");
        assert_eq!(normalize_log_level("4").unwrap(), "warn");
        assert_eq!(normalize_log_level("5").unwrap(), "info");
        assert_eq!(normalize_log_level("7").unwrap(), "debug");
        assert_eq!(normalize_log_level("WARN").unwrap(), "warn");
        assert!(normalize_log_level("loud").is_err());
    }
}
