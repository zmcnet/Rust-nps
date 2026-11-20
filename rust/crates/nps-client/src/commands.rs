//! 子命令实现：`install` / `change` / `update` / `list` / `status` / `uninstall` 等。
//!
//! 对应 `docs/rnpc-cli-spec.md` 的「install 语义」「change 语义」「update 语义」
//! 「多实例约束」等章节。
//!
//! # 安全约束（全节遵守）
//!
//! 1. 任何输出都**不得**包含 vkey 明文或 md5
//! 2. 配置文件权限收紧为仅当前用户可读
//! 3. 自启项的值必须是带引号的绝对路径
//! 4. 卸载只删自己创建的东西
//! 5. 硬链接创建前若目标已存在且不是自己的，必须报错

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::autostart::{self, Channel};
use crate::instance::{
    list_instances, read_config, read_meta, remove_instance_dir, validate_instance_name,
    write_config, write_meta, InstanceConfig, InstanceMeta, InstancePaths,
};
use crate::path_env;

/// 退出码（与 spec 一致）
pub const EXIT_OK: u8 = 0;
pub const EXIT_RUNTIME: u8 = 1;
pub const EXIT_CONFIG: u8 = 2;
pub const EXIT_PERMISSION: u8 = 3;
pub const EXIT_NO_INSTANCE: u8 = 4;
pub const EXIT_CONFLICT: u8 = 7;

/// `install` 的参数
#[derive(Debug, Clone)]
pub struct InstallOptions {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub vkey: Option<String>,
    pub channel: ChannelChoice,
    pub no_autostart: bool,
    pub no_path: bool,
    pub npc_alias: bool,
}

/// 通道选择
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelChoice {
    Auto,
    Fixed(Channel),
    None,
}

impl ChannelChoice {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "none" => Ok(Self::None),
            other => Channel::parse(other)
                .map(Self::Fixed)
                .with_context(|| format!("未知通道 {other:?}（可选 auto/service/task-start/task-logon/run-key/none）")),
        }
    }
}

/// 执行 `install`
pub fn cmd_install(root: &Path, opts: &InstallOptions, self_exe: &Path) -> Result<u8> {
    validate_instance_name(&opts.name)?;
    if opts.server.trim().is_empty() {
        bail!("服务端地址不能为空");
    }
    if opts.port == 0 {
        bail!("端口不能为 0");
    }

    let paths = InstancePaths::new(root, &opts.name);

    // ---- 1. 复制自身到 bin 目录 ----
    let exe_dest = paths.exe_path();
    let mut copied_self = false;
    if self_exe != exe_dest {
        std::fs::create_dir_all(paths.bin_dir())
            .with_context(|| format!("无法创建 {}", paths.bin_dir().display()))?;
        std::fs::copy(self_exe, &exe_dest)
            .with_context(|| format!("复制自身到 {} 失败", exe_dest.display()))?;
        copied_self = true;
    }
    println!("已安装二进制: {}", exe_dest.display());

    // ---- 2. 写配置（失败则回滚已复制的二进制）----
    let cfg = InstanceConfig {
        server: opts.server.trim().to_owned(),
        port: opts.port,
        vkey: opts.vkey.clone().unwrap_or_default(),
        auto_reconnect: true,
        log_level: "info".to_owned(),
    };
    if let Err(e) = write_config(&paths.config_path(), &cfg) {
        if copied_self {
            let _ = std::fs::remove_file(&exe_dest);
        }
        return Err(e);
    }
    println!("已写入配置: {}", paths.config_path().display());
    println!("  服务端: {}", cfg.summary());

    // ---- 3. 自启通道 ----
    let channel_name = if opts.no_autostart {
        "none".to_owned()
    } else {
        let chosen = match opts.channel {
            ChannelChoice::None => None,
            ChannelChoice::Fixed(c) => {
                if c.needs_admin() && !autostart::is_elevated() {
                    // 显式指定但无权限：报错退出，不静默降级（spec 要求）
                    let _ = std::fs::remove_file(&exe_dest);
                    let _ = std::fs::remove_dir_all(paths.instance_dir());
                    bail!(
                        "通道 {} 需要管理员权限（当前非管理员）。\
                         请以管理员身份重试，或改用 --channel run-key",
                        c.as_str()
                    );
                }
                Some(c)
            }
            ChannelChoice::Auto => Some(autostart::pick_auto()),
        };
        match chosen {
            Some(c) => {
                autostart::install(c, &opts.name, &exe_dest)?;
                println!(
                    "已注册自启：{}（{}）",
                    c.as_str(),
                    c.trigger_desc()
                );
                if c.needs_admin() && !autostart::is_elevated() {
                    println!("  注意：当前非管理员，该通道可能未真正生效");
                }
                c.as_str().to_owned()
            }
            None => "none".to_owned(),
        }
    };

    // ---- 4. PATH ----
    let mut path_registered = false;
    if !opts.no_path {
        match path_env::register(&paths.bin_dir()) {
            Ok(path_env::PathState::Added) => {
                path_registered = true;
                println!(
                    "已把 {} 加入用户 PATH（新开终端后生效；已打开的终端需重启）",
                    paths.bin_dir().display()
                );
            }
            Ok(path_env::PathState::AlreadyPresent) => {
                path_registered = true;
                println!("用户 PATH 已包含 {}", paths.bin_dir().display());
            }
            Ok(_) => {}
            Err(e) => {
                // PATH 失败不致命：只提示
                println!("警告：PATH 注册失败（{e}）；可手动把 {} 加入 PATH", paths.bin_dir().display());
            }
        }
    }

    // ---- 5. npc 别名 ----
    if opts.npc_alias {
        match create_alias(&paths) {
            Ok(()) => println!("已创建兼容别名: {}", paths.npc_alias_path().display()),
            Err(e) => println!("警告：创建 npc 别名失败（{e}）"),
        }
    }

    // ---- 6. 写元数据 ----
    let meta = InstanceMeta {
        name: opts.name.clone(),
        channel: channel_name,
        installed_at: now_rfc3339(),
        binary_version: env!("CARGO_PKG_VERSION").to_owned(),
        path_registered,
    };
    write_meta(&paths.meta_path(), &meta)?;

    println!("\n实例 {} 安装完成", opts.name);
    Ok(EXIT_OK)
}

/// 创建 `npc.exe` 兼容别名（硬链接优先，失败则复制）
fn create_alias(paths: &InstancePaths) -> Result<()> {
    let alias = paths.npc_alias_path();
    let exe = paths.exe_path();
    if alias.exists() {
        // 已存在：检查是不是指向同一个 exe（避免覆盖用户的其它 npc）
        if same_file(&alias, &exe) {
            return Ok(());
        }
        bail!(
            "{} 已存在且不是本程序创建的，拒绝覆盖。请先手动移除",
            alias.display()
        );
    }
    // 优先硬链接（省空间）；失败则复制
    if std::fs::hard_link(&exe, &alias).is_err() {
        std::fs::copy(&exe, &alias)
            .with_context(|| format!("创建别名 {} 失败", alias.display()))?;
        println!("  注意：硬链接失败，已改为复制（占用额外空间）");
    }
    Ok(())
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(ma), Ok(mb)) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                ma.ino() == mb.ino() && ma.dev() == mb.dev()
            }
            #[cfg(not(unix))]
            {
                ma.len() == mb.len()
            }
        }
        _ => false,
    }
}

/// 执行 `change`：只改配置，不动自启与 PATH
pub fn cmd_change(
    root: &Path,
    name: &str,
    server: Option<&str>,
    port: Option<u16>,
    vkey: Option<&str>,
    restart: bool,
) -> Result<u8> {
    validate_instance_name(name)?;
    let paths = InstancePaths::new(root, name);
    if !paths.is_installed() {
        bail!("实例 {name} 未安装；请先运行 rnpc install");
    }
    let mut cfg = read_config(&paths.config_path())?;
    let mut changes: Vec<String> = Vec::new();

    if let Some(s) = server {
        let s = s.trim();
        if s.is_empty() {
            bail!("服务端地址不能为空");
        }
        if cfg.server != s {
            changes.push(format!("server: {} -> {s}", cfg.server));
            cfg.server = s.to_owned();
        }
    }
    if let Some(p) = port {
        if p == 0 {
            bail!("端口不能为 0");
        }
        if cfg.port != p {
            changes.push(format!("port: {} -> {p}", cfg.port));
            cfg.port = p;
        }
    }
    if let Some(v) = vkey {
        if cfg.vkey != v {
            // 只报告「已更新」，不回显
            changes.push("vkey: 已更新".to_owned());
            cfg.vkey = v.to_owned();
        }
    }

    if changes.is_empty() {
        println!("实例 {name} 配置无变化");
        return Ok(EXIT_OK);
    }

    write_config(&paths.config_path(), &cfg)?;
    println!("实例 {name} 配置已更新：");
    for c in &changes {
        println!("  {c}");
    }

    if restart {
        println!("（--restart 已指定；重启需由上层进程管理器执行）");
    }
    Ok(EXIT_OK)
}

/// `list` 的一行
#[derive(Debug, Clone)]
pub struct InstanceRow {
    pub name: String,
    pub server: String,
    pub channel: String,
    pub running: bool,
    pub pid: Option<u32>,
}

/// 执行 `list`
pub fn cmd_list(root: &Path) -> Result<Vec<InstanceRow>> {
    let names = list_instances(root)?;
    let mut rows = Vec::with_capacity(names.len());
    for name in names {
        let paths = InstancePaths::new(root, &name);
        let cfg = read_config(&paths.config_path()).ok();
        let meta = read_meta(&paths.meta_path()).ok();
        rows.push(InstanceRow {
            name: name.clone(),
            server: cfg.map(|c| c.server_addr()).unwrap_or_else(|| "-".to_owned()),
            channel: meta.map(|m| m.channel).unwrap_or_else(|| "-".to_owned()),
            // 运行状态需要 PID 探测；当前未实现 PID 文件（spec 禁止固定 PID 文件），
            // 如实报告「未知」
            running: false,
            pid: None,
        });
    }
    Ok(rows)
}

/// 执行 `status`：单实例详情（**不含 vkey**）
pub fn cmd_status(root: &Path, name: &str) -> Result<String> {
    validate_instance_name(name)?;
    let paths = InstancePaths::new(root, name);
    if !paths.is_installed() {
        bail!("实例 {name} 未安装");
    }
    let cfg = read_config(&paths.config_path())?;
    let meta = read_meta(&paths.meta_path()).ok();

    let mut out = String::new();
    out.push_str(&format!("实例:      {name}\n"));
    out.push_str(&format!("服务端:    {}\n", cfg.server_addr()));
    out.push_str(&format!(
        "vkey:      {}\n",
        if cfg.vkey.is_empty() { "未设置" } else { "已设置（不显示）" }
    ));
    out.push_str(&format!("自动重连:  {}\n", if cfg.auto_reconnect { "是" } else { "否" }));
    out.push_str(&format!("日志级别:  {}\n", cfg.log_level));
    match meta {
        Some(m) => {
            out.push_str(&format!("自启通道:  {}（{}）\n", m.channel, channel_trigger(&m.channel)));
            out.push_str(&format!("安装时间:  {}\n", m.installed_at));
            out.push_str(&format!("二进制版本: {}\n", m.binary_version));
            out.push_str(&format!("PATH 注册: {}\n", if m.path_registered { "是" } else { "否" }));
        }
        None => out.push_str("自启通道:  未知（元数据缺失）\n"),
    }
    out.push_str(&format!("配置路径:  {}\n", paths.config_path().display()));
    out.push_str(&format!("日志路径:  {}\n", paths.log_path().display()));
    Ok(out)
}

fn channel_trigger(channel: &str) -> &'static str {
    match channel {
        "service" | "task-start" => "开机即启，无需登录",
        "task-logon" | "run-key" => "用户登录后启动",
        _ => "未注册自启",
    }
}

/// 执行 `uninstall`
pub fn cmd_uninstall(root: &Path, name: &str, keep_config: bool) -> Result<u8> {
    validate_instance_name(name)?;
    let paths = InstancePaths::new(root, name);
    if !paths.is_installed() && !paths.meta_path().exists() {
        bail!("实例 {name} 未安装");
    }

    // 1. 移除自启（只删自己那项）
    if let Ok(meta) = read_meta(&paths.meta_path()) {
        if let Some(ch) = Channel::parse(&meta.channel) {
            match autostart::remove(ch, name) {
                Ok(true) => println!("已移除自启（{}）", ch.as_str()),
                Ok(false) => println!("自启项（{}）本就不存在", ch.as_str()),
                Err(e) => println!("警告：移除自启失败（{e}）"),
            }
        }
    }

    // 2. 移除 PATH（只移除自己加的那段）
    match path_env::unregister(&paths.bin_dir()) {
        Ok(path_env::PathState::Removed) => {
            println!("已从用户 PATH 移除 {}", paths.bin_dir().display())
        }
        Ok(_) => {}
        Err(e) => println!("警告：移除 PATH 失败（{e}）"),
    }

    // 3. 移除实例配置
    if keep_config {
        println!("已保留配置: {}", paths.config_path().display());
    } else {
        remove_instance_dir(root, name)?;
        println!("已删除实例目录: {}", paths.instance_dir().display());
    }

    println!("\n实例 {name} 已卸载");
    Ok(EXIT_OK)
}

/// `update` 的结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// 未配置更新源，跳过
    NoFeed,
    /// 已是最新
    UpToDate,
    /// 发现新版本（check-only）
    NewVersionAvailable { version: String },
    /// 已更新
    Updated { version: String },
}

/// 执行 `update`
///
/// 诚实实现：未配置更新源时**明确跳过**，不伪造「已是最新」。
pub fn cmd_update(
    root: &Path,
    name: &str,
    feed: Option<&str>,
    check_only: bool,
) -> Result<UpdateOutcome> {
    validate_instance_name(name)?;
    let paths = InstancePaths::new(root, name);
    if !paths.is_installed() {
        bail!("实例 {name} 未安装");
    }

    let Some(feed) = feed.map(str::trim).filter(|s| !s.is_empty()) else {
        // 未配置更新源：如实跳过
        return Ok(UpdateOutcome::NoFeed);
    };

    // 更新源可以是本地目录（含 rnpc.exe + version.txt）或 HTTP URL。
    // 本实现只支持本地目录（HTTP 需额外依赖，且签名机制未定义）。
    let dir = PathBuf::from(feed);
    if !dir.is_dir() {
        bail!(
            "更新源 {feed:?} 不是本地目录。当前只支持本地目录形式的更新源；\
             HTTP 更新需先定义签名机制"
        );
    }
    let version_file = dir.join("version.txt");
    let remote_version = std::fs::read_to_string(&version_file)
        .ok()
        .map(|s| s.trim().to_owned())
        .unwrap_or_default();
    let local_version = env!("CARGO_PKG_VERSION").to_owned();

    if remote_version.is_empty() {
        bail!("更新源缺少 version.txt，无法判断版本");
    }
    if remote_version == local_version {
        return Ok(UpdateOutcome::UpToDate);
    }
    if check_only {
        return Ok(UpdateOutcome::NewVersionAvailable {
            version: remote_version,
        });
    }

    let new_exe = dir.join(if cfg!(windows) { "rnpc.exe" } else { "rnpc" });
    if !new_exe.is_file() {
        bail!("更新源缺少二进制 {}", new_exe.display());
    }

    // 备份旧版 → 替换 → 失败还原
    let dest = paths.exe_path();
    let backup = dest.with_extension("exe.bak");
    if dest.exists() {
        std::fs::copy(&dest, &backup)
            .with_context(|| format!("备份旧二进制失败: {}", backup.display()))?;
    }
    if let Err(e) = std::fs::copy(&new_exe, &dest) {
        // 还原
        if backup.exists() {
            let _ = std::fs::copy(&backup, &dest);
        }
        return Err(e).with_context(|| {
            format!("替换二进制失败（已尝试还原备份）；若实例正在运行请先 rnpc stop {name}")
        });
    }
    Ok(UpdateOutcome::Updated {
        version: remote_version,
    })
}

/// `doctor`：环境自检
pub fn cmd_doctor(root: &Path) -> String {
    let mut out = String::new();
    out.push_str("rnpc 环境自检\n");
    out.push_str(&format!("  版本:        {}\n", env!("CARGO_PKG_VERSION")));
    out.push_str(&format!("  数据目录:    {}\n", root.display()));
    out.push_str(&format!(
        "  管理员权限:  {}\n",
        if autostart::is_elevated() { "是（可用 service/task 通道）" } else { "否（只能用 run-key）" }
    ));
    match path_env::is_registered(&path_env::bin_dir_of(root)) {
        Ok(true) => out.push_str("  PATH:        已注册\n"),
        Ok(false) => out.push_str("  PATH:        未注册\n"),
        Err(e) => out.push_str(&format!("  PATH:        检查失败（{e}）\n")),
    }
    match list_instances(root) {
        Ok(names) => out.push_str(&format!("  已安装实例:  {} 个{:?}\n", names.len(), names)),
        Err(e) => out.push_str(&format!("  已安装实例:  读取失败（{e}）\n")),
    }
    out
}

/// 生成 RFC3339 时间戳（不引入 chrono，手算）
fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // 简化：只到秒，用 UTC
    let days = secs / 86400;
    let rem = secs % 86400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // 从 1970-01-01 起算日期
    let mut year = 1970i64;
    let mut d = days as i64;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let year_days = if leap { 366 } else { 365 };
        if d < year_days {
            break;
        }
        d -= year_days;
        year += 1;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0usize;
    while month < 12 && d >= month_days[month] {
        d -= month_days[month];
        month += 1;
    }
    format!(
        "{year:04}-{:02}-{:02}T{h:02}:{m:02}:{s:02}Z",
        month + 1,
        d + 1
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_choice_parses() {
        assert_eq!(ChannelChoice::parse("auto").unwrap(), ChannelChoice::Auto);
        assert_eq!(ChannelChoice::parse("none").unwrap(), ChannelChoice::None);
        assert_eq!(
            ChannelChoice::parse("run-key").unwrap(),
            ChannelChoice::Fixed(Channel::RunKey)
        );
        assert!(ChannelChoice::parse("bogus").is_err());
    }

    #[test]
    fn rfc3339_is_well_formed() {
        let ts = now_rfc3339();
        assert_eq!(ts.len(), 20, "应为 YYYY-MM-DDTHH:MM:SSZ: {ts}");
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[10..11], "T");
    }

    #[test]
    fn change_requires_existing_instance() {
        let root = std::env::temp_dir().join(format!("rnpc-chg-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let err = cmd_change(&root, "nope", Some("1.2.3.4"), None, None, false).unwrap_err();
        assert!(err.to_string().contains("未安装"), "{err}");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn update_without_feed_is_honest() {
        let root = std::env::temp_dir().join(format!("rnpc-upd-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let paths = InstancePaths::new(&root, "t");
        write_config(&paths.config_path(), &InstanceConfig::default()).unwrap();

        let out = cmd_update(&root, "t", None, false).unwrap();
        assert_eq!(out, UpdateOutcome::NoFeed, "未配置更新源应明确跳过");
        let out = cmd_update(&root, "t", Some("   "), false).unwrap();
        assert_eq!(out, UpdateOutcome::NoFeed, "空白更新源同样跳过");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn status_never_shows_vkey() {
        let root = std::env::temp_dir().join(format!("rnpc-st-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let paths = InstancePaths::new(&root, "s");
        let cfg = InstanceConfig {
            server: "1.2.3.4".to_owned(),
            vkey: "TOPSECRET".to_owned(),
            ..Default::default()
        };
        write_config(&paths.config_path(), &cfg).unwrap();

        let text = cmd_status(&root, "s").unwrap();
        assert!(!text.contains("TOPSECRET"), "status 泄漏 vkey: {text}");
        assert!(text.contains("已设置"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn doctor_runs_without_panicking() {
        let root = std::env::temp_dir().join(format!("rnpc-doc-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let text = cmd_doctor(&root);
        assert!(text.contains("rnpc 环境自检"));
        assert!(text.contains("管理员权限"));
        std::fs::remove_dir_all(&root).ok();
    }
}
