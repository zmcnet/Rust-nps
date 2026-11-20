//! 实例模型与持久化存储。
//!
//! 对应 `docs/rnpc-cli-spec.md` 的「实例模型」「文件布局」「配置内容」三节。
//!
//! # 布局
//!
//! ```text
//! %LOCALAPPDATA%\rnpc\
//! ├─ bin\rnpc.exe                   install 时复制自身
//! ├─ bin\npc.exe                    （可选）兼容别名
//! ├─ instances\<name>\config.json   实例配置（含 vkey，权限收紧）
//! ├─ instances\<name>\instance.json 元数据：通道、安装时间、二进制版本
//! └─ logs\<name>.log                日志
//! ```
//!
//! # 多实例
//!
//! 一切按实例名隔离：**没有**全局锁、没有固定 PID 文件、没有固定临时文件名。
//! 同一台机器可跑任意多个实例。

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// 保留实例名（不能用作实例名）
pub const RESERVED_NAMES: &[&str] = &["all", "rnpc"];
/// 实例名最大长度
pub const MAX_NAME_LEN: usize = 32;

/// 校验实例名。
///
/// 规则：`[a-z0-9]([a-z0-9_-]{0,30}[a-z0-9])?`，即小写字母数字开头结尾，
/// 中间允许 `-` 与 `_`，总长 1..=32。
pub fn validate_instance_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("实例名不能为空");
    }
    if name.len() > MAX_NAME_LEN {
        bail!("实例名过长（{} > {MAX_NAME_LEN}）", name.len());
    }
    if RESERVED_NAMES.contains(&name) {
        bail!("实例名 {name:?} 是保留名（{}）", RESERVED_NAMES.join(" / "));
    }
    let bytes = name.as_bytes();
    let is_ok_char = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_';
    let is_edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();

    if !is_edge(bytes[0]) || !is_edge(bytes[bytes.len() - 1]) {
        bail!("实例名必须以小写字母或数字开头/结尾: {name:?}");
    }
    if !bytes.iter().all(|b| is_ok_char(*b)) {
        bail!("实例名只能包含小写字母、数字、- 和 _: {name:?}");
    }
    // 防止路径穿越（虽然字符集已排除 / 与 .，这里再明确一次）
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        bail!("实例名不能包含路径分隔符: {name:?}");
    }
    Ok(())
}

/// 实例配置（`config.json`）
///
/// `Debug` 手写，**vkey 输出 `<redacted>`**。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceConfig {
    /// 服务端主机（不含端口）
    pub server: String,
    /// 服务端端口
    #[serde(default = "default_port")]
    pub port: u16,
    /// 客户端认证密钥；可空（由服务端下发）
    #[serde(default)]
    pub vkey: String,
    /// 自动重连
    #[serde(default = "default_true")]
    pub auto_reconnect: bool,
    /// 日志级别
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_port() -> u16 {
    8024
}

fn default_true() -> bool {
    true
}

fn default_log_level() -> String {
    "info".to_owned()
}

impl Default for InstanceConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: default_port(),
            vkey: String::new(),
            auto_reconnect: true,
            log_level: default_log_level(),
        }
    }
}

impl std::fmt::Debug for InstanceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstanceConfig")
            .field("server", &self.server)
            .field("port", &self.port)
            .field("vkey", &if self.vkey.is_empty() { "<unset>" } else { "<redacted>" })
            .field("auto_reconnect", &self.auto_reconnect)
            .field("log_level", &self.log_level)
            .finish()
    }
}

impl InstanceConfig {
    /// `host:port` 形式（IPv6 自动加方括号）
    pub fn server_addr(&self) -> String {
        if self.server.contains(':') && !self.server.starts_with('[') {
            format!("[{}]:{}", self.server, self.port)
        } else {
            format!("{}:{}", self.server, self.port)
        }
    }

    /// 供展示用的摘要（**不含 vkey**）
    pub fn summary(&self) -> String {
        format!(
            "{}（vkey: {}）",
            self.server_addr(),
            if self.vkey.is_empty() { "未设置" } else { "已设置" }
        )
    }
}

/// 实例元数据（`instance.json`）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceMeta {
    pub name: String,
    /// 实际生效的自启通道（`service` / `task-start` / `task-logon` / `run-key` / `none`）
    pub channel: String,
    /// 安装时间（RFC3339）
    pub installed_at: String,
    /// 二进制版本
    pub binary_version: String,
    /// PATH 是否已注册
    #[serde(default)]
    pub path_registered: bool,
}

/// 数据根目录解析。
///
/// 优先 `RNPC_DATA_DIR` 环境变量（便于测试与自定义部署），
/// 否则 `%LOCALAPPDATA%\rnpc`。
pub fn data_root() -> PathBuf {
    if let Ok(custom) = std::env::var("RNPC_DATA_DIR") {
        if !custom.trim().is_empty() {
            return PathBuf::from(custom);
        }
    }
    #[cfg(windows)]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            if !local.trim().is_empty() {
                return PathBuf::from(local).join("rnpc");
            }
        }
    }
    // 非 Windows 或环境变量缺失：退回用户目录下的隐藏目录
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_owned());
    PathBuf::from(home).join(".rnpc")
}

/// 一个实例的路径集合
#[derive(Debug, Clone)]
pub struct InstancePaths {
    pub root: PathBuf,
    pub name: String,
}

impl InstancePaths {
    pub fn new(root: impl Into<PathBuf>, name: impl Into<String>) -> Self {
        Self {
            root: root.into(),
            name: name.into(),
        }
    }

    pub fn bin_dir(&self) -> PathBuf {
        self.root.join("bin")
    }

    pub fn exe_path(&self) -> PathBuf {
        self.bin_dir().join(if cfg!(windows) { "rnpc.exe" } else { "rnpc" })
    }

    pub fn npc_alias_path(&self) -> PathBuf {
        self.bin_dir().join(if cfg!(windows) { "npc.exe" } else { "npc" })
    }

    pub fn instance_dir(&self) -> PathBuf {
        self.root.join("instances").join(&self.name)
    }

    pub fn config_path(&self) -> PathBuf {
        self.instance_dir().join("config.json")
    }

    pub fn meta_path(&self) -> PathBuf {
        self.instance_dir().join("instance.json")
    }

    pub fn log_path(&self) -> PathBuf {
        self.root.join("logs").join(format!("{}.log", self.name))
    }

    /// 该实例是否已安装（配置文件存在即视为已安装）
    pub fn is_installed(&self) -> bool {
        self.config_path().exists()
    }
}

/// 原子写文件（临时文件 + 改名）。
///
/// 临时文件名**按实例名隔离**（`<name>.json.tmp`），避免多实例并发写冲突。
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("无法创建目录 {}", parent.display()))?;
    }
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("config.json");
    let tmp = path.with_file_name(format!("{file_name}.tmp"));

    {
        let mut f = std::fs::File::create(&tmp)
            .with_context(|| format!("无法创建临时文件 {}", tmp.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("写入临时文件失败: {}", tmp.display()))?;
        f.sync_all().ok();
    }

    // Windows 上 rename 到已存在文件会失败，先删
    if path.exists() {
        std::fs::remove_file(path)
            .with_context(|| format!("无法替换旧文件 {}", path.display()))?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("替换文件失败: {} -> {}", tmp.display(), path.display()))?;

    restrict_permissions(path);
    Ok(())
}

/// 收紧文件权限为「仅当前用户可读写」。
///
/// Unix 用 0600；Windows 用 `icacls` 移除继承并只给当前用户。
/// 失败不致命（记录警告），因为部分受限环境无法改 ACL。
fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(windows)]
    {
        // 用 icacls 移除继承并只授权当前用户（不依赖额外 crate）
        let user = std::env::var("USERNAME").unwrap_or_default();
        if user.is_empty() {
            return;
        }
        let _ = std::process::Command::new("icacls")
            .arg(path)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(format!("{user}:F"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// 读实例配置
pub fn read_config(path: &Path) -> Result<InstanceConfig> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("无法读取配置 {}", path.display()))?;
    let cfg: InstanceConfig = serde_json::from_slice(&bytes).with_context(|| {
        format!("配置格式无效（{}），请对照文档检查", path.display())
    })?;
    Ok(cfg)
}

/// 写实例配置（原子 + 权限收紧）
pub fn write_config(path: &Path, cfg: &InstanceConfig) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(cfg).context("序列化配置失败")?;
    write_atomic(path, &bytes)
}

/// 读实例元数据
pub fn read_meta(path: &Path) -> Result<InstanceMeta> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("无法读取实例元数据 {}", path.display()))?;
    let meta: InstanceMeta = serde_json::from_slice(&bytes)
        .with_context(|| format!("实例元数据格式无效（{}）", path.display()))?;
    Ok(meta)
}

/// 写实例元数据
pub fn write_meta(path: &Path, meta: &InstanceMeta) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(meta).context("序列化实例元数据失败")?;
    write_atomic(path, &bytes)
}

/// 枚举所有已安装实例（按名字排序）
pub fn list_instances(root: &Path) -> Result<Vec<String>> {
    let dir = root.join("instances");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .with_context(|| format!("无法读取实例目录 {}", dir.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        // 只认有 config.json 的目录
        if entry.path().join("config.json").exists() {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// 运行时记录（`instances/<name>/runtime.json`）。
///
/// 规格禁止「固定路径的 PID 文件」——但按**实例名隔离**的运行时记录是允许的，
/// 因为 key 就是实例名，多实例天然不会碰撞。
///
/// 记录里的 PID 可能因进程退出后被系统复用，**读取方必须校验归属**
/// （见 `process::state`），不能盲信。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeRecord {
    /// 进程 ID
    pub pid: u32,
    /// 启动时间（RFC3339），用于辅助判断是否陈旧
    pub started_at: String,
    /// 可执行文件绝对路径
    pub exe: String,
    /// 实例名（冗余存一份，便于校验）
    pub name: String,
}

impl InstancePaths {
    /// 运行时记录路径
    pub fn runtime_path(&self) -> PathBuf {
        self.instance_dir().join("runtime.json")
    }
}

/// 读运行时记录（不存在返回 None；格式损坏视为陈旧并删除）
pub fn read_runtime(path: &Path) -> Option<RuntimeRecord> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<RuntimeRecord>(&bytes) {
        Ok(record) => Some(record),
        Err(_) => {
            // 损坏的记录直接删掉，避免永远读不到状态
            let _ = std::fs::remove_file(path);
            None
        }
    }
}

/// 记录当前进程（供 `rnpc run --name` 调用）。
///
/// 用独占创建 + 先读后写的方式，避免两个进程同时写坏文件。
pub fn record_runtime(path: &Path, name: &str) -> Result<()> {
    let exe = std::env::current_exe().context("无法获取自身可执行文件路径")?;
    let record = RuntimeRecord {
        pid: std::process::id(),
        started_at: now_rfc3339(),
        exe: exe.display().to_string(),
        name: name.to_owned(),
    };
    let bytes = serde_json::to_vec_pretty(&record).context("序列化运行时记录失败")?;
    write_atomic(path, &bytes)
}

/// 清除运行时记录（只清除属于自己的那条，避免误删后继进程的记录）
pub fn clear_runtime(path: &Path) -> Result<bool> {
    let Some(record) = read_runtime(path) else {
        return Ok(false);
    };
    if record.pid != std::process::id() {
        // 记录已被另一个进程覆盖，不要动
        return Ok(false);
    }
    std::fs::remove_file(path).context("删除运行时记录失败")?;
    Ok(true)
}

/// RFC3339 时间戳（UTC，秒精度）
pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86400;
    let rem = secs % 86400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
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

/// 枚举系统中正在运行的进程：`(pid, 映像名小写)`。
///
/// 一次性调用 `tasklist`，避免为每个实例各 spawn 一次。
/// 非 Windows 返回空集合（调用方按「未知」处理）。
pub fn running_processes() -> Vec<(u32, String)> {
    #[cfg(windows)]
    {
        let Ok(output) = std::process::Command::new("tasklist")
            .args(["/FO", "CSV", "/NH"])
            .output()
        else {
            return Vec::new();
        };
        let text = String::from_utf8_lossy(&output.stdout);
        let mut out = Vec::new();
        for line in text.lines() {
            // 形如: "rnpc.exe","13304","Console","1","5,120 K"
            let mut parts = line.splitn(3, ',');
            let (Some(name), Some(pid)) = (parts.next(), parts.next()) else {
                continue;
            };
            let name = name.trim().trim_matches('"').to_ascii_lowercase();
            let Ok(pid) = pid.trim().trim_matches('"').parse::<u32>() else {
                continue;
            };
            out.push((pid, name));
        }
        out
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

/// 判断运行时记录是否仍然有效。
///
/// 三个条件同时满足才算「在运行」：
/// 1. PID 存在于当前进程表
/// 2. 映像名与记录里的 exe 文件名一致（防 PID 复用）
/// 3. 记录里的实例名与查询的实例名一致
pub fn runtime_is_live(
    record: &RuntimeRecord,
    instance: &str,
    processes: &[(u32, String)],
) -> bool {
    if record.name != instance {
        return false;
    }
    let exe_name = std::path::Path::new(&record.exe)
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    processes
        .iter()
        .any(|(pid, name)| *pid == record.pid && *name == exe_name)
}

/// 删除实例目录（uninstall 用）
pub fn remove_instance_dir(root: &Path, name: &str) -> Result<bool> {
    let dir = root.join("instances").join(name);
    if !dir.exists() {
        return Ok(false);
    }
    std::fs::remove_dir_all(&dir)
        .with_context(|| format!("无法删除实例目录 {}", dir.display()))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rnpc-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn instance_names_are_validated() {
        for ok in ["default", "web", "a", "a-b", "a_b", "abc123", "x1"] {
            validate_instance_name(ok).unwrap_or_else(|e| panic!("{ok} 应合法: {e}"));
        }
        for bad in ["", "A", "1a-", "-a", "a-", "a b", "a/b", "a\\b", "a..b", "all", "rnpc"] {
            assert!(
                validate_instance_name(bad).is_err(),
                "{bad:?} 应被拒绝"
            );
        }
        // 超长
        let long = "a".repeat(MAX_NAME_LEN + 1);
        assert!(validate_instance_name(&long).is_err());
        // 边界长度
        let edge = format!("a{}", "b".repeat(MAX_NAME_LEN - 1));
        assert!(validate_instance_name(&edge).is_ok());
    }

    #[test]
    fn paths_are_isolated_per_instance() {
        let root = PathBuf::from("/tmp/rnpc");
        let a = InstancePaths::new(&root, "web");
        let b = InstancePaths::new(&root, "db");
        assert_ne!(a.config_path(), b.config_path());
        assert_ne!(a.log_path(), b.log_path());
        assert_ne!(a.meta_path(), b.meta_path());
        // 二进制目录共享（同一份安装）
        assert_eq!(a.exe_path(), b.exe_path());
        // 临时文件也按实例隔离
        assert!(a.config_path().to_string_lossy().contains("web"));
    }

    #[test]
    fn config_debug_redacts_vkey() {
        let cfg = InstanceConfig {
            server: "10.0.0.1".to_owned(),
            port: 8024,
            vkey: "super-secret-key".to_owned(),
            ..Default::default()
        };
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("super-secret-key"), "Debug 泄漏 vkey: {rendered}");
        assert!(rendered.contains("<redacted>"));
        // summary 也不含 vkey
        let summary = cfg.summary();
        assert!(!summary.contains("super-secret-key"));
        assert!(summary.contains("已设置"));
    }

    #[test]
    fn server_addr_handles_ipv6() {
        let v4 = InstanceConfig {
            server: "10.0.0.1".to_owned(),
            port: 8024,
            ..Default::default()
        };
        assert_eq!(v4.server_addr(), "10.0.0.1:8024");

        let v6 = InstanceConfig {
            server: "2001:db8::1".to_owned(),
            port: 8024,
            ..Default::default()
        };
        assert_eq!(v6.server_addr(), "[2001:db8::1]:8024");

        // 已带方括号的不重复加
        let v6b = InstanceConfig {
            server: "[::1]".to_owned(),
            port: 8024,
            ..Default::default()
        };
        assert_eq!(v6b.server_addr(), "[::1]:8024");
    }

    #[test]
    fn atomic_write_and_read_roundtrip() {
        let root = tmp_root("cfg");
        let paths = InstancePaths::new(&root, "default");
        let cfg = InstanceConfig {
            server: "127.0.0.1".to_owned(),
            port: 8024,
            vkey: "k".to_owned(),
            ..Default::default()
        };
        write_config(&paths.config_path(), &cfg).unwrap();
        assert!(paths.is_installed());

        let loaded = read_config(&paths.config_path()).unwrap();
        assert_eq!(loaded, cfg);

        // 临时文件不应残留
        let tmp = paths.config_path().with_file_name("config.json.tmp");
        assert!(!tmp.exists(), "临时文件应被改名");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn atomic_write_overwrites_existing() {
        let root = tmp_root("overwrite");
        let paths = InstancePaths::new(&root, "default");
        let mut cfg = InstanceConfig {
            server: "a".to_owned(),
            ..Default::default()
        };
        write_config(&paths.config_path(), &cfg).unwrap();
        cfg.server = "b".to_owned();
        write_config(&paths.config_path(), &cfg).unwrap();
        assert_eq!(read_config(&paths.config_path()).unwrap().server, "b");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn list_and_remove_instances() {
        let root = tmp_root("list");
        for name in ["web", "db"] {
            let p = InstancePaths::new(&root, name);
            write_config(&p.config_path(), &InstanceConfig::default()).unwrap();
        }
        let names = list_instances(&root).unwrap();
        assert_eq!(names, vec!["db".to_owned(), "web".to_owned()], "应按名字排序");

        assert!(remove_instance_dir(&root, "web").unwrap());
        assert_eq!(list_instances(&root).unwrap(), vec!["db".to_owned()]);
        assert!(!remove_instance_dir(&root, "web").unwrap(), "重复删除返回 false");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn empty_root_lists_nothing() {
        let root = tmp_root("empty");
        assert!(list_instances(&root).unwrap().is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn corrupt_config_reports_error() {
        let root = tmp_root("corrupt");
        let paths = InstancePaths::new(&root, "bad");
        std::fs::create_dir_all(paths.instance_dir()).unwrap();
        std::fs::write(paths.config_path(), b"{ not json").unwrap();
        assert!(read_config(&paths.config_path()).is_err());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn meta_roundtrip() {
        let root = tmp_root("meta");
        let paths = InstancePaths::new(&root, "default");
        let meta = InstanceMeta {
            name: "default".to_owned(),
            channel: "run-key".to_owned(),
            installed_at: "2026-11-20T00:00:00Z".to_owned(),
            binary_version: "0.1.0".to_owned(),
            path_registered: true,
        };
        write_meta(&paths.meta_path(), &meta).unwrap();
        assert_eq!(read_meta(&paths.meta_path()).unwrap(), meta);
        std::fs::remove_dir_all(&root).ok();
    }
}
