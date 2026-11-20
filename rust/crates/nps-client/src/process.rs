//! 按实例的进程发现与 start/stop/restart。
//!
//! 对应 `docs/rnpc-cli-spec.md` 的「多实例约束」一节：
//!
//! - **禁止**固定 PID 文件、全局锁文件——多实例会互相踩。
//! - 运行时记录按实例名隔离：`<root>\instances\<name>\runtime.json`。
//! - PID 会复用，读到记录后**必须校验归属**（比对进程实际 exe + 命令行 `--name <name>`）。
//! - 写记录用 `create_new` 独占创建，避免两个进程同时写坏文件。
//!
//! 非 Windows 平台：除 [`state`] 外所有函数返回 Unsupported 错误；
//! [`state`] 仍可读取记录并如实报告 [`RunState::Unknown`]。
//!
//! # 已知限制
//!
//! - [`stop`] 的优雅阶段用 `taskkill /PID <pid>`（不带 `/F`）。被启动的实例以
//!   `CREATE_NO_WINDOW` 分离运行，没有可接收 `WM_CLOSE` 的窗口，因此常见结果是
//!   优雅阶段超时后走 `taskkill /F` 强杀。**强杀会丢失未持久化的流量统计**。
//! - `state()` 依赖 `tasklist` 与 PowerShell CIM 探查进程；后者被策略禁用时，
//!   只能报告 [`RunState::Unknown`]（不会误删记录）。

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
// 运行时记录的**存储格式与读写**统一由 `instance` 模块负责，
// 本模块只在它之上做「PID 归属校验 + 进程控制」，避免两处格式各自漂移。
use crate::instance::{
    now_rfc3339, read_runtime, validate_instance_name, InstancePaths,
};

/// 运行时记录（复用 [`crate::instance::RuntimeRecord`]，此处 re-export 便于调用方使用）。
pub use crate::instance::RuntimeRecord;

/// 进程控制仅 Windows 实现。
pub const UNSUPPORTED_MSG: &str = "进程控制仅 Windows 实现";

/// 启动后等待 runtime.json 出现的最长时间。
const START_WAIT: Duration = Duration::from_secs(15);
/// 轮询间隔。
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// 实例运行时状态
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunState {
    /// 确认在运行（PID 已校验归属）
    Running { pid: u32 },
    /// 未运行（无记录，或记录已过期/归属不符）
    Stopped,
    /// 记录存在但 PID 归属无法确认（权限不足等原因）
    Unknown { pid: u32, reason: String },
}

// ---------------------------------------------------------------------------
// 路径与校验
// ---------------------------------------------------------------------------

/// 路径规范化后比较（去 `\\?\` 前缀、统一分隔符与大小写）。
fn path_equal(a: &Path, b: &Path) -> bool {
    fn norm(p: &Path) -> String {
        let s = p.to_string_lossy();
        let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
        s.replace('/', "\\").to_ascii_lowercase()
    }
    norm(a) == norm(b)
}

/// 从命令行提取 `--name` 的值（支持 `--name x` 与 `--name=x`）。
fn instance_marker(cmdline: &str) -> Option<String> {
    let tokens: Vec<&str> = cmdline.split_whitespace().collect();
    let mut i = 0;
    while i < tokens.len() {
        let token = tokens[i];
        if token == "--name" || token == "-name" {
            return tokens
                .get(i + 1)
                .map(|v| v.trim_matches('"').trim_matches('\'').to_owned());
        }
        if let Some(v) = token
            .strip_prefix("--name=")
            .or_else(|| token.strip_prefix("-name="))
        {
            return Some(v.trim_matches('"').trim_matches('\'').to_owned());
        }
        i += 1;
    }
    None
}

// ---------------------------------------------------------------------------
// Windows 进程查询
// ---------------------------------------------------------------------------

/// 进程查询结果
#[cfg(windows)]
struct ProcessInfo {
    /// 可执行文件全路径（权限不足时可能为空）
    exe: Option<String>,
    /// 命令行（权限不足时可能为空）
    cmdline: Option<String>,
}

/// 拿某 PID 的 `ExecutablePath` 与 `CommandLine`。
///
/// 用 PowerShell CIM（`wmic` 在新版 Windows 已被移除）。
/// 用哨兵标签分隔两个字段，避免命令行自身含换行时解析错位。
#[cfg(windows)]
fn query_process(pid: u32) -> Option<ProcessInfo> {
    const EXE_TAG: &str = "RNPC_EXE=";
    const CMD_TAG: &str = "RNPC_CMD=";
    let script = format!(
        "$p = Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\" -ErrorAction SilentlyContinue; \
         if ($p) {{ \"{EXE_TAG}\" + $p.ExecutablePath; \"{CMD_TAG}\" + $p.CommandLine }}"
    );
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut exe = None;
    let mut cmdline = None;
    let mut found = false;
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(v) = line.strip_prefix(EXE_TAG) {
            found = true;
            exe = (!v.trim().is_empty()).then(|| v.to_owned());
        } else if let Some(v) = line.strip_prefix(CMD_TAG) {
            found = true;
            cmdline = (!v.trim().is_empty()).then(|| v.to_owned());
        }
    }
    if !found {
        return None;
    }
    Some(ProcessInfo { exe, cmdline })
}

/// 用 `tasklist` 拿进程名；`None` 表示进程不存在（或无法枚举）。
#[cfg(windows)]
fn tasklist_image_name(pid: u32) -> Option<String> {
    let output = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    // CSV: "rnpc.exe","1234","Console","1","1,234 K"
    // 没有匹配项时是本地化的「信息: 没有运行的任务…」，没有引号，直接跳过。
    for line in text.lines() {
        let line = line.trim().trim_start_matches('\u{feff}');
        if !line.starts_with('"') {
            continue;
        }
        let first = line.split(',').next()?;
        return Some(first.trim_matches('"').to_ascii_lowercase());
    }
    None
}

/// 进程是否仍存在（只看 PID 存活，不校验归属）。
#[cfg(windows)]
fn process_alive(pid: u32) -> bool {
    tasklist_image_name(pid).is_some()
}

// ---------------------------------------------------------------------------
// 公开 API
// ---------------------------------------------------------------------------

/// 校验某 PID 是否属于指定实例。
///
/// Windows 实现：
/// 1. `tasklist /FI "PID eq <pid>" /FO CSV /NH` → 比对进程名与 `exe` 文件名；
/// 2. PowerShell CIM `Get-CimInstance Win32_Process -Filter "ProcessId=<pid>"` →
///    比对 `ExecutablePath` 与命令行含 `--name <name>`。
///
/// **拿不到命令行时保守返回 false**（不冒险认定归属）。
/// 非 Windows：始终返回 false。
pub fn pid_belongs_to(pid: u32, exe: &Path, name: &str) -> bool {
    #[cfg(not(windows))]
    {
        let _ = (pid, exe, name);
        false
    }

    #[cfg(windows)]
    {
        // 第一层：进程存在 + 进程名（快，且不依赖 PowerShell）
        let image = match tasklist_image_name(pid) {
            Some(i) => i,
            None => return false,
        };
        let exe_file = match exe.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_ascii_lowercase(),
            None => return false,
        };
        if image != exe_file {
            return false;
        }

        // 第二层：命令行确认实例标记
        let info = match query_process(pid) {
            Some(i) => i,
            None => return false,
        };
        let cmdline = match info.cmdline.as_deref() {
            Some(c) => c,
            None => return false,
        };
        instance_marker(cmdline).as_deref() == Some(name)
    }
}

/// 读取实例运行状态（会校验 PID 归属，并清理陈旧记录）。
///
/// 判定规则（Windows）：
/// - 无记录 / 记录损坏 / 进程已不存在 → [`RunState::Stopped`]，并删除记录。
/// - 进程实际 exe 文件名与记录不符 → 归属不符（典型：PID 被复用），删除记录并报 `Stopped`。
/// - 能拿到 `ExecutablePath` 且与记录 exe 不符 → 同上。
/// - 命令行明确指向**另一个**实例（`--name <other>`）→ 同上。
/// - 命令行含 `--name <name>` → [`RunState::Running`]。
/// - 命令行不可读，或不含任何 `--name` 标记 → [`RunState::Unknown`]（**不删记录**，
///   因为无法区分「正常运行但权限受限」与「PID 被复用」）。
///
/// 非 Windows：读到记录即返回 `Unknown { reason: "仅 Windows 实现…" }`，否则 `Stopped`。
pub fn state(root: &Path, name: &str) -> Result<RunState> {
    validate_instance_name(name)?;
    let path = InstancePaths::new(root, name).runtime_path();
    let Some(record) = read_runtime(&path) else {
        return Ok(RunState::Stopped);
    };

    #[cfg(not(windows))]
    {
        let _ = root;
        Ok(RunState::Unknown {
            pid: record.pid,
            reason: format!("{UNSUPPORTED_MSG}：无法校验 PID {} 的归属", record.pid),
        })
    }

    #[cfg(windows)]
    {
        // 1) 进程是否还在
        let image = match tasklist_image_name(record.pid) {
            Some(i) => i,
            None => {
                // 进程已退出：陈旧记录
                let _ = std::fs::remove_file(&path);
                return Ok(RunState::Stopped);
            }
        };

        // 2) 进程名 vs 记录里的 exe 文件名（无需 PowerShell，拦截绝大多数 PID 复用）
        let rec_exe = PathBuf::from(&record.exe);
        if let Some(rec_file) = rec_exe.file_name().and_then(|n| n.to_str()) {
            if !rec_file.is_empty() && rec_file.to_ascii_lowercase() != image {
                let _ = std::fs::remove_file(&path);
                return Ok(RunState::Stopped);
            }
        }

        // 3) 进一步拿全路径与命令行
        let info = match query_process(record.pid) {
            Some(i) => i,
            None => {
                return Ok(RunState::Unknown {
                    pid: record.pid,
                    reason: "无法查询进程信息（权限不足或进程已退出）".to_owned(),
                });
            }
        };

        // 3a) 全路径比对
        if let Some(actual) = info.exe.as_deref() {
            if !record.exe.is_empty() && !path_equal(Path::new(actual), &rec_exe) {
                let _ = std::fs::remove_file(&path);
                return Ok(RunState::Stopped);
            }
        }

        // 3b) 命令行实例标记
        let Some(cmdline) = info.cmdline.as_deref() else {
            return Ok(RunState::Unknown {
                pid: record.pid,
                reason: "无法读取进程命令行（权限不足？）".to_owned(),
            });
        };
        match instance_marker(cmdline) {
            Some(marker) if marker == name => Ok(RunState::Running { pid: record.pid }),
            Some(other) => {
                // 明确是另一个实例占用了该 PID → 陈旧记录
                let _ = std::fs::remove_file(&path);
                let _ = other;
                Ok(RunState::Stopped)
            }
            None => Ok(RunState::Unknown {
                pid: record.pid,
                reason: "命令行不含 --name 实例标记，无法确认归属".to_owned(),
            }),
        }
    }
}

/// 写入运行时记录（由被启动的进程自己调用，记录自己的 PID）。
///
/// 用 `create_new` 独占创建，避免两个进程同时写坏同一个 `runtime.json`。
/// 已存在时：
/// - 若属于**本进程 + 本实例**（同 PID 重复调用）→ 幂等成功；
/// - 否则删除陈旧记录后重建（重建仍用 `create_new`，失败则报错）。
pub fn record_self(root: &Path, name: &str) -> Result<()> {
    // 纯文件操作，跨平台都能做：`rnpc run --name` 在 Linux 上同样要能被 `list` 看到。
    {
        validate_instance_name(name)?;
        let path = InstancePaths::new(root, name).runtime_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("无法创建实例目录 {}", parent.display()))?;
        }

        let exe = std::env::current_exe().context("无法获取自身可执行文件路径")?;
        let record = RuntimeRecord {
            pid: std::process::id(),
            started_at: now_rfc3339(),
            exe: exe.display().to_string(),
            name: name.to_owned(),
        };
        let bytes = serde_json::to_vec_pretty(&record).context("序列化运行时记录失败")?;

        match write_new(&path, &bytes) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(e).with_context(|| format!("写运行时记录失败: {}", path.display()));
            }
        }

        // 已存在：本进程重复调用 → 幂等
        if let Some(existing) = read_runtime(&path) {
            if existing.pid == std::process::id() && existing.name == name {
                return Ok(());
            }
        }
        // 陈旧记录：清掉重建
        let _ = std::fs::remove_file(&path);
        write_new(&path, &bytes).with_context(|| format!("重建运行时记录失败: {}", path.display()))
    }
}

/// 用 `create_new` 独占创建并写入。
fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// 清除运行时记录（进程正常退出时调用）。
///
/// 只清除属于当前进程的那条记录，避免误删后继进程覆盖后的记录。
pub fn clear_self(root: &Path, name: &str) -> Result<()> {
    // 同 record_self：纯文件操作，跨平台一致。
    {
        validate_instance_name(name)?;
        let path = InstancePaths::new(root, name).runtime_path();
        let Some(record) = read_runtime(&path) else {
            return Ok(());
        };
        if record.pid != std::process::id() {
            return Ok(());
        }
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("删除运行时记录失败: {}", path.display())),
        }
    }
}

/// 安装目录下的 rnpc 可执行文件路径（自行拼路径，不依赖 `instance` 模块）。
#[cfg(windows)]
fn installed_exe_path(root: &Path) -> PathBuf {
    root.join("bin").join("rnpc.exe")
}

/// 启动实例（分离子进程，不阻塞），返回子进程 PID。
///
/// Windows 用 `CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP` 分离启动，父进程退出后子进程继续跑。
/// 子进程参数：`<exe> run --name <name>`。
/// 启动后轮询等待 runtime.json 出现**且**记录 PID 等于子进程 PID、记录 exe 一致（最多 15 秒）。
pub fn start(root: &Path, name: &str) -> Result<u32> {
    #[cfg(not(windows))]
    {
        let _ = (root, name);
        bail!("{UNSUPPORTED_MSG}")
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

        validate_instance_name(name)?;

        match state(root, name)? {
            RunState::Stopped => {}
            RunState::Running { pid } => bail!("实例 {name} 已在运行（PID {pid}）"),
            RunState::Unknown { pid, reason } => bail!(
                "实例 {name} 可能仍在运行（PID {pid}：{reason}）；请先 rnpc stop {name} 或手工确认该进程"
            ),
        }

        let exe = installed_exe_path(root);
        if !exe.is_file() {
            bail!("未找到可执行文件 {}；请先 rnpc install", exe.display());
        }

        // 守护进程**不能继承调用方的 stdio**：
        // 1) 继承 stdout 会让调用方的管道永不关闭，上层命令（如 `restart`）看起来"挂住"；
        // 2) 实例日志本来就该落在 `<root>\logs\<name>.log`（`rnpc logs` 读的就是它）。
        let log_path = InstancePaths::new(root, name).log_path();
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("无法创建日志目录 {}", parent.display()))?;
        }
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .with_context(|| format!("无法打开实例日志 {}", log_path.display()))?;
        let log_err = log
            .try_clone()
            .with_context(|| format!("无法复制日志句柄 {}", log_path.display()))?;

        let mut child = std::process::Command::new(&exe)
            .args(["run", "--name", name])
            // 让子进程认同一个数据根（否则它会按 LOCALAPPDATA 自行推断，导致
            // 记录写到别处、start 永远等不到 runtime.json）。
            .env("RNPC_DATA_DIR", root)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(log))
            .stderr(std::process::Stdio::from(log_err))
            .creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP)
            .spawn()
            .with_context(|| format!("启动 {} 失败", exe.display()))?;
        let pid = child.id();

        let path = InstancePaths::new(root, name).runtime_path();
        let deadline = SystemTime::now() + START_WAIT;
        loop {
            if let Some(record) = read_runtime(&path) {
                // 记录必须由我们刚启动的这个 PID 写入，且 exe 一致
                if record.pid == pid && path_equal(Path::new(&record.exe), &exe) {
                    drop(child); // 只关闭句柄，不终止进程
                    return Ok(pid);
                }
            }
            if SystemTime::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let _ = std::fs::remove_file(&path);
                bail!("启动实例 {name} 超时：15 秒内未检测到有效的运行时记录");
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }
}

/// 停止实例（先优雅终止，超时后强杀）。
///
/// 返回 `Ok(true)` 表示进程已结束，`Ok(false)` 表示本来就没在运行。
/// 状态为 [`RunState::Unknown`] 时**拒绝终止**并返回错误：PID 归属无法确认时，
/// 贸然 `taskkill` 有杀掉被复用 PID 的无关进程的风险。
///
/// **注意**：强杀（`taskkill /F`）会让实例来不及持久化流量统计，可能丢失这部分数据。
pub fn stop(root: &Path, name: &str, timeout: Duration) -> Result<bool> {
    #[cfg(not(windows))]
    {
        let _ = (root, name, timeout);
        bail!("{UNSUPPORTED_MSG}")
    }

    #[cfg(windows)]
    {
        let pid = match state(root, name)? {
            RunState::Stopped => return Ok(false),
            RunState::Running { pid } => pid,
            RunState::Unknown { pid, reason } => {
                bail!("拒绝终止 PID {pid}：无法确认归属（{reason}）")
            }
        };

        // 1) 请求优雅退出（不带 /F）
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string()])
            .output();

        let deadline = SystemTime::now() + timeout;
        while SystemTime::now() < deadline {
            if !process_alive(pid) {
                clear_record_if_pid(root, name, pid);
                return Ok(true);
            }
            std::thread::sleep(POLL_INTERVAL);
        }

        // 2) 超时强杀
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .output();
        clear_record_if_pid(root, name, pid);
        Ok(true)
    }
}

/// 仅当记录中的 PID 匹配时才删除（避免误删后继进程的记录）。
fn clear_record_if_pid(root: &Path, name: &str, pid: u32) {
    let path = InstancePaths::new(root, name).runtime_path();
    if let Some(record) = read_runtime(&path) {
        if record.pid == pid {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// 重启：先停止（若未运行则忽略）再启动，返回新 PID。
pub fn restart(root: &Path, name: &str, timeout: Duration) -> Result<u32> {
    stop(root, name, timeout)?;
    start(root, name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_path_is_isolated_per_name() {
        let root = PathBuf::from("/tmp/rnpc");
        let a = InstancePaths::new(&root, "web").runtime_path();
        let b = InstancePaths::new(&root, "db").runtime_path();
        assert_ne!(a, b);
        assert!(a.ends_with("runtime.json"));
        assert!(a.to_string_lossy().contains("web"));
    }

    #[test]
    fn names_with_path_traversal_are_rejected() {
        for bad in ["", "..", "a/b", "a\\b", "A", "all", "rnpc", ".", "-a", "a-"] {
            assert!(validate_instance_name(bad).is_err(), "{bad:?} 应被拒绝");
        }
        for ok in ["default", "web", "a", "a-b", "a_b", "abc123"] {
            validate_instance_name(ok).unwrap_or_else(|e| panic!("{ok} 应合法: {e}"));
        }
    }

    #[test]
    fn rfc3339_is_well_formed() {
        let s = now_rfc3339();
        assert_eq!(s.len(), 20, "{s}");
        assert!(s.ends_with('Z'), "{s}");
        assert_eq!(s.as_bytes()[4], b'-');
        assert_eq!(s.as_bytes()[7], b'-');
        assert_eq!(s.as_bytes()[10], b'T');
    }

    #[test]
    fn path_equal_normalizes_prefix_and_case() {
        let a = PathBuf::from(r"C:/Program Files/RNPC/rnpc.EXE");
        let b = PathBuf::from(r"c:\program files\rnpc\rnpc.exe");
        assert!(path_equal(&a, &b));
        assert!(!path_equal(&a, &PathBuf::from(r"c:\other\rnpc.exe")));
    }

    #[test]
    fn instance_marker_parses_both_forms() {
        assert_eq!(
            instance_marker(r#""C:\a\rnpc.exe" run --name web"#),
            Some("web".to_owned())
        );
        assert_eq!(
            instance_marker(r#""C:\a\rnpc.exe" run --name=db"#),
            Some("db".to_owned())
        );
        assert_eq!(instance_marker(r#""C:\a\rnpc.exe" run"#), None);
    }
}
