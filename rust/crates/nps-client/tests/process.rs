//! 进程发现 / start / stop 的集成测试（**真实调用 tasklist / PowerShell / taskkill**）。
//!
//! 覆盖任务要求的 6 项：
//! 1. 不存在的实例 → `Stopped`；
//! 2. 记录存在但 exe 路径错误（PID 用当前进程）→ 判陈旧、清理、`Stopped`；
//! 3. 记录用当前测试进程 PID 且 exe 正确 → `Running` 或 `Unknown`（本文件断言实际行为）；
//! 4. 两个线程并发写 runtime.json → 至少一个成功且文件可解析；
//! 5. `stop()` 对不存在的实例 → `Ok(false)` 且不 panic；
//! 6. `create_new` 的独占语义（第二次创建必须失败）。
//!
//! 额外：用 `cmd.exe` 起一个命令行含 `--name <name>` 的牺牲进程，验证
//! 「归属校验通过 → Running」以及 `stop()` 的真实终止路径。
//!
//! 每个测试用独立的临时根目录 + 唯一实例名，互不干扰。

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use nps_client::process::{self, RunState, RuntimeRecord};

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

/// 每次唯一的临时根目录。
fn temp_root(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "rnpc-proc-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn runtime_path(root: &Path, name: &str) -> PathBuf {
    root.join("instances").join(name).join("runtime.json")
}

/// 手写一条运行时记录（模拟别的进程留下的 / 陈旧的记录）。
fn write_record(root: &Path, name: &str, pid: u32, exe: &Path) {
    let path = runtime_path(root, name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let record = RuntimeRecord {
        pid,
        started_at: "2026-11-20T00:00:00Z".to_owned(),
        exe: exe.display().to_string(),
        name: name.to_owned(),
    };
    let bytes = serde_json::to_vec_pretty(&record).unwrap();
    std::fs::write(&path, bytes).unwrap();
}

/// 进程是否还存在（用 tasklist，与实现同源）。
fn alive(pid: u32) -> bool {
    let out = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .output()
        .expect("tasklist 应可执行");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .any(|line| line.trim_start().starts_with('"'))
}

/// 牺牲进程：命令行里带 `--name <name>`，用于真实的正向归属校验。
/// `Drop` 时强杀，测试失败也不会留残渣。
struct Sacrifice {
    pid: u32,
}

impl Drop for Sacrifice {
    fn drop(&mut self) {
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &self.pid.to_string(), "/F"])
            .output();
    }
}

/// 启动一个 `cmd.exe` 牺牲进程（`ping` 让它在约 20 秒内保持存活），
/// 命令行里刻意带上 `--name <name>`，使归属校验能识别为「本实例」。
fn spawn_sacrifice(name: &str) -> (Sacrifice, PathBuf) {
    let comspec = std::env::var("ComSpec").unwrap_or_else(|_| {
        r"C:\Windows\System32\cmd.exe".to_owned()
    });
    let child = std::process::Command::new(&comspec)
        .args([
            "/c",
            &format!("ping -n 20 127.0.0.1 >nul 2>nul & rem --name {name}"),
        ])
        .spawn()
        .expect("无法启动 cmd.exe 牺牲进程");
    let pid = child.id();
    std::mem::forget(child); // 让进程继续跑；由 Sacrifice::Drop 负责清理
    (Sacrifice { pid }, PathBuf::from(comspec))
}

// ---------------------------------------------------------------------------
// 1. 不存在的实例 → Stopped
// ---------------------------------------------------------------------------

#[test]
fn missing_instance_is_stopped() {
    let root = temp_root("missing");
    let st = process::state(&root, "default").unwrap();
    assert_eq!(st, RunState::Stopped, "不存在的实例应为 Stopped");
    assert!(
        !runtime_path(&root, "default").exists(),
        "不应凭空创建 runtime.json"
    );
    std::fs::remove_dir_all(&root).ok();
}

// ---------------------------------------------------------------------------
// 2. 陈旧记录（当前 PID + 错误 exe）→ Stopped 且清理
// ---------------------------------------------------------------------------

#[test]
fn stale_record_with_wrong_exe_is_stopped_and_cleaned() {
    let root = temp_root("stale");
    let bogus_exe = PathBuf::from(r"C:\definitely-not\rnpc-elsewhere\rnpc.exe");
    write_record(&root, "default", std::process::id(), &bogus_exe);
    assert!(runtime_path(&root, "default").exists());

    let st = process::state(&root, "default").unwrap();
    assert_eq!(
        st,
        RunState::Stopped,
        "exe 路径不符应判为陈旧（PID 走的是当前测试进程）"
    );
    assert!(
        !runtime_path(&root, "default").exists(),
        "陈旧记录应被删除"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn corrupt_record_is_treated_as_stale() {
    let root = temp_root("corrupt");
    let path = runtime_path(&root, "default");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"{ this is not json").unwrap();

    assert_eq!(process::state(&root, "default").unwrap(), RunState::Stopped);
    assert!(!path.exists(), "损坏记录应被删除，避免永远读不到状态");
    std::fs::remove_dir_all(&root).ok();
}

// ---------------------------------------------------------------------------
// 3. 当前测试进程 PID + 正确 exe → Running 或 Unknown（断言实际行为）
// ---------------------------------------------------------------------------

#[test]
fn current_process_record_is_running_or_unknown() {
    let root = temp_root("self");
    let my_exe = std::env::current_exe().unwrap();
    let pid = std::process::id();
    // 注意：测试进程自己的命令行里没有 `--name default`，
    // 因此归属校验只能确认到 exe 一致，最终应为 Unknown（无法确认实例）。
    write_record(&root, "default", pid, &my_exe);

    let st = process::state(&root, "default").unwrap();
    println!("[实际行为] state(当前测试进程 PID, exe 正确) = {st:?}");

    match &st {
        RunState::Running { pid: p } => {
            assert_eq!(*p, pid);
            println!("[实际行为] 判为 Running：测试进程命令行恰好含实例标记");
        }
        RunState::Unknown { pid: p, reason } => {
            assert_eq!(*p, pid);
            assert!(!reason.is_empty(), "Unknown 必须带原因");
            println!("[实际行为] 判为 Unknown，原因：{reason}");
        }
        RunState::Stopped => {
            panic!("exe 一致的活进程不应被判为 Stopped（记录已被误删？）");
        }
    }
    // 无论 Running 还是 Unknown，都不能删掉记录
    assert!(
        runtime_path(&root, "default").exists(),
        "无法确认归属时不得删除记录"
    );
    std::fs::remove_dir_all(&root).ok();
}

/// 正向确认：命令行真的带 `--name <name>` 时必须判为 `Running`。
#[test]
fn process_with_matching_marker_is_running() {
    let root = temp_root("marker");
    let name = "probe";
    let (sacrifice, exe) = spawn_sacrifice(name);
    // 记录里的 PID 是牺牲进程，exe 是它自己的真实路径
    write_record(&root, name, sacrifice.pid, &exe);

    let st = process::state(&root, name).unwrap();
    assert_eq!(
        st,
        RunState::Running { pid: sacrifice.pid },
        "命令行含 --name {name} 且 exe 匹配时应判为 Running"
    );
    assert!(
        process::pid_belongs_to(sacrifice.pid, &exe, name),
        "pid_belongs_to 应确认归属"
    );
    // 名字不同则不应认领
    assert!(
        !process::pid_belongs_to(sacrifice.pid, &exe, "other"),
        "实例名不匹配时不应确认归属"
    );
    std::fs::remove_dir_all(&root).ok();
}

// ---------------------------------------------------------------------------
// 4. 并发写 runtime.json 不应损坏
// ---------------------------------------------------------------------------

#[test]
fn concurrent_record_self_keeps_file_parseable() {
    let root = temp_root("concurrent");
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let root = root.clone();
            std::thread::spawn(move || process::record_self(&root, "default"))
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let ok_count = results.iter().filter(|r| r.is_ok()).count();
    assert!(ok_count >= 1, "至少一个线程应成功: {results:?}");

    let path = runtime_path(&root, "default");
    let bytes = std::fs::read(&path).expect("runtime.json 应存在");
    let record: RuntimeRecord =
        serde_json::from_slice(&bytes).expect("并发写后文件必须是合法 JSON");
    assert_eq!(record.pid, std::process::id(), "记录应是本进程的 PID");
    assert_eq!(record.name, "default");

    process::clear_self(&root, "default").unwrap();
    assert!(!path.exists(), "clear_self 应删除记录");
    std::fs::remove_dir_all(&root).ok();
}

/// `record_self` 对陈旧记录应能替换，而不是永久卡住。
#[test]
fn record_self_replaces_stale_record() {
    let root = temp_root("replace");
    // 伪造一条别人的陈旧记录
    write_record(&root, "default", 0xFFFF_FFF0, Path::new(r"C:\old\rnpc.exe"));

    process::record_self(&root, "default").expect("应能替换陈旧记录");
    let bytes = std::fs::read(runtime_path(&root, "default")).unwrap();
    let record: RuntimeRecord = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(record.pid, std::process::id());
    assert_eq!(record.name, "default");

    process::clear_self(&root, "default").unwrap();
    std::fs::remove_dir_all(&root).ok();
}

// ---------------------------------------------------------------------------
// 5. stop() 对不存在的实例 → Ok(false)，不 panic
// ---------------------------------------------------------------------------

#[test]
fn stop_missing_instance_is_false() {
    let root = temp_root("stop-missing");
    let stopped = process::stop(&root, "default", Duration::from_millis(300))
        .expect("stop 不应返回错误");
    assert!(!stopped, "本来就没在运行，应返回 false");
    std::fs::remove_dir_all(&root).ok();
}

/// 真实终止路径：命令行带 `--name` 的牺牲进程应被 stop() 杀掉。
#[test]
fn stop_terminates_verified_process() {
    let root = temp_root("stop-real");
    let name = "victim";
    let (sacrifice, exe) = spawn_sacrifice(name);
    let pid = sacrifice.pid;
    write_record(&root, name, pid, &exe);
    assert!(alive(pid), "牺牲进程应已启动");

    let stopped = process::stop(&root, name, Duration::from_millis(500))
        .expect("stop 应成功");
    assert!(stopped, "应报告确实停止了进程");

    // 强杀是异步生效的，给它一点时间
    let mut gone = false;
    for _ in 0..30 {
        if !alive(pid) {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(gone, "stop 之后进程应已退出");
    std::fs::remove_dir_all(&root).ok();
}

/// 归属无法确认（命令行无 `--name`）时必须拒绝终止，避免误杀复用 PID 的进程。
#[test]
fn stop_refuses_unverified_pid() {
    let root = temp_root("stop-refuse");
    let my_exe = std::env::current_exe().unwrap();
    // 当前测试进程：exe 正确但命令行没有 --name probe
    write_record(&root, "probe", std::process::id(), &my_exe);

    let st = process::state(&root, "probe").unwrap();
    if matches!(st, RunState::Unknown { .. }) {
        let err = process::stop(&root, "probe", Duration::from_millis(200))
            .expect_err("Unknown 状态下必须拒绝终止");
        let msg = format!("{err:#}");
        assert!(msg.contains("拒绝终止"), "错误信息应说明拒绝原因: {msg}");
        assert!(alive(std::process::id()), "测试进程自己不能被误杀");
    } else {
        println!("[跳过] 当前测试进程命令行被识别为实例 probe：{st:?}");
    }
    std::fs::remove_dir_all(&root).ok();
}

// ---------------------------------------------------------------------------
// 6. create_new 独占语义
// ---------------------------------------------------------------------------

#[test]
fn create_new_is_exclusive() {
    let root = temp_root("exclusive");
    let path = root.join("probe.lock");
    std::fs::create_dir_all(&root).unwrap();

    // 第一次独占创建成功
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("首次 create_new 应成功");
    // 第二次必须失败（这正是 record_self 避免并发写坏文件的机制）
    let err = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .expect_err("重复 create_new 必须失败");
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);

    // record_self 写完的记录同样受独占保护
    process::record_self(&root, "default").unwrap();
    let rec_path = runtime_path(&root, "default");
    let err = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&rec_path)
        .expect_err("runtime.json 已存在，重复独占创建必须失败");
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);

    process::clear_self(&root, "default").unwrap();
    std::fs::remove_dir_all(&root).ok();
}

// ---------------------------------------------------------------------------
// 启动前置条件（不真实启动：本机没有 install 过的实例）
// ---------------------------------------------------------------------------

#[test]
fn start_without_installed_binary_reports_actionable_error() {
    let root = temp_root("start-noinstall");
    let err = process::start(&root, "default").expect_err("未安装时应报错");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("rnpc install"),
        "错误信息应提示先 install: {msg}"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn invalid_instance_name_is_rejected() {
    let root = temp_root("badname");
    for bad in ["", "..", "a/b", "a\\b", "ALL", "all"] {
        assert!(
            process::state(&root, bad).is_err(),
            "{bad:?} 应被拒绝（防路径穿越）"
        );
    }
    std::fs::remove_dir_all(&root).ok();
}
