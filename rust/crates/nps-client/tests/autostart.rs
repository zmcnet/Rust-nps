//! 自启通道集成测试：**真实注册表** + **真实 schtasks / sc**。
//!
//! 开发机是非管理员，因此：
//! - `run-key` 走完整成功路径（注册 → `reg query` 校验 → 幂等重装 → 移除 → 确认删除）；
//! - `task-start` / `service` 只验证「无权限时给出明确错误」，成功路径未验证
//!   （见任务报告「未验证项」）。
//!
//! 所有测试用唯一实例名，并在 [`Cleanup`] 的 `Drop` 里清理，失败也不会留下残渣。

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nps_client::autostart::{self, Channel};

const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

/// 合法实例名（小写字母数字 + `-`，字母开头，≤32 字符）且每次唯一。
fn unique_name(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    format!("at-{}-{tag}-{nanos}", std::process::id())
}

/// 带空格的可执行文件路径：专门验证引号是否正确。
fn exe_with_spaces() -> PathBuf {
    PathBuf::from(r"C:\Program Files\Rust nps\rnpc.exe")
}

fn value_name(name: &str) -> String {
    format!("rnpc-{name}")
}

/// `reg query` 我们的值：返回 (是否存在, 原始输出)。
///
/// 通过 `cmd /c chcp 65001` 强制 UTF-8 输出，便于断言失败时看清本地化报文
/// （中文 Windows 上 `reg.exe` 默认输出 GBK）。
fn reg_query(name: &str) -> (bool, String) {
    // 路径与值名都不含空格，因此不需要（也不能）加引号：cmd.exe 不认 `\"`。
    let command = format!(
        "chcp 65001>nul & reg query {RUN_KEY} /v {}",
        value_name(name)
    );
    let output = Command::new("cmd")
        .args(["/c", &command])
        .output()
        .expect("无法执行 cmd.exe / reg.exe");
    let text = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);
    (output.status.success(), text)
}

/// 整个 Run 键里出现我们值名的行数（用于验证幂等：只能是 1）。
///
/// 并行测试会同时读写这个键，`reg query` 可能偶发拿到空输出；这里带重试，
/// 并在断言失败时带上原始输出便于定位。
fn count_value_lines(name: &str) -> (usize, String) {
    let needle = value_name(name);
    let mut last = String::new();
    for _ in 0..20 {
        let output = Command::new("reg")
            .args(["query", RUN_KEY])
            .output()
            .expect("无法执行 reg.exe");
        last = String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr);
        if !output.status.success() {
            std::thread::sleep(std::time::Duration::from_millis(25));
            continue;
        }
        let count = last
            .lines()
            .filter(|line| line.split_whitespace().next() == Some(needle.as_str()))
            .count();
        if count > 0 {
            return (count, last);
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    (0, last)
}

/// 直接在注册表里写一个「不是本程序创建」的值，用于验证拒绝删除。
fn reg_add_foreign(name: &str, data: &str) {
    let output = Command::new("reg")
        .args([
            "add",
            RUN_KEY,
            "/v",
            &value_name(name),
            "/t",
            "REG_SZ",
            "/d",
            data,
            "/f",
        ])
        .output()
        .expect("无法执行 reg.exe");
    assert!(
        output.status.success(),
        "reg add 失败: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// 独立探针：`net session` 只有管理员能跑成功。
fn net_session_admin() -> bool {
    Command::new("net")
        .arg("session")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// 测试残渣清理（panic 也会执行）。
struct Cleanup {
    name: String,
}

impl Cleanup {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
        }
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for channel in Channel::all() {
            let _ = autostart::remove(channel, &self.name);
        }
        // 兜底：即使上面因「不是本程序创建」拒绝删除，也把值清掉。
        let _ = Command::new("reg")
            .args(["delete", RUN_KEY, "/v", &value_name(&self.name), "/f"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

// ---------------------------------------------------------------------------
// run-key：完整成功路径
// ---------------------------------------------------------------------------

#[test]
fn run_key_install_status_remove_roundtrip() {
    let name = unique_name("rk1");
    let _guard = Cleanup::new(&name);
    let exe = exe_with_spaces();

    // 1. 安装前：不存在
    let (exists_before, raw_before) = reg_query(&name);
    eprintln!("[before] reg query -> exists={exists_before}, output={raw_before:?}");
    assert!(!exists_before, "测试开始前不应已存在同名自启项");
    let before = autostart::status(Channel::RunKey, &name).unwrap();
    assert!(!before.installed);
    assert_eq!(before.command, None);

    // 2. 注册（run-key 不需要管理员）
    autostart::install(Channel::RunKey, &name, &exe).expect("run-key 安装应成功");

    // 3. 用 reg query 独立确认（不经过本程序代码）
    let (exists_after, raw_after) = reg_query(&name);
    eprintln!("[after]  reg query -> exists={exists_after}, output={raw_after:?}");
    assert!(exists_after, "reg query 应能查到 rnpc-{name}");
    assert!(
        raw_after.contains(r#""C:\Program Files\Rust nps\rnpc.exe" run --name"#),
        "值必须是带引号的绝对路径 + run --name：{raw_after}"
    );
    assert!(raw_after.contains(&format!("--name {name}")));
    assert!(
        !raw_after.contains("vkey"),
        "自启项不得包含 vkey：{raw_after}"
    );

    // 4. 幂等重装：不产生重复项
    autostart::install(Channel::RunKey, &name, &exe).expect("重复安装应成功");
    let (rows, raw_rows) = count_value_lines(&name);
    assert_eq!(
        rows, 1,
        "重复安装后 Run 键应只有一项，实际 {rows} 项；reg query 输出：{raw_rows:?}"
    );

    // 5. 状态查询
    let status = autostart::status(Channel::RunKey, &name).unwrap();
    eprintln!(
        "[status] installed={}, command={:?}",
        status.installed, status.command
    );
    assert!(status.installed);
    let command = status.command.expect("应有注册的命令行");
    assert_eq!(command, format!(r#""{}" run --name {name}"#, exe.display()));

    // 6. 移除 → 确认删除
    assert!(autostart::remove(Channel::RunKey, &name).unwrap());
    let (exists_gone, raw_gone) = reg_query(&name);
    eprintln!("[removed] reg query -> exists={exists_gone}, output={raw_gone:?}");
    assert!(!exists_gone, "移除后 reg query 应失败");
    assert!(!autostart::status(Channel::RunKey, &name).unwrap().installed);

    // 7. 再删一次：本来就不存在 → false
    assert!(!autostart::remove(Channel::RunKey, &name).unwrap());
}

#[test]
fn remove_refuses_value_not_created_by_us() {
    let name = unique_name("rk2");
    let _guard = Cleanup::new(&name);

    // 同名的值，但内容与 rnpc / 实例名无关
    reg_add_foreign(&name, r"C:\Windows\System32\notepad.exe");

    let error = autostart::remove(Channel::RunKey, &name)
        .expect_err("不是本程序创建的值必须拒绝删除")
        .to_string();
    eprintln!("[拒绝删除] {error}");
    assert!(
        error.contains("拒绝删除"),
        "错误信息应说明拒绝原因：{error}"
    );

    // 值必须还在（没被误删）
    assert!(reg_query(&name).0, "拒绝删除后值应原样保留");

    // 状态如实报告：值在，但不是我们注册的
    let status = autostart::status(Channel::RunKey, &name).unwrap();
    assert!(!status.installed);
    assert!(status
        .command
        .as_deref()
        .unwrap_or_default()
        .contains("notepad.exe"));
}

#[test]
fn install_rejects_relative_executable_path() {
    let name = unique_name("rel");
    let _guard = Cleanup::new(&name);
    let error = autostart::install(Channel::RunKey, &name, Path::new("rnpc.exe"))
        .expect_err("相对路径必须被拒绝")
        .to_string();
    eprintln!("[相对路径] {error}");
    assert!(
        error.contains("绝对路径"),
        "错误信息应说明要求绝对路径：{error}"
    );
}

// ---------------------------------------------------------------------------
// 提权检测
// ---------------------------------------------------------------------------

#[test]
fn is_elevated_matches_independent_probe() {
    // 检测方式：OpenProcessToken + GetTokenInformation(TokenElevation)，
    // 失败时回退 net session。这里用 net session 作为独立探针交叉验证。
    let probe = net_session_admin();
    let detected = autostart::is_elevated();
    eprintln!("[is_elevated] detected={detected}, net_session_probe={probe}");

    assert_eq!(
        detected, probe,
        "令牌检测与 net session 探针结论不一致（{detected} vs {probe}）"
    );
    if !probe {
        // 开发机是非管理员：必须真的检测为 false，不能是常量 true。
        assert!(!detected, "非管理员机器上 is_elevated() 必须返回 false");
    }
}

// ---------------------------------------------------------------------------
// task-* / service：非管理员时的错误路径
// ---------------------------------------------------------------------------

#[test]
fn admin_channels_report_permission_error_when_not_elevated() {
    if autostart::is_elevated() {
        eprintln!("当前进程已是管理员，跳过非管理员错误路径验证（成功路径未在本机验证）");
        return;
    }
    let name = unique_name("adm");
    let _guard = Cleanup::new(&name);
    let exe = exe_with_spaces();

    // service / task-start 是硬性需要管理员的通道：必须在动手之前就明确报错。
    for channel in [Channel::TaskStart, Channel::Service] {
        let error = autostart::install(channel, &name, &exe)
            .expect_err("非管理员安装需要管理员的通道必须失败")
            .to_string();
        eprintln!("[{channel}] install 错误：{error}");
        assert!(
            error.contains("管理员"),
            "错误信息必须说清楚需要管理员权限：{error}"
        );
        assert!(
            !autostart::status(channel, &name).unwrap().installed,
            "失败后不应留下任何自启项（{channel}）"
        );
    }

    // task-logon 是「视策略」：不前置拦截，交给系统裁决。
    // 被拒时错误必须点明管理员权限，且不能是命令行引号构造错误。
    match autostart::install(Channel::TaskLogon, &name, &exe) {
        Ok(()) => {
            eprintln!("[task-logon] 当前策略允许非管理员创建登录任务（已清理）");
            let _ = autostart::remove(Channel::TaskLogon, &name);
        }
        Err(error) => {
            let error = error.to_string();
            eprintln!("[task-logon] install 错误：{error}");
            assert!(
                error.contains("管理员"),
                "错误信息必须说清楚需要管理员权限：{error}"
            );
            assert!(
                !error.contains("无效参数") && !error.contains("Invalid argument"),
                "/tr 命令行引号构造有误（schtasks 拒绝了解析）：{error}"
            );
            assert!(
                !autostart::status(Channel::TaskLogon, &name)
                    .unwrap()
                    .installed
            );
        }
    }
}

#[test]
fn status_of_unknown_instance_is_not_an_error() {
    let name = unique_name("none");
    for channel in Channel::all() {
        let status = autostart::status(channel, &name)
            .unwrap_or_else(|e| panic!("{channel} 查询未安装的实例不应报错: {e}"));
        assert!(!status.installed, "{channel} 应报告未安装");
        assert_eq!(status.command, None);
    }
}

// ---------------------------------------------------------------------------
// task-* 的引号构造：用非管理员可建的 `once` 任务做真实验证
// ---------------------------------------------------------------------------

/// `/sc onstart` / `onlogon` 需要管理员，本机无法验证成功路径。
///
/// 但「`/tr` 的引号能否穿过 Rust 的 `Command` 参数转义并被 schtasks 正确
/// 拆成 `<Command>` + `<Arguments>`」是**同一套代码路径**。这里用非管理员
/// 可以创建的 `/sc once` 任务复现完全相同的 `/tr` 取值，真实验证引号构造。
#[test]
fn task_tr_quoting_survives_schtasks() {
    let name = unique_name("tr");
    let task = value_name(&name);
    let exe = exe_with_spaces();
    // 与 autostart::run_command 的输出保持一致（单测已锁定该格式）
    let command = format!(r#""{}" run --name {name}"#, exe.display());

    let cleanup = TaskCleanup { task: task.clone() };

    let created = Command::new("schtasks")
        .args([
            "/create", "/tn", &task, "/tr", &command,
            // `onstart` / `onlogon` 需要管理员；`monthly /d 1` 是普通用户可建、
            // 且不需要本地化日期的等价触发器，用来验证同一套 /tr 构造。
            "/sc", "monthly", "/d", "1", "/st", "23:59", "/f",
        ])
        .output()
        .expect("无法执行 schtasks.exe");
    let created_text = String::from_utf8_lossy(&created.stdout).into_owned()
        + &String::from_utf8_lossy(&created.stderr);
    eprintln!(
        "[create once] status={:?}, output={created_text:?}",
        created.status
    );
    assert!(
        created.status.success(),
        "用与 task 通道相同的 /tr 构造创建 once 任务失败（引号构造有问题）：{created_text}"
    );

    // 回读 XML，确认路径带引号、参数分开存放
    let queried = Command::new("schtasks")
        .args(["/query", "/tn", &task, "/xml", "ONE"])
        .output()
        .expect("无法执行 schtasks.exe");
    assert!(queried.status.success());
    let xml = decode_oem(&queried.stdout);
    eprintln!("[xml] {xml}");
    assert!(
        xml.contains(&format!("<Command>\"{}\"</Command>", exe.display())),
        "schtasks 应把带引号的绝对路径整体存进 <Command>：{xml}"
    );
    assert!(
        xml.contains(&format!("<Arguments>run --name {name}</Arguments>")),
        "参数应独立存进 <Arguments>：{xml}"
    );
    assert!(!xml.contains("vkey"));

    drop(cleanup);
    assert!(
        !Command::new("schtasks")
            .args(["/query", "/tn", &task, "/fo", "list"])
            .output()
            .expect("无法执行 schtasks.exe")
            .status
            .success(),
        "清理后任务应已删除"
    );
}

/// 把控制台 OEM 输出转成可读文本（中文系统是 GBK）。
fn decode_oem(bytes: &[u8]) -> String {
    let path = std::env::temp_dir().join(format!("rnpc-oem-{}.bin", std::process::id()));
    if std::fs::write(&path, bytes).is_ok() {
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "[Console]::OutputEncoding=[Text.Encoding]::GetEncoding(936);\
                     [IO.File]::ReadAllText('{}',[Text.Encoding]::GetEncoding(936))",
                    path.display()
                ),
            ])
            .output();
        let _ = std::fs::remove_file(&path);
        if let Ok(output) = output {
            if output.status.success() {
                return String::from_utf8_lossy(&output.stdout).into_owned();
            }
        }
    }
    String::from_utf8_lossy(bytes).into_owned()
}

struct TaskCleanup {
    task: String,
}

impl Drop for TaskCleanup {
    fn drop(&mut self) {
        let _ = Command::new("schtasks")
            .args(["/delete", "/tn", &self.task, "/f"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}
