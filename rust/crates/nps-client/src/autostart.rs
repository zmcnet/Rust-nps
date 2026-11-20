//! Windows 自启通道：`service` / `task-start` / `task-logon` / `run-key`。
//!
//! 对应 `docs/rnpc-cli-spec.md` 的「自启通道」一节。本模块只负责
//! **注册 / 移除 / 查询** 这四个通道，与 CLI、连接逻辑完全解耦。
//!
//! # 通道能力
//!
//! | 通道 | 需要管理员 | 触发时机 |
//! | --- | --- | --- |
//! | [`Channel::Service`] | 是 | 开机即启，无需登录 |
//! | [`Channel::TaskStart`] | 是 | 开机即启 |
//! | [`Channel::TaskLogon`] | 视策略（本机实测普通用户被拒） | 用户登录 |
//! | [`Channel::RunKey`] | 否 | 用户登录 |
//!
//! # 实现方式（刻意保持轻量）
//!
//! - `run-key`：直接 `advapi32` 注册表 API（手写 FFI，见下方 `win` 模块），
//!   不引入 `winreg`。写入 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`。
//! - `task-start` / `task-logon`：调用 `schtasks.exe`（不引入 Task Scheduler COM）。
//!   查询走 `schtasks /query /xml`：XML 标签名不随系统语言变化，`/fo list`
//!   的字段名会随系统语言本地化，无法可靠解析。
//! - `service`：用 `windows-service` crate 的 typed API（`CreateServiceW` /
//!   `ChangeServiceConfigW` / `DeleteService`），拿到 Win32 错误码而不是
//!   解析 `sc.exe` 的本地化文本。
//! - 提权检测：`OpenProcessToken` + `GetTokenInformation(TokenElevation)`，
//!   失败时回退到 `net session`（慢但可靠）。
//!
//! # 安全约束
//!
//! 1. 自启项命令行**只含** `run --name <name>`，绝不写入 vkey（vkey 在配置文件里）。
//! 2. 可执行文件路径一律用双引号包裹绝对路径，避免空格导致自启解析错位。
//! 3. [`remove`] 删除前校验目标确实由本程序创建（内容包含 `rnpc` 且 `--name` 匹配），
//!    不匹配则拒绝删除并报错，绝不批量清理。

#![cfg_attr(not(windows), allow(dead_code))]

use std::path::Path;

use anyhow::{bail, Result};

/// 一个自启通道。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// Windows 服务，开机即启，无需登录
    Service,
    /// 计划任务 `/sc onstart`，开机即启
    TaskStart,
    /// 计划任务 `/sc onlogon`，用户登录后启动
    TaskLogon,
    /// 注册表 `HKCU\...\CurrentVersion\Run`，用户登录后启动
    RunKey,
}

impl Channel {
    /// 是否需要管理员权限。
    ///
    /// `task-logon` 按规格是「视策略」：默认策略下普通用户建登录触发任务会被
    /// 系统拒绝，但组策略可能放开。因此这里返回 `false`（不做前置拦截），
    /// 由真实调用结果决定——被拒时错误信息会明确提示需要管理员权限。
    pub fn needs_admin(self) -> bool {
        match self {
            Channel::Service | Channel::TaskStart => true,
            Channel::TaskLogon | Channel::RunKey => false,
        }
    }

    /// 触发时机的人类可读描述（用于安装后的提示）。
    pub fn trigger_desc(self) -> &'static str {
        match self {
            Channel::Service => "开机即启（无需用户登录）",
            Channel::TaskStart => "开机即启",
            Channel::TaskLogon => "用户登录后启动",
            Channel::RunKey => "用户登录后启动（开机即启需要管理员权限）",
        }
    }

    /// 序列化名：`service` / `task-start` / `task-logon` / `run-key`。
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Service => "service",
            Channel::TaskStart => "task-start",
            Channel::TaskLogon => "task-logon",
            Channel::RunKey => "run-key",
        }
    }

    /// 由序列化名解析。`auto` / `none` 不是通道，返回 `None`。
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "service" => Some(Channel::Service),
            "task-start" => Some(Channel::TaskStart),
            "task-logon" => Some(Channel::TaskLogon),
            "run-key" => Some(Channel::RunKey),
            _ => None,
        }
    }

    /// 全部通道（按优先级从强到弱）。
    pub fn all() -> [Channel; 4] {
        [
            Channel::Service,
            Channel::TaskStart,
            Channel::TaskLogon,
            Channel::RunKey,
        ]
    }
}

impl std::fmt::Display for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 通道操作结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelStatus {
    /// 查询的通道
    pub channel: Channel,
    /// 是否已由本程序注册
    pub installed: bool,
    /// 实际注册的命令行（用于诊断；**不含 vkey**）
    pub command: Option<String>,
}

/// 当前进程是否以管理员身份运行。
///
/// Windows 上通过进程令牌的 `TokenElevation` 判断（真正的权限检查，
/// 而不是看用户名或组成员）；令牌查询失败时回退到 `net session`。
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        if let Some(elevated) = win::token_is_elevated() {
            return elevated;
        }
        win::net_session_is_elevated()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// 按权限自动选择通道（规格里的 `auto` 策略首选通道）。
///
/// 管理员 → [`Channel::Service`]；否则 → [`Channel::RunKey`]。
///
/// 规格中的「服务安装失败则降级 task-start，再降级 run-key」是**安装期**行为，
/// 由调用方在 `install` 失败后依次尝试 [`Channel::TaskStart`]、[`Channel::RunKey`]。
pub fn pick_auto() -> Channel {
    if is_elevated() {
        Channel::Service
    } else {
        Channel::RunKey
    }
}

/// 注册自启（幂等：重复调用不产生重复项）。
///
/// `name` 必须是合法实例名（见 [`crate::instance::validate_instance_name`]）；
/// `exe` 必须是绝对路径（自启时工作目录不可控，相对路径会失效）。
pub fn install(channel: Channel, name: &str, exe: &Path) -> Result<()> {
    let name = validate(name)?;
    let exe = absolute_exe(exe)?;
    ensure_elevated(channel)?;

    #[cfg(windows)]
    {
        match channel {
            Channel::RunKey => win::run_key_install(name, &exe),
            Channel::TaskStart | Channel::TaskLogon => win::task_install(channel, name, &exe),
            Channel::Service => win::service_install(name, &exe),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (name, exe);
        bail!("自启通道仅在 Windows 上可用（当前平台不支持 {}）", channel)
    }
}

/// 移除自启。返回 `true` 表示确实删掉了一项，`false` 表示本来就不存在。
///
/// 只删自己写的那一项：目标内容必须包含 `rnpc` 且实例名匹配，否则拒绝删除并报错。
pub fn remove(channel: Channel, name: &str) -> Result<bool> {
    let name = validate(name)?;
    ensure_elevated(channel)?;

    #[cfg(windows)]
    {
        match channel {
            Channel::RunKey => win::run_key_remove(name),
            Channel::TaskStart | Channel::TaskLogon => win::task_remove(channel, name),
            Channel::Service => win::service_remove(name),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        bail!("自启通道仅在 Windows 上可用（当前平台不支持 {}）", channel)
    }
}

/// 查询通道状态。
pub fn status(channel: Channel, name: &str) -> Result<ChannelStatus> {
    let name = validate(name)?;

    #[cfg(windows)]
    {
        match channel {
            Channel::RunKey => win::run_key_status(name),
            Channel::TaskStart | Channel::TaskLogon => win::task_status(channel, name),
            Channel::Service => win::service_status(name),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        Ok(ChannelStatus {
            channel,
            installed: false,
            command: None,
        })
    }
}

// ---------------------------------------------------------------------------
// 与平台无关的构造 / 校验逻辑（可单测）
// ---------------------------------------------------------------------------

/// 注册表值名 / 计划任务名 / 服务名统一前缀。
pub const ITEM_PREFIX: &str = "rnpc-";

/// 服务名安全上限（Windows 限制 256，这里留足余量）。
const MAX_SERVICE_NAME_LEN: usize = 128;

/// 校验实例名，返回原名。
fn validate(name: &str) -> Result<&str> {
    crate::instance::validate_instance_name(name)?;
    Ok(name)
}

/// 校验可执行文件路径：必须绝对、不含双引号，并去掉末尾多余分隔符。
fn absolute_exe(exe: &Path) -> Result<String> {
    if !exe.is_absolute() {
        bail!(
            "可执行文件路径必须是绝对路径（自启时工作目录不可控）：{}",
            exe.display()
        );
    }
    let mut s = exe.to_string_lossy().into_owned();
    if s.contains('"') {
        bail!("可执行文件路径包含双引号，无法安全注册：{s}");
    }
    // 末尾反斜杠会转义掉收尾引号（`"C:\dir\"`），去掉它（保留盘根 `C:\`）。
    while s.len() > 3 && (s.ends_with('\\') || s.ends_with('/')) {
        s.pop();
    }
    Ok(s)
}

/// 给路径加引号。含空格的路径必须加引号，否则自启后无法启动。
fn quote_path(path: &str) -> String {
    format!("\"{path}\"")
}

/// `run` 子命令的参数部分（**只有** 实例名，绝不包含 vkey）。
fn run_args(name: &str) -> String {
    format!("run --name {name}")
}

/// 注册到自启项里的完整命令行：`"<绝对路径>" run --name <name>`。
fn run_command(exe: &str, name: &str) -> String {
    format!("{} {}", quote_path(exe), run_args(name))
}

/// 服务通道的命令行：`"<绝对路径>" service-host --name <name>`。
///
/// `service-host` 是仅供 SCM 调用的内部子命令（见规格「服务通道实现要点」）。
fn service_command(exe: &str, name: &str) -> String {
    format!("{} service-host --name {name}", quote_path(exe))
}

/// 注册表值名 / 计划任务名。
fn item_name(name: &str) -> String {
    format!("{ITEM_PREFIX}{name}")
}

/// 服务名：`rnpc-<name>`，超长时截断并追加 8 位哈希保持唯一。
fn service_name(name: &str) -> String {
    let full = item_name(name);
    if full.len() <= MAX_SERVICE_NAME_LEN {
        return full;
    }
    let hash = fnv1a_32(full.as_bytes());
    let keep = MAX_SERVICE_NAME_LEN - 9; // "-" + 8 位十六进制
    let mut truncated = String::with_capacity(MAX_SERVICE_NAME_LEN);
    truncated.extend(full.chars().take(keep));
    truncated.push_str(&format!("-{hash:08x}"));
    truncated
}

/// FNV-1a 32 位哈希（不引入依赖，仅用于截断后的唯一后缀）。
fn fnv1a_32(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for b in bytes {
        hash ^= u32::from(*b);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// 取命令行里 `--name` 的实参。
fn name_arg(command: &str) -> Option<&str> {
    let mut tokens = command.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "--name" {
            return tokens.next().map(|value| value.trim_matches('"'));
        }
    }
    None
}

/// 判断一段已注册的命令行是否由本程序为 `name` 创建。
///
/// 规则（规格「安全约束 4」）：内容包含 `rnpc`，且 `--name` 的实参等于实例名。
fn owned_by_instance(command: &str, name: &str) -> bool {
    command.to_ascii_lowercase().contains("rnpc") && name_arg(command) == Some(name)
}

/// 已注册的命令行是否与期望的可执行文件 + 实例名一致。
///
/// 与 `run_command` 严格比较会误判：`schtasks` 可能把 `/tr` 里的路径引号
/// 拆进 `<Command>` / `<Arguments>` 两个字段。这里按「前缀是同一个 exe，
/// 且 `--name` 匹配」比较语义。
fn registered_as(command: &str, exe: &str, name: &str) -> bool {
    if !owned_by_instance(command, name) {
        return false;
    }
    let quoted = quote_path(exe);
    let rest = if let Some(rest) = command.strip_prefix(&quoted) {
        rest
    } else if let Some(rest) = command.strip_prefix(exe) {
        rest
    } else {
        return false;
    };
    rest.is_empty() || rest.starts_with(' ')
}

/// 非管理员时调用需管理员的通道 → 明确报错，不静默失败。
fn ensure_elevated(channel: Channel) -> Result<()> {
    if channel.needs_admin() && !is_elevated() {
        bail!(
            "通道 {} 需要管理员权限：当前进程未提权，请以「管理员身份运行」后重试（触发时机：{}）",
            channel,
            channel.trigger_desc()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows 实现
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::io;
    use std::process::{Command, Output};
    use std::ptr;

    use anyhow::{anyhow, bail, Context, Result};

    use super::{
        item_name, owned_by_instance, registered_as, run_command, service_command, service_name,
        Channel, ChannelStatus,
    };

    // -- Win32 手写 FFI ----------------------------------------------------
    //
    // 注册表读写与提权检测只用少数几个极其稳定的接口，直接手写 FFI，
    // 不额外引入 `winreg` / `windows-sys`。服务通道才用 `windows-service`。

    type Handle = *mut c_void;
    type Hkey = *mut c_void;
    type Lstatus = i32;
    type Bool = i32;

    const HKEY_CURRENT_USER: Hkey = 0x8000_0001usize as Hkey;

    const KEY_QUERY_VALUE: u32 = 0x0001;
    const KEY_SET_VALUE: u32 = 0x0002;

    const REG_SZ: u32 = 1;
    const ERROR_FILE_NOT_FOUND: Lstatus = 2;

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_ELEVATION_CLASS: i32 = 20; // TokenElevation

    const CP_OEMCP: u32 = 1;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegOpenKeyExW(
            hkey: Hkey,
            lpsubkey: *const u16,
            uloptions: u32,
            samdesired: u32,
            phkresult: *mut Hkey,
        ) -> Lstatus;
        fn RegCreateKeyExW(
            hkey: Hkey,
            lpsubkey: *const u16,
            reserved: u32,
            lpclass: *const u16,
            dwoptions: u32,
            samdesired: u32,
            lpsecurityattributes: *const c_void,
            phkresult: *mut Hkey,
            lpdwdisposition: *mut u32,
        ) -> Lstatus;
        fn RegSetValueExW(
            hkey: Hkey,
            lpvaluename: *const u16,
            reserved: u32,
            dwtype: u32,
            lpdata: *const u8,
            cbdata: u32,
        ) -> Lstatus;
        fn RegQueryValueExW(
            hkey: Hkey,
            lpvaluename: *const u16,
            lpreserved: *const u32,
            lptype: *mut u32,
            lpdata: *mut u8,
            lpcbdata: *mut u32,
        ) -> Lstatus;
        fn RegDeleteValueW(hkey: Hkey, lpvaluename: *const u16) -> Lstatus;
        fn RegCloseKey(hkey: Hkey) -> Lstatus;
        fn OpenProcessToken(
            processhandle: Handle,
            desiredaccess: u32,
            tokenhandle: *mut Handle,
        ) -> Bool;
        fn GetTokenInformation(
            tokenhandle: Handle,
            tokeninformationclass: i32,
            tokeninformation: *mut c_void,
            tokeninformationlength: u32,
            returnlength: *mut u32,
        ) -> Bool;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CloseHandle(hobject: Handle) -> Bool;
        fn GetCurrentProcess() -> Handle;
        fn MultiByteToWideChar(
            codepage: u32,
            dwflags: u32,
            lpmultibytestr: *const u8,
            cbmultibyte: i32,
            lpwidecharstr: *mut u16,
            cchwidechar: i32,
        ) -> i32;
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn err(code: Lstatus) -> io::Error {
        io::Error::from_raw_os_error(code)
    }

    /// 注册表键的 RAII 句柄。
    struct Key(Hkey);

    impl Drop for Key {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { RegCloseKey(self.0) };
            }
        }
    }

    fn open_key(root: Hkey, sub: &str, access: u32, create: bool) -> io::Result<Key> {
        let sub_w = wide(sub);
        let mut handle: Hkey = ptr::null_mut();
        let rc = unsafe {
            if create {
                let mut disposition: u32 = 0;
                RegCreateKeyExW(
                    root,
                    sub_w.as_ptr(),
                    0,
                    ptr::null(),
                    0, // REG_OPTION_NON_VOLATILE
                    access,
                    ptr::null(),
                    &mut handle,
                    &mut disposition,
                )
            } else {
                RegOpenKeyExW(root, sub_w.as_ptr(), 0, access, &mut handle)
            }
        };
        if rc != 0 {
            return Err(err(rc));
        }
        Ok(Key(handle))
    }

    /// 读字符串值。值或键不存在都返回 `Ok(None)`。
    fn read_string_value(root: Hkey, sub: &str, value: &str) -> io::Result<Option<String>> {
        let key = match open_key(root, sub, KEY_QUERY_VALUE, false) {
            Ok(key) => key,
            Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => return Ok(None),
            Err(e) => return Err(e),
        };
        let value_w = wide(value);
        let mut kind: u32 = 0;
        let mut len: u32 = 0;
        let rc = unsafe {
            RegQueryValueExW(
                key.0,
                value_w.as_ptr(),
                ptr::null(),
                &mut kind,
                ptr::null_mut(),
                &mut len,
            )
        };
        if rc == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if rc != 0 {
            return Err(err(rc));
        }
        if len == 0 {
            return Ok(Some(String::new()));
        }
        let mut buf = vec![0u8; len as usize];
        let mut len2 = len;
        let rc = unsafe {
            RegQueryValueExW(
                key.0,
                value_w.as_ptr(),
                ptr::null(),
                &mut kind,
                buf.as_mut_ptr(),
                &mut len2,
            )
        };
        if rc != 0 {
            return Err(err(rc));
        }
        buf.truncate(len2 as usize);
        // REG_SZ 是 UTF-16LE（含结尾 NUL）
        let mut units: Vec<u16> = buf
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        while units.last() == Some(&0) {
            units.pop();
        }
        Ok(Some(String::from_utf16_lossy(&units)))
    }

    /// 写字符串值（覆盖同名值，天然幂等）。
    fn write_string_value(root: Hkey, sub: &str, value: &str, data: &str) -> io::Result<()> {
        let key = open_key(root, sub, KEY_SET_VALUE, true)?;
        let value_w = wide(value);
        let data_w = wide(data);
        let bytes = unsafe {
            std::slice::from_raw_parts(
                data_w.as_ptr().cast::<u8>(),
                data_w.len() * std::mem::size_of::<u16>(),
            )
        };
        let rc = unsafe {
            RegSetValueExW(
                key.0,
                value_w.as_ptr(),
                0,
                REG_SZ,
                bytes.as_ptr(),
                bytes.len() as u32,
            )
        };
        if rc != 0 {
            return Err(err(rc));
        }
        Ok(())
    }

    /// 删字符串值。键或值不存在返回 `Ok(false)`。
    fn delete_string_value(root: Hkey, sub: &str, value: &str) -> io::Result<bool> {
        let key = match open_key(root, sub, KEY_SET_VALUE, false) {
            Ok(key) => key,
            Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => return Ok(false),
            Err(e) => return Err(e),
        };
        let value_w = wide(value);
        let rc = unsafe { RegDeleteValueW(key.0, value_w.as_ptr()) };
        match rc {
            0 => Ok(true),
            ERROR_FILE_NOT_FOUND => Ok(false),
            other => Err(err(other)),
        }
    }

    // -- 提权检测 ---------------------------------------------------------

    #[repr(C)]
    struct TokenElevation {
        token_is_elevated: u32,
    }

    /// 进程令牌的 TokenElevation；查询失败返回 `None`。
    pub(super) fn token_is_elevated() -> Option<bool> {
        unsafe {
            let mut token: Handle = ptr::null_mut();
            let ok = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token);
            if ok == 0 || token.is_null() {
                return None;
            }
            let mut info = TokenElevation {
                token_is_elevated: 0,
            };
            let mut returned: u32 = 0;
            let ok = GetTokenInformation(
                token,
                TOKEN_ELEVATION_CLASS,
                (&mut info as *mut TokenElevation).cast::<c_void>(),
                std::mem::size_of::<TokenElevation>() as u32,
                &mut returned,
            );
            CloseHandle(token);
            if ok == 0 {
                return None;
            }
            Some(info.token_is_elevated != 0)
        }
    }

    /// 兜底的提权检测：`net session` 只有管理员能执行成功。
    pub(super) fn net_session_is_elevated() -> bool {
        match hidden_command("net.exe").arg("session").output() {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    // -- 外部命令封装 -----------------------------------------------------

    fn hidden_command(program: &str) -> Command {
        use std::os::windows::process::CommandExt;
        let mut cmd = Command::new(program);
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd
    }

    /// 控制台程序输出解码。
    ///
    /// - 带 UTF-16LE / UTF-8 BOM：按 BOM 解码（`schtasks /xml` 偶发真 UTF-16 输出）。
    /// - 否则按 OEM 代码页解码（中文系统是 GBK），避免本地化错误信息变乱码。
    fn decode_console(bytes: &[u8]) -> String {
        if bytes.is_empty() {
            return String::new();
        }
        if bytes.starts_with(&[0xFF, 0xFE]) {
            let units: Vec<u16> = bytes[2..]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            return String::from_utf16_lossy(&units);
        }
        if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
            return String::from_utf8_lossy(&bytes[3..]).into_owned();
        }
        // 无 BOM 的 UTF-16LE：ASCII 文本的高字节全为 0。
        if bytes.len() >= 4
            && bytes.chunks_exact(2).filter(|p| p[1] == 0).count() * 4 >= bytes.len()
        {
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            return String::from_utf16_lossy(&units);
        }
        unsafe {
            let len = MultiByteToWideChar(
                CP_OEMCP,
                0,
                bytes.as_ptr(),
                bytes.len() as i32,
                ptr::null_mut(),
                0,
            );
            if len > 0 {
                let mut buf = vec![0u16; len as usize];
                let written = MultiByteToWideChar(
                    CP_OEMCP,
                    0,
                    bytes.as_ptr(),
                    bytes.len() as i32,
                    buf.as_mut_ptr(),
                    len,
                );
                if written > 0 {
                    buf.truncate(written as usize);
                    return String::from_utf16_lossy(&buf);
                }
            }
        }
        String::from_utf8_lossy(bytes).into_owned()
    }

    fn output_text(output: &Output) -> String {
        let mut text = decode_console(&output.stdout);
        let stderr = decode_console(&output.stderr);
        if !stderr.trim().is_empty() {
            if !text.trim().is_empty() {
                text.push('\n');
            }
            text.push_str(&stderr);
        }
        text.trim().to_owned()
    }

    /// 「目标不存在」在 `schtasks` / `sc` 里只表现为一段本地化文本，没有稳定错误码。
    fn looks_like_not_found(text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        const MARKERS: &[&str] = &[
            "找不到",
            "不存在",
            "does not exist",
            "cannot find",
            "can not find",
            "non-existent",
            "nonexistent",
            "no such",
        ];
        MARKERS
            .iter()
            .any(|marker| lower.contains(marker) || text.contains(marker))
    }

    fn looks_like_access_denied(text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        ["拒绝访问", "access is denied", "access denied", "权限不足"]
            .iter()
            .any(|marker| lower.contains(marker) || text.contains(marker))
    }

    fn admin_hint(channel: Channel, detail: &str) -> anyhow::Error {
        anyhow!(
            "通道 {channel} 操作被系统拒绝，需要管理员权限（请以「管理员身份运行」后重试）；系统返回：{detail}"
        )
    }

    // -- run-key ----------------------------------------------------------

    const RUN_KEY_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

    pub(super) fn run_key_install(name: &str, exe: &str) -> Result<()> {
        let value_name = item_name(name);
        let command = run_command(exe, name);
        write_string_value(HKEY_CURRENT_USER, RUN_KEY_PATH, &value_name, &command).with_context(
            || format!("写入注册表 Run 键失败：HKCU\\{RUN_KEY_PATH}\\{value_name}"),
        )?;

        // 回读校验：拿到的内容不是我们写的那条，说明写入被拦截/覆盖。
        let stored = read_string_value(HKEY_CURRENT_USER, RUN_KEY_PATH, &value_name)
            .context("回读注册表 Run 键失败")?;
        match stored {
            Some(value) if value == command => Ok(()),
            Some(value) => bail!(
                "注册表 Run 键写入后内容不一致（期望 {command:?}，实际 {value:?}），请检查是否被安全软件拦截"
            ),
            None => bail!("注册表 Run 键写入后读不到值 {value_name}，请检查是否被安全软件拦截"),
        }
    }

    pub(super) fn run_key_remove(name: &str) -> Result<bool> {
        let value_name = item_name(name);
        let stored = read_string_value(HKEY_CURRENT_USER, RUN_KEY_PATH, &value_name)
            .context("读取注册表 Run 键失败")?;
        let Some(value) = stored else {
            return Ok(false);
        };
        if !owned_by_instance(&value, name) {
            bail!(
                "拒绝删除自启项 {value_name}：现有内容 {value:?} 不是本程序为实例 {name:?} 创建的（应包含 rnpc 与 --name {name}）"
            );
        }
        delete_string_value(HKEY_CURRENT_USER, RUN_KEY_PATH, &value_name)
            .with_context(|| format!("删除注册表 Run 键值失败：{value_name}"))
    }

    pub(super) fn run_key_status(name: &str) -> Result<ChannelStatus> {
        let value_name = item_name(name);
        let stored = read_string_value(HKEY_CURRENT_USER, RUN_KEY_PATH, &value_name)
            .context("读取注册表 Run 键失败")?;
        let installed = stored
            .as_deref()
            .is_some_and(|value| owned_by_instance(value, name));
        Ok(ChannelStatus {
            channel: Channel::RunKey,
            installed,
            command: stored,
        })
    }

    // -- task-start / task-logon -----------------------------------------

    fn schedule_kind(channel: Channel) -> &'static str {
        match channel {
            Channel::TaskStart => "onstart",
            _ => "onlogon",
        }
    }

    /// 读取任务 XML 里的 `<Command>` + `<Arguments>`。
    ///
    /// 用 XML 而不是 `/fo list`：后者的字段名会被系统语言本地化（中文系统是
    /// 「要运行的任务」），XML 的标签名恒为英文。
    fn task_registered_command(channel: Channel, task: &str) -> Result<Option<String>> {
        let output = hidden_command("schtasks.exe")
            .args(["/query", "/tn", task, "/xml", "ONE"])
            .output()
            .context("无法执行 schtasks.exe")?;
        let text = output_text(&output);

        if !output.status.success() {
            if looks_like_access_denied(&text) {
                return Err(admin_hint(channel, &text));
            }
            if looks_like_not_found(&text) {
                return Ok(None);
            }
            bail!("查询计划任务 {task} 失败：{text}");
        }
        if !text.starts_with("<?xml") {
            bail!("查询计划任务 {task} 返回了非预期内容：{text}");
        }

        let command = xml_tag(&text, "Command").unwrap_or_default();
        let arguments = xml_tag(&text, "Arguments").unwrap_or_default();
        let full = if arguments.is_empty() {
            command
        } else {
            format!("{command} {arguments}")
        };
        Ok(Some(full))
    }

    /// 取 XML 中第一个 `<tag>...</tag>` 的文本（含最小实体反转义）。
    fn xml_tag(xml: &str, tag: &str) -> Option<String> {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let start = xml.find(&open)? + open.len();
        let end = xml[start..].find(&close)? + start;
        Some(xml_unescape(&xml[start..end]))
    }

    fn xml_unescape(text: &str) -> String {
        text.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&")
    }

    pub(super) fn task_install(channel: Channel, name: &str, exe: &str) -> Result<()> {
        let task = item_name(name);
        let command = run_command(exe, name);

        let output = hidden_command("schtasks.exe")
            .args([
                "/create",
                "/tn",
                &task,
                "/tr",
                &command,
                "/sc",
                schedule_kind(channel),
                "/f",
            ])
            .output()
            .context("无法执行 schtasks.exe")?;
        let text = output_text(&output);
        if !output.status.success() {
            if looks_like_access_denied(&text) {
                return Err(admin_hint(channel, &text));
            }
            bail!("创建计划任务 {task} 失败：{text}");
        }

        // 回读校验：任务里存的命令行必须指向同一个可执行文件、同一个实例。
        match task_registered_command(channel, &task)? {
            Some(stored) if registered_as(&stored, exe, name) => Ok(()),
            Some(stored) => {
                bail!("计划任务 {task} 写入后命令行不一致（期望 {command:?}，实际 {stored:?}）")
            }
            None => bail!("计划任务 {task} 创建后查询不到，请检查系统策略"),
        }
    }

    pub(super) fn task_remove(channel: Channel, name: &str) -> Result<bool> {
        let task = item_name(name);
        let Some(stored) = task_registered_command(channel, &task)? else {
            return Ok(false);
        };
        if !owned_by_instance(&stored, name) {
            bail!("拒绝删除计划任务 {task}：现有内容 {stored:?} 不是本程序为实例 {name:?} 创建的");
        }
        let output = hidden_command("schtasks.exe")
            .args(["/delete", "/tn", &task, "/f"])
            .output()
            .context("无法执行 schtasks.exe")?;
        let text = output_text(&output);
        if !output.status.success() {
            if looks_like_access_denied(&text) {
                return Err(admin_hint(channel, &text));
            }
            if looks_like_not_found(&text) {
                return Ok(false);
            }
            bail!("删除计划任务 {task} 失败：{text}");
        }
        Ok(true)
    }

    pub(super) fn task_status(channel: Channel, name: &str) -> Result<ChannelStatus> {
        let task = item_name(name);
        let command = task_registered_command(channel, &task)?;
        let installed = command
            .as_deref()
            .is_some_and(|value| owned_by_instance(value, name));
        Ok(ChannelStatus {
            channel,
            installed,
            command,
        })
    }

    // -- service ----------------------------------------------------------
    //
    // 服务通道用 `windows-service` crate（typed Win32 错误码 + 正确的
    // `CreateServiceW` 转义），不解析 `sc.exe` 的本地化输出。

    use windows_service::service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    /// 服务不存在（SCM 返回码）
    const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

    fn sc_manager(access: ServiceManagerAccess) -> Result<ServiceManager> {
        ServiceManager::local_computer(None::<&str>, access).map_err(
            |error| match scm_access_denied(&error) {
                true => admin_hint(Channel::Service, &error.to_string()),
                false => anyhow!("连接服务控制管理器失败：{error}"),
            },
        )
    }

    /// 错误是否为「权限不足」（Windows 错误码 5）。
    fn scm_access_denied(error: &windows_service::Error) -> bool {
        match error {
            windows_service::Error::Winapi(io) => io.raw_os_error() == Some(5),
            _ => false,
        }
    }

    fn service_info(service: &str, name: &str, exe: &str) -> ServiceInfo {
        ServiceInfo {
            name: service.into(),
            display_name: format!("rnpc {name} (Rust-nps client)").into(),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe.into(),
            // SCM 从 System32 启动，因此命令行只有内部子命令 + 实例名。
            launch_arguments: vec!["service-host".into(), "--name".into(), name.into()],
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        }
    }

    /// SCM 实际记录的二进制命令行（含参数串）。
    fn service_configured_command(service: &str) -> Result<Option<String>> {
        let manager = sc_manager(ServiceManagerAccess::CONNECT)?;
        match manager.open_service(service, ServiceAccess::QUERY_CONFIG) {
            Ok(handle) => {
                let config = handle
                    .query_config()
                    .map_err(|error| anyhow!("查询服务 {service} 配置失败：{error}"))?;
                Ok(Some(config.executable_path.to_string_lossy().into_owned()))
            }
            Err(windows_service::Error::Winapi(io))
                if io.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST) =>
            {
                Ok(None)
            }
            Err(error) if scm_access_denied(&error) => {
                Err(admin_hint(Channel::Service, &error.to_string()))
            }
            Err(error) => Err(anyhow!("打开服务 {service} 失败：{error}")),
        }
    }

    pub(super) fn service_install(name: &str, exe: &str) -> Result<()> {
        let service = service_name(name);
        let info = service_info(&service, name, exe);
        let expected = service_command(exe, name);

        let manager =
            sc_manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;

        match service_configured_command(&service)? {
            // 已存在：只允许改自己那一项（幂等），改完再回读校验。
            Some(existing) => {
                if !owned_by_instance(&existing, name) {
                    bail!(
                        "服务 {service} 已存在且不是本程序创建的（现命令行 {existing:?}），拒绝覆盖"
                    );
                }
                let handle = manager
                    .open_service(service.as_str(), ServiceAccess::CHANGE_CONFIG)
                    .map_err(|error| {
                        if scm_access_denied(&error) {
                            admin_hint(Channel::Service, &error.to_string())
                        } else {
                            anyhow!("打开服务 {service} 失败：{error}")
                        }
                    })?;
                handle.change_config(&info).map_err(|error| {
                    if scm_access_denied(&error) {
                        admin_hint(Channel::Service, &error.to_string())
                    } else {
                        anyhow!("更新服务 {service} 配置失败：{error}")
                    }
                })?;
            }
            None => {
                manager
                    .create_service(&info, ServiceAccess::QUERY_CONFIG)
                    .map_err(|error| {
                        if scm_access_denied(&error) {
                            admin_hint(Channel::Service, &error.to_string())
                        } else {
                            anyhow!("创建服务 {service} 失败：{error}")
                        }
                    })?;
            }
        }

        match service_configured_command(&service)? {
            Some(stored) if registered_as(&stored, exe, name) => Ok(()),
            Some(stored) => {
                bail!("服务 {service} 写入后命令行不一致（期望 {expected:?}，实际 {stored:?}）")
            }
            None => bail!("服务 {service} 创建后读不到配置，请检查系统策略"),
        }
    }

    pub(super) fn service_remove(name: &str) -> Result<bool> {
        let service = service_name(name);
        let Some(stored) = service_configured_command(&service)? else {
            return Ok(false);
        };
        if !owned_by_instance(&stored, name) {
            bail!("拒绝删除服务 {service}：现有命令行 {stored:?} 不是本程序为实例 {name:?} 创建的");
        }

        let manager = sc_manager(ServiceManagerAccess::CONNECT)?;
        let access = ServiceAccess::DELETE | ServiceAccess::QUERY_CONFIG | ServiceAccess::STOP;
        let handle = manager
            .open_service(service.as_str(), access)
            .map_err(|error| {
                if scm_access_denied(&error) {
                    admin_hint(Channel::Service, &error.to_string())
                } else {
                    anyhow!("打开服务 {service} 失败：{error}")
                }
            })?;

        // 先尝试停止（失败不影响删除：未运行 / 已在停止中都算正常）。
        let _ = handle.stop();

        handle.delete().map_err(|error| {
            if scm_access_denied(&error) {
                admin_hint(Channel::Service, &error.to_string())
            } else {
                anyhow!("删除服务 {service} 失败：{error}")
            }
        })?;
        Ok(true)
    }

    pub(super) fn service_status(name: &str) -> Result<ChannelStatus> {
        let service = service_name(name);
        let stored = service_configured_command(&service)?;
        let installed = stored
            .as_deref()
            .is_some_and(|value| owned_by_instance(value, name));
        Ok(ChannelStatus {
            channel: Channel::Service,
            installed,
            command: stored,
        })
    }
}

// ---------------------------------------------------------------------------
// 单测
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_names_roundtrip() {
        for channel in Channel::all() {
            assert_eq!(Channel::parse(channel.as_str()), Some(channel));
        }
        // `auto` / `none` 是 CLI 策略，不是通道
        assert_eq!(Channel::parse("auto"), None);
        assert_eq!(Channel::parse("none"), None);
        assert_eq!(Channel::parse("Service"), None);
        assert_eq!(Channel::as_str(Channel::TaskStart), "task-start");
    }

    #[test]
    fn admin_requirement_matches_spec() {
        assert!(Channel::Service.needs_admin());
        assert!(Channel::TaskStart.needs_admin());
        // 「视策略」：不前置拦截，由实际调用结果决定
        assert!(!Channel::TaskLogon.needs_admin());
        assert!(!Channel::RunKey.needs_admin());
    }

    #[test]
    fn trigger_desc_is_human_readable() {
        assert!(Channel::Service.trigger_desc().contains("无需用户登录"));
        assert!(Channel::TaskStart.trigger_desc().contains("开机即启"));
        assert!(Channel::TaskLogon.trigger_desc().contains("登录"));
        assert!(Channel::RunKey.trigger_desc().contains("管理员权限"));
    }

    #[test]
    fn path_with_spaces_is_quoted() {
        let cmd = run_command(r"C:\Program Files\Rust nps\rnpc.exe", "web");
        assert_eq!(
            cmd,
            r#""C:\Program Files\Rust nps\rnpc.exe" run --name web"#
        );
        assert!(cmd.starts_with('"'));
        assert!(cmd.contains("\" run --name web"));
    }

    #[test]
    fn path_without_spaces_is_still_quoted() {
        // 无条件加引号：规格要求「必须用带引号的绝对路径」
        let cmd = run_command(r"C:\rnpc\rnpc.exe", "db");
        assert_eq!(cmd, r#""C:\rnpc\rnpc.exe" run --name db"#);
    }

    #[test]
    fn trailing_separator_is_trimmed_so_quote_is_not_escaped() {
        let exe = absolute_exe(Path::new(r"C:\Program Files\rnpc\")).unwrap();
        assert_eq!(exe, r"C:\Program Files\rnpc");
        let cmd = run_command(&exe, "web");
        assert!(!cmd.contains("\\\""), "末尾反斜杠不应转义收尾引号: {cmd}");

        // 盘根保留
        assert_eq!(absolute_exe(Path::new(r"C:\")).unwrap(), r"C:\");
    }

    #[test]
    fn relative_path_is_rejected() {
        assert!(absolute_exe(Path::new("rnpc.exe")).is_err());
        assert!(absolute_exe(Path::new(r"..\rnpc.exe")).is_err());
    }

    #[test]
    fn command_never_contains_vkey() {
        // 自启命令行只允许 `run --name <name>`；vkey 只存在于配置文件。
        let cmd = run_command(r"C:\rnpc\rnpc.exe", "web");
        assert!(!cmd.contains("vkey"), "自启项不得包含 vkey: {cmd}");
        assert!(!cmd.contains("-vkey"));
        assert_eq!(run_args("web"), "run --name web");
        assert_eq!(
            service_command(r"C:\rnpc\rnpc.exe", "web").contains("vkey"),
            false
        );
    }

    #[test]
    fn service_command_uses_internal_subcommand() {
        let cmd = service_command(r"C:\Program Files\rnpc\rnpc.exe", "web");
        assert_eq!(
            cmd,
            r#""C:\Program Files\rnpc\rnpc.exe" service-host --name web"#
        );
    }

    #[test]
    fn ownership_detection() {
        let web = r#""C:\rnpc\rnpc.exe" run --name web"#;
        assert!(owned_by_instance(web, "web"));
        // 实例名不匹配 → 不是自己的
        assert!(!owned_by_instance(web, "db"));
        // 不是本程序写的
        assert!(!owned_by_instance(
            r#""C:\other\app.exe" run --name web"#,
            "web"
        ));
        assert!(!owned_by_instance("notepad.exe", "web"));
        // 子串陷阱：rnpc 出现但 --name 不符
        assert!(!owned_by_instance(
            r#""C:\rnpc\rnpc.exe" run --name rnpc-other"#,
            "other"
        ));
        // service-host 形式也能识别
        assert!(owned_by_instance(
            r#""C:\rnpc\rnpc.exe" service-host --name web"#,
            "web"
        ));
    }

    #[test]
    fn registered_as_tolerates_schtasks_splitting_quotes() {
        let exe = r"C:\Program Files\rnpc\rnpc.exe";
        // 保留引号
        assert!(registered_as(
            r#""C:\Program Files\rnpc\rnpc.exe" run --name web"#,
            exe,
            "web"
        ));
        // schtasks 把路径与参数拆进两个字段、去掉引号
        assert!(registered_as(
            r"C:\Program Files\rnpc\rnpc.exe run --name web",
            exe,
            "web"
        ));
        // 路径被 MUI 化或换了二进制 → 不算
        assert!(!registered_as(
            r#""C:\other\rnpc.exe" run --name web"#,
            exe,
            "web"
        ));
        // 前缀相同的另一个 exe 不能误判
        assert!(!registered_as(
            r#""C:\Program Files\rnpc\rnpc.exe.bak" run --name web"#,
            exe,
            "web"
        ));
        assert!(!registered_as(
            r#""C:\Program Files\rnpc\rnpc.exe" run --name other"#,
            exe,
            "web"
        ));
    }

    #[test]
    fn name_arg_extraction() {
        assert_eq!(name_arg("x run --name web"), Some("web"));
        assert_eq!(name_arg(r#"x run --name "web""#), Some("web"));
        assert_eq!(name_arg("x run"), None);
    }

    #[test]
    fn service_name_is_bounded_and_unique() {
        assert_eq!(service_name("web"), "rnpc-web");

        let long_a = "a".repeat(200);
        let long_b = format!("{}b", "a".repeat(199));
        let a = service_name(&long_a);
        let b = service_name(&long_b);
        assert!(a.len() <= 128, "服务名过长: {}", a.len());
        assert!(b.len() <= 128, "服务名过长: {}", b.len());
        assert!(a.starts_with("rnpc-"));
        assert_ne!(a, b, "截断后必须保持唯一");
        assert_eq!(service_name("web"), item_name("web"));
    }

    #[test]
    fn invalid_instance_names_are_rejected_before_touching_system() {
        for bad in [
            "",
            "A",
            "a b",
            "a/b",
            "all",
            "rnpc",
            "x".repeat(33).as_str(),
        ] {
            assert!(validate(bad).is_err(), "{bad:?} 应被拒绝");
            // status/remove 必须先校验名字，不能带着非法名去碰系统
            assert!(status(Channel::RunKey, bad).is_err());
            assert!(remove(Channel::RunKey, bad).is_err());
        }
    }
}
