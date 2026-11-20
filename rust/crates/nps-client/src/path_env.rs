//! 用户级 PATH 管理。
//!
//! 对应 `docs/rnpc-cli-spec.md` 的「PATH 注册」一节。
//!
//! 只动 **用户级** PATH（Windows 是 `HKCU\Environment` 的 `Path` 值），
//! 绝不碰系统级 PATH。所有操作幂等，且只移除自己加的那一段。

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// 用户级 PATH 的长度上限（Windows 约 32767，留出余量）
pub const MAX_PATH_LEN: usize = 30_000;

/// PATH 注册结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathState {
    /// 已存在（本次未改动）
    AlreadyPresent,
    /// 本次新增
    Added,
    /// 本次移除
    Removed,
    /// 不存在（移除时）
    NotPresent,
}

/// 规范化路径用于比较：忽略大小写（Windows）与末尾分隔符
fn normalize(path: &str) -> String {
    let trimmed = path.trim().trim_matches('"');
    let stripped = trimmed.trim_end_matches(['\\', '/']);
    if cfg!(windows) {
        stripped.to_ascii_lowercase().replace('/', "\\")
    } else {
        stripped.to_owned()
    }
}

/// 把 PATH 字符串按分隔符切成条目
fn split_path(value: &str) -> Vec<String> {
    value
        .split(if cfg!(windows) { ';' } else { ':' })
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// 判断目录是否已在 PATH 中
pub fn contains(current: &str, dir: &Path) -> bool {
    let want = normalize(&dir.to_string_lossy());
    split_path(current).iter().any(|e| normalize(e) == want)
}

/// 把目录加入 PATH 字符串（幂等）。返回新值与状态。
pub fn add(current: &str, dir: &Path) -> Result<(String, PathState)> {
    if contains(current, dir) {
        return Ok((current.to_owned(), PathState::AlreadyPresent));
    }
    let sep = if cfg!(windows) { ';' } else { ':' };
    let dir_text = dir.to_string_lossy();
    let new_value = if current.trim().is_empty() {
        dir_text.to_string()
    } else {
        let trimmed = current.trim_end_matches(sep);
        format!("{trimmed}{sep}{dir_text}")
    };
    if new_value.len() > MAX_PATH_LEN {
        bail!(
            "PATH 过长（{} > {MAX_PATH_LEN} 字符），拒绝写入以免截断。\
             请先清理 PATH 中的无用条目",
            new_value.len()
        );
    }
    Ok((new_value, PathState::Added))
}

/// 从 PATH 字符串移除目录（幂等，只移除完全匹配的条目）
pub fn remove(current: &str, dir: &Path) -> (String, PathState) {
    let want = normalize(&dir.to_string_lossy());
    let sep = if cfg!(windows) { ';' } else { ':' };
    let entries = split_path(current);
    let before = entries.len();
    let kept: Vec<String> = entries
        .into_iter()
        .filter(|e| normalize(e) != want)
        .collect();
    if kept.len() == before {
        return (current.to_owned(), PathState::NotPresent);
    }
    (kept.join(&sep.to_string()), PathState::Removed)
}

// ---------------------------------------------------------------------------
// 平台读写
// ---------------------------------------------------------------------------

/// 读取用户级 PATH
pub fn read_user_path() -> Result<String> {
    #[cfg(windows)]
    {
        // 用 reg query 读取（不引入 winreg 依赖）
        let output = std::process::Command::new("reg")
            .args(["query", "HKCU\\Environment", "/v", "Path"])
            .output()
            .context("无法执行 reg query")?;
        if !output.status.success() {
            // 值不存在视为空 PATH（不是错误）
            return Ok(String::new());
        }
        let text = String::from_utf8_lossy(&output.stdout);
        // 输出形如: "    Path    REG_EXPAND_SZ    C:\a;C:\b"
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("Path") {
                let mut parts = rest.splitn(2, "REG_EXPAND_SZ");
                if parts.next().is_some() {
                    if let Some(v) = parts.next() {
                        return Ok(v.trim().to_owned());
                    }
                }
                // 也可能是 REG_SZ
                let mut parts = rest.splitn(2, "REG_SZ");
                if parts.next().is_some() {
                    if let Some(v) = parts.next() {
                        return Ok(v.trim().to_owned());
                    }
                }
            }
        }
        Ok(String::new())
    }
    #[cfg(not(windows))]
    {
        Ok(std::env::var("PATH").unwrap_or_default())
    }
}

/// 写入用户级 PATH
pub fn write_user_path(value: &str) -> Result<()> {
    if value.len() > MAX_PATH_LEN {
        bail!("PATH 过长（{} > {MAX_PATH_LEN}），拒绝写入", value.len());
    }
    #[cfg(windows)]
    {
        let output = std::process::Command::new("reg")
            .args([
                "add",
                "HKCU\\Environment",
                "/v",
                "Path",
                "/t",
                "REG_EXPAND_SZ",
                "/d",
                value,
                "/f",
            ])
            .output()
            .context("无法执行 reg add")?;
        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            bail!("写入用户 PATH 失败: {}", err.trim());
        }
        broadcast_setting_change();
        Ok(())
    }
    #[cfg(not(windows))]
    {
        // 非 Windows 不自动改 shell 配置（避免破坏用户环境），
        // 只提示用户手动添加
        let _ = value;
        bail!(
            "非 Windows 平台不自动修改 PATH。请手动把目标目录加入 PATH，\
             例如在 ~/.bashrc 中追加 export PATH=\"$PATH:<dir>\""
        )
    }
}

/// 广播 WM_SETTINGCHANGE，让新开的终端尽快看到 PATH 变化。
///
/// 对**已打开**的终端无效——这是系统行为，不是缺陷。
#[cfg(windows)]
fn broadcast_setting_change() {
    // 用 powershell 调 SendMessageTimeout 太重；这里用 setx 的副作用
    // （setx 本身会广播）。但 setx 有 1024 字符限制，不能用于 PATH。
    // 因此改用 rundll32 触发环境变量刷新提示。
    let _ = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Environment]::SetEnvironmentVariable('RNPC_PATH_BROADCAST', $null, 'User'); \
             Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition \
             '[DllImport(\"user32.dll\", SetLastError=true, CharSet=CharSet.Auto)] \
              public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, \
              string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);'; \
             $r = [UIntPtr]::Zero; \
             [Win32.NativeMethods]::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, \
             'Environment', 2, 5000, [ref]$r) | Out-Null",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(not(windows))]
fn broadcast_setting_change() {}

/// 把目录注册进用户 PATH（读-改-写）
pub fn register(dir: &Path) -> Result<PathState> {
    let current = read_user_path()?;
    let (new_value, state) = add(&current, dir)?;
    if state == PathState::Added {
        write_user_path(&new_value)?;
    }
    Ok(state)
}

/// 从用户 PATH 移除目录
pub fn unregister(dir: &Path) -> Result<PathState> {
    let current = read_user_path()?;
    let (new_value, state) = remove(&current, dir);
    if state == PathState::Removed {
        write_user_path(&new_value)?;
    }
    Ok(state)
}

/// 查询目录是否在用户 PATH 中
pub fn is_registered(dir: &Path) -> Result<bool> {
    Ok(contains(&read_user_path()?, dir))
}

/// 计算 bin 目录（供上层使用）
pub fn bin_dir_of(data_root: &Path) -> PathBuf {
    data_root.join("bin")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_is_idempotent_and_preserves_order() {
        let dir = PathBuf::from(r"C:\Tools\rnpc\bin");
        let (v1, s1) = add(r"C:\Windows;C:\Other", &dir).unwrap();
        assert_eq!(s1, PathState::Added);
        assert!(v1.starts_with(r"C:\Windows;C:\Other"));

        let (v2, s2) = add(&v1, &dir).unwrap();
        assert_eq!(s2, PathState::AlreadyPresent);
        assert_eq!(v2, v1, "重复添加不应改变 PATH");
    }

    #[test]
    fn add_handles_empty_and_trailing_sep() {
        let dir = PathBuf::from(r"C:\x");
        let (v, s) = add("", &dir).unwrap();
        assert_eq!(s, PathState::Added);
        assert_eq!(v, r"C:\x");

        let (v2, s2) = add(r"C:\a;", &dir).unwrap();
        assert_eq!(s2, PathState::Added);
        assert_eq!(v2, r"C:\a;C:\x", "不应产生双分号");
    }

    #[test]
    fn comparison_ignores_case_and_trailing_slash() {
        let current = r"C:\Tools\RNPC\bin\";
        assert!(contains(current, &PathBuf::from(r"c:\tools\rnpc\bin")));
        assert!(contains(current, &PathBuf::from(r"C:\Tools\rnpc\bin\")));
    }

    #[test]
    fn remove_only_removes_exact_entry() {
        let dir = PathBuf::from(r"C:\x");
        let current = r"C:\x;C:\xy;C:\z";
        let (after, state) = remove(current, &dir);
        assert_eq!(state, PathState::Removed);
        assert_eq!(after, r"C:\xy;C:\z", "不应误删前缀相同的目录");
    }

    #[test]
    fn remove_missing_returns_not_present() {
        let (after, state) = remove(r"C:\a;C:\b", &PathBuf::from(r"C:\nope"));
        assert_eq!(state, PathState::NotPresent);
        assert_eq!(after, r"C:\a;C:\b");
    }

    #[test]
    fn too_long_path_is_rejected() {
        let long = "x".repeat(MAX_PATH_LEN + 100);
        let err = add(&long, &PathBuf::from(r"C:\x")).unwrap_err();
        assert!(err.to_string().contains("PATH 过长"), "{err}");
    }

    #[test]
    fn quoted_entries_are_normalized() {
        let current = r#""C:\Program Files\rnpc\bin";C:\other"#;
        assert!(contains(current, &PathBuf::from(r"C:\Program Files\rnpc\bin")));
    }
}
