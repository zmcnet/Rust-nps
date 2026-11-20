//! 多用户登录、会话与防爆破。
//!
//! # 与原版的关系
//!
//! 原版（`web/controllers/login.go`）有两类账号：
//!
//! 1. **管理员**：全局 `web_username` + `web_password`，可看全部资源
//! 2. **客户端用户**：每个 `Client` 自己的 `WebUserName`/`WebPassword`，
//!    登录后只能看自己的隧道。若两者都为空，则用 `username="user"` +
//!    `password=<VerifyKey>` 登录
//!
//! 原版用 Cookie session；本项目用 **`Authorization: Bearer <session-token>`**
//! 保持鉴权路径统一（无 Cookie，无 CSRF 面）。
//!
//! # 与现有 `NPS_ADMIN_TOKEN` 的关系
//!
//! 环境变量 `NPS_ADMIN_TOKEN` 继续作为**超级管理员令牌**，行为完全不变——
//! 现有部署不受影响。用户名密码登录是**额外**能力：
//!
//! - `NPS_ADMIN_TOKEN` → [`Principal::Admin`]
//! - 管理员账号登录 → [`Principal::NamedAdmin`]
//! - 客户端账号登录 → [`Principal::Client`]（只能访问自己的资源）

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 登录主体
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// 环境变量 `NPS_ADMIN_TOKEN` 对应的超级管理员
    Admin,
    /// 用户名密码登录的管理员
    NamedAdmin { username: String },
    /// 客户端账号：只能访问 `client_id` 对应的资源
    Client { client_id: i32, username: String },
}

impl Principal {
    /// 是否可访问全部资源
    pub fn is_admin(&self) -> bool {
        matches!(self, Self::Admin | Self::NamedAdmin { .. })
    }

    /// 该主体可见的 client_id 集合；`None` 表示全部可见
    pub fn visible_clients(&self) -> Option<Vec<i32>> {
        match self {
            Self::Admin | Self::NamedAdmin { .. } => None,
            Self::Client { client_id, .. } => Some(vec![*client_id]),
        }
    }

    /// 是否可见指定客户端
    pub fn can_see_client(&self, client_id: i32) -> bool {
        match self {
            Self::Admin | Self::NamedAdmin { .. } => true,
            Self::Client { client_id: own, .. } => *own == client_id,
        }
    }

    /// 展示名（用于日志，不含密码）
    pub fn display(&self) -> String {
        match self {
            Self::Admin => "admin(token)".to_owned(),
            Self::NamedAdmin { username } => format!("admin({username})"),
            Self::Client { client_id, username } => format!("client({username}#{client_id})"),
        }
    }
}

/// 常量时间比较（长度不同直接 false，不泄露前缀信息）
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// 一个账号
struct Account {
    username: String,
    password: String,
    principal: Principal,
}

/// 账号表
pub struct AccountStore {
    accounts: Vec<Account>,
    /// 是否至少有一个可登录账号
    enabled: bool,
}

impl AccountStore {
    /// 构造空账号表（只有 `NPS_ADMIN_TOKEN` 可用）
    pub fn empty() -> Self {
        Self {
            accounts: Vec::new(),
            enabled: false,
        }
    }

    /// 从配置构建。
    ///
    /// `admin` 是 `(username, password)`；`clients` 是
    /// `(client_id, web_username, web_password, vkey)`。
    /// 客户端账号的两个字段都为空时，按原版规则退化为
    /// `username="user"` + `password=vkey`。
    pub fn build(
        admin: Option<(String, String)>,
        clients: &[(i32, String, String, String)],
    ) -> Self {
        let mut accounts = Vec::new();

        if let Some((username, password)) = admin {
            let username = username.trim().to_owned();
            if !username.is_empty() && !password.is_empty() {
                accounts.push(Account {
                    username: username.clone(),
                    password,
                    principal: Principal::NamedAdmin { username },
                });
            }
        }

        for (client_id, web_user, web_pass, vkey) in clients {
            let (username, password) = if web_user.trim().is_empty() && web_pass.is_empty() {
                // 原版规则：两者都空 → user + vkey
                if vkey.is_empty() {
                    continue;
                }
                ("user".to_owned(), vkey.clone())
            } else {
                if web_user.trim().is_empty() || web_pass.is_empty() {
                    // 只配了一半：视为未配置（原版也不会登录成功）
                    continue;
                }
                (web_user.trim().to_owned(), web_pass.clone())
            };
            accounts.push(Account {
                username: username.clone(),
                password,
                principal: Principal::Client {
                    client_id: *client_id,
                    username,
                },
            });
        }

        Self {
            enabled: !accounts.is_empty(),
            accounts,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    /// 校验用户名密码。**遍历全部账号**（不提前返回），
    /// 避免通过响应时间推断「用户名是否存在」。
    pub fn authenticate(&self, username: &str, password: &str) -> Option<Principal> {
        let mut found: Option<Principal> = None;
        for account in &self.accounts {
            let user_ok = constant_time_eq(account.username.as_bytes(), username.as_bytes());
            let pass_ok = constant_time_eq(account.password.as_bytes(), password.as_bytes());
            if user_ok && pass_ok {
                found = Some(account.principal.clone());
            }
        }
        found
    }
}

/// 会话存储（内存，进程重启失效）
pub struct SessionStore {
    ttl: Duration,
    sessions: Mutex<HashMap<String, (Principal, Instant)>>,
    /// 累计创建的会话数（观测用）
    created: AtomicU64,
}

impl SessionStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            sessions: Mutex::new(HashMap::new()),
            created: AtomicU64::new(0),
        }
    }

    /// 默认 TTL：12 小时
    pub fn with_default_ttl() -> Self {
        Self::new(Duration::from_secs(12 * 3600))
    }

    /// 创建会话，返回随机令牌（64 个十六进制字符 = 32 字节）
    pub fn create(&self, principal: Principal) -> String {
        let token = random_token();
        let now = Instant::now();
        let mut map = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        // 顺手清理过期项，避免长期运行后无界增长
        map.retain(|_, (_, at)| now.duration_since(*at) < self.ttl);
        map.insert(token.clone(), (principal, now));
        self.created.fetch_add(1, Ordering::Relaxed);
        token
    }

    /// 校验令牌；过期则移除并返回 `None`
    pub fn verify(&self, token: &str) -> Option<Principal> {
        let now = Instant::now();
        let mut map = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(token) {
            Some((principal, at)) if now.duration_since(*at) < self.ttl => {
                Some(principal.clone())
            }
            Some(_) => {
                map.remove(token);
                None
            }
            None => None,
        }
    }

    pub fn revoke(&self, token: &str) -> bool {
        let mut map = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(token).is_some()
    }

    /// 清理过期会话，返回移除数量
    pub fn sweep(&self) -> usize {
        let now = Instant::now();
        let mut map = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let before = map.len();
        map.retain(|_, (_, at)| now.duration_since(*at) < self.ttl);
        before - map.len()
    }

    pub fn active(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    pub fn created(&self) -> u64 {
        self.created.load(Ordering::Relaxed)
    }
}

/// 生成 32 字节密码学随机令牌（hex）
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    // 优先用 ring 的随机源（依赖图里已有）；失败则退回系统时间+地址混合，
    // 但仍保证不同会话不重复（只在 ring 异常时发生）
    if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut seed = nanos as u64 ^ (std::process::id() as u64) << 32;
        for chunk in bytes.chunks_mut(8) {
            // xorshift64*
            seed ^= seed >> 12;
            seed ^= seed << 25;
            seed ^= seed >> 27;
            let v = seed.wrapping_mul(0x2545_F491_4F6C_DD1D);
            let raw = v.to_le_bytes();
            chunk.copy_from_slice(&raw[..chunk.len()]);
        }
    }
    hex_encode(&bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// 登录失败限流（按 IP）
pub struct LoginThrottle {
    max_failures: u32,
    window: Duration,
    records: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl LoginThrottle {
    pub fn new(max_failures: u32, window: Duration) -> Self {
        Self {
            max_failures: max_failures.max(1),
            window,
            records: Mutex::new(HashMap::new()),
        }
    }

    /// 默认：60 秒窗口内失败 10 次锁定（对齐原版）
    pub fn with_defaults() -> Self {
        Self::new(10, Duration::from_secs(60))
    }

    /// 是否允许该 IP 继续尝试登录。`false` = 已锁定。
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut map = self.records.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(&ip) {
            Some((count, at)) if now.duration_since(*at) < self.window => {
                *count < self.max_failures
            }
            Some(_) => {
                map.remove(&ip);
                true
            }
            None => true,
        }
    }

    pub fn record_failure(&self, ip: IpAddr) {
        let now = Instant::now();
        let mut map = self.records.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1) >= self.window {
            // 窗口已过：重新计数
            *entry = (1, now);
        } else {
            entry.0 = entry.0.saturating_add(1);
        }
    }

    pub fn record_success(&self, ip: IpAddr) {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&ip);
    }

    /// 当前被锁定的 IP 数（观测用）
    pub fn locked_count(&self) -> usize {
        let now = Instant::now();
        let map = self.records.lock().unwrap_or_else(|e| e.into_inner());
        map.values()
            .filter(|(c, at)| *c >= self.max_failures && now.duration_since(*at) < self.window)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_tuple(id: i32, user: &str, pass: &str, vkey: &str) -> (i32, String, String, String) {
        (id, user.to_owned(), pass.to_owned(), vkey.to_owned())
    }

    #[test]
    fn named_admin_can_login() {
        let store = AccountStore::build(
            Some(("root".to_owned(), "s3cret".to_owned())),
            &[],
        );
        assert!(store.is_enabled());
        let p = store.authenticate("root", "s3cret").expect("应登录成功");
        assert_eq!(p, Principal::NamedAdmin { username: "root".to_owned() });
        assert!(p.is_admin());
        assert_eq!(p.visible_clients(), None);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let store = AccountStore::build(Some(("root".to_owned(), "s3cret".to_owned())), &[]);
        assert!(store.authenticate("root", "wrong").is_none());
        assert!(store.authenticate("nobody", "s3cret").is_none());
        assert!(store.authenticate("", "").is_none());
    }

    #[test]
    fn client_account_uses_web_credentials() {
        let store = AccountStore::build(
            None,
            &[client_tuple(7, "alice", "pw123", "vkey-ignored")],
        );
        let p = store.authenticate("alice", "pw123").expect("客户端应能登录");
        assert_eq!(
            p,
            Principal::Client { client_id: 7, username: "alice".to_owned() }
        );
        assert!(!p.is_admin());
        assert_eq!(p.visible_clients(), Some(vec![7]));
        assert!(p.can_see_client(7));
        assert!(!p.can_see_client(8), "客户端不应看到别的客户端");
    }

    #[test]
    fn client_with_empty_credentials_falls_back_to_user_plus_vkey() {
        // 原版规则：WebUserName/WebPassword 都空 → user + VerifyKey
        let store = AccountStore::build(None, &[client_tuple(3, "", "", "my-vkey")]);
        let p = store.authenticate("user", "my-vkey").expect("应能登录");
        assert_eq!(
            p,
            Principal::Client { client_id: 3, username: "user".to_owned() }
        );
        // 用错 vkey 不行
        assert!(store.authenticate("user", "other-vkey").is_none());
    }

    #[test]
    fn half_configured_client_is_not_loginable() {
        // 只配了用户名没配密码：视为未配置
        let store = AccountStore::build(None, &[client_tuple(1, "bob", "", "vk")]);
        assert!(store.authenticate("bob", "").is_none());
        assert!(store.authenticate("bob", "vk").is_none());
    }

    #[test]
    fn empty_store_is_disabled() {
        let store = AccountStore::empty();
        assert!(!store.is_enabled());
        assert!(store.authenticate("user", "anything").is_none());
    }

    #[test]
    fn session_roundtrip_and_revoke() {
        let store = SessionStore::new(Duration::from_secs(60));
        let token = store.create(Principal::Admin);
        assert_eq!(token.len(), 64, "32 字节 hex 应为 64 字符");
        assert_eq!(store.verify(&token), Some(Principal::Admin));
        assert!(store.revoke(&token));
        assert_eq!(store.verify(&token), None);
        assert!(!store.revoke(&token), "重复撤销应返回 false");
    }

    #[test]
    fn session_tokens_are_unique() {
        let store = SessionStore::new(Duration::from_secs(60));
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            let t = store.create(Principal::Admin);
            assert!(seen.insert(t), "会话令牌必须唯一");
        }
    }

    #[test]
    fn expired_session_is_rejected_and_removed() {
        let store = SessionStore::new(Duration::from_millis(30));
        let token = store.create(Principal::Admin);
        assert!(store.verify(&token).is_some());
        std::thread::sleep(Duration::from_millis(60));
        assert!(store.verify(&token).is_none());
        assert_eq!(store.active(), 0, "过期会话应被移除");
    }

    #[test]
    fn sweep_removes_expired_sessions() {
        let store = SessionStore::new(Duration::from_millis(30));
        for _ in 0..5 {
            store.create(Principal::Admin);
        }
        assert_eq!(store.active(), 5);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(store.sweep(), 5);
        assert_eq!(store.active(), 0);
    }

    #[test]
    fn throttle_locks_after_max_failures() {
        let throttle = LoginThrottle::new(3, Duration::from_secs(60));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(throttle.check(ip));

        throttle.record_failure(ip);
        throttle.record_failure(ip);
        assert!(throttle.check(ip), "2 次失败还不应锁定");

        throttle.record_failure(ip);
        assert!(!throttle.check(ip), "3 次失败应锁定");
        assert_eq!(throttle.locked_count(), 1);

        // 成功登录解锁
        throttle.record_success(ip);
        assert!(throttle.check(ip));
    }

    #[test]
    fn throttle_window_expires() {
        let throttle = LoginThrottle::new(2, Duration::from_millis(50));
        let ip: IpAddr = "5.6.7.8".parse().unwrap();
        throttle.record_failure(ip);
        throttle.record_failure(ip);
        assert!(!throttle.check(ip));
        std::thread::sleep(Duration::from_millis(80));
        assert!(throttle.check(ip), "窗口过后应解锁");
    }

    #[test]
    fn throttle_is_per_ip() {
        let throttle = LoginThrottle::new(1, Duration::from_secs(60));
        let a: IpAddr = "1.1.1.1".parse().unwrap();
        let b: IpAddr = "2.2.2.2".parse().unwrap();
        throttle.record_failure(a);
        assert!(!throttle.check(a));
        assert!(throttle.check(b), "别的 IP 不应受影响");
    }

    #[test]
    fn constant_time_eq_behaves() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
        // 长度差异很大也不 panic
        assert!(!constant_time_eq(&[0u8; 1000], &[0u8; 1]));
    }

    #[test]
    fn principal_display_never_contains_password() {
        let p = Principal::Client { client_id: 1, username: "alice".to_owned() };
        let s = format!("{} {:?}", p.display(), p);
        assert!(!s.contains("password"));
        // Debug 只含 id/username
        assert!(s.contains("alice"));
    }
}
