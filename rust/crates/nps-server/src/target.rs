//! 多目标负载均衡与目标健康检查。
//!
//! 对齐 Go 原版 `lib/file/obj.go` 的 `Target.GetRandomTarget`（**顺序轮询**，
//! 名字叫 Random 但实现是轮询）与 `client/health.go` 的健康检查语义：
//! ```text
//! 目标列表 "a:80\nb:80\nc:80"（也接受逗号分隔）
//!   ├─ 顺序轮询：A → B → C → A …（不是随机）
//!   ├─ 健康检查（tcp / http）并发探测所有目标
//!   ├─ 连续失败 max_failed 次 → 标记离线并从轮询中摘除
//!   ├─ 离线目标继续探测，成功一次 → 恢复并重新加入轮询
//!   └─ 全部离线 → next() 返回 Err（调用方据此回 502，绝不 panic/空串）
//! ```
//!
//! # 与原版的差异（有意为之）
//! - 原版把失败计数放在 `HealthMap` 里，并靠 `% max_failed == 0` 反复发送
//!   「移除」信令；这里改为显式的 [`HealthState`]：计数、摘除/恢复各只发生一次。
//! - 原版只对 `HealthCheckTarget` 做检查、与轮询用的 `TargetArr` 各自独立；
//!   这里 [`HealthChecker`] 直接作用于 [`TargetPool`]，检查目标与轮询目标
//!   是同一份列表，不会出现「检查 A、轮询 B」的错位。
//! - 探测**并发**执行：N 个目标的最坏耗时 ≈ 单次超时，而不是 N × 超时。
//!
//! # 能力边界
//! - 只做探测与摘除/恢复，不负责重试、熔断统计、慢启动。
//! - HTTP 检查手写最小请求，不依赖 HTTP 客户端库，也不跟随重定向；
//!   状态码 2xx / 3xx 视为健康（与原版 `StatusCode != 200` 的严格判定相比
//!   略宽松，适配 301/302 的后端）。

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

/// 默认单次探测超时（秒级）。对齐原版「秒」粒度。
pub const DEFAULT_HEALTH_TIMEOUT: Duration = Duration::from_secs(5);
/// 默认连续失败阈值。
pub const DEFAULT_HEALTH_MAX_FAILED: u32 = 3;
/// 默认检查间隔。
pub const DEFAULT_HEALTH_INTERVAL: Duration = Duration::from_secs(10);
/// 时间参数下限：避免配置成 0 时忙循环 / 立即超时。
const MIN_DURATION: Duration = Duration::from_millis(10);
/// HTTP 探测响应状态行的读取上限，防止对端吐无限数据。
const MAX_STATUS_LINE_BYTES: usize = 8 * 1024;

/// 目标池错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    /// 目标列表为空（未配置任何可用目标）。
    Empty,
    /// 目标地址不是合法的 `host:port`。
    InvalidTarget(String),
    /// 所有目标都被健康检查标记为离线。
    AllOffline,
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "目标列表为空"),
            Self::InvalidTarget(t) => write!(f, "目标地址非法（应为 host:port）: {t:?}"),
            Self::AllOffline => write!(f, "all inward-bending targets are offline（所有目标均已离线）"),
        }
    }
}

impl std::error::Error for TargetError {}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // 目标池/状态表没有可被中断的共享不变量：中毒时继续用内部值，
    // 比在转发路径上 panic 更安全。
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// 目标池：顺序轮询 + 离线过滤
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct PoolState {
    /// 被健康检查摘除的目标（按字符串匹配）。
    offline: HashSet<String>,
    /// 下一次轮询的起始下标（指向完整目标列表）。
    cursor: usize,
}

/// 多目标轮询池。
///
/// 解析时保留配置顺序（同名重复项也被保留，等价于加权），轮询时**跳过**离线项：
/// 例如 `[A, B, C]` 中 B 离线后依次返回 `A, C, A, C …`。
///
/// 所有方法都是 `&self`，内部用锁保护游标与离线集合，可直接被多个转发任务共享
/// （通常包在 `Arc<TargetPool>` 里）。
#[derive(Debug)]
pub struct TargetPool {
    targets: Vec<String>,
    state: Mutex<PoolState>,
}

impl TargetPool {
    /// 解析目标列表。
    ///
    /// 分隔符：换行（兼容 `\r\n`）与逗号；空白项被忽略。每一项必须是
    /// `host:port`（IPv6 用 `[::1]:80`），否则返回 [`TargetError::InvalidTarget`]。
    /// 单目标池（配置已校验过地址合法性时的快捷构造）。
    pub fn single(target: &str) -> Self {
        Self {
            targets: vec![target.to_owned()],
            state: Mutex::new(PoolState::default()),
        }
    }

    pub fn parse(spec: &str) -> Result<Self, TargetError> {
        let mut targets = Vec::new();
        for raw in spec.split(['\n', '\r', ',']) {
            let item = raw.trim();
            if item.is_empty() {
                continue;
            }
            if split_host_port(item).is_none() {
                return Err(TargetError::InvalidTarget(item.to_owned()));
            }
            targets.push(item.to_owned());
        }
        if targets.is_empty() {
            return Err(TargetError::Empty);
        }
        Ok(Self {
            targets,
            state: Mutex::new(PoolState::default()),
        })
    }

    /// 当前可用（未离线）的目标，保持配置顺序。
    pub fn targets(&self) -> Vec<String> {
        let st = lock(&self.state);
        self.targets
            .iter()
            .filter(|t| !st.offline.contains(*t))
            .cloned()
            .collect()
    }

    /// 配置里的全部目标（含离线），保持配置顺序。
    pub fn all_targets(&self) -> Vec<String> {
        self.targets.clone()
    }

    /// 顺序轮询取下一个可用目标。
    ///
    /// 首次调用返回配置中的第一个目标；到达末尾后回绕。全部离线返回
    /// [`TargetError::AllOffline`]（调用方应据此返回 502，而不是 panic）。
    pub fn next(&self) -> Result<String, TargetError> {
        if self.targets.is_empty() {
            return Err(TargetError::Empty);
        }
        let n = self.targets.len();
        let mut st = lock(&self.state);
        for step in 0..n {
            let idx = (st.cursor + step) % n;
            if !st.offline.contains(&self.targets[idx]) {
                st.cursor = (idx + 1) % n;
                return Ok(self.targets[idx].clone());
            }
        }
        Err(TargetError::AllOffline)
    }

    /// 标记目标离线（幂等）。未知目标被忽略，避免离线集合无限增长。
    pub fn mark_offline(&self, target: &str) {
        if !self.targets.iter().any(|t| t == target) {
            return;
        }
        let mut st = lock(&self.state);
        if st.offline.insert(target.to_owned()) {
            debug!(target, "目标已摘除");
        }
    }

    /// 标记目标恢复（幂等）。
    pub fn mark_online(&self, target: &str) {
        let mut st = lock(&self.state);
        if st.offline.remove(target) {
            debug!(target, "目标已恢复");
        }
    }

    /// 目标是否被标记为离线。未知目标返回 false。
    pub fn is_offline(&self, target: &str) -> bool {
        lock(&self.state).offline.contains(target)
    }

    /// 当前可用目标数（不是配置总数；总数见 [`Self::total`]）。
    pub fn len(&self) -> usize {
        let st = lock(&self.state);
        self.targets
            .iter()
            .filter(|t| !st.offline.contains(*t))
            .count()
    }

    /// 配置中的目标总数（含离线）。
    pub fn total(&self) -> usize {
        self.targets.len()
    }

    /// 是否没有可用目标。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------
// 健康检查配置与状态
// ---------------------------------------------------------------------------

/// 探测方式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthCheckKind {
    /// TCP 握手（`TcpStream::connect`）。
    Tcp,
    /// HTTP GET，2xx / 3xx 算健康。`path` 为空时用 `/`。
    Http { path: String },
}

impl HealthCheckKind {
    /// 按原版配置字段构造：`health_check_type` 只有 `"tcp"` 是 TCP，
    /// 其余（含空值）都按 HTTP 处理（与 Go `client/health.go` 一致）。
    pub fn from_config(kind: &str, http_url: &str) -> Self {
        if kind.trim().eq_ignore_ascii_case("tcp") {
            Self::Tcp
        } else {
            Self::Http {
                path: http_url.trim().to_owned(),
            }
        }
    }
}

/// 健康检查配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthCheckConfig {
    /// 单次探测超时。
    pub timeout: Duration,
    /// 连续失败多少次才摘除；`0` 按 1 处理。
    pub max_failed: u32,
    /// 检查间隔；`0` 按 10ms 处理（避免忙循环）。
    pub interval: Duration,
    /// 探测方式。
    pub kind: HealthCheckKind,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_HEALTH_TIMEOUT,
            max_failed: DEFAULT_HEALTH_MAX_FAILED,
            interval: DEFAULT_HEALTH_INTERVAL,
            kind: HealthCheckKind::Tcp,
        }
    }
}

/// 单个目标当前的健康状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthState {
    /// 连续失败次数（成功即清零）。
    pub consecutive_failures: u32,
    /// 下次计划检查时间。
    pub next_check: std::time::Instant,
    /// 是否已因健康检查被摘除。
    pub offline: bool,
}

// ---------------------------------------------------------------------------
// 健康检查器
// ---------------------------------------------------------------------------

/// 周期探测 [`TargetPool`] 中所有目标，并同步维护离线集合。
///
/// `check_once` 对**全部**目标（含已离线）并发探测；离线目标成功一次即恢复。
pub struct HealthChecker {
    pool: Arc<TargetPool>,
    cfg: HealthCheckConfig,
    states: Mutex<HashMap<String, HealthState>>,
}

impl HealthChecker {
    /// 创建检查器。参数为 0 的时长/阈值会被安全下限兜住，不会忙循环或立即超时。
    pub fn new(pool: Arc<TargetPool>, cfg: HealthCheckConfig) -> Self {
        Self {
            pool,
            cfg,
            states: Mutex::new(HashMap::new()),
        }
    }

    /// 当前配置。
    pub fn config(&self) -> &HealthCheckConfig {
        &self.cfg
    }

    /// 目标池引用。
    pub fn pool(&self) -> &Arc<TargetPool> {
        &self.pool
    }

    /// 某个目标的最近状态；尚未检查过时返回 `None`。
    pub fn state_of(&self, target: &str) -> Option<HealthState> {
        lock(&self.states).get(target).copied()
    }

    fn interval(&self) -> Duration {
        self.cfg.interval.max(MIN_DURATION)
    }

    fn max_failed(&self) -> u32 {
        self.cfg.max_failed.max(1)
    }

    /// 对所有目标并发跑一次检查，返回 `(目标, 是否健康)`。
    ///
    /// 结果顺序与 [`TargetPool::all_targets`] 一致，便于日志与断言。
    /// 同时更新每个目标的连续失败计数、离线标记（达到阈值才摘除）与恢复。
    pub async fn check_once(&self) -> Vec<(String, bool)> {
        let targets = self.pool.all_targets();
        let mut set = JoinSet::new();
        for (idx, target) in targets.iter().enumerate() {
            let target = target.clone();
            let cfg = self.cfg.clone();
            // 每个目标一个独立任务：N 个目标的耗时 ≈ 单次超时，而不是累加。
            set.spawn(async move {
                let ok = probe(&target, &cfg).await;
                (idx, target, ok)
            });
        }

        let mut slots: Vec<Option<(String, bool)>> = vec![None; targets.len()];
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((idx, target, ok)) => slots[idx] = Some((target, ok)),
                Err(e) => warn!(error = %e, "健康检查任务异常结束"),
            }
        }
        let results: Vec<(String, bool)> = slots.into_iter().flatten().collect();

        let now = std::time::Instant::now();
        let next_check = now + self.interval();
        let mut newly_offline = Vec::new();
        let mut recovered = Vec::new();
        {
            let mut states = lock(&self.states);
            for (target, ok) in &results {
                let st = states.entry(target.clone()).or_insert(HealthState {
                    consecutive_failures: 0,
                    next_check,
                    offline: self.pool.is_offline(target),
                });
                st.next_check = next_check;
                if *ok {
                    let was_offline = st.offline;
                    st.consecutive_failures = 0;
                    st.offline = false;
                    if was_offline {
                        recovered.push(target.clone());
                    }
                } else {
                    st.consecutive_failures = st.consecutive_failures.saturating_add(1);
                    if !st.offline && st.consecutive_failures >= self.max_failed() {
                        st.offline = true;
                        newly_offline.push(target.clone());
                    }
                }
            }
        }

        // 锁外同步到目标池，避免与转发路径上的 `next()` 长时间争用。
        for target in &newly_offline {
            self.pool.mark_offline(target);
            warn!(
                target,
                max_failed = self.max_failed(),
                "健康检查连续失败达到阈值，摘除目标"
            );
        }
        for target in &recovered {
            self.pool.mark_online(target);
            info!(target, "健康检查通过，目标已恢复");
        }

        results
    }

    /// 周期检查循环，收到 `cancel = true`（或发送端被丢弃）后退出。
    ///
    /// 启动后立即检查一次，之后每 `interval` 检查一次；便于启动阶段尽快
    /// 发现坏目标。
    pub async fn run(self: Arc<Self>, mut cancel: watch::Receiver<bool>) {
        let interval = self.interval();
        loop {
            if *cancel.borrow() {
                break;
            }
            let results = self.check_once().await;
            let healthy = results.iter().filter(|(_, ok)| *ok).count();
            debug!(
                healthy,
                total = results.len(),
                "健康检查完成；可用目标 {} 个",
                self.pool.len()
            );

            tokio::select! {
                changed = cancel.changed() => {
                    // 发送端销毁（Err）也视为停止信号。
                    if changed.is_err() || *cancel.borrow() {
                        break;
                    }
                }
                _ = tokio::time::sleep(interval) => {}
            }
        }
        debug!("健康检查循环已退出");
    }
}

// ---------------------------------------------------------------------------
// 探测实现
// ---------------------------------------------------------------------------

/// 对单个目标执行一次探测；任何失败（含超时、DNS 失败、非 2xx/3xx）都返回 false。
pub async fn probe(target: &str, cfg: &HealthCheckConfig) -> bool {
    let timeout = cfg.timeout.max(MIN_DURATION);
    match &cfg.kind {
        HealthCheckKind::Tcp => tcp_probe(target, timeout).await,
        HealthCheckKind::Http { path } => http_probe(target, path, timeout).await,
    }
}

async fn tcp_probe(target: &str, timeout: Duration) -> bool {
    match tokio::time::timeout(timeout, TcpStream::connect(target)).await {
        Ok(Ok(stream)) => {
            drop(stream);
            true
        }
        Ok(Err(e)) => {
            debug!(target, error = %e, "TCP 健康检查失败");
            false
        }
        Err(_) => {
            debug!(target, "TCP 健康检查超时");
            false
        }
    }
}

async fn http_probe(target: &str, path: &str, timeout: Duration) -> bool {
    let Some((host, _port)) = split_host_port(target) else {
        return false;
    };
    let path = normalize_path(path);
    // 手写最小 HTTP/1.1：只关心状态行，`Connection: close` 后对端会关闭连接。
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: rnps-health/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );

    let exchange = async move {
        let mut stream = TcpStream::connect(target).await.ok()?;
        stream.write_all(request.as_bytes()).await.ok()?;
        stream.flush().await.ok()?;

        let mut buf = Vec::with_capacity(256);
        let mut chunk = [0u8; 256];
        loop {
            if let Some(line_end) = buf.iter().position(|&b| b == b'\n') {
                return parse_status_code(&buf[..line_end]);
            }
            if buf.len() > MAX_STATUS_LINE_BYTES {
                return None;
            }
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                // 对端没给完整行就关了：仍尝试按已有字节解析。
                return parse_status_code(&buf);
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    };

    match tokio::time::timeout(timeout, exchange).await {
        Ok(Some(code)) if (200..400).contains(&code) => true,
        Ok(Some(code)) => {
            debug!(target, code, "HTTP 健康检查状态码不健康");
            false
        }
        Ok(None) => {
            debug!(target, "HTTP 健康检查响应无法解析");
            false
        }
        Err(_) => {
            debug!(target, "HTTP 健康检查超时");
            false
        }
    }
}

/// 从状态行（不含换行）解析状态码：`HTTP/1.1 200 OK` -> 200。
fn parse_status_code(line: &[u8]) -> Option<u16> {
    let line = std::str::from_utf8(line).ok()?.trim_end_matches('\r');
    let mut parts = line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse::<u16>().ok()
}

/// 校验并拆分 `host:port`。IPv6 必须写成 `[::1]:80`；端口必须是数字。
fn split_host_port(s: &str) -> Option<(&str, u16)> {
    let s = s.trim();
    if s.is_empty() || s.chars().any(char::is_whitespace) {
        return None;
    }
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port = rest[end + 1..].strip_prefix(':')?.parse::<u16>().ok()?;
        return (!host.is_empty()).then_some((host, port));
    }
    let (host, port) = s.rsplit_once(':')?;
    if host.is_empty() || host.contains(':') {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    Some((host, port))
}

/// HTTP 检查路径：空 -> `/`，非 `/` 开头补上前导斜杠。
fn normalize_path(path: &str) -> String {
    let path = path.trim();
    if path.is_empty() {
        "/".to_owned()
    } else if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn split_host_port_accepts_domain_ipv4_and_ipv6() {
        assert_eq!(split_host_port("a.example.com:8080"), Some(("a.example.com", 8080)));
        assert_eq!(split_host_port("127.0.0.1:80"), Some(("127.0.0.1", 80)));
        assert_eq!(split_host_port("[::1]:443"), Some(("::1", 443)));
    }

    #[test]
    fn split_host_port_rejects_bad_input() {
        for bad in ["", ":80", "host:", "host:abc", "::1:80", "a b:80"] {
            assert_eq!(split_host_port(bad), None, "应拒绝 {bad:?}");
        }
    }

    #[test]
    fn parse_accepts_newline_and_comma() {
        let pool = TargetPool::parse("a:1\nb:2\r\nc:3, d:4").unwrap();
        assert_eq!(pool.all_targets(), ["a:1", "b:2", "c:3", "d:4"]);
        assert_eq!(pool.total(), 4);
        assert_eq!(pool.len(), 4);
    }

    #[test]
    fn parse_rejects_empty_and_invalid() {
        assert_eq!(TargetPool::parse(" \n , ").unwrap_err(), TargetError::Empty);
        assert_eq!(
            TargetPool::parse("a:1\nbad").unwrap_err(),
            TargetError::InvalidTarget("bad".into())
        );
    }

    #[test]
    fn parse_keeps_duplicates_in_order() {
        let pool = TargetPool::parse("a:1\na:1\nb:2").unwrap();
        let got: Vec<_> = (0..4).map(|_| pool.next().unwrap()).collect();
        assert_eq!(got, ["a:1", "a:1", "b:2", "a:1"]);
    }

    #[test]
    fn unknown_target_offline_is_ignored() {
        let pool = TargetPool::parse("a:1").unwrap();
        pool.mark_offline("zzz:9");
        assert!(!pool.is_offline("zzz:9"));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn normalize_path_variants() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/health"), "/health");
        assert_eq!(normalize_path("health"), "/health");
    }

    #[test]
    fn health_kind_from_config_matches_go() {
        assert_eq!(HealthCheckKind::from_config("tcp", "/x"), HealthCheckKind::Tcp);
        assert_eq!(HealthCheckKind::from_config("TCP ", "/x"), HealthCheckKind::Tcp);
        assert_eq!(
            HealthCheckKind::from_config("http", "/x"),
            HealthCheckKind::Http { path: "/x".into() }
        );
        assert_eq!(
            HealthCheckKind::from_config("", ""),
            HealthCheckKind::Http { path: String::new() }
        );
    }
}
