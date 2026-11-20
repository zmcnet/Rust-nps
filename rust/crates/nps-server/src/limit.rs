//! 流控三件套：**限速**（`rate_limit`）、**流量上限**（`flow_limit`）、
//! **IP 访问限制**（`ip_limit` 的简化版）。
//!
//! 对应 Go 原版：
//! - `lib/rate/rate.go` + `lib/rate/conn.go` —— 令牌桶，单位 KB/s
//! - `lib/file/obj.go` 的 `Flow` + `server/proxy/base.go::CheckFlowAndConnNum`
//! - `bridge/bridge.go::SendLinkInfo` 的 `ipVerify`（简化：只做静态白名单，
//!   不做 `rgst` 注册流程）
//!
//! # 与 Go 版的差异（有意为之）
//! - Go 的令牌桶由后台 goroutine 每秒 tick 补充，容量是 `2 × addSize`。
//!   这里改为**惰性补充**（按真实流逝时间折算），并按 1 秒的突发量设容量，
//!   这样既不占后台任务、精度也更高（sleep 超时不会累计丢吞吐，因为补充量
//!   按真实时间算）。
//! - Go 的 `Get(size)` 以 100ms 轮询等待；这里直接按缺口算出需要等待的时长
//!   再 sleep，等待精度只受 OS 定时器粒度影响。
//!
//! # 并发模型
//! 桶状态只被一个**极短**的临界区保护（加减令牌 + 记账），任何等待都发生在
//! 锁外（`tokio::time::sleep`）。因此多条连接共享同一个桶时互不阻塞，总吞吐
//! 仍是配置的单份速率，而不是「每条连接各一份」。
//!
//! # 溢出安全
//! 所有累加走 `saturating_add`。`FlowCounter::exceeded()` 一旦为 `true`
//! 就永久为 `true`（与 Go 版一致：流量超标后不会因为计数变化而恢复）。

use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::time::Instant;

/// 1 KB = 1024 字节（`rate_limit` / `flow_limit` 的单位都是 KB）
pub const BYTES_PER_KB: u64 = 1024;
/// 单次等待的下限，避免浮点误差导致忙等空转
const MIN_SLEEP: Duration = Duration::from_millis(1);

// ---------------------------------------------------------------------------
// 令牌桶限速
// ---------------------------------------------------------------------------

/// 令牌桶限速器（KB/s），线程安全，**可被多条连接共享**（放进 `Arc` 即可）。
///
/// `kb_per_sec == 0` 表示不限速：`acquire` 直接返回，不做任何加锁。
///
/// ```no_run
/// # use std::sync::Arc;
/// # use nps_server::TokenBucket;
/// # async fn f() {
/// let bucket = Arc::new(TokenBucket::new(100)); // 100 KB/s
/// bucket.acquire(4096).await;                   // 等够 4 KiB 配额再放行
/// # }
/// ```
pub struct TokenBucket {
    /// 每秒补充的字节数（0 = 不限速）
    bytes_per_sec: u64,
    /// 桶容量（字节）：等于 1 秒的配额，即允许 1 秒的突发
    capacity: f64,
    inner: Mutex<BucketState>,
}

#[derive(Debug)]
struct BucketState {
    /// 当前可用令牌（字节，保留小数，避免小包被取整吃掉吞吐）
    tokens: f64,
    /// 上次补充时刻
    last: Instant,
}

impl TokenBucket {
    /// 按 KB/s 建桶；`0` 表示不限速。
    pub fn new(kb_per_sec: u64) -> Self {
        let bytes_per_sec = kb_per_sec.saturating_mul(BYTES_PER_KB);
        let capacity = bytes_per_sec as f64;
        Self {
            bytes_per_sec,
            capacity,
            // 初始满桶：空闲链路的第一段数据不该被拖延
            inner: Mutex::new(BucketState {
                tokens: capacity,
                last: Instant::now(),
            }),
        }
    }

    /// 是否不限速
    pub fn is_unlimited(&self) -> bool {
        self.bytes_per_sec == 0
    }

    /// 观测用：配置的速率（KB/s）
    pub fn current_rate(&self) -> u64 {
        self.bytes_per_sec / BYTES_PER_KB
    }

    /// 申请 `n` 字节配额；额度不足时等待到够用为止。
    ///
    /// 不限速、或 `n == 0` 时立即返回（无锁、无 await）。
    pub async fn acquire(&self, n: usize) {
        if n == 0 || self.is_unlimited() {
            return;
        }
        // 单次申请可能大于桶容量（例如一次性 1 MB）：拆成若干片，
        // 否则永远等不满，会死等。
        let chunk_cap = self.capacity as u64;
        let mut remaining = n as u64;
        while remaining > 0 {
            let chunk = remaining.min(chunk_cap);
            self.acquire_chunk(chunk).await;
            remaining -= chunk;
        }
    }

    async fn acquire_chunk(&self, n: u64) {
        loop {
            let wait_secs = {
                let mut state = self.lock();
                let now = Instant::now();
                let elapsed = now.saturating_duration_since(state.last).as_secs_f64();
                if elapsed > 0.0 {
                    // 按真实流逝时间补充：sleep 超时不会累计丢吞吐
                    state.tokens =
                        (state.tokens + elapsed * self.bytes_per_sec as f64).min(self.capacity);
                    state.last = now;
                }
                if state.tokens >= n as f64 {
                    state.tokens -= n as f64;
                    return;
                }
                // 临界区外再 sleep：等待期间其它连接照常取令牌
                (n as f64 - state.tokens) / self.bytes_per_sec as f64
            };
            let wait = Duration::from_secs_f64(wait_secs).max(MIN_SLEEP);
            tokio::time::sleep(wait).await;
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BucketState> {
        // 锁中毒不影响令牌语义（状态只是计数），直接取出内部值继续用
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl fmt::Debug for TokenBucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.lock();
        f.debug_struct("TokenBucket")
            .field("kb_per_sec", &self.current_rate())
            .field("capacity_bytes", &self.capacity)
            .field("tokens", &state.tokens)
            .field("unlimited", &self.is_unlimited())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// 流量计数 + 上限
// ---------------------------------------------------------------------------

/// 客户端总流量计数与上限（KB）。
///
/// 达标判定对齐 Go `CheckFlowAndConnNum`：`limit != 0 && total > limit` 即算超限。
/// `exceeded()` 一旦为真就**永久**为真。
pub struct FlowCounter {
    /// 上限（字节）；0 = 不限
    limit_bytes: u64,
    up: AtomicU64,
    down: AtomicU64,
    total: AtomicU64,
    exceeded: AtomicBool,
}

impl FlowCounter {
    /// 按 KB 建计数器；`limit_kb == 0` 表示不限流量。
    pub fn new(limit_kb: u64) -> Self {
        Self {
            limit_bytes: limit_kb.saturating_mul(BYTES_PER_KB),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            total: AtomicU64::new(0),
            exceeded: AtomicBool::new(false),
        }
    }

    /// 累加一次转发的字节数。`up` 为上行（进客户端），`down` 为下行（出客户端）。
    pub fn add(&self, up: u64, down: u64) {
        if up != 0 {
            let _ = self.up.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_add(up))
            });
        }
        if down != 0 {
            let _ = self
                .down
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_add(down))
                });
        }
        let delta = up.saturating_add(down);
        if delta == 0 {
            return;
        }
        // total 单独维护，保证「超限」判断单调（不受 up/down 分别读取的竞态影响）
        let _ = self
            .total
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_add(delta))
            });
        if self.limit_bytes != 0 && self.total.load(Ordering::Relaxed) > self.limit_bytes {
            self.exceeded.store(true, Ordering::Relaxed);
        }
    }

    /// 已用流量 `(上行, 下行)`，单位字节。
    pub fn total(&self) -> (u64, u64) {
        (
            self.up.load(Ordering::Relaxed),
            self.down.load(Ordering::Relaxed),
        )
    }

    /// 是否已超限（一旦为真永久为真）
    pub fn exceeded(&self) -> bool {
        self.exceeded.load(Ordering::Relaxed)
    }

    /// 上限（KB）；0 表示不限
    pub fn limit_kb(&self) -> u64 {
        self.limit_bytes / BYTES_PER_KB
    }
}

impl fmt::Debug for FlowCounter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (up, down) = self.total();
        f.debug_struct("FlowCounter")
            .field("limit_kb", &self.limit_kb())
            .field("up_bytes", &up)
            .field("down_bytes", &down)
            .field("exceeded", &self.exceeded())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// IP 白名单
// ---------------------------------------------------------------------------

/// 一条网络：单个 IP 或 CIDR
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpNet {
    base: IpAddr,
    prefix: u8,
}

impl IpNet {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.base, ip) {
            (IpAddr::V4(base), IpAddr::V4(ip)) => {
                mask_v4(u32::from(base), self.prefix) == mask_v4(u32::from(ip), self.prefix)
            }
            (IpAddr::V6(base), IpAddr::V6(ip)) => {
                mask_v6(u128::from(base), self.prefix) == mask_v6(u128::from(ip), self.prefix)
            }
            // 不同地址族不匹配（IPv4-mapped IPv6 由调用方先做归一化）
            _ => false,
        }
    }
}

fn mask_v4(bits: u32, prefix: u8) -> u32 {
    let prefix = prefix.min(32);
    if prefix == 0 {
        0
    } else {
        bits & (u32::MAX << (32 - prefix))
    }
}

fn mask_v6(bits: u128, prefix: u8) -> u128 {
    let prefix = prefix.min(128);
    if prefix == 0 {
        0
    } else {
        bits & (u128::MAX << (128 - prefix))
    }
}

/// IP 白名单（支持单 IP 与 CIDR，IPv4 / IPv6 均可）。
///
/// **空表 = 全部允许**（对齐「未配置 ip_limit 即不限制」的默认行为）。
#[derive(Debug, Clone, Default)]
pub struct IpAllowList {
    entries: Vec<IpNet>,
}

impl IpAllowList {
    /// 解析配置条目，如 `"1.2.3.4"` / `"10.0.0.0/8"` / `"2001:db8::/32"`。
    ///
    /// 空条目、非法 IP、前缀越界都会报错（不静默跳过，避免配置写错后
    /// 意外放开全部来源）。
    pub fn new(entries: &[String]) -> Result<Self> {
        let mut parsed = Vec::with_capacity(entries.len());
        for raw in entries {
            let entry = raw.trim();
            if entry.is_empty() {
                bail!("IP 白名单存在空条目");
            }
            parsed.push(parse_entry(entry).with_context(|| {
                format!("IP 白名单条目非法: {entry:?}（应为 IP 或 CIDR，如 10.0.0.0/8）")
            })?);
        }
        Ok(Self { entries: parsed })
    }

    /// 是否未配置任何条目（此时 [`Self::allows`] 恒为 `true`）
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 该来源 IP 是否被允许
    pub fn allows(&self, ip: IpAddr) -> bool {
        if self.entries.is_empty() {
            return true;
        }
        // IPv4-mapped IPv6（::ffff:1.2.3.4）归一成 IPv4 再比，避免双栈监听下漏判
        let ip = normalize(ip);
        self.entries.iter().any(|net| net.contains(ip))
    }
}

/// 把 IPv4-mapped IPv6 归一成 IPv4
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

fn parse_entry(entry: &str) -> Result<IpNet> {
    match entry.split_once('/') {
        None => {
            let ip: IpAddr = entry.parse().context("无法解析 IP 字面量")?;
            let prefix = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            Ok(IpNet {
                base: normalize(ip),
                prefix,
            })
        }
        Some((addr, len)) => {
            let ip: IpAddr = addr.trim().parse().context("无法解析 CIDR 的地址部分")?;
            let len: u8 = len.trim().parse().context("无法解析 CIDR 的前缀长度")?;
            let (max, v4) = match ip {
                IpAddr::V4(_) => (32u8, true),
                IpAddr::V6(_) => (128u8, false),
            };
            if len > max {
                bail!("CIDR 前缀长度超出范围: /{len}（最大 /{max}）");
            }
            // IPv4-mapped CIDR 归一后前缀要减 96，这里直接拒绝这种写法，避免歧义
            if !v4 && ip.to_string().starts_with("::ffff:") {
                bail!("IPv4-mapped IPv6 网段请直接写 IPv4 CIDR（如 10.0.0.0/8）");
            }
            Ok(IpNet {
                base: ip,
                prefix: len,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// 客户端流控组合 / 单方向节流视图
// ---------------------------------------------------------------------------

/// 单个客户端的流控组合。
///
/// 原版 NPS 的 `rate_limit` / `flow_limit` 是**客户端级**配额（该客户端名下
/// 所有隧道共享一份），`ip_limit` 是服务端级白名单。本结构把三者打成一包，
/// 让每条转发路径只需要接收一个参数，而不是「三个 Option 满天飞」——
/// 这是覆盖全部转发路径（UDP / SOCKS5 / HTTP / file / secret / conf）
/// 时最容易出错的地方。
///
/// `Default` = 不限速、不限流量、白名单为空（全部允许）。
#[derive(Clone, Default)]
pub struct ClientControls {
    /// 限速（与同客户端其它路径共享）
    pub rate: Option<Arc<TokenBucket>>,
    /// 流量上限（与同客户端其它路径共享）
    pub flow: Option<Arc<FlowCounter>>,
    /// 来源 IP 白名单（空表 = 全部允许）
    pub ip_allow: Arc<IpAllowList>,
}

impl ClientControls {
    /// 该来源 IP 是否被允许（空表恒为 true）
    pub fn ip_allowed(&self, ip: IpAddr) -> bool {
        self.ip_allow.allows(ip)
    }

    /// 流量是否已超限（`flow_limit == 0` 时恒为 false）
    pub fn flow_exceeded(&self) -> bool {
        self.flow.as_ref().is_some_and(|f| f.exceeded())
    }

    /// 申请 `n` 字节的发送配额（不限速时立即返回）
    pub async fn throttle(&self, n: usize) {
        if let Some(rate) = &self.rate {
            rate.acquire(n).await;
        }
    }

    /// 记 `(上行, 下行)` 字节（未配置流量上限时是空操作）
    pub fn count(&self, up: u64, down: u64) {
        if let Some(flow) = &self.flow {
            flow.add(up, down);
        }
    }
}

/// 一条转发方向上的节流视图：把 [`ClientControls`] 绑定到「上行 / 下行」，
/// 调用点只需 `gate(n)` + `count(n)`，不必每次重复方向判断。
///
/// `up = true` 表示「外部 → 客户端」（服务端视角的上行），
/// `up = false` 表示「客户端 → 外部」。
#[derive(Clone)]
pub struct Throttle {
    rate: Option<Arc<TokenBucket>>,
    flow: Option<Arc<FlowCounter>>,
    up: bool,
}

impl Throttle {
    /// 没有该客户端的流控配置时退化为「不限速、不记账」。
    pub fn optional(controls: Option<&ClientControls>, up: bool) -> Self {
        match controls {
            Some(c) => Self::new(c, up),
            None => Self {
                rate: None,
                flow: None,
                up,
            },
        }
    }

    pub fn new(controls: &ClientControls, up: bool) -> Self {
        Self {
            rate: controls.rate.clone(),
            flow: controls.flow.clone(),
            up,
        }
    }

    /// 写数据前申请配额（数据量大时可能等待）
    pub async fn gate(&self, n: usize) {
        if let Some(rate) = &self.rate {
            rate.acquire(n).await;
        }
    }

    /// 写成功后记账（按构造时固定的方向）
    pub fn count(&self, n: usize) {
        if let Some(flow) = &self.flow {
            let n = n as u64;
            if self.up {
                flow.add(n, 0);
            } else {
                flow.add(0, n);
            }
        }
    }
}
