//! 桥端口 vkey 防爆破：按来源 IP 的握手失败记账。
//!
//! 为什么需要：桥端口接受任意来源的 TCP 连接，握手失败原本只关闭连接、
//! 不做任何记账——攻击者可以无限制地穷举 vkey。这里按来源 IP 记录滑动
//! 窗口内的握手失败次数，达到阈值后该 IP 进入冷却期：冷却期内的新连接
//! 直接关闭（不再进握手），且冷却期内每次被拒的连接都会顺延冷却期，
//! 持续尝试的攻击者永远等不到冷却期结束。
//!
//! 内存安全设计：
//! - 跟踪的 IP 数量有硬上限（[`GuardConfig::max_ips`]），满了先回收过期
//!   记录腾位，仍满则按「最近活动」淘汰最旧的，绝不无限增长、绝不 panic；
//! - 没有独立后台任务：过期回收搭便车于正常流量（每条连接入口都会经过
//!   [`IpGuard::is_blocked`]，每次失败记账都会经过 [`IpGuard::record_failure`]），
//!   按窗口长度节流；即使流量完全停止，映射也保持在上限之内。
//!
//! 日志约定：调用方只记来源 IP 与失败原因类别，绝不出现 vkey 或
//! md5(vkey) 的值。

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// 防爆破参数。
///
/// 默认值的取舍：
/// - 阈值 10 次 / 窗口 10 分钟：NAT 后面常有多个合法用户共享同一出口 IP，
///   阈值过紧会误伤；正常用户几乎不可能在 10 分钟内握手失败 10 次。
/// - 冷却 10 分钟：足以让脚本化穷举失去效率，又不至于把动态 IP 用户
///   永久挡在门外。
/// - 上限 10000 条：来源 IP 数爆炸时的内存保险丝（每条记录仅几十字节，
///   1 万条远小于 1MB），满了按最旧淘汰。
#[derive(Debug, Clone)]
pub(crate) struct GuardConfig {
    /// 滑动窗口长度：只统计最近这段时长内的失败
    pub(crate) window: Duration,
    /// 窗口内失败达到该次数即进入冷却期
    pub(crate) max_failures: usize,
    /// 冷却期时长：期间新连接直接关闭，且每次被拒的尝试都会顺延
    pub(crate) cooldown: Duration,
    /// 跟踪的 IP 数上限，满了按最近活动最旧淘汰
    pub(crate) max_ips: usize,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(10 * 60),
            max_failures: 10,
            cooldown: Duration::from_secs(10 * 60),
            max_ips: 10_000,
        }
    }
}

/// 单次失败记账的结果（供调用方决定日志级别）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailureOutcome {
    /// 记了一次失败，尚未达到阈值
    Counted,
    /// 窗口内失败达到阈值，进入冷却期
    CooldownStarted,
    /// 该 IP 已在冷却期内：本次尝试被拒，冷却期顺延
    CooldownExtended,
}

/// 单个来源 IP 的失败记录。
struct IpRecord {
    /// 滑动窗口内的失败时刻（升序；进入冷却期时清空，冷却结束后从零计起）
    failures: VecDeque<Instant>,
    /// 冷却截止时刻；`None` = 从未进入冷却期
    cooldown_until: Option<Instant>,
    /// 最近活动时刻（淘汰依据）：每次记账都刷新
    last_active: Instant,
}

/// 按来源 IP 的失败记账器。
///
/// 所有方法都显式接收 `now`：`Instant` 不受 tokio 假时钟影响，若在方法内
/// 隐式取当前时间，单测就得睡真实时间，又慢又脆；显式传时刻后，测试用
/// 「基准时刻 + 偏移」的合成时刻即可做确定性断言。
pub(crate) struct IpGuard {
    cfg: GuardConfig,
    records: HashMap<IpAddr, IpRecord>,
    /// 上次全量回收时刻（回收按窗口长度节流，避免每次记账都 O(n) 扫全表）
    last_sweep: Instant,
}

impl IpGuard {
    pub(crate) fn new(cfg: GuardConfig) -> Self {
        Self {
            cfg,
            records: HashMap::new(),
            last_sweep: Instant::now(),
        }
    }

    /// 该 IP 是否处于冷却期（连接入口调用：是则直接关闭、不进握手）。
    /// 顺带按窗口节流回收过期记录。
    pub(crate) fn is_blocked(&mut self, now: Instant, ip: &IpAddr) -> bool {
        self.maybe_sweep(now);
        match self.records.get(ip) {
            Some(r) => matches!(r.cooldown_until, Some(until) if until > now),
            None => false,
        }
    }

    /// 记一次失败（vkey 校验不过 / 超时 / 协议错，含冷却期内被拒的尝试）。
    pub(crate) fn record_failure(&mut self, now: Instant, ip: &IpAddr) -> FailureOutcome {
        self.maybe_sweep(now);

        // 内存保险丝：新 IP 进表前若已达上限，先回收过期记录腾位；
        // 仍满则按最近活动淘汰最旧的。O(n) 扫描只在「插入新 IP 且满员」
        // 时发生（上限 1 万，每条连接至多一次），常数开销可忽略——换来
        // 不需要维护额外的、本身也会无界增长的 LRU 链表结构。
        if !self.records.contains_key(ip) && self.records.len() >= self.cfg.max_ips {
            self.sweep(now);
            if self.records.len() >= self.cfg.max_ips {
                let oldest = self
                    .records
                    .iter()
                    .min_by_key(|(_, r)| r.last_active)
                    .map(|(k, _)| *k);
                if let Some(oldest) = oldest {
                    self.records.remove(&oldest);
                }
            }
        }

        let cfg = &self.cfg;
        let r = self.records.entry(*ip).or_insert_with(|| IpRecord {
            failures: VecDeque::new(),
            cooldown_until: None,
            last_active: now,
        });
        r.last_active = now;

        // 冷却期内被拒的尝试同样算失败：顺延冷却期，持续重试的攻击者
        // 永远出不了冷却期。注意顺延不向窗口追加失败——冷却结束后从
        // 零计起，避免历史拒绝把冷却结束后的第一次普通失败又立即顶回
        // 冷却期。
        if matches!(r.cooldown_until, Some(until) if until > now) {
            r.cooldown_until = Some(now + cfg.cooldown);
            return FailureOutcome::CooldownExtended;
        }

        // 滑动窗口：丢弃窗口外的旧失败
        while let Some(front) = r.failures.front() {
            if front.saturating_duration_since(now) > cfg.window {
                r.failures.pop_front();
            } else {
                break;
            }
        }
        r.failures.push_back(now);

        if r.failures.len() >= cfg.max_failures {
            r.cooldown_until = Some(now + cfg.cooldown);
            r.failures.clear();
            FailureOutcome::CooldownStarted
        } else {
            FailureOutcome::Counted
        }
    }

    /// 校验成功：立即清除该 IP 的全部失败记录。
    ///
    /// 为什么整条记录删除而不只是清零失败数：成功即代表该来源是合法
    /// 客户端（NAT 场景下同一出口 IP 的其他用户也因此受益），历史失败
    /// 与冷却状态一并作废。
    pub(crate) fn clear(&mut self, ip: &IpAddr) {
        self.records.remove(ip);
    }

    /// 全量回收：删除「冷却已结束 且 窗口内无失败」的记录。
    ///
    /// 搭便车于正常流量（[`Self::is_blocked`] / [`Self::record_failure`]
    /// 都按窗口节流调用），不设独立后台任务——无流量时映射也保持在上限
    /// 之内，不会无限增长。
    pub(crate) fn sweep(&mut self, now: Instant) {
        self.last_sweep = now;
        self.records.retain(|_, r| {
            let in_cooldown = matches!(r.cooldown_until, Some(until) if until > now);
            // failures 升序，队尾即最新一次失败；最新一次仍在窗口内则整条保留
            let recent_failure = r
                .failures
                .back()
                .is_some_and(|f| f.saturating_duration_since(now) <= self.cfg.window);
            in_cooldown || recent_failure
        });
    }

    fn maybe_sweep(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_sweep) >= self.cfg.window {
            self.sweep(now);
        }
    }
}

/// 归一化来源 IP：把 IPv4-mapped IPv6（`::ffff:a.b.c.d`）折算回 IPv4。
///
/// dual-stack 监听下同一来源可能以 v4 / v6-mapped 两种形态出现，
/// 不折算会各记一份账、阈值被稀释一倍。
pub(crate) fn normalize_peer_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造参数（测试用简写）
    fn cfg(window_secs: u64, max_failures: usize, cooldown_secs: u64, max_ips: usize) -> GuardConfig {
        GuardConfig {
            window: Duration::from_secs(window_secs),
            max_failures,
            cooldown: Duration::from_secs(cooldown_secs),
            max_ips,
        }
    }

    /// 测试基准时刻。所有合成时刻都取 `基准 + 偏移`（只加不减），
    /// 避免 `Instant::now() - 长时长` 在刚开机等场景下下溢 panic。
    fn t0() -> Instant {
        Instant::now()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// 窗口内失败达到阈值才进入冷却期；阈值前不拦截。
    #[test]
    fn failure_counting_reaches_threshold() {
        let mut g = IpGuard::new(cfg(600, 10, 600, 100));
        let now = t0();
        let a = ip("203.0.113.9");
        for i in 1..10 {
            let at = now + Duration::from_secs(i);
            assert_eq!(g.record_failure(at, &a), FailureOutcome::Counted);
            assert!(!g.is_blocked(at, &a), "未达阈值不应拦截");
        }
        assert_eq!(
            g.record_failure(now + Duration::from_secs(10), &a),
            FailureOutcome::CooldownStarted
        );
        assert!(g.is_blocked(now + Duration::from_secs(11), &a));
        // 其他 IP 不受影响
        assert!(!g.is_blocked(now + Duration::from_secs(11), &ip("203.0.113.10")));
    }

    /// 冷却期过后重新放行，且从零计起（历史失败已清空，不会立即再触发）。
    #[test]
    fn cooldown_expires_and_restarts_from_zero() {
        let mut g = IpGuard::new(cfg(600, 10, 30, 100));
        let now = t0();
        let a = ip("203.0.113.9");
        for i in 1..=10 {
            g.record_failure(now + Duration::from_secs(i), &a);
        }
        // 冷却从第 10 次失败（+10s）起算 30s，截止 +40s
        assert!(g.is_blocked(now + Duration::from_secs(20), &a));
        assert!(!g.is_blocked(now + Duration::from_secs(41), &a), "冷却 30s 已过");
        // 冷却结束后的一次普通失败只算 1 次，不再进冷却
        assert_eq!(
            g.record_failure(now + Duration::from_secs(42), &a),
            FailureOutcome::Counted
        );
        assert!(!g.is_blocked(now + Duration::from_secs(43), &a));
        let r = g.records.get(&a).unwrap();
        assert_eq!(r.failures.len(), 1);
    }

    /// 冷却期内的尝试被拒且顺延冷却期：持续重试者出不了冷却期。
    #[test]
    fn failures_during_cooldown_extend_it() {
        let mut g = IpGuard::new(cfg(600, 3, 100, 100));
        let now = t0();
        let a = ip("203.0.113.9");
        for i in 1..=3 {
            g.record_failure(now + Duration::from_secs(i), &a);
        }
        // 原冷却截止 = +3s + 100s = +103s
        assert!(g.is_blocked(now + Duration::from_secs(50), &a));
        // +50s 的重试被拒，冷却顺延到 +150s
        assert_eq!(
            g.record_failure(now + Duration::from_secs(50), &a),
            FailureOutcome::CooldownExtended
        );
        assert!(g.is_blocked(now + Duration::from_secs(104), &a), "顺延后原截止点仍应拦截");
        // 再次重试继续顺延到 +220s
        g.record_failure(now + Duration::from_secs(120), &a);
        assert!(g.is_blocked(now + Duration::from_secs(219), &a));
        assert!(!g.is_blocked(now + Duration::from_secs(221), &a), "停止重试后冷却应最终结束");
    }

    /// 校验成功立即清除该 IP 的全部失败记录。
    #[test]
    fn success_clears_record() {
        let mut g = IpGuard::new(cfg(600, 3, 600, 100));
        let now = t0();
        let a = ip("203.0.113.9");
        g.record_failure(now + Duration::from_secs(1), &a);
        g.record_failure(now + Duration::from_secs(2), &a);
        g.clear(&a);
        assert!(g.records.is_empty(), "成功后记录应整条删除");
        // 清零后再失败 2 次也不该触发冷却（阈值 3）
        g.record_failure(now + Duration::from_secs(3), &a);
        g.record_failure(now + Duration::from_secs(4), &a);
        assert!(!g.is_blocked(now + Duration::from_secs(5), &a));
        assert_eq!(g.record_failure(now + Duration::from_secs(6), &a), FailureOutcome::CooldownStarted);
    }

    /// 滑动窗口：窗口外的旧失败不再计入阈值。
    ///
    /// 特意留一条窗口内的近期失败，让记录在回收时因「仍有近期失败」而
    /// 保留，从而真正走到记账前的窗口剪枝路径（而非整条记录被 sweep 删掉）。
    #[test]
    fn window_slides_old_failures_expire() {
        let mut g = IpGuard::new(cfg(60, 5, 600, 100));
        let now = t0();
        let a = ip("203.0.113.9");
        for i in 1..=3 {
            g.record_failure(now + Duration::from_secs(i), &a);
        }
        g.record_failure(now + Duration::from_secs(55), &a);
        // +65s 时最早 3 次失败（+1..+3s）已滑出 60s 窗口，只剩近期 1 次
        // 加本次：若窗口不滑动，这里会数到 5 次而立即触发冷却
        assert_eq!(
            g.record_failure(now + Duration::from_secs(65), &a),
            FailureOutcome::Counted
        );
        assert!(!g.is_blocked(now + Duration::from_secs(66), &a));
        let r = g.records.get(&a).unwrap();
        assert_eq!(r.failures.len(), 2, "旧失败应被剪掉，只剩窗口内的");
    }

    /// IP 上限淘汰：满了按最近活动最旧淘汰，被活跃访问的 IP 不被误删。
    #[test]
    fn ip_cap_evicts_least_recently_active() {
        let mut g = IpGuard::new(cfg(600, 10, 600, 3));
        let now = t0();
        let (a, b, c, d) = (
            ip("203.0.113.1"),
            ip("203.0.113.2"),
            ip("203.0.113.3"),
            ip("203.0.113.4"),
        );
        g.record_failure(now + Duration::from_secs(1), &a);
        g.record_failure(now + Duration::from_secs(2), &b);
        g.record_failure(now + Duration::from_secs(3), &c);
        // 再次活跃 a：最旧变成 b
        g.record_failure(now + Duration::from_secs(4), &a);
        // 第 4 个 IP 进表：淘汰 b（最近活动最旧），保留 a/c/d
        g.record_failure(now + Duration::from_secs(5), &d);
        assert!(!g.records.contains_key(&b), "应淘汰最久未活动的 b");
        assert!(g.records.contains_key(&a));
        assert!(g.records.contains_key(&c));
        assert!(g.records.contains_key(&d));
        assert_eq!(g.records.len(), 3);
    }

    /// IP 上限是硬上限：大量不同来源涌入时映射长度不超上限、不 panic。
    #[test]
    fn ip_cap_bounds_size_under_flood() {
        let mut g = IpGuard::new(cfg(600, 10, 600, 5));
        let now = t0();
        for i in 0..20u32 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, (i + 1) as u8));
            g.record_failure(now + Duration::from_millis(i as u64 * 10), &ip);
        }
        assert_eq!(g.records.len(), 5, "映射长度必须被硬上限约束");
    }

    /// 过期回收：窗口外无失败的记录被删，冷却中的记录保留到冷却结束。
    #[test]
    fn sweep_removes_expired_records_and_keeps_cooling_ones() {
        let mut g = IpGuard::new(cfg(60, 10, 100, 100));
        let now = t0();
        let (a, b) = (ip("203.0.113.1"), ip("203.0.113.2"));
        g.record_failure(now + Duration::from_secs(1), &a);
        for i in 1..=10u64 {
            g.record_failure(now + Duration::from_millis(i), &b);
        }
        // b 进了冷却（截止 +100s），a 只有窗口外的旧失败
        assert!(g.is_blocked(now + Duration::from_secs(2), &b));
        g.sweep(now + Duration::from_secs(62));
        assert!(!g.records.contains_key(&a), "a 的失败已全部滑出窗口，应被回收");
        assert!(g.records.contains_key(&b), "b 还在冷却期，必须保留");
        // b 冷却结束后也被回收
        g.sweep(now + Duration::from_secs(101));
        assert!(g.records.is_empty());
    }

    /// 满员时优先靠回收腾位：过期记录先删，避免误淘汰活跃 IP。
    #[test]
    fn full_map_sweeps_expired_first_before_evicting() {
        let mut g = IpGuard::new(cfg(60, 10, 600, 2));
        let now = t0();
        let (a, b, c) = (ip("203.0.113.1"), ip("203.0.113.2"), ip("203.0.113.3"));
        g.record_failure(now + Duration::from_secs(1), &a);
        g.record_failure(now + Duration::from_secs(1), &b);
        // +62s：a、b 的失败都已滑出 60s 窗口；c 进表时应先回收它们，
        // 而不是把「仍可能活跃」的记录当最旧淘汰
        g.record_failure(now + Duration::from_secs(62), &c);
        assert_eq!(g.records.len(), 1);
        assert!(g.records.contains_key(&c));
        assert!(!g.records.contains_key(&a) && !g.records.contains_key(&b));
    }

    /// IPv4-mapped IPv6 折算回 IPv4；普通 IPv6 保持不变。
    #[test]
    fn normalize_peer_ip_folds_ipv4_mapped() {
        assert_eq!(
            normalize_peer_ip("::ffff:203.0.113.9".parse().unwrap()),
            ip("203.0.113.9")
        );
        assert_eq!(
            normalize_peer_ip("2001:db8::1".parse().unwrap()),
            ip("2001:db8::1")
        );
    }
}
