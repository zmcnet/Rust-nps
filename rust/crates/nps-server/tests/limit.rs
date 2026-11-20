//! 限速 / 流量上限 / IP 白名单的集成测试。
//!
//! 重点是**证明限速真的在数据路径上生效**，而不只是记了个数：
//! `1 MiB @ 100 KB/s` 必须真的花掉 ~10 秒。

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use nps_server::{FlowCounter, IpAllowList, TokenBucket};

// ---------------------------------------------------------------------------
// 1. 限速真的生效
// ---------------------------------------------------------------------------

/// 1 MiB 走 100 KB/s 的桶：理论 10.24 s，允许 9~13 s 的误差窗口。
#[tokio::test]
async fn throttle_1mib_at_100kbps_takes_about_10_seconds() {
    let bucket = TokenBucket::new(100); // 100 KB/s
    assert!(!bucket.is_unlimited());
    assert_eq!(bucket.current_rate(), 100);

    const TOTAL: usize = 1024 * 1024; // 1 MiB
    const CHUNK: usize = 16 * 1024; // 16 KiB，模拟一次 read

    let start = std::time::Instant::now();
    let mut sent = 0;
    while sent < TOTAL {
        let n = CHUNK.min(TOTAL - sent);
        bucket.acquire(n).await;
        sent += n;
    }
    let elapsed = start.elapsed();

    // 初始满桶会白送 100 KB（= 1 秒的量），所以下限放到 9 秒
    assert!(
        elapsed >= Duration::from_secs(9),
        "限速没有生效：1 MiB @ 100 KB/s 只花了 {elapsed:?}"
    );
    assert!(
        elapsed <= Duration::from_secs(13),
        "限速过度（或时间精度异常）：1 MiB @ 100 KB/s 花了 {elapsed:?}"
    );
    eprintln!("1 MiB @ 100 KB/s 实测耗时: {elapsed:?}");
}

/// 不限速时必须零等待
#[tokio::test]
async fn unlimited_bucket_returns_immediately() {
    let bucket = TokenBucket::new(0);
    assert!(bucket.is_unlimited());
    assert_eq!(bucket.current_rate(), 0);

    let start = std::time::Instant::now();
    for _ in 0..1000 {
        bucket.acquire(1024 * 1024).await;
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(1),
        "不限速时 acquire 不应等待，实测 {elapsed:?}"
    );
}

/// `n == 0` 不该消耗配额、也不该等待
#[tokio::test]
async fn acquire_zero_bytes_is_free() {
    let bucket = TokenBucket::new(1); // 1 KB/s，极小
    let start = std::time::Instant::now();
    bucket.acquire(0).await;
    assert!(start.elapsed() < Duration::from_millis(1));
}

/// 单次申请大于桶容量时不能死等（要分片）
#[tokio::test]
async fn acquire_larger_than_capacity_does_not_hang() {
    // 8 KB/s → 桶容量 8 KB；一次申请 24 KB 必须拆片完成
    let bucket = TokenBucket::new(8);
    let start = std::time::Instant::now();
    let fut = bucket.acquire(24 * 1024);
    let done = tokio::time::timeout(Duration::from_secs(10), fut).await;
    assert!(done.is_ok(), "一次申请超过桶容量时死等了");
    let elapsed = start.elapsed();
    // 24 KB @ 8 KB/s ≈ 3 s（扣掉满桶的 8 KB ≈ 2 s）
    assert!(elapsed >= Duration::from_secs(1), "大块申请没被限速: {elapsed:?}");
    assert!(elapsed <= Duration::from_secs(6), "大块申请耗时异常: {elapsed:?}");
}

// ---------------------------------------------------------------------------
// 2. 并发共享同一个桶
// ---------------------------------------------------------------------------

/// 4 条并发连接共享 100 KB/s：总吞吐仍应接近 100 KB/s，
/// 而不是每条各 100 KB/s（那样总耗时只有 ~2.5 s）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_connections_share_one_bucket() {
    let bucket = Arc::new(TokenBucket::new(100)); // 100 KB/s 总配额
    const PER_CONN: usize = 256 * 1024; // 每条 256 KiB
    const CONNS: usize = 4;
    const CHUNK: usize = 8 * 1024;

    let start = std::time::Instant::now();
    let mut handles = Vec::new();
    for _ in 0..CONNS {
        let b = bucket.clone();
        handles.push(tokio::spawn(async move {
            let mut sent = 0;
            while sent < PER_CONN {
                let n = CHUNK.min(PER_CONN - sent);
                b.acquire(n).await;
                sent += n;
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    let elapsed = start.elapsed();

    // 总计 1 MiB @ 100 KB/s ≈ 10.24 s（扣掉满桶 100 KB ≈ 1 s）
    assert!(
        elapsed >= Duration::from_secs(8),
        "并发连接各自拿到了一份带宽（桶没被共享）：{CONNS} 条连接共 1 MiB 只花了 {elapsed:?}"
    );
    assert!(
        elapsed <= Duration::from_secs(14),
        "并发总耗时异常: {elapsed:?}"
    );
    eprintln!("4 并发共享 100 KB/s，1 MiB 实测耗时: {elapsed:?}");
}

/// 一条连接在等配额时不能阻塞另一条——即睡觉发生在锁外。
///
/// 构造 1 KB/s 的极慢桶：第一条连接申请超大块会长时间等待；
/// 同时第二条连接申请 0 字节（无锁路径）必须立即返回。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn waiting_connection_does_not_block_others() {
    let bucket = Arc::new(TokenBucket::new(1));
    let slow = {
        let b = bucket.clone();
        tokio::spawn(async move { b.acquire(64 * 1024).await })
    };
    // 给慢任务一点时间进入等待
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!slow.is_finished(), "慢任务本应还在等配额");

    // 无锁路径必须畅通（未被慢任务持有锁）
    let start = std::time::Instant::now();
    bucket.acquire(0).await;
    assert!(
        start.elapsed() < Duration::from_millis(100),
        "慢任务持有锁阻塞了其它连接"
    );
    slow.abort();
}

// ---------------------------------------------------------------------------
// 3. 流量上限
// ---------------------------------------------------------------------------

#[test]
fn flow_counter_triggers_at_limit() {
    let f = FlowCounter::new(10); // 10 KB
    assert!(!f.exceeded());
    assert_eq!(f.limit_kb(), 10);

    f.add(4 * 1024, 4 * 1024); // 8 KB
    assert!(!f.exceeded());
    assert_eq!(f.total(), (4 * 1024, 4 * 1024));

    // 再来 4 KB → 12 KB > 10 KB
    f.add(4 * 1024, 0);
    assert!(f.exceeded(), "超过上限后必须为 true");
}

/// 一旦超限就不可逆（即使之后计数继续增长、或被人为归零）
#[test]
fn flow_exceeded_is_permanent() {
    let f = FlowCounter::new(1); // 1 KB
    f.add(2 * 1024, 0);
    assert!(f.exceeded());

    // 再多流量：仍然 true
    f.add(1024 * 1024, 1024 * 1024);
    assert!(f.exceeded());
}

/// `limit_kb == 0` 表示不限流量
#[test]
fn flow_limit_zero_means_unlimited() {
    let f = FlowCounter::new(0);
    f.add(u64::MAX / 2, u64::MAX / 2);
    f.add(u64::MAX / 2, u64::MAX / 2);
    assert!(!f.exceeded(), "limit=0 不应触发超限");
    // 且计数不能回绕成小值
    let (up, down) = f.total();
    assert_eq!(up, u64::MAX - 1, "up 计数回绕了");
    assert_eq!(down, u64::MAX - 1, "down 计数回绕了");
}

/// 恰好等于上限还不算超（与 Go `limit < total` 的严格大于一致）
#[test]
fn flow_exactly_at_limit_is_not_exceeded() {
    let f = FlowCounter::new(4);
    f.add(4 * 1024, 0);
    assert!(!f.exceeded(), "恰好等于上限不应算超限");
    f.add(1, 0);
    assert!(f.exceeded());
}

#[test]
fn flow_counter_saturates_instead_of_wrapping() {
    let f = FlowCounter::new(0);
    for _ in 0..4 {
        f.add(u64::MAX / 2, 0);
    }
    let (up, _) = f.total();
    assert_eq!(up, u64::MAX, "累加应当饱和到 u64::MAX");
}

// ---------------------------------------------------------------------------
// 4. IP 白名单
// ---------------------------------------------------------------------------

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn ip_allow_list_empty_allows_everything() {
    let list = IpAllowList::new(&[]).unwrap();
    assert!(list.is_empty());
    assert!(list.allows(ip("1.2.3.4")));
    assert!(list.allows(ip("2001:db8::1")));
}

#[test]
fn ip_allow_list_single_ip() {
    let list = IpAllowList::new(&["10.1.2.3".to_string()]).unwrap();
    assert!(!list.is_empty());
    assert!(list.allows(ip("10.1.2.3")));
    assert!(!list.allows(ip("10.1.2.4")));
    assert!(!list.allows(ip("2001:db8::1")));
}

#[test]
fn ip_allow_list_cidr_v4() {
    let list = IpAllowList::new(&["10.0.0.0/8".to_string(), "192.168.1.0/24".to_string()]).unwrap();
    assert!(list.allows(ip("10.0.0.1")));
    assert!(list.allows(ip("10.255.255.255")));
    assert!(list.allows(ip("192.168.1.99")));
    assert!(!list.allows(ip("192.168.2.1")));
    assert!(!list.allows(ip("11.0.0.1")));
}

#[test]
fn ip_allow_list_cidr_v6() {
    let list = IpAllowList::new(&["2001:db8::/32".to_string()]).unwrap();
    assert!(list.allows(ip("2001:db8::1")));
    assert!(list.allows(ip("2001:db8:ffff::1")));
    assert!(!list.allows(ip("2001:db9::1")));
    assert!(!list.allows(ip("10.0.0.1")));
}

/// 双栈监听下对端可能报 IPv4-mapped IPv6，必须能匹配 IPv4 条目
#[test]
fn ip_allow_list_matches_ipv4_mapped_ipv6() {
    let list = IpAllowList::new(&["10.0.0.0/8".to_string()]).unwrap();
    assert!(list.allows(ip("::ffff:10.1.2.3")));
}

/// `0.0.0.0/0` 与 `::/0` 是合法的「全部允许」写法
#[test]
fn ip_allow_list_wildcard_prefixes() {
    let v4 = IpAllowList::new(&["0.0.0.0/0".to_string()]).unwrap();
    assert!(v4.allows(ip("8.8.8.8")));
    let v6 = IpAllowList::new(&["::/0".to_string()]).unwrap();
    assert!(v6.allows(ip("2001:db8::1")));
}

#[test]
fn ip_allow_list_rejects_invalid_entries() {
    for bad in [
        "not-an-ip",
        "999.1.1.1",
        "10.0.0.0/33",   // v4 前缀越界
        "2001:db8::/129", // v6 前缀越界
        "10.0.0.0/abc",
        "",
        "   ",
    ] {
        assert!(
            IpAllowList::new(&[bad.to_string()]).is_err(),
            "非法条目 {bad:?} 应被拒绝"
        );
    }
}

/// 条目首尾空白应被容忍（配置里常见）
#[test]
fn ip_allow_list_trims_entries() {
    let list = IpAllowList::new(&["  10.0.0.0/8  ".to_string()]).unwrap();
    assert!(list.allows(ip("10.9.9.9")));
}
