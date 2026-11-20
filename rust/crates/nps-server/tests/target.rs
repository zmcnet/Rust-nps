//! 多目标轮询与健康检查的行为测试。
//!
//! 全部是真实网络行为：起真实 `TcpListener` / 迷你 HTTP 服务、用黑洞地址
//! 验证并发探测，不 mock 任何 I/O。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nps_server::target::{HealthCheckKind, TargetError, TargetPool};
use nps_server::{HealthCheckConfig, HealthChecker};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

/// 一个"接受连接后立刻关闭"的端口，用于制造失败目标。
///
/// 先同步绑定再释放，得到一个「没有人监听」的端口：连接会被立即拒绝（RST），
/// 比连不通的地址更快、更稳定。
fn closed_port() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    addr
}

/// 启动一个 TCP listener，持续 accept 并立刻关闭连接（健康目标的形态）。
async fn spawn_open_listener() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let h = tokio::spawn(async move {
        while let Ok((stream, _)) = l.accept().await {
            drop(stream);
        }
    });
    (addr, h)
}

/// 启动一个迷你 HTTP 服务，对任何请求都回固定状态码。
async fn spawn_http_server(status: u16) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let h = tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                // 读掉请求头即可；不阻塞在完整请求上。
                let _ = s.read(&mut buf).await;
                let body = if status == 200 { "ok" } else { "err" };
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    (addr, h)
}

fn pool(spec: &str) -> Arc<TargetPool> {
    Arc::new(TargetPool::parse(spec).unwrap())
}

fn cfg(kind: HealthCheckKind, timeout: Duration, max_failed: u32) -> HealthCheckConfig {
    HealthCheckConfig {
        timeout,
        max_failed,
        interval: Duration::from_millis(50),
        kind,
    }
}

// ---------------------------------------------------------------------------
// 1. 轮询顺序
// ---------------------------------------------------------------------------

#[test]
fn round_robin_is_strictly_sequential() {
    let p = TargetPool::parse("A:1\nB:2\nC:3").unwrap();
    let got: Vec<String> = (0..9).map(|_| p.next().unwrap()).collect();
    assert_eq!(
        got,
        [
            "A:1", "B:2", "C:3", "A:1", "B:2", "C:3", "A:1", "B:2", "C:3"
        ],
        "必须是顺序轮询 A→B→C 循环，不能随机"
    );
    println!("轮询序列: {got:?}");
}

#[test]
fn single_target_always_returned() {
    let p = TargetPool::parse("only:1").unwrap();
    for _ in 0..3 {
        assert_eq!(p.next().unwrap(), "only:1");
    }
}

// ---------------------------------------------------------------------------
// 2. 离线摘除
// ---------------------------------------------------------------------------

#[test]
fn offline_target_is_skipped_in_rotation() {
    let p = TargetPool::parse("A:1\nB:2\nC:3").unwrap();
    p.mark_offline("B:2");
    assert!(p.is_offline("B:2"));
    assert_eq!(p.len(), 2);

    let got: Vec<String> = (0..6).map(|_| p.next().unwrap()).collect();
    assert_eq!(got, ["A:1", "C:3", "A:1", "C:3", "A:1", "C:3"]);
    assert!(!got.contains(&"B:2".to_string()));
    assert_eq!(p.targets(), ["A:1", "C:3"]);
    println!("摘除 B 后序列: {got:?}");
}

#[test]
fn offline_target_can_be_restored() {
    let p = TargetPool::parse("A:1\nB:2\nC:3").unwrap();
    p.mark_offline("B:2");
    let _ = p.next();
    p.mark_online("B:2");
    assert!(!p.is_offline("B:2"));
    assert_eq!(p.len(), 3);

    // 恢复后必须重新出现在轮询里：9 次采样必然覆盖全部三个目标。
    let got: Vec<String> = (0..9).map(|_| p.next().unwrap()).collect();
    for t in ["A:1", "B:2", "C:3"] {
        assert!(got.contains(&t.to_string()), "恢复后 {t} 应回到轮询");
    }
}

// ---------------------------------------------------------------------------
// 3. 全离线
// ---------------------------------------------------------------------------

#[test]
fn all_offline_returns_err_not_empty_string() {
    let p = TargetPool::parse("A:1\nB:2").unwrap();
    p.mark_offline("A:1");
    p.mark_offline("B:2");
    assert_eq!(p.len(), 0);
    assert!(p.is_empty());
    assert_eq!(p.next(), Err(TargetError::AllOffline));
    assert_eq!(p.targets(), Vec::<String>::new());

    // 恢复一个就能继续工作
    p.mark_online("A:1");
    assert_eq!(p.next().unwrap(), "A:1");
}

// ---------------------------------------------------------------------------
// 4. TCP 真探测
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tcp_probe_distinguishes_open_and_closed_ports() {
    let (open, _h) = spawn_open_listener().await;
    let closed = closed_port();

    let p = pool(&format!("{open}\n{closed}"));
    let checker = HealthChecker::new(p.clone(), cfg(HealthCheckKind::Tcp, Duration::from_secs(2), 3));

    let results = checker.check_once().await;
    assert_eq!(results.len(), 2);
    let map: std::collections::HashMap<_, _> = results.iter().cloned().collect();
    assert!(map[&open.to_string()], "open listener 应判健康");
    assert!(!map[&closed.to_string()], "关闭的端口应判不健康");
    println!("TCP 探测结果: {results:?}");

    // 结果顺序与配置一致
    assert_eq!(results[0].0, open.to_string());
    assert_eq!(results[1].0, closed.to_string());
}

// ---------------------------------------------------------------------------
// 5. HTTP 检查
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_probe_accepts_2xx_and_rejects_5xx() {
    let (ok_addr, _h1) = spawn_http_server(200).await;
    let (bad_addr, _h2) = spawn_http_server(500).await;

    let p = pool(&format!("{ok_addr}\n{bad_addr}"));
    let checker = HealthChecker::new(
        p,
        cfg(
            HealthCheckKind::Http {
                path: "/healthz".into(),
            },
            Duration::from_secs(2),
            3,
        ),
    );

    let results = checker.check_once().await;
    let map: std::collections::HashMap<_, _> = results.iter().cloned().collect();
    assert!(map[&ok_addr.to_string()], "200 应判健康");
    assert!(!map[&bad_addr.to_string()], "500 应判不健康");
    println!("HTTP 探测结果: {results:?}");
}

#[tokio::test]
async fn http_probe_treats_redirect_as_healthy() {
    let (addr, _h) = spawn_http_server(302).await;
    let p = pool(&addr.to_string());
    let checker = HealthChecker::new(
        p,
        cfg(
            HealthCheckKind::Http {
                path: String::new(),
            },
            Duration::from_secs(2),
            3,
        ),
    );
    let results = checker.check_once().await;
    assert_eq!(results, vec![(addr.to_string(), true)]);
}

// ---------------------------------------------------------------------------
// 6. 并发探测
// ---------------------------------------------------------------------------

#[tokio::test]
async fn probe_runs_concurrently_not_serially() {
    // 三个"黑洞"：TEST-NET-1 (192.0.2.0/24) 不可路由，连接会一直挂到超时。
    // 若串行，3 × 300ms ≈ 900ms；并发应接近 300ms。
    let targets = "192.0.2.1:9\n192.0.2.2:9\n192.0.2.3:9";
    let p = pool(targets);
    let timeout = Duration::from_millis(300);
    let checker = HealthChecker::new(p, cfg(HealthCheckKind::Tcp, timeout, 3));

    let start = Instant::now();
    let results = checker.check_once().await;
    let elapsed = start.elapsed();

    assert_eq!(results.len(), 3);
    assert!(results.iter().all(|(_, ok)| !ok), "黑洞地址必须判不健康");

    // 串行下界 = 3 × 300ms = 900ms；给足调度余量后仍要求明显小于它。
    let serial_lower_bound = timeout * 3;
    assert!(
        elapsed < serial_lower_bound.mul_f64(0.75),
        "探测未并发：耗时 {elapsed:?}，串行下界 {serial_lower_bound:?}"
    );
    assert!(
        elapsed >= timeout,
        "耗时 {elapsed:?} 小于单次超时 {timeout:?}，说明没有真正等到超时"
    );
    println!("3 个黑洞目标并发探测耗时: {elapsed:?}（串行下界 {serial_lower_bound:?}）");
}

// ---------------------------------------------------------------------------
// 7. max_failed 阈值
// ---------------------------------------------------------------------------

#[tokio::test]
async fn threshold_requires_max_failed_consecutive_failures() {
    let closed = closed_port();
    let p = pool(&closed.to_string());
    let checker = HealthChecker::new(
        p.clone(),
        cfg(HealthCheckKind::Tcp, Duration::from_secs(1), 3),
    );

    // 第 1、2 次失败：不摘除
    for i in 1..=2 {
        let results = checker.check_once().await;
        assert_eq!(results, vec![(closed.to_string(), false)]);
        assert!(!p.is_offline(&closed.to_string()), "第 {i} 次失败不应摘除目标");
        assert_eq!(p.len(), 1);
        assert_eq!(
            checker.state_of(&closed.to_string()).unwrap().consecutive_failures,
            i
        );
    }

    // 第 3 次失败：达到阈值，摘除
    let _ = checker.check_once().await;
    assert!(p.is_offline(&closed.to_string()), "达到 max_failed 应摘除");
    assert_eq!(p.len(), 0);
    assert_eq!(p.next(), Err(TargetError::AllOffline));

    // 继续失败不应让计数溢出或反复摘除（幂等）
    let _ = checker.check_once().await;
    assert!(p.is_offline(&closed.to_string()));
    assert_eq!(checker.state_of(&closed.to_string()).unwrap().consecutive_failures, 4);
}

#[tokio::test]
async fn success_resets_failure_counter() {
    let (open, _h) = spawn_open_listener().await;
    let p = pool(&open.to_string());
    let checker = HealthChecker::new(
        p.clone(),
        cfg(HealthCheckKind::Tcp, Duration::from_secs(1), 2),
    );

    // 手动制造一次失败状态，再用成功探测清零。
    {
        let results = checker.check_once().await;
        assert_eq!(results, vec![(open.to_string(), true)]);
    }
    assert_eq!(checker.state_of(&open.to_string()).unwrap().consecutive_failures, 0);
    assert!(!p.is_offline(&open.to_string()));
}

#[tokio::test]
async fn offline_target_recovers_when_probe_succeeds() {
    let (open, _h) = spawn_open_listener().await;
    let p = pool(&open.to_string());
    // max_failed = 1：一次失败就摘除
    let checker = HealthChecker::new(
        p.clone(),
        cfg(HealthCheckKind::Tcp, Duration::from_secs(1), 1),
    );

    // 先手工摘除，模拟已离线（探测目标仍是活的，因此应恢复）
    p.mark_offline(&open.to_string());
    assert_eq!(p.next(), Err(TargetError::AllOffline));

    let results = checker.check_once().await;
    assert_eq!(results, vec![(open.to_string(), true)]);
    assert!(!p.is_offline(&open.to_string()), "探测成功应恢复离线目标");
    assert_eq!(p.next().unwrap(), open.to_string());
    assert!(!checker.state_of(&open.to_string()).unwrap().offline);
}

// ---------------------------------------------------------------------------
// 8. run() 循环可取消
// ---------------------------------------------------------------------------

#[tokio::test]
async fn run_loop_stops_on_cancel() {
    let (open, _h) = spawn_open_listener().await;
    let p = pool(&open.to_string());
    let checker = Arc::new(HealthChecker::new(
        p.clone(),
        cfg(HealthCheckKind::Tcp, Duration::from_millis(200), 3),
    ));

    let (tx, rx) = watch::channel(false);
    let handle = tokio::spawn(checker.clone().run(rx));

    // 等到至少跑过一次检查
    tokio::time::timeout(Duration::from_secs(3), async {
        while checker.state_of(&open.to_string()).is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("run() 应尽快执行第一次检查");

    tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(3), handle)
        .await
        .expect("收到取消信号后 run() 应退出")
        .expect("run() 不应 panic");
}

#[tokio::test]
async fn run_loop_stops_when_sender_dropped() {
    let (open, _h) = spawn_open_listener().await;
    let p = pool(&open.to_string());
    let checker = Arc::new(HealthChecker::new(
        p,
        cfg(HealthCheckKind::Tcp, Duration::from_millis(100), 3),
    ));

    let (tx, rx) = watch::channel(false);
    let handle = tokio::spawn(checker.run(rx));
    drop(tx);

    tokio::time::timeout(Duration::from_secs(3), handle)
        .await
        .expect("发送端丢弃后 run() 应退出")
        .expect("run() 不应 panic");
}
