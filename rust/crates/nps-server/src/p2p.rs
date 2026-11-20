//! `p2p` 模式：UDP 会合（rendezvous）服务器。
//!
//! # 原版行为（`server/proxy/p2p.go`）
//!
//! 服务端只做**信令**，流量不经过它：
//!
//! 1. 监听一个 UDP 端口（`p2p_port`）
//! 2. 客户端（provider）与访客（visitor）各自发一个 UDP 包，内容是
//!    `"<password>*#*<role>"`，role 为 `p2pv`（visitor）或 `p2pp`（provider）
//! 3. 服务端按 password 记录双方 `UDPAddr`
//! 4. visitor 侧循环等最多 20 秒，provider 到齐后
//!    **把对方地址互发给对方**（各发一个纯文本 `ip:port`）
//! 5. 双方拿到地址后直连，服务端条目删除
//!
//! # 本实现
//!
//! 同样的协议、同样的超时与报文格式。服务端不解析、不转发任何业务数据。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// 角色：访客（发起方）
pub const ROLE_VISITOR: &str = "p2pv";
/// 角色：提供方（被访问方）
pub const ROLE_PROVIDER: &str = "p2pp";

/// visitor 等待 provider 到齐的最长时间（对齐原版 20 秒）
const VISITOR_WAIT: Duration = Duration::from_secs(20);
/// 单条会合记录的空闲回收时间（双方一直不齐时避免泄漏）
const ENTRY_TTL: Duration = Duration::from_secs(300);
/// 单包上限（原版用 16KB 缓冲；我们只要 password+role，1KB 足够）
const MAX_DATAGRAM: usize = 1024;

/// 一条会合记录
#[derive(Debug, Default)]
struct Rendezvous {
    visitor: Option<SocketAddr>,
    provider: Option<SocketAddr>,
    /// 最后活跃时间（用于 TTL 回收）
    last_seen: Option<std::time::Instant>,
}

/// p2p 会合服务
pub struct P2pRendezvous {
    /// 本地端口（`:0` 表示系统分配）
    listen_addr: SocketAddr,
    /// password -> 会合记录
    entries: Arc<tokio::sync::Mutex<HashMap<String, Rendezvous>>>,
    /// 成功配对次数
    paired: AtomicU64,
    /// 解析失败/非法报文次数
    malformed: AtomicU64,
}

impl P2pRendezvous {
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            entries: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            paired: AtomicU64::new(0),
            malformed: AtomicU64::new(0),
        }
    }

    pub fn paired(&self) -> u64 {
        self.paired.load(Ordering::Relaxed)
    }

    pub fn malformed(&self) -> u64 {
        self.malformed.load(Ordering::Relaxed)
    }

    pub async fn bind(&self) -> Result<UdpSocket> {
        UdpSocket::bind(self.listen_addr)
            .await
            .with_context(|| format!("p2p 会合端口绑定失败: {}", self.listen_addr))
    }

    /// 在已绑定的 socket 上跑接收循环。
    pub async fn serve(self: Arc<Self>, socket: Arc<UdpSocket>, mut cancel: watch::Receiver<bool>) {
        let bound = socket.local_addr().ok();
        info!("p2p 会合服务监听 {:?}（仅信令，不转发业务数据）", bound);
        let mut buf = vec![0u8; MAX_DATAGRAM];

        loop {
            let recv = tokio::select! {
                _ = cancel.changed() => break,
                r = socket.recv_from(&mut buf) => r,
            };
            let (n, peer) = match recv {
                Ok(v) => v,
                Err(e) => {
                    warn!("p2p recv_from 失败: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let text = match std::str::from_utf8(&buf[..n]) {
                Ok(t) => t.trim(),
                Err(_) => {
                    self.malformed.fetch_add(1, Ordering::Relaxed);
                    debug!("p2p: 收到非 UTF-8 报文（{n} 字节），忽略");
                    continue;
                }
            };
            if let Err(e) = self.handle_datagram(&socket, peer, text).await {
                debug!("p2p: {e}");
            }
        }
        debug!("p2p 会合循环退出");
    }

    /// 处理一个会合报文：`"<password>*#*<role>"`
    async fn handle_datagram(
        &self,
        socket: &UdpSocket,
        peer: SocketAddr,
        text: &str,
    ) -> Result<()> {
        let Some((password, role)) = text.split_once("*#*") else {
            self.malformed.fetch_add(1, Ordering::Relaxed);
            anyhow::bail!("报文格式应为 <password>*#*<role>，收到 {text:?}");
        };
        if password.is_empty() || password.len() > 256 {
            self.malformed.fetch_add(1, Ordering::Relaxed);
            anyhow::bail!("password 长度非法（{}）", password.len());
        }

        match role {
            ROLE_PROVIDER => {
                let mut map = self.entries.lock().await;
                let e = map.entry(password.to_owned()).or_default();
                e.provider = Some(peer);
                e.last_seen = Some(std::time::Instant::now());
                debug!("p2p: provider 已登记（{} 个会合中）", map.len());
                Ok(())
            }
            ROLE_VISITOR => {
                // 登记 visitor，然后最多等 20 秒让 provider 到齐
                {
                    let mut map = self.entries.lock().await;
                    let e = map.entry(password.to_owned()).or_default();
                    e.visitor = Some(peer);
                    e.last_seen = Some(std::time::Instant::now());
                }

                let deadline = tokio::time::Instant::now() + VISITOR_WAIT;
                loop {
                    let provider = {
                        let map = self.entries.lock().await;
                        map.get(password).and_then(|e| e.provider)
                    };
                    if let Some(provider_addr) = provider {
                        // 把对方地址互发（原版发的是纯文本 "ip:port"）
                        let to_visitor = provider_addr.to_string();
                        let to_provider = peer.to_string();
                        if let Err(e) = socket.send_to(to_visitor.as_bytes(), peer).await {
                            warn!("p2p: 通知 visitor 失败: {e}");
                        }
                        if let Err(e) = socket
                            .send_to(to_provider.as_bytes(), provider_addr)
                            .await
                        {
                            warn!("p2p: 通知 provider 失败: {e}");
                        }
                        self.paired.fetch_add(1, Ordering::Relaxed);
                        info!(
                            "p2p: 配对成功 visitor={peer} provider={provider_addr}（之后直连，流量不过服务端）"
                        );
                        // 配对完成即删除记录（对齐原版 delete(s.p2p, arr[0])）
                        self.entries.lock().await.remove(password);
                        return Ok(());
                    }
                    if tokio::time::Instant::now() >= deadline {
                        self.entries.lock().await.remove(password);
                        anyhow::bail!("visitor 等待 provider 超时（{}s）", VISITOR_WAIT.as_secs());
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
            other => {
                self.malformed.fetch_add(1, Ordering::Relaxed);
                anyhow::bail!("未知角色 {other:?}（应为 {ROLE_VISITOR} 或 {ROLE_PROVIDER}）");
            }
        }
    }

    /// 回收长期无人配对的条目（避免内存泄漏）
    pub async fn sweep_stale(&self) -> usize {
        let mut map = self.entries.lock().await;
        let before = map.len();
        let now = std::time::Instant::now();
        map.retain(|_, e| {
            e.last_seen
                .map(|t| now.duration_since(t) < ENTRY_TTL)
                .unwrap_or(false)
        });
        before - map.len()
    }

    pub async fn pending(&self) -> usize {
        self.entries.lock().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup() -> (Arc<P2pRendezvous>, Arc<UdpSocket>, SocketAddr, watch::Sender<bool>) {
        let svc = Arc::new(P2pRendezvous::new("127.0.0.1:0".parse().unwrap()));
        let socket = Arc::new(svc.bind().await.unwrap());
        let addr = socket.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        let s = svc.clone();
        let sock = socket.clone();
        tokio::spawn(async move { s.serve(sock, rx).await });
        (svc, socket, addr, tx)
    }

    #[tokio::test]
    async fn provider_then_visitor_are_paired() {
        let (svc, _sock, addr, _tx) = setup().await;

        let provider = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let visitor = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let provider_addr = provider.local_addr().unwrap();
        let visitor_addr = visitor.local_addr().unwrap();

        // provider 先登记
        provider
            .send_to(format!("pw1*#*{ROLE_PROVIDER}").as_bytes(), addr)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        // visitor 发起会合
        visitor
            .send_to(format!("pw1*#*{ROLE_VISITOR}").as_bytes(), addr)
            .await
            .unwrap();

        // visitor 应收到 provider 地址
        let mut buf = [0u8; 256];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), visitor.recv_from(&mut buf))
            .await
            .expect("visitor 应收到配对地址")
            .unwrap();
        let got = std::str::from_utf8(&buf[..n]).unwrap().trim().to_owned();
        assert_eq!(got, provider_addr.to_string(), "visitor 应拿到 provider 地址");

        // provider 应收到 visitor 地址
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), provider.recv_from(&mut buf))
            .await
            .expect("provider 应收到配对地址")
            .unwrap();
        let got = std::str::from_utf8(&buf[..n]).unwrap().trim().to_owned();
        assert_eq!(got, visitor_addr.to_string(), "provider 应拿到 visitor 地址");

        assert_eq!(svc.paired(), 1);
        // 配对后条目应被删除
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(svc.pending().await, 0);
    }

    #[tokio::test]
    async fn malformed_datagrams_are_counted_not_panicking() {
        let (svc, _sock, addr, _tx) = setup().await;
        let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        for bad in ["", "no-separator", "pw*#*unknown-role", "*#*p2pv"] {
            c.send_to(bad.as_bytes(), addr).await.unwrap();
            tokio::time::sleep(Duration::from_millis(80)).await;
        }
        // 非 UTF-8
        c.send_to(&[0xff, 0xfe, 0xfd], addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(svc.malformed() >= 4, "非法报文应被计数: {}", svc.malformed());
        assert_eq!(svc.paired(), 0);
    }

    #[tokio::test]
    async fn visitor_without_provider_times_out() {
        // 这里只验证「provider 缺失时 visitor 不会立即被配对」，
        // 完整的 20 秒超时在集成脚本里验证（避免测试跑 20 秒）
        let (svc, _sock, addr, _tx) = setup().await;
        let visitor = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        visitor
            .send_to(format!("pw-timeout*#*{ROLE_VISITOR}").as_bytes(), addr)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(600)).await;

        // 应有一条 pending（visitor 在等）
        assert_eq!(svc.pending().await, 1);
        assert_eq!(svc.paired(), 0);
    }

    #[tokio::test]
    async fn sweep_removes_stale_entries() {
        let svc = P2pRendezvous::new("127.0.0.1:0".parse().unwrap());
        {
            let mut map = svc.entries.lock().await;
            map.insert(
                "old".to_owned(),
                Rendezvous {
                    provider: Some("1.2.3.4:1".parse().unwrap()),
                    last_seen: Some(std::time::Instant::now() - ENTRY_TTL * 2),
                    ..Default::default()
                },
            );
            map.insert(
                "fresh".to_owned(),
                Rendezvous {
                    provider: Some("1.2.3.4:2".parse().unwrap()),
                    last_seen: Some(std::time::Instant::now()),
                    ..Default::default()
                },
            );
        }
        assert_eq!(svc.sweep_stale().await, 1);
        assert_eq!(svc.pending().await, 1);
    }
}
