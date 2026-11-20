//! 流控（限速 / 流量上限 / IP 白名单）在**全部转发路径**上的接线测试。
//!
//! 这些测试刻意走 `Server::start`（而不是直接构造单个模块），因为要验证的
//! 正是「`server.rs` 把 per-client 流控传给了每个模块」这件事——模块内部
//! 的逻辑已有各自的测试覆盖。
//!
//! 覆盖：
//! - UDP：白名单拒绝时静默丢包，不建流；
//! - HTTP：白名单拒绝 → 403；
//! - SOCKS5：白名单拒绝 → 静默关闭（不写任何应答字节）；
//! - conf 注册的隧道继承客户端的白名单（不能成为绕过限制的后门）；
//! - per-client 流量上限跨路径共享：TCP 隧道打满后，同一客户端的 HTTP 站点返回 503。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nps_legacy::mux::MuxSession;
use nps_server::{
    ClientConfig, HttpSiteConfig, Server, ServerConfig, Socks5Config, TcpTunnelConfig,
    UdpTunnelConfig,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;

const VKEY: &str = "controls-wiring-vkey-4f7c21";

// ---------------------------------------------------------------------------
// 基础设施
// ---------------------------------------------------------------------------

fn client(rate_limit: u64, flow_limit: u64) -> ClientConfig {
    ClientConfig {
        id: 1,
        name: "npc".into(),
        vkey: VKEY.into(),
        rate_limit,
        flow_limit,
        crypt: false,
        compress: false,
        web_username: None,
        web_password: None,
    }
}

fn config(ip_limit: Vec<String>, rate_limit: u64, flow_limit: u64) -> ServerConfig {
    ServerConfig {
        bridge_addr: "127.0.0.1:0".into(),
        web_addr: "127.0.0.1:0".into(),
        clients: vec![client(rate_limit, flow_limit)],
        ip_limit,
        ..Default::default()
    }
}

async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

async fn npc_handshake(addr: SocketAddr, conn_type: &[u8; 4]) -> TcpStream {
    let mut c = TcpStream::connect(addr).await.unwrap();
    c.write_all(b"TST").await.unwrap();
    nps_legacy::write_len_content(&mut c, nps_proto::CORE_VERSION.as_bytes())
        .await
        .unwrap();
    nps_legacy::write_len_content(&mut c, b"0.26.10")
        .await
        .unwrap();
    let mut digest = [0u8; 32];
    c.read_exact(&mut digest).await.unwrap();
    assert_eq!(
        &digest,
        nps_legacy::md5_hex(nps_proto::CORE_VERSION).as_bytes()
    );
    c.write_all(nps_legacy::md5_hex(VKEY).as_bytes())
        .await
        .unwrap();
    let mut ok = [0u8; 4];
    c.read_exact(&mut ok).await.unwrap();
    assert_eq!(&ok, nps_proto::VERIFY_SUCCESS.as_bytes());
    c.write_all(conn_type).await.unwrap();
    c
}

/// 假 npc：main 保活 + chan mux 接受子流并回显。
///
/// `accepted` 统计**服务端真实建出的子流数**——白名单/流量上限生效时
/// 它必须保持 0（说明服务端根本没消耗 npc 侧的目标连接）。
async fn spawn_echo_npc(bridge: SocketAddr, accepted: Arc<AtomicUsize>) -> tokio::task::JoinHandle<()> {
    let (ready_tx, ready_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut main = npc_handshake(bridge, b"main").await;
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while matches!(main.read(&mut buf).await, Ok(n) if n > 0) {}
        });
        let chan = npc_handshake(bridge, b"chan").await;
        let mux = MuxSession::new(chan);
        let _ = ready_tx.send(());
        while let Ok(mut stream) = mux.accept_stream().await {
            accepted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                // 首帧是 Link JSON，丢弃后回显
                if stream.recv_data().await.is_none() {
                    return;
                }
                while let Some(data) = stream.recv_data().await {
                    if stream.send_data(&data).await.is_err() {
                        break;
                    }
                }
                stream.close();
            });
        }
    });
    let _ = tokio::time::timeout(Duration::from_secs(10), ready_rx).await;
    task
}

async fn wait_client_online(server: &Server) {
    for _ in 0..200 {
        let snap = server.snapshot().await;
        if snap.clients.iter().any(|c| c.id == 1 && c.online) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("等待假 npc 在线超时");
}

/// 读取 HTTP 状态码（只读响应头第一行）
async fn read_http_status(stream: &mut TcpStream) -> u16 {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 256];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 8192 {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .expect("读取 HTTP 响应超时")
            .expect("读取 HTTP 响应失败");
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let text = String::from_utf8_lossy(&buf);
    let line = text.lines().next().unwrap_or_default();
    let mut parts = line.split_whitespace();
    let _version = parts.next();
    parts
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("响应行非法: {line:?}"))
}

// ---------------------------------------------------------------------------
// 1. UDP：白名单
// ---------------------------------------------------------------------------

#[tokio::test]
async fn udp_ip_whitelist_drops_datagrams_without_opening_stream() {
    let mut cfg = config(vec!["192.0.2.1".into()], 0, 0);
    cfg.udp_tunnels = vec![UdpTunnelConfig {
        id: 1,
        name: "dns".into(),
        client_id: 1,
        listen_addr: "127.0.0.1:0".into(),
        target_addr: "127.0.0.1:9".into(),
        enabled: true,
        idle_timeout_secs: 600,
        max_sessions: 64,
    }];

    let server = Server::start(cfg).await.unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let npc = spawn_echo_npc(server.bridge_addr(), accepted.clone()).await;
    wait_client_online(&server).await;

    // 快照里拿系统分配的实际 UDP 端口
    let snap = server.snapshot().await;
    let udp_addr = snap
        .tunnels
        .iter()
        .find(|t| t.id == 1)
        .and_then(|t| t.bound_addr.as_deref())
        .expect("UDP 隧道应有 bound_addr")
        .parse::<SocketAddr>()
        .unwrap();

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(b"not-allowed", udp_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "白名单拒绝时不应向 npc 建流"
    );
    let snap = server.snapshot().await;
    let udp = snap.tunnels.iter().find(|t| t.id == 1).unwrap();
    assert_eq!(udp.active_connections, 0);
    assert_eq!((udp.bytes_to_client, udp.bytes_from_client), (0, 0));

    server.shutdown().await;
    npc.abort();
}

// ---------------------------------------------------------------------------
// 2. HTTP：白名单 → 403
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_site_ip_whitelist_returns_403() {
    let http_port = free_port().await;
    let mut cfg = config(vec!["192.0.2.1".into()], 0, 0);
    cfg.http_listen_addr = Some(format!("127.0.0.1:{http_port}"));
    cfg.http_sites = vec![HttpSiteConfig {
        id: 1,
        name: "site".into(),
        client_id: 1,
        domain: "deny.test".into(),
        target_addr: "127.0.0.1:9".into(),
        routes: Vec::new(),
        websocket: true,
        enabled: true,
        tls_mode: nps_server::TlsMode::Off,
        force_https: false,
    }];

    // 本用例刻意不启动 npc：白名单检查在 open_stream 之前，必须能在客户端
    // 离线的情况下独立生效（否则说明检查点放错了位置）。
    let server = Server::start(cfg).await.unwrap();

    let mut c = TcpStream::connect(("127.0.0.1", http_port)).await.unwrap();
    c.write_all(b"GET / HTTP/1.1\r\nHost: deny.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(read_http_status(&mut c).await, 403);

    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// 3. SOCKS5：白名单 → 静默关闭
// ---------------------------------------------------------------------------

#[tokio::test]
async fn socks5_ip_whitelist_closes_without_reply() {
    let socks_port = free_port().await;
    let mut cfg = config(vec!["192.0.2.1".into()], 0, 0);
    cfg.socks5_listeners = vec![Socks5Config {
        id: 1,
        name: "px".into(),
        client_id: 1,
        listen_addr: format!("127.0.0.1:{socks_port}"),
        users: Vec::new(),
        enabled: true,
    }];

    let server = Server::start(cfg).await.unwrap();

    let mut c = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
    // 发半段 greeting 也无所谓：白名单在协商之前就关闭连接
    c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf))
        .await
        .expect("等待连接关闭超时")
        .expect("读取失败");
    assert_eq!(n, 0, "白名单拒绝必须静默关闭，不返回任何字节");

    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// 4. conf 注册的隧道继承白名单
// ---------------------------------------------------------------------------

async fn send_frame(stream: &mut TcpStream, flag: &[u8; 4], body: &serde_json::Value) {
    let raw = serde_json::to_vec(body).unwrap();
    nps_legacy::write_flag_content(stream, flag, &raw)
        .await
        .unwrap();
}

fn task_frame(port: u16) -> serde_json::Value {
    json!({
        "Id": 0,
        "Port": 0,
        "ServerIp": "",
        "Mode": "tcp",
        "Status": true,
        "RunStatus": false,
        "Client": null,
        "Ports": port.to_string(),
        "Flow": null,
        "Password": "",
        "Remark": "conf-reg",
        "TargetAddr": "",
        "NoStore": true,
        "LocalPath": "",
        "StripPre": "",
        "Target": {
            "TargetStr": "127.0.0.1:9",
            "TargetArr": null,
            "LocalProxy": false
        },
        "MultiAccount": null
    })
}

#[tokio::test]
async fn conf_registered_tunnel_inherits_ip_whitelist() {
    let port = free_port().await;
    let mut cfg = config(vec!["192.0.2.1".into()], 0, 0);
    cfg.conf_register = true;
    cfg.conf_listen_host = "127.0.0.1".into();
    cfg.conf_max_tunnels = 8;

    let server = Server::start(cfg).await.unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let npc = spawn_echo_npc(server.bridge_addr(), accepted.clone()).await;
    wait_client_online(&server).await;

    // conf 会话：握手 → isPub(false) → task 帧 → 应答 true
    let mut conf = npc_handshake(server.bridge_addr(), b"conf").await;
    let mut is_pub = [0u8; 1];
    conf.read_exact(&mut is_pub).await.unwrap();
    assert_eq!(is_pub[0], 0, "本实现不动态创建客户端，isPub 必须为 false");
    send_frame(&mut conf, b"task", &task_frame(port)).await;
    let mut ok = [0u8; 1];
    conf.read_exact(&mut ok).await.unwrap();
    assert_ne!(ok[0], 0, "注册应成功");

    // 注册的隧道出现在快照里
    let snap = server.snapshot().await;
    assert!(
        snap.tunnels.iter().any(|t| t.name == "conf-reg"),
        "注册隧道应出现在快照中"
    );

    // 白名单拒绝：连接被直接关闭，且不向 npc 建流
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf))
        .await
        .expect("等待连接关闭超时")
        .expect("读取失败");
    assert_eq!(n, 0, "白名单拒绝时应直接关闭，不转发");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "被白名单拒绝的连接不应消耗 npc 侧子流"
    );

    drop(conf);
    server.shutdown().await;
    npc.abort();
}

// ---------------------------------------------------------------------------
// 5. per-client 流量上限跨路径共享
// ---------------------------------------------------------------------------

#[tokio::test]
async fn flow_limit_is_shared_across_tcp_and_http() {
    let tcp_port = free_port().await;
    let http_port = free_port().await;
    // 1 KB 上限：TCP 隧道往返 2 KiB 就会打满（上下行都计数）
    let mut cfg = config(Vec::new(), 0, 1);
    cfg.tunnels = vec![TcpTunnelConfig {
        id: 1,
        name: "tcp".into(),
        client_id: 1,
        listen_addr: format!("127.0.0.1:{tcp_port}"),
        target_addr: "127.0.0.1:9".into(),
        enabled: true,
        target_addrs: Vec::new(),
        health_check: None,
    }];
    cfg.http_listen_addr = Some(format!("127.0.0.1:{http_port}"));
    cfg.http_sites = vec![HttpSiteConfig {
        id: 2,
        name: "site".into(),
        client_id: 1,
        domain: "flow.test".into(),
        target_addr: "127.0.0.1:9".into(),
        routes: Vec::new(),
        websocket: true,
        enabled: true,
        tls_mode: nps_server::TlsMode::Off,
        force_https: false,
    }];

    let server = Server::start(cfg).await.unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let npc = spawn_echo_npc(server.bridge_addr(), accepted.clone()).await;
    wait_client_online(&server).await;

    // 经 TCP 隧道打满流量（回显 npc：发 2 KiB、收 2 KiB）
    let mut tcp = TcpStream::connect(("127.0.0.1", tcp_port)).await.unwrap();
    let payload = vec![0x5au8; 2048];
    tcp.write_all(&payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), tcp.read_exact(&mut echoed))
        .await
        .expect("等待回显超时")
        .expect("回显读取失败");
    assert_eq!(echoed, payload);
    drop(tcp);
    // 记账发生在写入之后，给它一点时间
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 同一客户端的 HTTP 站点必须被拒（503），且不向 npc 建流
    let before = accepted.load(Ordering::SeqCst);
    let mut http = TcpStream::connect(("127.0.0.1", http_port)).await.unwrap();
    http.write_all(b"GET / HTTP/1.1\r\nHost: flow.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(read_http_status(&mut http).await, 503);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        before,
        "流量超限的 HTTP 请求不应建流"
    );

    server.shutdown().await;
    npc.abort();
}
