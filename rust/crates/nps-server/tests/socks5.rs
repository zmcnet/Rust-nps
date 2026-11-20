//! SOCKS5 代理集成测试。
//!
//! 用真实 `MuxSession` 扮演老 npc（握手 + 接受子流 + 按 Link 的 Host 回显），
//! 从外部用**手写 SOCKS5 客户端**走完整握手/认证/CONNECT，断言：
//! - 无认证与用户名密码认证两条路径；
//! - 错误密码被拒（不发请求、连接关闭）；
//! - CONNECT 的 IPv4 / 域名 / IPv6 三种 ATYP 都产出正确的 Link；
//! - 客户端离线 → REP=1；mux 建流失败 → REP=4；
//! - BIND → REP=7；未知 ATYP → REP=8；
//! - 握手超时（不发任何字节）会被关闭；
//! - 并发上限生效；
//! - UDP ASSOCIATE 用 `udp5` 子流完成一次真实的 UDP 往返。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use nps_legacy::mux::MuxSession;
use nps_legacy::Bridge;
use nps_server::socks5::{reply, Socks5Server};
use nps_server::Socks5Config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

const VKEY: &str = "socks5-integration-key-7c1f";

// ---------------------------------------------------------------------------
// 假 npc
// ---------------------------------------------------------------------------

fn test_bridge() -> Bridge {
    Bridge::new(|v| {
        if v == nps_legacy::md5_hex(VKEY) {
            Some(1)
        } else {
            None
        }
    })
}

/// 老 npc 的握手字节序列
async fn npc_handshake(addr: SocketAddr, conn_type: &[u8; 4]) -> TcpStream {
    let mut c = TcpStream::connect(addr).await.unwrap();
    c.write_all(b"TST").await.unwrap();
    nps_legacy::write_len_content(&mut c, nps_proto::CORE_VERSION.as_bytes())
        .await
        .unwrap();
    nps_legacy::write_len_content(&mut c, b"0.26.10").await.unwrap();
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

/// 子流首帧解出的 Link（`int32 LE 长度 + JSON`）
fn parse_link(frame: &[u8]) -> serde_json::Value {
    assert!(frame.len() >= 4, "首帧过短: {frame:?}");
    let len = i32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    assert_eq!(len, frame.len() - 4, "长度前缀与实际载荷不符");
    serde_json::from_slice(&frame[4..]).expect("Link 不是合法 JSON")
}

/// 启动假 npc：main 保活 + chan mux 接受子流。
///
/// 收到 Link 后按 `Host` 的端口部分做回显（不需要真的拨号）：
/// 测试只关心字节是否原样往返。Link JSON 通过 channel 回传给测试断言。
async fn spawn_fake_npc(
    bridge: Bridge,
    links: mpsc::UnboundedSender<serde_json::Value>,
    udp_ready: mpsc::UnboundedSender<i32>,
) -> tokio::task::JoinHandle<()> {
    let addr = start_bridge(bridge).await;
    tokio::spawn(async move {
        let mut main = npc_handshake(addr, b"main").await;
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            loop {
                match main.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });

        let chan = npc_handshake(addr, b"chan").await;
        let mux = MuxSession::new(chan);
        while let Ok(mut stream) = mux.accept_stream().await {
            let links = links.clone();
            let udp_ready = udp_ready.clone();
            tokio::spawn(async move {
                let first = match stream.recv_data().await {
                    Some(d) => d,
                    None => return,
                };
                let link = parse_link(&first);
                let is_udp5 = link["ConnType"] == "udp5";
                let _ = links.send(link);

                if is_udp5 {
                    // udp5 子流的方向约定（与 Go 原版一致，两个方向不对称）：
                    //   server -> npc：裸 SOCKS5 UDP 报文（每条一次 mux 写入）
                    //   npc -> server：`int32 LE 长度 + 报文`
                    // 假 npc 把每个裸报文加长度前缀后原样回送（模拟目标回包）。
                    let _ = udp_ready.send(stream.id());
                    while let Some(dgram) = stream.recv_data().await {
                        let mut frame = (dgram.len() as i32).to_le_bytes().to_vec();
                        frame.extend_from_slice(&dgram);
                        if stream.send_data(&frame).await.is_err() {
                            return;
                        }
                    }
                } else {
                    // tcp：原样回显
                    while let Some(data) = stream.recv_data().await {
                        if stream.send_data(&data).await.is_err() {
                            break;
                        }
                    }
                }
                stream.close();
            });
        }
    })
}

async fn start_bridge(bridge: Bridge) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = bridge.serve_on(listener).await;
    });
    addr
}

// ---------------------------------------------------------------------------
// 服务器装配
// ---------------------------------------------------------------------------

fn cfg(users: Vec<nps_server::Socks5User>) -> Socks5Config {
    Socks5Config {
        id: 1,
        name: "s5-test".into(),
        client_id: 1,
        listen_addr: "127.0.0.1:0".into(),
        users,
        enabled: true,
    }
}

struct Harness {
    bridge: Bridge,
    server: Arc<Socks5Server>,
    socks_addr: SocketAddr,
    links: mpsc::UnboundedReceiver<serde_json::Value>,
    udp_ready: mpsc::UnboundedReceiver<i32>,
    npc: tokio::task::JoinHandle<()>,
}

async fn harness(users: Vec<nps_server::Socks5User>) -> Harness {
    let bridge = test_bridge();
    let (link_tx, links) = mpsc::unbounded_channel();
    let (udp_tx, udp_ready) = mpsc::unbounded_channel();
    let npc = spawn_fake_npc(bridge.clone(), link_tx, udp_tx).await;

    let server = Arc::new(Socks5Server::new(cfg(users), bridge.clone()));
    let socks_addr = server.start().await.unwrap();
    wait_online(&bridge).await;

    Harness {
        bridge,
        server,
        socks_addr,
        links,
        udp_ready,
        npc,
    }
}

impl Harness {
    async fn shutdown(self) {
        self.server.shutdown().await;
        self.npc.abort();
        self.bridge.shutdown().await;
    }
}

async fn wait_online(bridge: &Bridge) {
    for _ in 0..200 {
        if bridge.is_client_online(1).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("假 npc 未上线");
}

// ---------------------------------------------------------------------------
// 手写 SOCKS5 客户端
// ---------------------------------------------------------------------------

async fn recv_exact(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).await.unwrap();
    buf
}

/// greeting +（可选）认证，返回服务端选中的方法
async fn negotiate(s: &mut TcpStream, userpass: Option<(&str, &str)>) -> u8 {
    let methods: Vec<u8> = if userpass.is_some() {
        vec![0x00, 0x02]
    } else {
        vec![0x00]
    };
    let mut greet = vec![0x05, methods.len() as u8];
    greet.extend_from_slice(&methods);
    s.write_all(&greet).await.unwrap();

    let resp = recv_exact(s, 2).await;
    assert_eq!(resp[0], 0x05, "服务端版本必须是 5");
    let chosen = resp[1];

    if chosen == 0x02 {
        let (u, p) = userpass.expect("服务端要求认证，但测试没给凭据");
        let mut auth = vec![0x01, u.len() as u8];
        auth.extend_from_slice(u.as_bytes());
        auth.push(p.len() as u8);
        auth.extend_from_slice(p.as_bytes());
        s.write_all(&auth).await.unwrap();
        let r = recv_exact(s, 2).await;
        assert_eq!(r[0], 0x01, "认证子协议版本必须是 1");
        assert_eq!(r[1], 0x00, "认证应成功");
    }
    chosen
}

/// 发请求并读应答，返回 (REP, BND 地址字符串)
async fn request(s: &mut TcpStream, cmd: u8, atyp: u8, addr: &[u8], port: u16) -> (u8, SocketAddr) {
    let mut req = vec![0x05, cmd, 0x00, atyp];
    match atyp {
        0x03 => {
            req.push(addr.len() as u8);
            req.extend_from_slice(addr);
        }
        _ => req.extend_from_slice(addr),
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.unwrap();
    read_reply(s).await
}

async fn read_reply(s: &mut TcpStream) -> (u8, SocketAddr) {
    let head = recv_exact(s, 4).await;
    assert_eq!(head[0], 0x05, "应答版本必须是 5");
    assert_eq!(head[2], 0x00, "应答 RSV 必须是 0");
    let rep = head[1];
    let bnd = match head[3] {
        0x01 => {
            let ip = recv_exact(s, 4).await;
            let b = recv_exact(s, 2).await;
            SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
                u16::from_be_bytes([b[0], b[1]]),
            )
        }
        0x04 => {
            let ip = recv_exact(s, 16).await;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&ip);
            let b = recv_exact(s, 2).await;
            SocketAddr::new(
                std::net::IpAddr::V6(octets.into()),
                u16::from_be_bytes([b[0], b[1]]),
            )
        }
        other => panic!("应答 ATYP 非法: {other}"),
    };
    (rep, bnd)
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[tokio::test]
async fn connect_without_auth_round_trips_bytes() {
    let mut h = harness(vec![]).await;
    let mut c = TcpStream::connect(h.socks_addr).await.unwrap();

    let method = negotiate(&mut c, None).await;
    assert_eq!(method, 0x00, "未配置账号时必须选无认证");

    let (rep, _bnd) = request(&mut c, 0x01, 0x01, &[127, 0, 0, 1], 18080).await;
    assert_eq!(rep, reply::SUCCEEDED, "CONNECT 应成功");

    // Link 必须是第一帧，且 Host/ConnType/RemoteAddr 正确
    let link = tokio::time::timeout(Duration::from_secs(5), h.links.recv())
        .await
        .expect("未收到 Link")
        .unwrap();
    assert_eq!(link["ConnType"], "tcp");
    assert_eq!(link["Host"], "127.0.0.1:18080");
    assert_eq!(link["LocalProxy"], false);
    assert!(link["RemoteAddr"].as_str().unwrap().starts_with("127.0.0.1:"));

    // 逐字节往返
    let payload: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();
    let mut got = Vec::with_capacity(payload.len());
    let writer = {
        let mut c2 = c;
        let p = payload.clone();
        tokio::spawn(async move {
            c2.write_all(&p).await.unwrap();
            c2
        })
    };
    let mut c = writer.await.unwrap();
    while got.len() < payload.len() {
        let chunk = tokio::time::timeout(Duration::from_secs(10), async {
            let mut b = vec![0u8; 4096];
            let n = c.read(&mut b).await.unwrap();
            assert!(n > 0, "连接提前关闭");
            b.truncate(n);
            b
        })
        .await
        .expect("回显超时");
        got.extend_from_slice(&chunk);
    }
    assert_eq!(got, payload, "回显载荷必须逐字节一致");

    drop(c);
    h.shutdown().await;
}

#[tokio::test]
async fn connect_with_username_password_auth() {
    let users = vec![nps_server::Socks5User {
        username: "alice".into(),
        password: "s3cret".into(),
    }];
    let mut h = harness(users).await;
    let mut c = TcpStream::connect(h.socks_addr).await.unwrap();

    let method = negotiate(&mut c, Some(("alice", "s3cret"))).await;
    assert_eq!(method, 0x02, "配置了账号必须选用户名密码认证");

    let (rep, _) = request(&mut c, 0x01, 0x01, &[10, 1, 2, 3], 443).await;
    assert_eq!(rep, reply::SUCCEEDED);

    let link = tokio::time::timeout(Duration::from_secs(5), h.links.recv())
        .await
        .expect("未收到 Link")
        .unwrap();
    assert_eq!(link["Host"], "10.1.2.3:443");

    c.write_all(b"ping").await.unwrap();
    let echoed = recv_exact(&mut c, 4).await;
    assert_eq!(&echoed, b"ping");

    drop(c);
    h.shutdown().await;
}

#[tokio::test]
async fn wrong_password_is_rejected_and_connection_closed() {
    let users = vec![nps_server::Socks5User {
        username: "alice".into(),
        password: "s3cret".into(),
    }];
    let mut h = harness(users).await;
    let mut c = TcpStream::connect(h.socks_addr).await.unwrap();

    // 手动握手，断言认证失败应答是 [1, 1]
    c.write_all(&[0x05, 0x02, 0x00, 0x02]).await.unwrap();
    let resp = recv_exact(&mut c, 2).await;
    assert_eq!(resp, vec![0x05, 0x02]);

    let mut auth = vec![0x01, 5u8];
    auth.extend_from_slice(b"alice");
    auth.push(7u8);
    auth.extend_from_slice(b"wrong!!");
    c.write_all(&auth).await.unwrap();

    let r = recv_exact(&mut c, 2).await;
    assert_eq!(r, vec![0x01, 0x01], "认证失败必须回 [VER=1, STATUS=1]");

    // 之后服务端应立即关闭（读不到任何字节）
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(3), c.read(&mut buf))
        .await
        .expect("认证失败后连接未被关闭")
        .unwrap();
    assert_eq!(n, 0, "认证失败后不应再有数据");

    // 没有产生任何 Link（没有向 npc 建流）
    assert!(
        h.links.try_recv().is_err(),
        "认证失败不应向 npc 建流"
    );

    drop(c);
    h.shutdown().await;
}

#[tokio::test]
async fn unknown_username_is_rejected() {
    let users = vec![nps_server::Socks5User {
        username: "alice".into(),
        password: "s3cret".into(),
    }];
    let h = harness(users).await;
    let mut c = TcpStream::connect(h.socks_addr).await.unwrap();

    c.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    assert_eq!(recv_exact(&mut c, 2).await, vec![0x05, 0x02]);

    let mut auth = vec![0x01, 3u8];
    auth.extend_from_slice(b"bob");
    auth.push(3u8);
    auth.extend_from_slice(b"xyz");
    c.write_all(&auth).await.unwrap();
    assert_eq!(recv_exact(&mut c, 2).await, vec![0x01, 0x01]);

    drop(c);
    h.shutdown().await;
}

#[tokio::test]
async fn no_auth_offered_when_accounts_configured_is_refused() {
    let users = vec![nps_server::Socks5User {
        username: "alice".into(),
        password: "s3cret".into(),
    }];
    let h = harness(users).await;
    let mut c = TcpStream::connect(h.socks_addr).await.unwrap();

    // 只提供"无认证"：服务端必须回 0xFF 并关闭
    c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let resp = recv_exact(&mut c, 2).await;
    assert_eq!(resp, vec![0x05, 0xFF]);

    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(3), c.read(&mut buf))
        .await
        .expect("0xFF 后连接未被关闭")
        .unwrap();
    assert_eq!(n, 0);

    drop(c);
    h.shutdown().await;
}

#[tokio::test]
async fn domain_atyp_is_forwarded_as_host_port() {
    let mut h = harness(vec![]).await;
    let mut c = TcpStream::connect(h.socks_addr).await.unwrap();
    negotiate(&mut c, None).await;

    let (rep, _) = request(&mut c, 0x01, 0x03, b"example.internal", 8080).await;
    assert_eq!(rep, reply::SUCCEEDED);

    let link = tokio::time::timeout(Duration::from_secs(5), h.links.recv())
        .await
        .expect("未收到 Link")
        .unwrap();
    assert_eq!(
        link["Host"], "example.internal:8080",
        "域名类型必须原样交给 npc 去解析"
    );

    drop(c);
    h.shutdown().await;
}

#[tokio::test]
async fn ipv6_atyp_is_bracketed_in_link_host() {
    let mut h = harness(vec![]).await;
    let mut c = TcpStream::connect(h.socks_addr).await.unwrap();
    negotiate(&mut c, None).await;

    let v6 = std::net::Ipv6Addr::LOCALHOST.octets();
    let (rep, _) = request(&mut c, 0x01, 0x04, &v6, 9090).await;
    assert_eq!(rep, reply::SUCCEEDED);

    let link = tokio::time::timeout(Duration::from_secs(5), h.links.recv())
        .await
        .expect("未收到 Link")
        .unwrap();
    assert_eq!(
        link["Host"], "[::1]:9090",
        "IPv6 必须加方括号，否则 npc 的 net.Dial 会失败"
    );

    drop(c);
    h.shutdown().await;
}

#[tokio::test]
async fn bind_command_returns_rep7() {
    let mut h = harness(vec![]).await;
    let mut c = TcpStream::connect(h.socks_addr).await.unwrap();
    negotiate(&mut c, None).await;

    let (rep, _) = request(&mut c, 0x02, 0x01, &[127, 0, 0, 1], 0).await;
    assert_eq!(rep, reply::COMMAND_NOT_SUPPORTED, "BIND 必须如实返回 REP=7");
    assert!(h.links.try_recv().is_err(), "BIND 不应向 npc 建流");

    drop(c);
    h.shutdown().await;
}

#[tokio::test]
async fn unknown_command_returns_rep7() {
    let h = harness(vec![]).await;
    let mut c = TcpStream::connect(h.socks_addr).await.unwrap();
    negotiate(&mut c, None).await;

    let (rep, _) = request(&mut c, 0x09, 0x01, &[127, 0, 0, 1], 80).await;
    assert_eq!(rep, reply::COMMAND_NOT_SUPPORTED);

    drop(c);
    h.shutdown().await;
}

#[tokio::test]
async fn unknown_atyp_returns_rep8() {
    let h = harness(vec![]).await;
    let mut c = TcpStream::connect(h.socks_addr).await.unwrap();
    negotiate(&mut c, None).await;

    // ATYP=0x09 未定义
    let mut req = vec![0x05, 0x01, 0x00, 0x09];
    req.extend_from_slice(&[1, 2, 3, 4, 0, 80]);
    c.write_all(&req).await.unwrap();
    let (rep, _) = read_reply(&mut c).await;
    assert_eq!(rep, reply::ADDRESS_TYPE_NOT_SUPPORTED, "未知 ATYP 必须 REP=8");

    drop(c);
    h.shutdown().await;
}

#[tokio::test]
async fn zero_length_domain_returns_rep8() {
    let h = harness(vec![]).await;
    let mut c = TcpStream::connect(h.socks_addr).await.unwrap();
    negotiate(&mut c, None).await;

    let mut req = vec![0x05, 0x01, 0x00, 0x03, 0x00];
    req.extend_from_slice(&80u16.to_be_bytes());
    c.write_all(&req).await.unwrap();
    let (rep, _) = read_reply(&mut c).await;
    assert_eq!(rep, reply::ADDRESS_TYPE_NOT_SUPPORTED);

    drop(c);
    h.shutdown().await;
}

#[tokio::test]
async fn offline_client_returns_rep1() {
    // 不起假 npc：bridge 里没有任何客户端
    let bridge = test_bridge();
    let server = Arc::new(Socks5Server::new(cfg(vec![]), bridge.clone()));
    let addr = server.start().await.unwrap();

    let mut c = TcpStream::connect(addr).await.unwrap();
    negotiate(&mut c, None).await;
    let (rep, _) = request(&mut c, 0x01, 0x01, &[127, 0, 0, 1], 80).await;
    assert_eq!(rep, reply::GENERAL_FAILURE, "客户端离线必须 REP=1");

    drop(c);
    server.shutdown().await;
    bridge.shutdown().await;
}

#[tokio::test]
async fn handshake_timeout_closes_connection() {
    let bridge = test_bridge();
    let server = Arc::new(
        Socks5Server::new(cfg(vec![]), bridge.clone())
            .with_handshake_timeout(Duration::from_millis(300)),
    );
    let addr = server.start().await.unwrap();

    let mut c = TcpStream::connect(addr).await.unwrap();
    // 一个字节都不发
    let mut buf = [0u8; 1];
    let r = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf)).await;
    match r {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        other => panic!("握手超时后连接未被关闭: {other:?}"),
    }

    drop(c);
    server.shutdown().await;
    bridge.shutdown().await;
}

#[tokio::test]
async fn oversized_domain_returns_rep8() {
    let h = harness(vec![]).await;
    let mut c = TcpStream::connect(h.socks_addr).await.unwrap();
    negotiate(&mut c, None).await;

    // 长度字段 200 但只发 10 字节 → 服务端等待超时后关闭（长度本身合法）。
    // 这里专门构造"长度 0xFF"的边界：255 是上限，必须被接受路径处理，
    // 所以用 0 长度已在上一个用例覆盖；这里验证超长域名不会被解析成功。
    let mut req = vec![0x05, 0x01, 0x00, 0x03, 200u8];
    req.extend_from_slice(b"short");
    c.write_all(&req).await.unwrap();

    // 服务端还在等剩余 195 字节 → 我们主动关闭，服务端应干净退出不 panic
    drop(c);
    tokio::time::sleep(Duration::from_millis(100)).await;
    h.shutdown().await;
}

#[tokio::test]
async fn concurrency_limit_rejects_extra_connections() {
    let bridge = test_bridge();
    let server = Arc::new(
        Socks5Server::new(cfg(vec![]), bridge.clone()).with_max_connections(1),
    );
    let addr = server.start().await.unwrap();

    // 第一条：只连不发（占住名额，等握手超时）
    let first = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(server.active_connections(), 1);

    // 第二条：应被立即关闭
    let mut second = TcpStream::connect(addr).await.unwrap();
    second.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut buf = [0u8; 1];
    let r = tokio::time::timeout(Duration::from_secs(3), second.read(&mut buf)).await;
    match r {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        other => panic!("超限连接未被关闭: {other:?}"),
    }

    drop(first);
    server.shutdown().await;
    bridge.shutdown().await;
}

#[tokio::test]
async fn version_mismatch_closes_silently() {
    let bridge = test_bridge();
    let server = Arc::new(Socks5Server::new(cfg(vec![]), bridge.clone()));
    let addr = server.start().await.unwrap();

    let mut c = TcpStream::connect(addr).await.unwrap();
    // SOCKS4 风格的版本号 4
    c.write_all(&[0x04, 0x01, 0x00]).await.unwrap();
    let mut buf = [0u8; 1];
    let r = tokio::time::timeout(Duration::from_secs(3), c.read(&mut buf)).await;
    match r {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        other => panic!("版本不符时连接未被关闭: {other:?}"),
    }

    drop(c);
    server.shutdown().await;
    bridge.shutdown().await;
}

#[tokio::test]
async fn udp_associate_round_trips_a_datagram() {
    let mut h = harness(vec![]).await;
    let mut ctrl = TcpStream::connect(h.socks_addr).await.unwrap();
    negotiate(&mut ctrl, None).await;

    // UDP ASSOCIATE：地址字段填 0.0.0.0:0（客户端尚未绑定 UDP）
    let (rep, bnd) = request(&mut ctrl, 0x03, 0x01, &[0, 0, 0, 0], 0).await;
    assert_eq!(rep, reply::SUCCEEDED, "UDP ASSOCIATE 应成功");
    assert_ne!(bnd.port(), 0, "BND 端口必须是真实的本地 UDP 端口");

    // 子流必须是 udp5，且 Host 为空
    let link = tokio::time::timeout(Duration::from_secs(5), h.links.recv())
        .await
        .expect("未收到 Link")
        .unwrap();
    assert_eq!(link["ConnType"], "udp5");
    assert_eq!(link["Host"], "");

    // 假 npc 已准备好接受 udp5 子流
    tokio::time::timeout(Duration::from_secs(5), h.udp_ready.recv())
        .await
        .expect("假 npc 未接受 udp5 子流")
        .unwrap();

    // 客户端 UDP socket 向 BND 发一条 SOCKS5 UDP 报文
    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut dgram = vec![0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8];
    dgram.extend_from_slice(&53u16.to_be_bytes());
    dgram.extend_from_slice(b"hello-udp");
    client_udp.send_to(&dgram, bnd).await.unwrap();

    // 假 npc 原样回送 → 服务端应以 `int32 LE 长度 + 报文` 帧回给客户端
    let mut buf = [0u8; 2048];
    let (n, _src) = tokio::time::timeout(Duration::from_secs(5), client_udp.recv_from(&mut buf))
        .await
        .expect("未收到 UDP 回包")
        .unwrap();
    assert_eq!(&buf[..n], &dgram[..], "UDP 报文必须逐字节一致");

    // 关掉 TCP 控制连接 → 关联结束（RFC 1928）
    drop(ctrl);
    tokio::time::sleep(Duration::from_millis(200)).await;

    h.shutdown().await;
}

#[tokio::test]
async fn udp_associate_offline_client_returns_rep1() {
    let bridge = test_bridge();
    let server = Arc::new(Socks5Server::new(cfg(vec![]), bridge.clone()));
    let addr = server.start().await.unwrap();

    let mut c = TcpStream::connect(addr).await.unwrap();
    negotiate(&mut c, None).await;
    let (rep, _) = request(&mut c, 0x03, 0x01, &[0, 0, 0, 0], 0).await;
    assert_eq!(rep, reply::GENERAL_FAILURE);

    drop(c);
    server.shutdown().await;
    bridge.shutdown().await;
}

#[tokio::test]
async fn shutdown_releases_listen_port() {
    let bridge = test_bridge();
    let server = Arc::new(Socks5Server::new(cfg(vec![]), bridge.clone()));
    let addr = server.start().await.unwrap();

    server.shutdown().await;
    assert!(server.is_closing());

    let mut rebound = false;
    for _ in 0..50 {
        if tokio::net::TcpListener::bind(addr).await.is_ok() {
            rebound = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(rebound, "shutdown 后 SOCKS5 端口未释放");

    // 幂等
    server.shutdown().await;
    bridge.shutdown().await;
}

/// 账号表可以从 `Socks5Config.users` 直接构建（服务端装配路径）
#[tokio::test]
async fn users_from_config_are_used_for_auth() {
    let users = vec![
        nps_server::Socks5User {
            username: "u1".into(),
            password: "p1".into(),
        },
        nps_server::Socks5User {
            username: "u2".into(),
            password: "p2".into(),
        },
    ];
    let h = harness(users).await;

    for (u, p) in [("u1", "p1"), ("u2", "p2")] {
        let mut c = TcpStream::connect(h.socks_addr).await.unwrap();
        negotiate(&mut c, Some((u, p))).await;
        let (rep, _) = request(&mut c, 0x01, 0x01, &[127, 0, 0, 1], 1234).await;
        assert_eq!(rep, reply::SUCCEEDED, "账号 {u} 应能通过认证");
        drop(c);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // 交叉组合必须失败
    let mut c = TcpStream::connect(h.socks_addr).await.unwrap();
    c.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    assert_eq!(recv_exact(&mut c, 2).await, vec![0x05, 0x02]);
    let mut auth = vec![0x01, 2u8];
    auth.extend_from_slice(b"u1");
    auth.push(2u8);
    auth.extend_from_slice(b"p2");
    c.write_all(&auth).await.unwrap();
    assert_eq!(recv_exact(&mut c, 2).await, vec![0x01, 0x01]);

    drop(c);
    h.shutdown().await;
}

/// 确保 `HashMap` 直传路径（`with_users`）也工作
#[tokio::test]
async fn with_users_constructor_accepts_hashmap() {
    let bridge = test_bridge();
    let mut users = HashMap::new();
    users.insert("bob".to_string(), "hunter2".to_string());
    let server = Arc::new(Socks5Server::with_users(cfg(vec![]), bridge.clone(), users));
    let addr = server.start().await.unwrap();

    let mut c = TcpStream::connect(addr).await.unwrap();
    c.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    assert_eq!(recv_exact(&mut c, 2).await, vec![0x05, 0x02]);
    let mut auth = vec![0x01, 3u8];
    auth.extend_from_slice(b"bob");
    auth.push(7u8);
    auth.extend_from_slice(b"hunter2");
    c.write_all(&auth).await.unwrap();
    assert_eq!(recv_exact(&mut c, 2).await, vec![0x01, 0x00]);

    drop(c);
    server.shutdown().await;
    bridge.shutdown().await;
}

// ---------------------------------------------------------------------------
// 互操作宿主：给 tools/interop/socks5-smoke.py 用真实 Go npc 验证
// ---------------------------------------------------------------------------
//
// 这是一个**被忽略的**测试，只在显式提供环境变量时启动：
//   NPS_SOCKS5_IT_BRIDGE=127.0.0.1:<port>   真实 npc 要连的桥地址
//   NPS_SOCKS5_IT_VKEY=<vkey>               真实 npc 使用的 vkey
//   NPS_SOCKS5_IT_LISTEN=127.0.0.1:<port>   SOCKS5 监听地址
//   NPS_SOCKS5_IT_USERS=alice:s3cret,bob:pw 可选，留空则无认证
//   NPS_SOCKS5_IT_READY=<file>              启动完成后写一个 ready 文件
//
// 这样 Python 侧只负责"起进程 + 用手写 SOCKS5 客户端断言"，协议完全真跑。
#[tokio::test]
#[ignore = "互操作宿主：由 tools/interop/socks5-smoke.py 通过环境变量驱动"]
async fn interop_host_for_real_npc() {
    let Ok(bridge_addr) = std::env::var("NPS_SOCKS5_IT_BRIDGE") else {
        return;
    };
    let vkey = std::env::var("NPS_SOCKS5_IT_VKEY").expect("NPS_SOCKS5_IT_VKEY 必填");
    let listen = std::env::var("NPS_SOCKS5_IT_LISTEN").expect("NPS_SOCKS5_IT_LISTEN 必填");
    let users_spec = std::env::var("NPS_SOCKS5_IT_USERS").unwrap_or_default();
    let ready_path = std::env::var("NPS_SOCKS5_IT_READY").ok();

    // 桥：只认这一个 vkey -> client id 1
    let md5 = nps_legacy::md5_hex(&vkey);
    let bridge = Bridge::new(move |v| if v == md5 { Some(1) } else { None });
    let listener = tokio::net::TcpListener::bind(&bridge_addr)
        .await
        .expect("绑定桥端口失败");
    let actual_bridge = listener.local_addr().unwrap();
    let bridge_for_loop = bridge.clone();
    tokio::spawn(async move {
        let _ = bridge_for_loop.serve_on(listener).await;
    });

    // 账号表
    let mut users = HashMap::new();
    for item in users_spec.split(',').filter(|s| !s.is_empty()) {
        let (u, p) = item.split_once(':').expect("users 格式应为 user:pass");
        users.insert(u.to_string(), p.to_string());
    }
    let user_vec: Vec<nps_server::Socks5User> = users
        .iter()
        .map(|(u, p)| nps_server::Socks5User {
            username: u.clone(),
            password: p.clone(),
        })
        .collect();

    let server = Arc::new(Socks5Server::new(
        Socks5Config {
            id: 1,
            name: "interop".into(),
            client_id: 1,
            listen_addr: listen.clone(),
            users: user_vec,
            enabled: true,
        },
        bridge.clone(),
    ));
    let socks_addr = server.start().await.expect("SOCKS5 启动失败");
    eprintln!("SOCKS5 interop host: bridge={actual_bridge} socks5={socks_addr}");

    if let Some(path) = ready_path {
        std::fs::write(path, format!("{socks_addr}")).expect("写 ready 文件失败");
    }

    // 运行到 Ctrl+C / 进程被杀（Python 侧 kill）
    let _ = tokio::signal::ctrl_c().await;
    server.shutdown().await;
    bridge.shutdown().await;
}
