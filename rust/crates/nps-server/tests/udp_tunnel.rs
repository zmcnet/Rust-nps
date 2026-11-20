//! UDP 隧道集成测试：用真实 `MuxSession` 扮演老 npc（与 `e2e_forwarding.rs`
//! 同一套握手字节序列），验证数据面、来源隔离、空闲回收、关闭清理与计数归零。
//!
//! 覆盖点：
//! 1. 绑定 `:0` + 快照；关闭后端口释放、快照 `enabled=false`
//! 2. 单包往返逐字节一致 + Link 首帧内容（ConnType=udp / Host / RemoteAddr）
//! 3. 多个不同来源端口并发，各收各的回显（addrMap 隔离）
//! 4. 空闲超时回收（可配置）
//! 5. 客户端离线：不建流、不 panic、计数归零
//! 6. 超出并发上限：丢包且不 panic
//! 7. 子流被对端关闭：映射清理、计数归零
//! 8. shutdown：计数归零、端口释放

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use nps_legacy::mux::MuxSession;
use nps_legacy::Bridge;
use nps_server::{UdpTunnel, UdpTunnelConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};

const VKEY: &str = "udp-test-key-7c31";
/// 测试里模拟的目标地址（fake npc 不回显真实拨号，仅校验 Link.Host）
const TARGET: &str = "127.0.0.1:9";

fn cfg(listen: &str) -> UdpTunnelConfig {
    UdpTunnelConfig {
        id: 1,
        name: "udp-echo".into(),
        client_id: 1,
        listen_addr: listen.into(),
        target_addr: TARGET.into(),
        enabled: true,
        idle_timeout_secs: 600,
        max_sessions: 512,
    }
}

/// 模拟老 npc 的握手字节序列
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
    c.write_all(nps_legacy::md5_hex(VKEY).as_bytes()).await.unwrap();
    let mut ok = [0u8; 4];
    c.read_exact(&mut ok).await.unwrap();
    assert_eq!(&ok, nps_proto::VERIFY_SUCCESS.as_bytes());
    c.write_all(conn_type).await.unwrap();
    c
}

/// 测试用桥：vkey -> client id 1
fn test_bridge() -> Bridge {
    Bridge::new(|v| {
        if v == nps_legacy::md5_hex(VKEY) {
            Some(1)
        } else {
            None
        }
    })
}

async fn serve_bridge(bridge: &Bridge) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let b = bridge.clone();
    tokio::spawn(async move {
        let _ = b.serve_on(listener).await;
    });
    addr
}

async fn wait_online(bridge: &Bridge) {
    for _ in 0..200 {
        if bridge.is_client_online(1).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("假 npc 未上线");
}

/// 启动假 npc：main + chan；对每个被接受的子流，解析首帧 Link 后原样回显。
///
/// 返回的 `mpsc::UnboundedSender` 会在每条子流建立时推送 Link JSON。
async fn spawn_fake_npc(
    bridge_addr: SocketAddr,
) -> (mpsc::UnboundedReceiver<String>, tokio::task::JoinHandle<()>) {
    let (link_tx, link_rx) = mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let handle = tokio::spawn(async move {
        // signal：保持打开并读走服务端数据
        let mut main = npc_handshake(bridge_addr, b"main").await;
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                match main.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });

        let chan = npc_handshake(bridge_addr, b"chan").await;
        let mux = MuxSession::new(chan);
        let _ = ready_tx.send(());

        while let Ok(mut stream) = mux.accept_stream().await {
            let links = link_tx.clone();
            tokio::spawn(async move {
                let first = match stream.recv_data().await {
                    Some(d) => d,
                    None => return,
                };
                if first.len() < 4 {
                    let _ = links.send(format!("BAD_FIRST_FRAME:{first:?}"));
                    return;
                }
                let len = i32::from_le_bytes([first[0], first[1], first[2], first[3]]) as usize;
                if first.len() < 4 + len {
                    let _ = links.send("SHORT_LINK_FRAME".into());
                    return;
                }
                let link = String::from_utf8_lossy(&first[4..4 + len]).to_string();
                let _ = links.send(link);

                while let Some(data) = stream.recv_data().await {
                    if stream.send_data(&data).await.is_err() {
                        break;
                    }
                }
                stream.close();
            });
        }
    });
    // 等 chan 建立完成（避免 send 时客户端还没上线）
    let _ = tokio::time::timeout(Duration::from_secs(5), ready_rx).await;
    (link_rx, handle)
}

/// 建一个带在线假 npc 的隧道，返回 (tunnel, 监听地址, links, npc 任务)
async fn setup(
    tunnel_cfg: UdpTunnelConfig,
    limits: Option<(Duration, usize, usize)>,
) -> (
    Arc<UdpTunnel>,
    SocketAddr,
    mpsc::UnboundedReceiver<String>,
    Bridge,
    tokio::task::JoinHandle<()>,
) {
    let bridge = test_bridge();
    let bridge_addr = serve_bridge(&bridge).await;
    let (links, npc_task) = spawn_fake_npc(bridge_addr).await;
    wait_online(&bridge).await;

    let tunnel = Arc::new(match limits {
        Some((idle, max, queue)) => UdpTunnel::with_limits(tunnel_cfg, idle, max, queue),
        None => UdpTunnel::new(tunnel_cfg),
    });
    let addr = tunnel.start(bridge.clone()).await.unwrap();
    (tunnel, addr, links, bridge, npc_task)
}

/// 收一个数据报（超时返回 None）
async fn recv_one(sock: &UdpSocket, wait: Duration) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 65536];
    match tokio::time::timeout(wait, sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

#[tokio::test]
async fn binds_ephemeral_reports_snapshot_and_releases_port_on_disable() {
    let bridge = test_bridge();
    let _bridge_addr = serve_bridge(&bridge).await;

    let tunnel = Arc::new(UdpTunnel::new(cfg("127.0.0.1:0")));
    let addr = tunnel.start(bridge.clone()).await.unwrap();
    assert_ne!(addr.port(), 0);

    let snap = tunnel.snapshot().await;
    assert!(snap.enabled);
    assert_eq!(snap.bound_addr.as_deref(), Some(addr.to_string().as_str()));
    assert_eq!(snap.active_connections, 0);
    assert_eq!(snap.bytes_to_client, 0);
    assert_eq!(snap.bytes_from_client, 0);
    assert!(tunnel.is_listening().await);

    tunnel.disable().await;
    let snap = tunnel.snapshot().await;
    assert!(!snap.enabled);
    assert_eq!(snap.bound_addr, None);
    assert!(!tunnel.is_listening().await);

    // 端口已释放（轮询，避免任务退出竞态）
    let mut rebound = false;
    for _ in 0..100 {
        if let Ok(s) = UdpSocket::bind(addr).await {
            drop(s);
            rebound = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(rebound, "disable 后 UDP 端口未释放: {addr}");

    // 幂等
    tunnel.disable().await;
}

#[tokio::test]
async fn single_datagram_roundtrip_is_byte_exact_and_counts_bytes() {
    let (tunnel, addr, mut links, _bridge, npc) = setup(cfg("127.0.0.1:0"), None).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = b"hello-udp-tunnel";
    client.send_to(payload, addr).await.unwrap();

    let echoed = recv_one(&client, Duration::from_secs(5))
        .await
        .expect("未收到 UDP 回显");
    assert_eq!(echoed, payload, "UDP 载荷必须逐字节一致");

    // Link 首帧：ConnType / Host / RemoteAddr
    let link = tokio::time::timeout(Duration::from_secs(5), links.recv())
        .await
        .expect("未收到 Link")
        .unwrap();
    assert!(link.contains("\"ConnType\":\"udp\""), "Link 内容异常: {link}");
    assert!(
        link.contains(&format!("\"Host\":\"{TARGET}\"")),
        "Link.Host 异常: {link}"
    );
    assert!(
        link.contains(&format!(
            "\"RemoteAddr\":\"{}\"",
            client.local_addr().unwrap()
        )),
        "Link.RemoteAddr 异常: {link}"
    );

    // 计数：上行 = 收到的 UDP 字节，下行 = 回显字节
    let mut counted = false;
    for _ in 0..200 {
        let (up, down) = tunnel.bytes();
        if up >= payload.len() as u64 && down >= payload.len() as u64 {
            assert_eq!(tunnel.active_flows(), 1);
            counted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(counted, "字节统计未更新: {:?}", tunnel.bytes());

    drop(client);
    tunnel.disable().await;
    assert_eq!(tunnel.active_flows(), 0, "关闭后活跃流数必须归零");
    npc.abort();
}

#[tokio::test]
async fn distinct_source_ports_are_isolated() {
    let (tunnel, addr, mut links, _bridge, npc) = setup(cfg("127.0.0.1:0"), None).await;

    // 4 个不同来源端口（不同 SocketAddr），各自发不同载荷、各收各的回显
    let mut clients = Vec::new();
    for i in 0..4u8 {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let payload = format!("payload-from-{i}").into_bytes();
        sock.send_to(&payload, addr).await.unwrap();
        clients.push((sock, payload));
    }

    for (sock, payload) in &clients {
        let echoed = recv_one(sock, Duration::from_secs(5))
            .await
            .unwrap_or_else(|| panic!("来源 {} 未收到回显", sock.local_addr().unwrap()));
        assert_eq!(&echoed, payload, "来源隔离失败：收到别人的响应");
    }

    // 4 条独立子流，RemoteAddr 各不相同
    let mut remotes = std::collections::HashSet::new();
    for _ in 0..4 {
        let link = tokio::time::timeout(Duration::from_secs(5), links.recv())
            .await
            .expect("未收到 Link")
            .unwrap();
        let client = clients
            .iter()
            .find(|(s, _)| link.contains(&format!("\"RemoteAddr\":\"{}\"", s.local_addr().unwrap())))
            .map(|(s, _)| s.local_addr().unwrap());
        assert!(client.is_some(), "Link 未对应任何来源: {link}");
        remotes.insert(client.unwrap());
    }
    assert_eq!(remotes.len(), 4, "4 个来源必须映射到 4 条子流");

    let mut active = 0;
    for _ in 0..200 {
        active = tunnel.active_flows();
        if active == 4 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(active, 4, "应按来源地址各建一条子流");

    drop(clients);
    tunnel.disable().await;
    assert_eq!(tunnel.active_flows(), 0);
    npc.abort();
}

#[tokio::test]
async fn idle_timeout_reclaims_flow() {
    // 空闲 200ms（IDLE_CHECK_INTERVAL=1s，实际约 1~2s 内回收）
    let (tunnel, addr, _links, _bridge, npc) =
        setup(cfg("127.0.0.1:0"), Some((Duration::from_millis(200), 8, 64))).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"idle-me", addr).await.unwrap();
    assert_eq!(
        recv_one(&client, Duration::from_secs(5)).await.as_deref(),
        Some(&b"idle-me"[..])
    );
    assert_eq!(tunnel.active_flows(), 1);

    // 等待空闲回收
    let mut zero = false;
    for _ in 0..80 {
        if tunnel.active_flows() == 0 {
            zero = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(zero, "空闲流未被回收: active={}", tunnel.active_flows());

    // 回收后同一来源再发仍可重建子流（映射没有残留）
    client.send_to(b"again", addr).await.unwrap();
    assert_eq!(
        recv_one(&client, Duration::from_secs(5)).await.as_deref(),
        Some(&b"again"[..]),
        "空闲回收后无法重建子流"
    );

    tunnel.disable().await;
    assert_eq!(tunnel.active_flows(), 0);
    npc.abort();
}

#[tokio::test]
async fn offline_client_drops_without_panic_or_leak() {
    // 桥在，但没有 main/chan 客户端 -> get_tunnel 返回 None
    let bridge = test_bridge();
    let _bridge_addr = serve_bridge(&bridge).await;

    let tunnel = Arc::new(UdpTunnel::new(cfg("127.0.0.1:0")));
    let addr = tunnel.start(bridge.clone()).await.unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for _ in 0..5 {
        client.send_to(b"nobody-listening", addr).await.unwrap();
    }
    // 不应收到任何回显
    assert!(recv_one(&client, Duration::from_millis(400)).await.is_none());

    // 名额必须归还（不泄漏）；错误被记录
    let mut zero = false;
    for _ in 0..100 {
        if tunnel.active_flows() == 0 {
            zero = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(zero, "离线客户端导致名额泄漏");
    let snap = tunnel.snapshot().await;
    assert!(snap.last_error.is_some(), "应记录客户端离线错误");

    tunnel.disable().await;
}

#[tokio::test]
async fn max_flows_limit_drops_excess_sources() {
    let (tunnel, addr, _links, _bridge, npc) =
        setup(cfg("127.0.0.1:0"), Some((Duration::from_secs(600), 1, 16))).await;

    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    a.send_to(b"first", addr).await.unwrap();
    // 等第一条流建立
    let mut active = 0;
    for _ in 0..200 {
        active = tunnel.active_flows();
        if active == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(active, 1);
    assert_eq!(
        recv_one(&a, Duration::from_secs(5)).await.as_deref(),
        Some(&b"first"[..])
    );

    // 第二个来源超限：丢包，不 panic、不建流
    b.send_to(b"second", addr).await.unwrap();
    assert!(
        recv_one(&b, Duration::from_millis(500)).await.is_none(),
        "超过 max_flows 的来源不应获得回显"
    );
    assert_eq!(tunnel.active_flows(), 1, "超限来源不应建流");

    tunnel.disable().await;
    npc.abort();
}

#[tokio::test]
async fn peer_close_clears_mapping_and_counters() {
    // 假 npc 收到子流后立刻关闭：服务端下行读到 None 应清理映射
    let bridge = test_bridge();
    let bridge_addr = serve_bridge(&bridge).await;
    let (ready_tx, ready_rx) = oneshot::channel();
    let npc = tokio::spawn(async move {
        let _main = npc_handshake(bridge_addr, b"main").await;
        let chan = npc_handshake(bridge_addr, b"chan").await;
        let mux = MuxSession::new(chan);
        let _ = ready_tx.send(());
        while let Ok(mut stream) = mux.accept_stream().await {
            // 读掉 Link 后立刻关闭整条子流
            let _ = stream.recv_data().await;
            stream.close();
        }
    });
    let _ = tokio::time::timeout(Duration::from_secs(5), ready_rx).await;
    wait_online(&bridge).await;

    let tunnel = Arc::new(UdpTunnel::new(cfg("127.0.0.1:0")));
    let addr = tunnel.start(bridge.clone()).await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"will-be-closed", addr).await.unwrap();

    let mut zero = false;
    for _ in 0..200 {
        if tunnel.active_flows() == 0 {
            zero = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(zero, "对端关闭子流后映射/计数未清理");

    tunnel.disable().await;
    npc.abort();
}

#[tokio::test]
async fn shutdown_from_many_flows_returns_to_zero() {
    let (tunnel, addr, _links, _bridge, npc) = setup(cfg("127.0.0.1:0"), None).await;

    let mut clients = Vec::new();
    for i in 0..8u8 {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.send_to(format!("p{i}").as_bytes(), addr).await.unwrap();
        clients.push(sock);
    }
    for c in &clients {
        assert!(recv_one(c, Duration::from_secs(5)).await.is_some());
    }
    assert_eq!(tunnel.active_flows(), 8);

    tunnel.shutdown().await;
    assert_eq!(tunnel.active_flows(), 0, "shutdown 后计数必须归零");
    let snap = tunnel.snapshot().await;
    assert!(!snap.enabled);
    assert_eq!(snap.active_connections, 0);

    // 关闭后原端口不应再回显
    let extra = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // 端口已释放，send_to 仍可能成功（UDP 无连接），但一定收不到响应
    let _ = extra.send_to(b"after-close", addr).await;
    assert!(recv_one(&extra, Duration::from_millis(300)).await.is_none());

    npc.abort();
}

// ============================================================================
// 真实原版 Go npc.exe 对接用 harness（由 tools/interop/udp-smoke.py 驱动）。
//
// 该 harness：
//   1) 起 Bridge（vkey 校验）+ 一个「接受所有 task 注册」的 conf 处理器，让
//      原版 npc 的 `-config=npc.conf`（含 `[udp] mode=udp`）注册阶段通过；
//   2) 起 UdpTunnel 监听 server_port，Link.Host 指向 UDP echo 目标；
//   3) 写 ready 文件后阻塞，等待真实 npc 建立 main/chan 并转发数据；
//   4) 父进程（Python）杀掉即可。
//
// 运行：
//   cargo test -p nps-server --test udp_tunnel --no-run --message-format=json
//   取 executable 后：
//   NPS_UDP_HARNESS_* ... <exe> --exact --ignored udp_interop_harness
// ============================================================================

use std::future::Future;
use std::pin::Pin;

use nps_legacy::bridge::{ConfSession, ConfSessionHandler};

/// 接受所有 task 注册的 conf 处理器（仅用于测试 harness）。
///
/// 真实 npc 的 `StartFromFile` 先连 `conf`，读到 isPub=false 后上报各 `[task]`，
/// 每条等 1 字节应答；全部通过后才建立 main/chan。这里不解析 JSON，
/// 一律回 true，因为监听端口由 harness 的 UdpTunnel 自己绑定。
struct AcceptAllConfHandler;

impl ConfSessionHandler for AcceptAllConfHandler {
    fn handle(&self, session: ConfSession) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let ConfSession {
                mut stream,
                mut closing,
                ..
            } = session;
            // isPub = false
            if stream.write_all(&[0u8]).await.is_err() {
                return;
            }
            loop {
                let flag = tokio::select! {
                    _ = closing.changed() => break,
                    r = nps_legacy::read_flag(&mut stream) => match r {
                        Ok(f) => f,
                        Err(_) => break, // npc 注册完会关闭 conf 连接
                    },
                };
                match &flag {
                    b"task" | b"host" => {
                        // 吃掉 int32 LE 长度 + JSON，回 1 字节 true
                        let ok = read_conf_frame(&mut stream, &mut closing).await;
                        if !ok || stream.write_all(&[1u8]).await.is_err() {
                            break;
                        }
                    }
                    b"stus" => {
                        let mut digest = [0u8; 32];
                        if stream.read_exact(&mut digest).await.is_err() {
                            break;
                        }
                        // 空 remark 列表：int32 LE 长度 0
                        if stream.write_all(&0i32.to_le_bytes()).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
            let _ = stream.shutdown().await;
        })
    }
}

async fn read_conf_frame(
    stream: &mut TcpStream,
    closing: &mut tokio::sync::watch::Receiver<bool>,
) -> bool {
    let len = tokio::select! {
        _ = closing.changed() => return false,
        r = nps_legacy::read_len_i32(stream) => match r {
            Ok(n) => n,
            Err(_) => return false,
        },
    };
    if len <= 0 || len as usize > 64 * 1024 {
        return false;
    }
    let mut buf = vec![0u8; len as usize];
    tokio::select! {
        _ = closing.changed() => false,
        r = stream.read_exact(&mut buf) => r.is_ok(),
    }
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("harness 缺少环境变量 {name}"))
}

/// 真实原版 npc 对接 harness（ignored，仅由 udp-smoke.py 调用）。
///
/// 环境变量：
///   NPS_UDP_HARNESS_BRIDGE  桥监听地址，如 127.0.0.1:18024
///   NPS_UDP_HARNESS_TUNNEL  UDP 隧道监听地址，如 127.0.0.1:19000
///   NPS_UDP_HARNESS_TARGET  UDP echo 目标地址，如 127.0.0.1:19001
///   NPS_UDP_HARNESS_VKEY    npc 使用的 vkey
///   NPS_UDP_HARNESS_READY   就绪标记文件路径（写 "ready"）
#[tokio::test]
#[ignore = "interop harness: driven by tools/interop/udp-smoke.py"]
async fn udp_interop_harness() {
    let bridge_addr = env("NPS_UDP_HARNESS_BRIDGE");
    let tunnel_addr = env("NPS_UDP_HARNESS_TUNNEL");
    let target_addr = env("NPS_UDP_HARNESS_TARGET");
    let vkey = env("NPS_UDP_HARNESS_VKEY");
    let ready_file = env("NPS_UDP_HARNESS_READY");
    let vkey_for_verify = vkey.clone();
    let expected_md5 = nps_legacy::md5_hex(&vkey);

    let bridge = Bridge::new(move |md5: &str| {
        if md5 == expected_md5 {
            Some(1)
        } else {
            None
        }
    });
    bridge.set_conf_handler(Arc::new(AcceptAllConfHandler));

    // 桥监听
    let listener = TcpListener::bind(&bridge_addr)
        .await
        .expect("harness 桥绑定失败");
    let bridge_for_task = bridge.clone();
    tokio::spawn(async move {
        let _ = bridge_for_task.serve_on(listener).await;
    });

    // UDP 隧道（target = echo 服务地址），由 harness 自己绑定监听端口
    let tunnel = Arc::new(UdpTunnel::new(UdpTunnelConfig {
        id: 1,
        name: "udp-interop".into(),
        client_id: 1,
        listen_addr: tunnel_addr.clone(),
        target_addr: target_addr.clone(),
        enabled: true,
        idle_timeout_secs: 600,
        max_sessions: 512,
    }));
    let bound = tunnel.start(bridge.clone()).await.expect("harness UDP 隧道绑定失败");
    eprintln!(
        "HARNESS_READY bridge={bridge_addr} tunnel={bound} target={target_addr} vkey_len={}",
        vkey_for_verify.len()
    );

    // 写就绪标记
    tokio::fs::write(&ready_file, b"ready").await.expect("写 ready 文件失败");

    // 阻塞直到被 Python 杀掉；每 500ms 打印一次活跃流数便于诊断
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
