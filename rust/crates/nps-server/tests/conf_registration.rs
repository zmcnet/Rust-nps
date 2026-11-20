//! 配置文件模式（`conf`）注册路径的集成测试。
//!
//! 覆盖：未开启时拒绝、注册成功并可见/可转发、重复注册幂等、
//! 隧道数上限、端口冲突、特权端口、host/NEW_CONF 诚实失败、`stus` 状态应答。
//!
//! 假客户端按原版 npc 的字节序列发送帧（`flag(4B) + int32 LE len + JSON`），
//! 并读取 1 字节 bool 应答。

use std::net::SocketAddr;
use std::time::Duration;

use nps_legacy::mux::MuxSession;
use nps_server::{ClientConfig, Server, ServerConfig};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

const VKEY: &str = "conf-register-vkey-7c31a0";
/// 该 vkey 必须不出现在任何快照/错误里
const SEQ: &str = "*#*";

fn config(conf_register: bool, max_tunnels: usize) -> ServerConfig {
    ServerConfig {
        bridge_addr: "127.0.0.1:0".into(),
        web_addr: "127.0.0.1:0".into(),
        clients: vec![ClientConfig {
            id: 1,
            name: "npc-conf".into(),
            vkey: VKEY.into(),
        }],
        tunnels: Vec::new(),
        conf_register,
        conf_max_tunnels: max_tunnels,
        conf_listen_host: "127.0.0.1".into(),
        ..Default::default()
    }
}

/// 原版 npc 的握手字节序列（与 e2e_forwarding.rs 一致）
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

async fn read_bool(stream: &mut TcpStream) -> bool {
    let mut b = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut b))
        .await
        .expect("等待 bool 应答超时")
        .expect("读取 bool 应答失败");
    b[0] != 0
}

async fn send_frame(stream: &mut TcpStream, flag: &[u8; 4], body: &serde_json::Value) {
    let raw = serde_json::to_vec(body).unwrap();
    nps_legacy::write_flag_content(stream, flag, &raw)
        .await
        .unwrap();
}

fn task(port: u16, target: &str, remark: &str) -> serde_json::Value {
    // 字段名对齐 Go `file.Tunnel`（无 json tag -> 导出字段名）
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
        "Remark": remark,
        "TargetAddr": "",
        "NoStore": true,
        "LocalPath": "",
        "StripPre": "",
        "Target": {
            "TargetStr": target,
            "TargetArr": null,
            "LocalProxy": false
        },
        "MultiAccount": null
    })
}

async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// 假 npc 的数据面：main + chan，接受子流并把收到的数据回显
async fn spawn_echo_npc(
    bridge: SocketAddr,
    ready: oneshot::Sender<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut main = npc_handshake(bridge, b"main").await;
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while matches!(main.read(&mut buf).await, Ok(n) if n > 0) {}
        });
        let chan = npc_handshake(bridge, b"chan").await;
        let mux = MuxSession::new(chan);
        let _ = ready.send(());
        while let Ok(mut stream) = mux.accept_stream().await {
            tokio::spawn(async move {
                // 第一帧是 Link JSON，丢弃后回显
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
    })
}

async fn wait_tunnels(server: &Server, expected: usize) {
    for _ in 0..200 {
        if server.snapshot().await.tunnels.len() == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("等待隧道数量 {expected} 超时");
}

// ---------------------------------------------------------------------------
// 1. 默认关闭：收到 conf 连接必须干净关闭（不挂起、不读不写）
// ---------------------------------------------------------------------------
#[tokio::test]
async fn conf_disabled_closes_connection_cleanly() {
    let server = Server::start(config(false, 8)).await.unwrap();
    let mut conn = npc_handshake(server.bridge_addr(), b"conf").await;

    let mut b = [0u8; 1];
    let r = tokio::time::timeout(Duration::from_secs(3), conn.read(&mut b)).await;
    match r {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("conf 关闭时服务端不应发送数据，实际读到 {n} 字节"),
        Err(_) => panic!("conf 关闭时连接挂起了（3s 内未关闭）"),
    }
    // 服务端不应注册任何隧道
    assert!(server.snapshot().await.tunnels.is_empty());
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// 2. 注册成功：快照可见 + 端口真的在监听
// ---------------------------------------------------------------------------
#[tokio::test]
async fn register_tcp_tunnel_is_visible_and_listening() {
    let server = Server::start(config(true, 8)).await.unwrap();
    let port = free_port().await;
    let target = format!("127.0.0.1:{}", free_port().await);

    let mut conn = npc_handshake(server.bridge_addr(), b"conf").await;
    // ① isPub = false
    assert!(!read_bool(&mut conn).await, "isPub 必须是 false");
    // ② task 帧
    send_frame(&mut conn, b"task", &task(port, &target, "echo")).await;
    assert!(read_bool(&mut conn).await, "首个 task 应注册成功");

    let snap = server.snapshot().await;
    assert_eq!(snap.tunnels.len(), 1);
    let t = &snap.tunnels[0];
    assert_eq!(t.name, "echo");
    assert_eq!(t.client_id, 1);
    assert_eq!(t.listen_addr, format!("127.0.0.1:{port}"));
    assert_eq!(t.target_addr, target);
    assert!(t.enabled);
    assert_eq!(
        t.bound_addr.as_deref(),
        Some(format!("127.0.0.1:{port}").as_str())
    );

    // 端口确实被占用（再绑一次应失败）
    assert!(
        TcpListener::bind(("127.0.0.1", port)).await.is_err(),
        "注册成功后监听端口应被占用"
    );

    // 快照不得包含 vkey
    let raw = serde_json::to_string(&snap).unwrap();
    assert!(!raw.contains(VKEY), "快照泄漏了 vkey");

    server.shutdown().await;
    // 关闭后端口释放
    let mut released = false;
    for _ in 0..50 {
        if TcpListener::bind(("127.0.0.1", port)).await.is_ok() {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(released, "shutdown 后注册隧道端口未释放");
}

// ---------------------------------------------------------------------------
// 3. 重复注册同一条隧道：幂等，不重复建监听
// ---------------------------------------------------------------------------
#[tokio::test]
async fn duplicate_registration_is_idempotent() {
    let server = Server::start(config(true, 8)).await.unwrap();
    let port = free_port().await;
    let target = format!("127.0.0.1:{}", free_port().await);

    let mut conn = npc_handshake(server.bridge_addr(), b"conf").await;
    assert!(!read_bool(&mut conn).await);

    send_frame(&mut conn, b"task", &task(port, &target, "dup")).await;
    assert!(read_bool(&mut conn).await);
    send_frame(&mut conn, b"task", &task(port, &target, "dup")).await;
    assert!(read_bool(&mut conn).await, "重复注册应返回 true");

    let snap = server.snapshot().await;
    assert_eq!(snap.tunnels.len(), 1, "重复注册不应新增隧道");
    assert_eq!(
        snap.tunnels[0].bound_addr.as_deref(),
        Some(format!("127.0.0.1:{port}").as_str())
    );

    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// 4. 隧道总数上限
// ---------------------------------------------------------------------------
#[tokio::test]
async fn tunnel_limit_is_enforced() {
    let server = Server::start(config(true, 1)).await.unwrap();
    let p1 = free_port().await;
    let p2 = free_port().await;
    let target = format!("127.0.0.1:{}", free_port().await);

    let mut conn = npc_handshake(server.bridge_addr(), b"conf").await;
    assert!(!read_bool(&mut conn).await);

    send_frame(&mut conn, b"task", &task(p1, &target, "one")).await;
    assert!(read_bool(&mut conn).await);

    send_frame(&mut conn, b"task", &task(p2, &target, "two")).await;
    assert!(
        !read_bool(&mut conn).await,
        "超过 conf_max_tunnels 必须返回 false"
    );

    assert_eq!(server.snapshot().await.tunnels.len(), 1);
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// 5. 端口被占用 -> false，且不留下幽灵隧道
// ---------------------------------------------------------------------------
#[tokio::test]
async fn port_conflict_returns_false_and_leaves_no_tunnel() {
    let holder = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = holder.local_addr().unwrap().port();

    let server = Server::start(config(true, 8)).await.unwrap();
    let target = format!("127.0.0.1:{}", free_port().await);

    let mut conn = npc_handshake(server.bridge_addr(), b"conf").await;
    assert!(!read_bool(&mut conn).await);
    send_frame(&mut conn, b"task", &task(port, &target, "busy")).await;
    assert!(!read_bool(&mut conn).await, "端口冲突必须返回 false");

    assert!(
        server.snapshot().await.tunnels.is_empty(),
        "失败注册不应留下隧道"
    );
    drop(holder);
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// 6. 特权端口（<1024）一律拒绝
// ---------------------------------------------------------------------------
#[tokio::test]
async fn privileged_port_is_rejected() {
    let server = Server::start(config(true, 8)).await.unwrap();
    let target = format!("127.0.0.1:{}", free_port().await);

    let mut conn = npc_handshake(server.bridge_addr(), b"conf").await;
    assert!(!read_bool(&mut conn).await);
    send_frame(&mut conn, b"task", &task(80, &target, "root")).await;
    assert!(!read_bool(&mut conn).await, "特权端口必须返回 false");
    assert!(server.snapshot().await.tunnels.is_empty());
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// 7. udp 模式注册成功并真的建 UDP 监听（对齐 Go 的 `OpenTask <- tl`）
// ---------------------------------------------------------------------------
#[tokio::test]
async fn udp_mode_registers_and_listens() {
    let server = Server::start(config(true, 8)).await.unwrap();
    let port = free_port().await;
    let target = format!("127.0.0.1:{}", free_port().await);
    let mut body = task(port, &target, "udp-tunnel");
    body["Mode"] = json!("udp");

    let mut conn = npc_handshake(server.bridge_addr(), b"conf").await;
    assert!(!read_bool(&mut conn).await);
    send_frame(&mut conn, b"task", &body).await;
    assert!(read_bool(&mut conn).await, "udp 模式必须注册成功");

    // 必须真的出现在快照里，且处于启用状态
    let snap = server.snapshot().await;
    let udp = snap
        .tunnels
        .iter()
        .find(|t| t.name == "udp-tunnel")
        .expect("udp 隧道应出现在快照中");
    assert!(udp.enabled, "udp 隧道应为启用状态");
    assert_eq!(udp.target_addr, target);
    assert_eq!(udp.client_id, 1);

    // 端口必须真的在监听（绑定失败即说明已被占用）
    assert!(
        std::net::UdpSocket::bind(format!("127.0.0.1:{port}")).is_err(),
        "udp 端口 {port} 应已被监听"
    );

    server.shutdown().await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        std::net::UdpSocket::bind(format!("127.0.0.1:{port}")).is_ok(),
        "shutdown 后 udp 端口 {port} 应已释放"
    );
}

// ---------------------------------------------------------------------------
// 7b. 未实现的模式仍诚实返回 false
// ---------------------------------------------------------------------------
#[tokio::test]
async fn unknown_mode_is_rejected() {
    let server = Server::start(config(true, 8)).await.unwrap();
    let port = free_port().await;
    let target = format!("127.0.0.1:{}", free_port().await);
    let mut body = task(port, &target, "weird");
    body["Mode"] = json!("socks5");

    let mut conn = npc_handshake(server.bridge_addr(), b"conf").await;
    assert!(!read_bool(&mut conn).await);
    send_frame(&mut conn, b"task", &body).await;
    assert!(!read_bool(&mut conn).await, "未实现的模式必须返回 false");
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// 8. host（域名代理）与 NEW_CONF 诚实返回 false，不伪造成功
// ---------------------------------------------------------------------------
#[tokio::test]
async fn host_and_new_conf_are_rejected_without_faking_success() {
    let server = Server::start(config(true, 8)).await.unwrap();
    let target = format!("127.0.0.1:{}", free_port().await);

    let mut conn = npc_handshake(server.bridge_addr(), b"conf").await;
    assert!(!read_bool(&mut conn).await);
    send_frame(
        &mut conn,
        b"host",
        &json!({"Id": 0, "Host": "a.example.com", "Target": {"TargetStr": target}}),
    )
    .await;
    assert!(!read_bool(&mut conn).await, "host 必须返回 false");

    let mut conn = npc_handshake(server.bridge_addr(), b"conf").await;
    assert!(!read_bool(&mut conn).await);
    send_frame(&mut conn, b"conf", &json!({"Id": 0, "Remark": "pub"})).await;
    assert!(!read_bool(&mut conn).await, "NEW_CONF 必须返回 false");

    assert!(server.snapshot().await.tunnels.is_empty());
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// 9. stus：读 32 字节 md5(vkey)，回 int32 len + 运行中隧道 remark 列表
// ---------------------------------------------------------------------------
#[tokio::test]
async fn status_returns_running_tunnel_remarks() {
    let server = Server::start(config(true, 8)).await.unwrap();
    let p1 = free_port().await;
    let p2 = free_port().await;
    let target = format!("127.0.0.1:{}", free_port().await);

    let mut conn = npc_handshake(server.bridge_addr(), b"conf").await;
    assert!(!read_bool(&mut conn).await);
    send_frame(&mut conn, b"task", &task(p1, &target, "alpha")).await;
    assert!(read_bool(&mut conn).await);
    send_frame(&mut conn, b"task", &task(p2, &target, "beta")).await;
    assert!(read_bool(&mut conn).await);

    // 新的 conf 连接做状态查询（原版 npc `-config` status 流程）
    let mut st = npc_handshake(server.bridge_addr(), b"conf").await;
    assert!(!read_bool(&mut st).await);
    st.write_all(b"stus").await.unwrap();
    st.write_all(nps_legacy::md5_hex(VKEY).as_bytes())
        .await
        .unwrap();

    let body = nps_legacy::read_short_len_content(&mut st).await.unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    let mut names: Vec<&str> = text.split(SEQ).filter(|s| !s.is_empty()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec!["alpha", "beta"],
        "stus 应返回运行中的隧道 remark"
    );

    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// 10. 注册的隧道真的转发数据（复用 Tunnel/ActiveGuard/统计体系）
// ---------------------------------------------------------------------------
#[tokio::test]
async fn registered_tunnel_forwards_through_client_mux() {
    let server = Server::start(config(true, 8)).await.unwrap();
    let port = free_port().await;
    let target = format!("127.0.0.1:{}", free_port().await);

    // 注册隧道（此时 npc 还没有 chan，注册本身不应依赖客户端在线）
    let mut conn = npc_handshake(server.bridge_addr(), b"conf").await;
    assert!(!read_bool(&mut conn).await);
    send_frame(&mut conn, b"task", &task(port, &target, "fwd")).await;
    assert!(read_bool(&mut conn).await);

    // 假 npc 建立 main + chan，开始接受子流
    let (ready_tx, ready_rx) = oneshot::channel();
    let npc = spawn_echo_npc(server.bridge_addr(), ready_tx).await;
    tokio::time::timeout(Duration::from_secs(5), ready_rx)
        .await
        .expect("假 npc 握手超时")
        .unwrap();

    let mut ext = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let payload = vec![0xABu8; 64 * 1024];
    ext.write_all(&payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), ext.read_exact(&mut echoed))
        .await
        .expect("等待回显超时")
        .unwrap();
    assert_eq!(echoed, payload);

    // 计数体系生效
    let mut counted = false;
    for _ in 0..200 {
        let snap = server.snapshot().await;
        let t = &snap.tunnels[0];
        if t.bytes_to_client >= payload.len() as u64 && t.bytes_from_client >= payload.len() as u64
        {
            counted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(counted, "注册隧道的字节统计未更新");

    drop(ext);
    server.shutdown().await;
    npc.abort();
}

// ---------------------------------------------------------------------------
// 11. shutdown 会关闭仍打开的 conf 会话（不遗留挂起任务）
// ---------------------------------------------------------------------------
#[tokio::test]
async fn shutdown_closes_open_conf_sessions() {
    let server = Server::start(config(true, 8)).await.unwrap();
    let mut conn = npc_handshake(server.bridge_addr(), b"conf").await;
    assert!(!read_bool(&mut conn).await);

    tokio::time::timeout(Duration::from_secs(5), server.shutdown())
        .await
        .expect("shutdown 不应被 conf 会话拖住");

    let mut buf = [0u8; 1];
    let r = tokio::time::timeout(Duration::from_secs(3), conn.read(&mut buf)).await;
    match r {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        other => panic!("shutdown 后 conf 连接仍未关闭: {other:?}"),
    }
    // 幂等
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// 12. 超长帧长度必须在分配前被拒，连接干净关闭（无 panic / 无 OOM）
// ---------------------------------------------------------------------------
#[tokio::test]
async fn oversized_frame_length_is_rejected() {
    let server = Server::start(config(true, 8)).await.unwrap();
    let mut conn = npc_handshake(server.bridge_addr(), b"conf").await;
    assert!(!read_bool(&mut conn).await);

    conn.write_all(b"task").await.unwrap();
    conn.write_all(&i32::MAX.to_le_bytes()).await.unwrap();

    let mut buf = [0u8; 1];
    let r = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut buf)).await;
    match r {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        other => panic!("超长帧应导致连接关闭: {other:?}"),
    }
    assert!(server.snapshot().await.tunnels.is_empty());
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// 13. 管理端停用后，客户端重新注册同一条隧道会重新启用（仍是同一条）
// ---------------------------------------------------------------------------
#[tokio::test]
async fn re_registration_reenables_admin_disabled_tunnel() {
    let server = Server::start(config(true, 8)).await.unwrap();
    let port = free_port().await;
    let target = format!("127.0.0.1:{}", free_port().await);

    let mut conn = npc_handshake(server.bridge_addr(), b"conf").await;
    assert!(!read_bool(&mut conn).await);
    send_frame(&mut conn, b"task", &task(port, &target, "toggle")).await;
    assert!(read_bool(&mut conn).await);

    let id = server.snapshot().await.tunnels[0].id;
    server.set_tunnel_enabled(id, false).await.unwrap();
    assert!(!server.snapshot().await.tunnels[0].enabled);

    send_frame(&mut conn, b"task", &task(port, &target, "toggle")).await;
    assert!(read_bool(&mut conn).await, "重新注册应成功并恢复监听");
    let snap = server.snapshot().await;
    assert_eq!(snap.tunnels.len(), 1, "不应新建隧道");
    assert!(snap.tunnels[0].enabled);
    assert_eq!(snap.tunnels[0].id, id);

    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// 14. 同一 vkey 的多个 conf 连接可以并行注册不同隧道（多实例基础）
// ---------------------------------------------------------------------------
#[tokio::test]
async fn two_conf_sessions_register_independent_tunnels() {
    let server = Server::start(config(true, 8)).await.unwrap();
    let p1 = free_port().await;
    let p2 = free_port().await;
    let t1 = format!("127.0.0.1:{}", free_port().await);
    let t2 = format!("127.0.0.1:{}", free_port().await);

    let mut a = npc_handshake(server.bridge_addr(), b"conf").await;
    let mut b = npc_handshake(server.bridge_addr(), b"conf").await;
    assert!(!read_bool(&mut a).await);
    assert!(!read_bool(&mut b).await);

    send_frame(&mut a, b"task", &task(p1, &t1, "inst-a")).await;
    send_frame(&mut b, b"task", &task(p2, &t2, "inst-b")).await;
    assert!(read_bool(&mut a).await);
    assert!(read_bool(&mut b).await);

    wait_tunnels(&server, 2).await;
    let snap = server.snapshot().await;
    let mut names: Vec<&str> = snap.tunnels.iter().map(|t| t.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, vec!["inst-a", "inst-b"]);
    assert!(snap.tunnels.iter().all(|t| t.client_id == 1));

    server.shutdown().await;
}
