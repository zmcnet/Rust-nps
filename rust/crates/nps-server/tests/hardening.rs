//! nps-server 运行时加固测试：
//!
//! 1. 连接计数在反复建连/断开、目标拒绝、写失败等路径后归零；
//! 2. 并发启停不重复绑定端口、不留孤儿监听器、不 panic；
//! 3. `shutdown()` 幂等（含并发），关闭后仍可读快照、启停返回明确错误；
//! 4. 错误文本与快照 JSON 不含 vkey / md5(vkey) / 管理令牌；
//! 5. 桥接重复登录的到达顺序（main 先 / chan 先 / 交错）不会产生两个入口。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use nps_legacy::mux::MuxSession;
use nps_server::{ClientConfig, Server, ServerConfig, TcpTunnelConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// 测试用 vkey：必须足够长以便断言"任何输出都不含它"。
const VKEY: &str = "hardening-test-vkey-4a91c7e2";
/// 模拟的管理令牌：rnps 从环境变量读取，本 crate 不持有，但快照里也不能出现。
const ADMIN_TOKEN: &str = "hardening-admin-token-should-never-appear";

fn config(listen_addr: &str) -> ServerConfig {
    ServerConfig {
        bridge_addr: "127.0.0.1:0".into(),
        web_addr: "127.0.0.1:0".into(),
        clients: vec![ClientConfig {
            id: 1,
            name: "npc".into(),
            vkey: VKEY.into(),
            rate_limit: 0,
            flow_limit: 0,
            crypt: false,
            compress: false,
            web_username: None,
            web_password: None,
        }],
        tunnels: vec![TcpTunnelConfig {
            id: 1,
            name: "t".into(),
            client_id: 1,
            listen_addr: listen_addr.into(),
            target_addr: "127.0.0.1:2222".into(),
            enabled: true,
            target_addrs: Vec::new(),
            health_check: None,
        }],
        conf_register: false,
        conf_max_tunnels: 32,
        conf_listen_host: "127.0.0.1".into(),
        ..Default::default()
    }
}

async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// 模拟老 npc 的握手字节序列（与 e2e_forwarding.rs 保持一致）。
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
    c.write_all(nps_legacy::md5_hex(VKEY).as_bytes())
        .await
        .unwrap();
    let mut ok = [0u8; 4];
    c.read_exact(&mut ok).await.unwrap();
    assert_eq!(&ok, nps_proto::VERIFY_SUCCESS.as_bytes());
    c.write_all(conn_type).await.unwrap();
    c
}

/// 假 npc：main + chan，按 `delay_chan` 决定到达顺序，接受子流并回显。
struct FakeNpc {
    task: tokio::task::JoinHandle<()>,
}

impl FakeNpc {
    async fn spawn(bridge: SocketAddr, delay_chan: Option<Duration>) -> Self {
        let (ready_tx, ready_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut main = npc_handshake(bridge, b"main").await;
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while matches!(main.read(&mut buf).await, Ok(n) if n > 0) {}
            });

            if let Some(delay) = delay_chan {
                tokio::time::sleep(delay).await;
            }
            let chan = npc_handshake(bridge, b"chan").await;
            let mux = MuxSession::new(chan);
            let _ = ready_tx.send(());
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
        });
        let _ = tokio::time::timeout(Duration::from_secs(10), ready_rx).await;
        Self { task }
    }

    fn abort(self) {
        self.task.abort();
    }
}

async fn wait_online(server: &Server) {
    for _ in 0..300 {
        if server.snapshot().await.clients[0].online {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("假 npc 未上线");
}

async fn wait_active(server: &Server, expected: u64) {
    for _ in 0..300 {
        if server.snapshot().await.tunnels[0].active_connections == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let got = server.snapshot().await.tunnels[0].active_connections;
    panic!("active_connections 期望 {expected}，实际 {got}");
}

/// 断言文本中不含任何密钥材料（明文 vkey、md5(vkey)、管理令牌）。
fn assert_no_secrets(text: &str, context: &str) {
    let md5 = nps_legacy::md5_hex(VKEY);
    for secret in [VKEY, md5.as_str(), ADMIN_TOKEN] {
        assert!(
            !text.contains(secret),
            "{context} 泄漏了密钥材料 {secret:?}: {text}"
        );
        // 管理令牌的词根同样不应出现
    }
    assert!(!text.contains("admin_token"), "{context} 出现了 admin_token: {text}");
}

// ---------------------------------------------------------------------------
// 1. 连接计数不泄漏
// ---------------------------------------------------------------------------

/// 反复建连/断开 100 次后计数必须归零（守卫覆盖所有退出路径）。
#[tokio::test]
async fn active_connections_returns_to_zero_after_100_cycles() {
    let server = Server::start(config("127.0.0.1:0")).await.unwrap();
    let npc = FakeNpc::spawn(server.bridge_addr(), None).await;
    wait_online(&server).await;
    let listen = server.snapshot().await.tunnels[0].bound_addr.clone().unwrap();

    for i in 0..100 {
        let mut ext = TcpStream::connect(&listen).await.unwrap();
        ext.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), ext.read_exact(&mut echoed))
            .await
            .unwrap_or_else(|_| panic!("第 {i} 次回显超时"))
            .unwrap();
        assert_eq!(&echoed, b"ping");
        drop(ext);
    }

    wait_active(&server, 0).await;
    // 再给一次机会让清理完成，然后断言稳定为 0
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(server.snapshot().await.tunnels[0].active_connections, 0);

    server.shutdown().await;
    npc.abort();
}

/// 目标离线（client 未连接）时外部连接被立即关闭，计数保持 0。
#[tokio::test]
async fn count_stays_zero_when_client_offline() {
    let server = Server::start(config("127.0.0.1:0")).await.unwrap();
    let listen = server.snapshot().await.tunnels[0].bound_addr.clone().unwrap();

    for _ in 0..20 {
        let mut ext = TcpStream::connect(&listen).await.unwrap();
        let mut buf = [0u8; 8];
        let closed = tokio::time::timeout(Duration::from_secs(2), ext.read(&mut buf)).await;
        match closed {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            other => panic!("离线客户端连接未被关闭: {other:?}"),
        }
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(server.snapshot().await.tunnels[0].active_connections, 0);

    server.shutdown().await;
}

/// 传输中途客户端消失（mux 写失败 / 子流断开）时计数仍归零。
#[tokio::test]
async fn count_returns_to_zero_when_client_dies_mid_transfer() {
    let server = Server::start(config("127.0.0.1:0")).await.unwrap();
    let npc = FakeNpc::spawn(server.bridge_addr(), None).await;
    wait_online(&server).await;
    let listen = server.snapshot().await.tunnels[0].bound_addr.clone().unwrap();

    let mut ext = TcpStream::connect(&listen).await.unwrap();
    ext.write_all(b"hello").await.unwrap();
    let mut echoed = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), ext.read_exact(&mut echoed))
        .await
        .expect("回显超时")
        .unwrap();
    wait_active(&server, 1).await;

    // npc 进程整体消失：chan 会话随之关闭，两侧泵的读写都会失败
    npc.abort();

    // 外部连接应被关闭（读到 EOF/错误），计数归零
    let mut buf = [0u8; 8];
    let closed = tokio::time::timeout(Duration::from_secs(5), ext.read(&mut buf)).await;
    match closed {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        other => panic!("客户端消失后外部连接未关闭: {other:?}"),
    }
    wait_active(&server, 0).await;

    server.shutdown().await;
}

/// 停用隧道时会 abort 连接任务；计数必须仍归零（守卫在 abort 路径生效）。
#[tokio::test]
async fn count_returns_to_zero_when_disable_aborts_connections() {
    let server = Server::start(config("127.0.0.1:0")).await.unwrap();
    let npc = FakeNpc::spawn(server.bridge_addr(), None).await;
    wait_online(&server).await;
    let listen = server.snapshot().await.tunnels[0].bound_addr.clone().unwrap();

    // 建立 4 条活跃连接并保持打开
    let mut ext = Vec::new();
    for _ in 0..4 {
        let mut s = TcpStream::connect(&listen).await.unwrap();
        s.write_all(b"x").await.unwrap();
        let mut one = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut one))
            .await
            .expect("转发未建立")
            .unwrap();
        ext.push(s);
    }
    wait_active(&server, 4).await;

    // 停用：连接任务被 JoinSet::shutdown abort，守卫随 Drop 归还计数
    server.set_tunnel_enabled(1, false).await.unwrap();
    wait_active(&server, 0).await;
    assert!(!server.snapshot().await.tunnels[0].enabled);

    drop(ext);
    server.shutdown().await;
    npc.abort();
}

/// mux 建流被 npc 拒绝（NewConnFail）时：外部连接关闭、计数归零、
/// `last_error` 记录原因且不含密钥。
#[tokio::test]
async fn count_returns_to_zero_when_mux_rejects_stream() {
    use nps_legacy::mux::{MuxFrame, MUX_NEW_CONN, MUX_NEW_CONN_FAIL};

    let server = Server::start(config("127.0.0.1:0")).await.unwrap();
    let listen = server.snapshot().await.tunnels[0].bound_addr.clone().unwrap();
    let bridge = server.bridge_addr();

    // main 保持在线；chan 用原始帧应答，对所有 NewConn 回 NewConnFail
    let mut main = npc_handshake(bridge, b"main").await;
    let mut chan = npc_handshake(bridge, b"chan").await;
    tokio::spawn(async move {
        let mut main_buf = [0u8; 256];
        while matches!(main.read(&mut main_buf).await, Ok(n) if n > 0) {}
    });
    let reject_task = tokio::spawn(async move {
        loop {
            match MuxFrame::decode(&mut chan).await {
                Ok(Some(frame)) if frame.flag == MUX_NEW_CONN => {
                    let fail = MuxFrame {
                        flag: MUX_NEW_CONN_FAIL,
                        id: frame.id,
                        content: None,
                        window: None,
                    };
                    if chan.write_all(&fail.encode()).await.is_err() {
                        break;
                    }
                }
                Ok(Some(_)) => {}
                _ => break,
            }
        }
    });
    wait_online(&server).await;

    // 外部连接：服务端 open_stream 收到 NewConnFail → 立即关闭，计数归零
    let mut ext = TcpStream::connect(&listen).await.unwrap();
    let mut buf = [0u8; 8];
    let closed = tokio::time::timeout(Duration::from_secs(5), ext.read(&mut buf)).await;
    match closed {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        other => panic!("建流被拒后外部连接未关闭: {other:?}"),
    }

    wait_active(&server, 0).await;
    let snap = server.snapshot().await;
    let last = snap.tunnels[0].last_error.as_deref().unwrap_or("");
    assert!(last.contains("mux 建流失败"), "last_error 未记录原因: {last}");
    assert_no_secrets(&serde_json::to_string(&snap).unwrap(), "建流失败快照");

    reject_task.abort();
    server.shutdown().await;
}

/// 停用/关闭后不遗留孤儿任务：端口可被立即重新绑定。
#[tokio::test]
async fn disable_with_live_connections_returns_quickly_and_releases_port() {
    let port = free_port().await;
    let listen = format!("127.0.0.1:{port}");
    let server = Server::start(config(&listen)).await.unwrap();
    let npc = FakeNpc::spawn(server.bridge_addr(), None).await;
    wait_online(&server).await;

    let mut ext = TcpStream::connect(&listen).await.unwrap();
    ext.write_all(b"x").await.unwrap();
    let mut one = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(5), ext.read_exact(&mut one))
        .await
        .expect("转发未建立")
        .unwrap();

    let started = std::time::Instant::now();
    server.set_tunnel_enabled(1, false).await.unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "停用耗时过长: {:?}",
        started.elapsed()
    );

    // 端口已释放
    let mut rebound = false;
    for _ in 0..100 {
        if TcpListener::bind(&listen).await.is_ok() {
            rebound = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(rebound, "停用后端口未释放（可能遗留孤儿监听器）");

    drop(ext);
    server.shutdown().await;
    npc.abort();
}

// ---------------------------------------------------------------------------
// 2. 启停竞态
// ---------------------------------------------------------------------------

/// 并发 enable/disable × N：不 panic、不重复绑定端口、最终状态与最后一次
/// 操作一致，且没有遗留监听器。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_enable_disable_is_serialized() {
    let port = free_port().await;
    let listen = format!("127.0.0.1:{port}");
    let server = Server::start(config(&listen)).await.unwrap();
    // 先停掉，让并发操作从"关闭"状态开始
    server.set_tunnel_enabled(1, false).await.unwrap();

    let mut tasks = Vec::new();
    for round in 0..8 {
        for idx in 0..4 {
            let s = server.clone();
            let enable = (round + idx) % 2 == 0;
            tasks.push(tokio::spawn(async move {
                s.set_tunnel_enabled(1, enable).await
            }));
        }
    }
    for task in tasks {
        // 并发启停不允许 panic；失败只允许是端口占用等可解释错误
        match task.await.expect("启停任务 panic") {
            Ok(()) => {}
            Err(e) => {
                let msg = format!("{e:#}");
                assert!(
                    msg.contains("启用隧道") || msg.contains("已关闭"),
                    "非预期错误: {msg}"
                );
            }
        }
    }

    // 服务端仍可用；最后一条命令决定状态
    let last = server.set_tunnel_enabled(1, true).await;
    assert!(last.is_ok(), "串行化后最终启用应成功: {last:?}");
    assert!(server.snapshot().await.tunnels[0].enabled);

    // 只有一个监听器占用该端口：此时第三方绑定必须失败
    let taken = TcpListener::bind(&listen).await;
    assert!(taken.is_err(), "并发启停留下了可重复绑定的监听器");

    // 停用后应可以绑定
    server.set_tunnel_enabled(1, false).await.unwrap();
    let mut rebound = false;
    for _ in 0..100 {
        if TcpListener::bind(&listen).await.is_ok() {
            rebound = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(rebound, "并发启停后停用未释放端口");

    server.shutdown().await;
}

/// 并发重复 enable：只应绑定一次，重复调用幂等（不能出现 bind 失败）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_enable_is_idempotent() {
    let port = free_port().await;
    let listen = format!("127.0.0.1:{port}");
    let server = Server::start(config(&listen)).await.unwrap();

    let mut tasks = Vec::new();
    for _ in 0..16 {
        let s = server.clone();
        tasks.push(tokio::spawn(async move { s.set_tunnel_enabled(1, true).await }));
    }
    for task in tasks {
        task.await
            .expect("并发 enable 任务 panic")
            .expect("重复 enable 应幂等成功");
    }
    assert_eq!(
        server.snapshot().await.tunnels[0].bound_addr.as_deref(),
        Some(listen.as_str())
    );

    server.shutdown().await;
}

/// 端口被外部占用时启用失败：错误可见、状态仍为未启用、不留监听器。
#[tokio::test]
async fn enable_reports_port_conflict_and_stays_disabled() {
    let holder = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = holder.local_addr().unwrap();
    let listen = addr.to_string();

    let mut cfg = config(&listen);
    cfg.tunnels[0].enabled = false;
    let server = Server::start(cfg).await.unwrap();
    assert!(!server.snapshot().await.tunnels[0].enabled);

    let err = server.set_tunnel_enabled(1, true).await.unwrap_err();
    assert_no_secrets(&format!("{err:#}"), "启用失败错误");
    let snap = server.snapshot().await;
    assert!(!snap.tunnels[0].enabled, "失败后不应显示已启用");
    assert!(snap.tunnels[0].bound_addr.is_none());
    assert!(snap.tunnels[0].last_error.is_some());

    drop(holder);
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// 3. shutdown 幂等
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_shutdown_is_idempotent_and_snapshot_still_readable() {
    let server = Server::start(config("127.0.0.1:0")).await.unwrap();
    let npc = FakeNpc::spawn(server.bridge_addr(), None).await;
    wait_online(&server).await;
    let listen = server.snapshot().await.tunnels[0].bound_addr.clone().unwrap();

    // 先建立一条活跃转发连接，确保 shutdown 需要真的回收连接任务
    let mut ext = TcpStream::connect(&listen).await.unwrap();
    ext.write_all(b"x").await.unwrap();
    let mut one = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(5), ext.read_exact(&mut one))
        .await
        .expect("转发未建立")
        .unwrap();
    wait_active(&server, 1).await;

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let s = server.clone();
        tasks.push(tokio::spawn(async move { s.shutdown().await }));
    }
    for task in tasks {
        task.await.expect("并发 shutdown 任务 panic");
    }

    assert!(server.is_shutdown());
    // 关闭后快照仍可读，且结构完整；连接计数已由守卫归零（shutdown 不清零）
    let snap = server.snapshot().await;
    assert_eq!(snap.clients.len(), 1);
    assert_eq!(snap.tunnels.len(), 1);
    assert!(!snap.tunnels[0].enabled, "关闭后隧道不应显示启用");
    assert_eq!(snap.tunnels[0].active_connections, 0);

    // 关闭后启停返回明确错误，不 panic
    let err = server.set_tunnel_enabled(1, true).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("已关闭"), "错误信息不明确: {msg}");
    assert_no_secrets(&msg, "关闭后启停错误");

    let err = server.set_tunnel_enabled(999, true).await.unwrap_err();
    assert!(format!("{err:#}").contains("不存在"));

    // 反复调用依然安全
    server.shutdown().await;
    server.shutdown().await;
    assert!(server.snapshot().await.tunnels.len() == 1);

    npc.abort();
}

/// shutdown 与 enable 交错时不允许出现"关闭后仍在监听"的孤儿端口。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enable_after_shutdown_never_leaves_listener() {
    let port = free_port().await;
    let listen = format!("127.0.0.1:{port}");
    let mut cfg = config(&listen);
    cfg.tunnels[0].enabled = false;
    let server = Server::start(cfg).await.unwrap();

    let enabler = {
        let s = server.clone();
        tokio::spawn(async move { s.set_tunnel_enabled(1, true).await })
    };
    let closer = {
        let s = server.clone();
        tokio::spawn(async move { s.shutdown().await })
    };
    let _ = enabler.await.expect("enable 任务 panic");
    closer.await.expect("shutdown 任务 panic");

    assert!(server.is_shutdown());
    // 无论交错结果如何，关闭完成后端口必须空闲
    let mut rebound = false;
    for _ in 0..200 {
        if TcpListener::bind(&listen).await.is_ok() {
            rebound = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(rebound, "shutdown 之后遗留了监听端口");
    assert!(!server.snapshot().await.tunnels[0].enabled);
}

// ---------------------------------------------------------------------------
// 4. 错误信息不泄漏密钥
// ---------------------------------------------------------------------------

/// 构造多种错误场景，遍历快照 JSON 与错误文本，断言不含密钥材料。
#[tokio::test]
async fn snapshots_and_errors_never_contain_secrets() {
    let mut cfg = config("127.0.0.1:0");
    cfg.tunnels[0].enabled = false;
    let server = Server::start(cfg).await.unwrap();

    // (a) 客户端离线 → handle_external 记录错误
    server.set_tunnel_enabled(1, true).await.unwrap();
    let listen = server.snapshot().await.tunnels[0].bound_addr.clone().unwrap();
    let mut ext = TcpStream::connect(&listen).await.unwrap();
    let mut buf = [0u8; 4];
    let _ = tokio::time::timeout(Duration::from_secs(2), ext.read(&mut buf)).await;

    // (b) 端口冲突 → enable 失败
    let holder = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut cfg2 = config(&holder.local_addr().unwrap().to_string());
    cfg2.tunnels[0].id = 2;
    cfg2.tunnels[0].enabled = false;
    // 用第二个 server 触发冲突，避免干扰主 server 的状态
    let server2 = Server::start(cfg2).await.unwrap();
    let conflict = server2.set_tunnel_enabled(2, true).await.unwrap_err();
    assert_no_secrets(&format!("{conflict:#}"), "端口冲突错误");

    // 快照 JSON 必须干净
    for s in [&server, &server2] {
        let snap = s.snapshot().await;
        let json = serde_json::to_string(&snap).unwrap();
        assert_no_secrets(&json, "快照 JSON");
        // 也检查 pretty 形式，避免字段拼接绕过
        assert_no_secrets(&serde_json::to_string_pretty(&snap).unwrap(), "快照 pretty JSON");
        for t in &snap.tunnels {
            if let Some(e) = &t.last_error {
                assert_no_secrets(e, "last_error");
            }
        }
    }

    // 配置校验错误也不回显 vkey
    let mut bad = config("127.0.0.1:0");
    bad.clients[0].vkey = "123".into();
    let err = match Server::start(bad).await {
        Ok(server) => {
            server.shutdown().await;
            panic!("默认 vkey 应被拒绝")
        }
        Err(e) => format!("{e:#}"),
    };
    assert!(!err.contains("123"), "校验错误回显了 vkey: {err}");

    drop(holder);
    drop(ext);
    server.shutdown().await;
    server2.shutdown().await;
}

/// 成功的转发会清空 last_error，且清空后仍不含密钥。
#[tokio::test]
async fn successful_forwarding_clears_error_without_leaking() {
    let server = Server::start(config("127.0.0.1:0")).await.unwrap();
    let listen = server.snapshot().await.tunnels[0].bound_addr.clone().unwrap();

    // 先制造一次离线错误
    let mut ext = TcpStream::connect(&listen).await.unwrap();
    let mut buf = [0u8; 4];
    let _ = tokio::time::timeout(Duration::from_secs(2), ext.read(&mut buf)).await;
    assert!(server.snapshot().await.tunnels[0].last_error.is_some());

    // npc 上线后再连一次，错误应被清空
    let npc = FakeNpc::spawn(server.bridge_addr(), None).await;
    wait_online(&server).await;
    let mut ext2 = TcpStream::connect(&listen).await.unwrap();
    ext2.write_all(b"ok").await.unwrap();
    let mut echoed = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), ext2.read_exact(&mut echoed))
        .await
        .expect("回显超时")
        .unwrap();
    assert_eq!(&echoed, b"ok");

    let snap = server.snapshot().await;
    assert!(snap.tunnels[0].last_error.is_none(), "成功转发后应清空 last_error");
    let json = serde_json::to_string(&snap).unwrap();
    assert_no_secrets(&json, "成功路径快照");

    drop(ext);
    drop(ext2);
    server.shutdown().await;
    npc.abort();
}

// ---------------------------------------------------------------------------
// 5. 桥接重复登录的到达顺序
// ---------------------------------------------------------------------------

/// 同一个客户端重复登录：旧 entry 被替换，永远只有一个 tunnel 入口。
/// 覆盖 chan 先到、main 先到、交错到达三种顺序。
#[tokio::test]
async fn duplicate_login_orderings_keep_single_tunnel_entry() {
    let server = Server::start(config("127.0.0.1:0")).await.unwrap();
    let bridge = server.bridge_addr();
    let listen = server.snapshot().await.tunnels[0].bound_addr.clone().unwrap();

    // (1) chan 先到，main 后到
    let chan_a = npc_handshake(bridge, b"chan").await;
    let mux_a = Arc::new(MuxSession::new(chan_a));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!server.snapshot().await.clients[0].online, "只有 chan 不应在线");

    let main_a = npc_handshake(bridge, b"main").await;
    wait_online(&server).await;

    // (2) 交错：新 chan 到达，应替换旧 mux
    let chan_b = npc_handshake(bridge, b"chan").await;
    let mux_b = Arc::new(MuxSession::new(chan_b));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(mux_a.is_closed(), "旧 tunnel 应被新连接替换并关闭");
    assert!(!mux_b.is_closed(), "新 tunnel 应保持打开");
    wait_online(&server).await;

    // (3) 新 main 到达，替换旧 signal
    let mut old_main = main_a;
    let main_b = npc_handshake(bridge, b"main").await;
    let mut one = [0u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(2), old_main.read(&mut one)).await;
    match closed {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        other => panic!("旧 main 未被关闭: {other:?}"),
    }
    wait_online(&server).await;

    // 仍然只有一个转发入口：外部连接能正常建立（第一帧是 Link）
    let mut ext = TcpStream::connect(&listen).await.unwrap();
    ext.write_all(b"z").await.unwrap();
    let mut z = [0u8; 1];
    let _ = tokio::time::timeout(Duration::from_secs(2), ext.read_exact(&mut z)).await;

    // 用一个独立 mux 侧统计：新会话上最多只会出现一条子流
    let accepted = tokio::time::timeout(Duration::from_secs(2), mux_b.accept_stream()).await;
    assert!(accepted.is_ok(), "新 tunnel 未收到子流");
    // 旧 mux 已关闭，不应再接受新子流
    let stale = tokio::time::timeout(Duration::from_millis(300), mux_a.accept_stream()).await;
    match stale {
        Ok(Err(_)) => {}
        Err(_) => {} // 超时：旧会话已不再服务，同样可接受
        Ok(Ok(_)) => panic!("旧 tunnel 仍在接受新子流（出现两个入口）"),
    }

    drop(ext);
    drop(main_b);
    drop(mux_b);
    server.shutdown().await;
}

/// chan 反复替换：每次替换都关闭旧 mux，计数与在线状态随之收敛。
#[tokio::test]
async fn repeated_chan_replacement_closes_previous_session() {
    let server = Server::start(config("127.0.0.1:0")).await.unwrap();
    let bridge = server.bridge_addr();

    let _main = npc_handshake(bridge, b"main").await;
    let mut previous: Option<Arc<MuxSession>> = None;
    for _ in 0..5 {
        let chan = npc_handshake(bridge, b"chan").await;
        let mux = Arc::new(MuxSession::new(chan));
        if let Some(old) = previous.replace(mux.clone()) {
            // 替换在服务端侧异步完成，稍等后旧会话必须已关闭
            for _ in 0..100 {
                if old.is_closed() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(old.is_closed(), "旧 mux 未被关闭");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(server.snapshot().await.clients[0].online);
    }

    // 断开当前 mux → 离线
    drop(previous);
    for _ in 0..100 {
        if !server.snapshot().await.clients[0].online {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!server.snapshot().await.clients[0].online);

    server.shutdown().await;
}

/// chan 比 main 更晚到达时（间隔一段时间），online 只在两者都在时为 true。
#[tokio::test]
async fn online_flips_only_when_both_halves_present() {
    let server = Server::start(config("127.0.0.1:0")).await.unwrap();
    let bridge = server.bridge_addr();

    let main = npc_handshake(bridge, b"main").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!server.snapshot().await.clients[0].online);

    let chan = npc_handshake(bridge, b"chan").await;
    wait_online(&server).await;

    // main 断开 → 立即离线（chan 仍在）
    drop(main);
    for _ in 0..200 {
        if !server.snapshot().await.clients[0].online {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!server.snapshot().await.clients[0].online);

    drop(chan);
    server.shutdown().await;
}

/// 快照包含 chan 上报的版本号，但不含任何密钥；channel 已被替换时版本保留。
#[tokio::test]
async fn client_version_is_reported_without_secrets() {
    let server = Server::start(config("127.0.0.1:0")).await.unwrap();
    let bridge = server.bridge_addr();

    let _main = npc_handshake(bridge, b"main").await;
    let _chan = npc_handshake(bridge, b"chan").await;
    wait_online(&server).await;

    let snap = server.snapshot().await;
    assert_eq!(snap.clients[0].version, "0.26.10");
    assert_no_secrets(&serde_json::to_string(&snap).unwrap(), "含版本的快照");

    server.shutdown().await;
}