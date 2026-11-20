//! 文件服务隧道（原版 nps `mode=file`）集成测试。
//!
//! 覆盖三块：
//! 1. **数据面**：用 [`MuxSession`] 的对偶模拟 npc 的 `file` 通道（npc 侧就是
//!    `nps_mux.NewMux(conn)` + `http.Server.Serve(mux)`），断言外部 HTTP 请求能
//!    原样到达 npc 侧并把文件内容带回来（子流上**没有** Link 首帧）。
//! 2. **运行态**：连接计数、快照口径、停用/关闭语义、file 通道缺失时的快速失败。
//! 3. **健康状态**：`TargetPool` + `HealthChecker` 的逐目标 healthy/failures 查询。
//!
//! 另有一个 `#[ignore]` 的 harness（`file_interop_harness`），由真实原版
//! `npc.exe -config=npc.conf` 驱动，见文件末尾说明。

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use nps_legacy::mux::{MuxSession, MuxStream};
use nps_legacy::Bridge;
use nps_server::file_service::{
    target_health_details, FileChannelRegistry, FileTunnel, FileTunnelConfig,
};
use nps_server::target::{HealthCheckConfig, HealthCheckKind, HealthChecker, TargetPool};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

fn config(listen_addr: &str) -> FileTunnelConfig {
    FileTunnelConfig {
        id: 21,
        name: "files".into(),
        client_id: 1,
        listen_addr: listen_addr.into(),
        enabled: true,
        target_addr: String::new(),
        local_path: "/srv/share".into(),
        strip_pre: "/files".into(),
    }
}

fn quiet_bridge() -> Bridge {
    Bridge::new(|_| None)
}

async fn wait_until<F, Fut>(mut f: F, timeout: Duration, what: &str)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if f().await {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "等待超时: {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// 假 npc 的 http.FileServer：把 `/files/<name>` 映射到 `root/<name>`。
///
/// 行为对齐 Go `http.StripPrefix(strip, http.FileServer(http.Dir(root)))`：
/// - 请求行必须以 `GET ` 开头（**这是「服务端没有发 Link 首帧」的断言点**：
///   若服务端先写 4 字节长度 + JSON，这里读到的首字节就不是 `GET`，测试失败）；
/// - 命中文件返回 `200` + `Content-Length`，未命中返回 `404`；
/// - 响应后关闭子流（等价 `Connection: close`）。
async fn fake_npc_serve_files(
    mux: Arc<MuxSession>,
    root: PathBuf,
    strip: String,
    first_line: tokio::sync::oneshot::Sender<String>,
) {
    let mut first_line = Some(first_line);
    loop {
        let mut stream: MuxStream = match mux.accept_stream().await {
            Ok(s) => s,
            Err(_) => break, // 会话关闭
        };
        let root = root.clone();
        let strip = strip.clone();
        let tx = first_line.take();
        tokio::spawn(async move {
            let mut buf = Vec::new();
            // 读到请求头结束
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.recv_data().await {
                    Some(chunk) => buf.extend_from_slice(&chunk),
                    None => return,
                }
                if buf.len() > 64 * 1024 {
                    return;
                }
            }
            let text = String::from_utf8_lossy(&buf).to_string();
            let line = text.lines().next().unwrap_or_default().to_string();
            if let Some(tx) = tx {
                let _ = tx.send(line.clone());
            }
            // 模拟 http.StripPrefix
            let path = line.split_whitespace().nth(1).unwrap_or("/");
            let rel = path.strip_prefix(strip.as_str()).unwrap_or(path);
            let file = root.join(rel.trim_start_matches('/'));
            let (status, body) = match std::fs::read(&file) {
                Ok(b) => ("200 OK", b),
                Err(_) => ("404 Not Found", b"not found".to_vec()),
            };
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.send_data(head.as_bytes()).await;
            let _ = stream.send_data(&body).await;
            stream.close();
        });
    }
}

/// 极简 HTTP/1.1 客户端：发一个 GET，读到 EOF，返回 `(状态码, body)`。
async fn http_get(addr: std::net::SocketAddr, path: &str) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect(addr).await.expect("连接文件隧道失败");
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.unwrap();
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("响应缺少头部结束标记");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let code = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .expect("无法解析状态行");
    (code, raw[split + 4..].to_vec())
}

/// 读到一个被立即关闭的连接：返回读到的字节。
///
/// Windows 上对端带未读数据关闭会回 RST，客户端 `read_to_end` 得到
/// `ConnectionReset`；这等价于「立刻关闭、零字节」，一并视为快速失败。
async fn read_until_closed(s: &mut TcpStream) -> Vec<u8> {
    let mut raw = Vec::new();
    match tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut raw)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Ok(Err(e)) => panic!("读取被拒绝的连接失败: {e}"),
        Err(_) => panic!("连接必须被立即关闭而不是挂起"),
    }
    raw
}

fn unique_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rnps-file-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("创建临时目录失败");
    dir
}

// ---------------------------------------------------------------------------
// 1. 数据面：外部 HTTP -> file mux -> 假 npc 的文件服务
// ---------------------------------------------------------------------------

#[tokio::test]
async fn file_tunnel_serves_file_without_link_frame() {
    let root = unique_dir("e2e");
    let body = b"hello from the file tunnel\n";
    std::fs::write(root.join("hello.txt"), body).unwrap();

    // npc 侧与 server 侧的一对 mux 会话（等价 npc 拨 WORK_FILE 后各自 NewMux）
    let (server_io, npc_io) = tokio::io::duplex(64 * 1024);
    let server_mux = Arc::new(MuxSession::new(server_io));
    let npc_mux = Arc::new(MuxSession::new(npc_io));

    let (line_tx, line_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(fake_npc_serve_files(
        npc_mux,
        root.clone(),
        "/files".into(),
        line_tx,
    ));

    let registry = Arc::new(FileChannelRegistry::new());
    assert!(registry.register(1, server_mux).is_none());

    let tunnel = Arc::new(FileTunnel::with_registry(
        config("127.0.0.1:0"),
        registry.clone(),
    ));
    let addr = tunnel.start(quiet_bridge()).await.expect("文件隧道启动失败");

    let (code, got) = http_get(addr, "/files/hello.txt").await;
    assert_eq!(code, 200, "响应体: {:?}", String::from_utf8_lossy(&got));
    assert_eq!(got, body, "下载内容必须与文件一致");

    // 关键断言：npc 侧收到的第一个字节就是 HTTP 请求行 —— 服务端没有发 Link 首帧
    let request_line = line_rx.await.expect("npc 侧没有收到请求");
    assert_eq!(request_line, "GET /files/hello.txt HTTP/1.1");

    // 快照与计数
    wait_until(
        || async { tunnel.active_connections() == 0 },
        Duration::from_secs(3),
        "连接计数归零",
    )
    .await;
    let snap = tunnel.snapshot().await;
    assert!(snap.enabled);
    assert_eq!(snap.bound_addr.as_deref(), Some(addr.to_string().as_str()));
    assert_eq!(snap.id, 21);
    assert_eq!(snap.name, "files");
    assert_eq!(snap.client_id, 1);
    assert_eq!(snap.target_addr, "/srv/share", "文件模式目标 = 客户端本地目录");
    assert!(snap.active_connections == 0);
    assert!(snap.bytes_to_client > 0, "必须统计外部 -> 客户端字节");
    assert!(snap.bytes_from_client >= body.len() as u64, "必须统计响应字节");
    assert!(snap.last_error.is_none());
    assert!(snap.targets.is_empty(), "文件模式没有目标列表");

    // 序列化契约：空 targets 不出现
    let json = serde_json::to_value(&snap).unwrap();
    assert!(json.get("targets").is_none(), "空 targets 不应序列化");

    tunnel.disable().await;
    std::fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn missing_file_channel_fails_fast_and_clears_counter() {
    let tunnel = Arc::new(FileTunnel::new(config("127.0.0.1:0")));
    let addr = tunnel.start(quiet_bridge()).await.unwrap();

    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let raw = read_until_closed(&mut s).await;
    assert!(raw.is_empty(), "没有 file 通道时不能返回任何字节");

    let snap = tunnel.snapshot().await;
    let err = snap.last_error.expect("必须记录失败原因");
    assert!(
        err.contains("客户端 1") && (err.contains("file 通道") || err.contains("离线")),
        "错误信息应点明客户端与缺通道/离线原因: {err}"
    );

    wait_until(
        || async { tunnel.active_connections() == 0 },
        Duration::from_secs(3),
        "失败路径也要归还连接计数",
    )
    .await;
    tunnel.disable().await;
}

#[tokio::test]
async fn disable_releases_port_and_aborts_inflight_connection() {
    let root = unique_dir("disable");
    std::fs::write(root.join("a.txt"), b"x").unwrap();

    let (server_io, npc_io) = tokio::io::duplex(64 * 1024);
    let server_mux = Arc::new(MuxSession::new(server_io));
    let npc_mux = Arc::new(MuxSession::new(npc_io));
    // 这个 npc 故意不回响应，让连接停留在转发中
    tokio::spawn(async move {
        while let Ok(stream) = npc_mux.accept_stream().await {
            tokio::spawn(async move {
                let mut stream = stream;
                // 一直持有子流直到被 abort / 会话关闭
                while stream.recv_data().await.is_some() {}
            });
        }
    });

    let registry = Arc::new(FileChannelRegistry::new());
    registry.register(1, server_mux);
    let tunnel = Arc::new(FileTunnel::with_registry(
        config("127.0.0.1:0"),
        registry,
    ));
    let addr = tunnel.start(quiet_bridge()).await.unwrap();

    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET /files/a.txt HTTP/1.1\r\n\r\n").await.unwrap();
    wait_until(
        || async { tunnel.active_connections() == 1 },
        Duration::from_secs(3),
        "连接进入转发",
    )
    .await;

    tunnel.disable().await;
    assert_eq!(tunnel.active_connections(), 0, "停用必须回收在飞连接");
    let snap = tunnel.snapshot().await;
    assert!(!snap.enabled);
    assert!(snap.bound_addr.is_none());

    // 端口已释放
    let mut rebound = false;
    for _ in 0..50 {
        match std::net::TcpListener::bind(addr) {
            Ok(_) => {
                rebound = true;
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    assert!(rebound, "disable 后端口未释放");

    drop(s);
    std::fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn shutdown_is_idempotent_and_blocks_restart() {
    let tunnel = Arc::new(FileTunnel::new(config("127.0.0.1:0")));
    tunnel.start(quiet_bridge()).await.unwrap();

    tunnel.shutdown().await;
    tunnel.shutdown().await; // 幂等
    assert!(tunnel.is_closed());
    assert!(!tunnel.is_listening().await);
    assert!(tunnel.start(quiet_bridge()).await.is_err(), "关闭后不允许重启");
}

#[tokio::test]
async fn ip_allow_list_rejects_untrusted_peer() {
    let allow = Arc::new(nps_server::IpAllowList::new(&["203.0.113.0/24".to_string()]).unwrap());
    let tunnel = Arc::new(FileTunnel::with_controls(
        config("127.0.0.1:0"),
        Arc::new(FileChannelRegistry::new()),
        None,
        None,
        allow,
    ));
    let addr = tunnel.start(quiet_bridge()).await.unwrap();

    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let raw = read_until_closed(&mut s).await;
    assert!(raw.is_empty());
    wait_until(
        || async { tunnel.active_connections() == 0 },
        Duration::from_secs(2),
        "拒绝后计数归零",
    )
    .await;
    tunnel.disable().await;
}

// ---------------------------------------------------------------------------
// 2. 健康状态：逐目标 healthy / failures
// ---------------------------------------------------------------------------

#[tokio::test]
async fn target_pool_exposes_per_target_healthy_and_failures() {
    // 健康目标：真实可连的 TCP 监听器
    let healthy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let healthy_addr = healthy_listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            if healthy_listener.accept().await.is_err() {
                break;
            }
        }
    });

    // 不健康目标：拿一个刚释放的端口（connect 会立刻被拒绝）
    let dead_addr = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap().to_string();
        drop(l);
        a
    };

    let pool = Arc::new(TargetPool::parse(&format!("{healthy_addr}\n{dead_addr}")).unwrap());
    let checker = HealthChecker::new(
        pool.clone(),
        HealthCheckConfig {
            timeout: Duration::from_millis(500),
            max_failed: 2,
            interval: Duration::from_millis(10),
            kind: HealthCheckKind::Tcp,
        },
    );

    // 第一次失败：还没到阈值，目标仍在池中但 failures 已计数
    checker.check_once().await;
    let after_one = target_health_details(&pool, Some(&checker));
    assert!(after_one[0].healthy, "健康目标必须保持可用");
    assert_eq!(after_one[0].failures, 0);
    assert_eq!(after_one[1].target, dead_addr);
    assert_eq!(after_one[1].failures, 1);
    assert!(after_one[1].healthy, "未达 max_failed 前不应摘除");

    // 第二次失败：达到阈值 -> 摘除
    checker.check_once().await;
    let details = target_health_details(&pool, Some(&checker));
    assert_eq!(details[0].target, healthy_addr);
    assert!(details[0].healthy);
    assert_eq!(details[0].failures, 0);
    assert!(!details[1].healthy, "达到阈值后必须标记不健康");
    assert!(details[1].failures >= 2);

    // TargetPool 本身的查询：可用列表已摘除不健康目标
    assert!(pool.is_offline(&dead_addr));
    assert!(!pool.is_offline(&healthy_addr));
    assert_eq!(pool.targets(), vec![healthy_addr.clone()]);
    assert_eq!(pool.total(), 2, "配置总数不变");
    assert_eq!(pool.len(), 1, "可用数减一");

    // 回填快照契约类型（将来 snapshot.rs 增加 failures 字段时直接透传）
    let snap = details[1].to_snapshot();
    assert_eq!(snap.target, dead_addr);
    assert!(!snap.healthy);

    // 未启用健康检查时：failures 恒为 0，healthy 只看离线集合
    let bare = target_health_details(&pool, None);
    assert_eq!(bare.len(), 2);
    assert!(bare.iter().all(|d| d.failures == 0));
    assert!(!bare[1].healthy);
}

// ---------------------------------------------------------------------------
// 3. 真实原版 npc.exe 对接 harness（ignored）
// ---------------------------------------------------------------------------
//
// 这个 harness 扮演「桥 + 服务器」两件事：
//   - 用真实 `nps_legacy::server_handshake` 处理 npc 的连接，按 conn type 分发；
//   - `conf`：回 isPub=false，并接受 npc 上报的 `[file] mode=file` 任务；
//   - `file`：`MuxSession::new(stream)` 后登记进 FileChannelRegistry
//     —— **这正是需要父代理加到 `nps-legacy/src/bridge.rs` 的分支**；
//   - `main` / `chan`：保持存活（file 模式的数据面不经过 chan）。
//
// 环境变量：
//   NPS_FILE_HARNESS_BRIDGE      桥监听地址，如 127.0.0.1:18024
//   NPS_FILE_HARNESS_TUNNEL      文件隧道监听地址（= npc.conf 的 server_port）
//   NPS_FILE_HARNESS_VKEY        npc 使用的 vkey
//   NPS_FILE_HARNESS_READY       就绪标记文件路径（写 "ready"）
//   NPS_FILE_HARNESS_LOCAL_PATH  仅用于快照展示的客户端目录
//   NPS_FILE_HARNESS_STRIP       仅用于快照展示的 strip_pre

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("harness 缺少环境变量 {name}"))
}

/// 处理一条已完成握手的桥连接（只实现 harness 需要的四种 conn type）。
async fn harness_dispatch(
    mut stream: TcpStream,
    expected_md5: String,
    registry: Arc<FileChannelRegistry>,
) {
    let verify = move |md5: &str| {
        if md5 == expected_md5 {
            Some(1)
        } else {
            None
        }
    };
    let hs = match nps_legacy::server_handshake(&mut stream, verify).await {
        Ok(hs) => hs,
        Err(e) => {
            eprintln!("harness: 握手失败: {e}");
            return;
        }
    };

    match &hs.conn_type {
        // 配置文件模式：先回 isPub=false，再逐条接受 task / host 注册
        b"conf" => {
            if stream.write_all(&[0u8]).await.is_err() {
                return;
            }
            loop {
                let flag = match nps_legacy::read_flag(&mut stream).await {
                    Ok(f) => f,
                    Err(_) => break, // npc 注册完会关闭 conf 连接
                };
                match &flag {
                    b"task" => {
                        let len = match nps_legacy::read_len_i32(&mut stream).await {
                            Ok(n) if n > 0 && n <= 64 * 1024 => n as usize,
                            _ => break,
                        };
                        let mut body = vec![0u8; len];
                        if stream.read_exact(&mut body).await.is_err() {
                            break;
                        }
                        let text = String::from_utf8_lossy(&body).to_string();
                        eprintln!("harness: 收到任务 {text}");
                        if stream.write_all(&[1u8]).await.is_err() {
                            break;
                        }
                    }
                    b"host" => {
                        let len = match nps_legacy::read_len_i32(&mut stream).await {
                            Ok(n) if n > 0 && n <= 64 * 1024 => n as usize,
                            _ => break,
                        };
                        let mut body = vec![0u8; len];
                        if stream.read_exact(&mut body).await.is_err() {
                            break;
                        }
                        if stream.write_all(&[1u8]).await.is_err() {
                            break;
                        }
                    }
                    b"stus" => {
                        let mut digest = [0u8; 32];
                        if stream.read_exact(&mut digest).await.is_err() {
                            break;
                        }
                        if stream.write_all(&0i32.to_le_bytes()).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
            let _ = stream.shutdown().await;
        }
        // 数据面：这条连接的 mux 就是该客户端的 file 通道
        b"file" => {
            eprintln!("harness: 收到 file 通道连接，登记 mux");
            let mux = Arc::new(MuxSession::new(stream));
            registry.register_and_watch(1, mux);
        }
        // file 模式不经过 chan / main，但 npc 会建立它们：保持存活即可
        b"chan" => {
            let mux = Arc::new(MuxSession::new(stream));
            tokio::spawn(async move {
                loop {
                    if mux.accept_stream().await.is_err() {
                        break;
                    }
                }
            });
        }
        b"main" => {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            });
        }
        other => {
            eprintln!("harness: 忽略连接类型 {other:?}");
        }
    }
}

#[tokio::test]
#[ignore = "interop harness: driven by a real npc.exe -config=npc.conf"]
async fn file_interop_harness() {
    let bridge_addr = env("NPS_FILE_HARNESS_BRIDGE");
    let tunnel_addr = env("NPS_FILE_HARNESS_TUNNEL");
    let vkey = env("NPS_FILE_HARNESS_VKEY");
    let ready_file = env("NPS_FILE_HARNESS_READY");
    let local_path = std::env::var("NPS_FILE_HARNESS_LOCAL_PATH").unwrap_or_default();
    let strip = std::env::var("NPS_FILE_HARNESS_STRIP").unwrap_or_else(|_| "/".into());
    let expected_md5 = nps_legacy::md5_hex(&vkey);

    let registry = Arc::new(FileChannelRegistry::new());
    let listener = TcpListener::bind(&bridge_addr)
        .await
        .expect("harness 桥绑定失败");
    let registry_for_accept = registry.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                break;
            };
            let reg = registry_for_accept.clone();
            let md5 = expected_md5.clone();
            tokio::spawn(async move {
                harness_dispatch(stream, md5, reg).await;
            });
        }
    });

    // 文件隧道：监听 npc.conf 里的 server_port，从 registry 取 file 通道
    let mut cfg = config(&tunnel_addr);
    cfg.local_path = local_path.clone();
    cfg.strip_pre = strip.clone();
    let tunnel = Arc::new(FileTunnel::with_registry(cfg, registry.clone()));
    let bound = tunnel
        .start(quiet_bridge())
        .await
        .expect("harness 文件隧道绑定失败");

    eprintln!(
        "HARNESS_READY bridge={bridge_addr} file_tunnel={bound} local_path={local_path} strip={strip}"
    );
    tokio::fs::write(&ready_file, b"ready")
        .await
        .expect("写 ready 文件失败");

    // 阻塞直到被父进程杀掉
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
