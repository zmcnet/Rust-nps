//! nps-server 集成测试：配置冲突、离线行为、启停端口释放、shutdown。

use std::time::Duration;

use nps_server::{ClientConfig, Server, ServerConfig, TcpTunnelConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn config(enabled: bool) -> ServerConfig {
    ServerConfig {
        bridge_addr: "127.0.0.1:0".into(),
        web_addr: "127.0.0.1:0".into(),
        clients: vec![ClientConfig {
            id: 1,
            name: "test-client".into(),
            vkey: "integration-test-key".into(),
            rate_limit: 0,
            flow_limit: 0,
            crypt: false,
            compress: false,
        }],
        tunnels: vec![TcpTunnelConfig {
            id: 1,
            name: "test-tunnel".into(),
            client_id: 1,
            listen_addr: "127.0.0.1:0".into(),
            target_addr: "127.0.0.1:22".into(),
            enabled,
            target_addrs: Vec::new(),
            health_check: None,
        }],
        conf_register: false,
        conf_max_tunnels: 32,
        conf_listen_host: "127.0.0.1".into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn start_snapshot_and_shutdown() {
    let server = Server::start(config(true)).await.unwrap();
    let addr = server.bridge_addr();
    assert_ne!(addr.port(), 0, ":0 时快照应给出实际端口");

    let snap = server.snapshot().await;
    assert_eq!(snap.bridge_addr, addr.to_string());
    assert_eq!(snap.clients.len(), 1);
    assert!(!snap.clients[0].online);
    assert_eq!(snap.tunnels.len(), 1);
    assert!(snap.tunnels[0].enabled);
    assert_eq!(snap.tunnels[0].active_connections, 0);

    // 快照不得泄漏密钥
    let json = serde_json::to_string(&snap).unwrap();
    assert!(!json.contains("integration-test-key"), "快照泄漏了 vkey");
    assert!(!json.contains("token"));

    let listen = snap.tunnels[0]
        .bound_addr
        .clone()
        .expect("启用隧道应有实际绑定地址");

    server.shutdown().await;
    assert!(server.is_shutdown());

    // 幂等
    server.shutdown().await;

    // 端口释放
    let mut ok = false;
    for _ in 0..50 {
        if TcpListener::bind(&listen).await.is_ok() {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(ok, "shutdown 后隧道端口未释放");
}

#[tokio::test]
async fn empty_deployment_starts_for_management_ui() {
    // 空 clients / tunnels 必须允许启动（进管理页后由用户添加）
    let cfg = ServerConfig {
        bridge_addr: "127.0.0.1:0".into(),
        web_addr: "127.0.0.1:0".into(),
        clients: Vec::new(),
        tunnels: Vec::new(),
        conf_register: false,
        conf_max_tunnels: 32,
        conf_listen_host: "127.0.0.1".into(),
        ..Default::default()
    };
    let server = Server::start(cfg).await.unwrap();
    let snap = server.snapshot().await;
    assert!(snap.clients.is_empty());
    assert!(snap.tunnels.is_empty());
    assert_ne!(server.bridge_addr().port(), 0);
    // 空部署下启停不存在的隧道应报错而不是 panic
    assert!(server.set_tunnel_enabled(1, true).await.is_err());
    server.shutdown().await;
}

#[tokio::test]
async fn start_rejects_default_vkey() {
    let mut cfg = config(true);
    cfg.clients[0].vkey = "123".into();
    let err = match Server::start(cfg).await {
        Ok(_) => panic!("默认 vkey 应被拒绝"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("vkey"), "{err}");
    // 错误信息不得回显 vkey 本身
    assert!(!err.contains("\"123\""), "错误消息泄漏了 vkey: {err}");
}

#[tokio::test]
async fn start_rejects_port_conflict() {
    // 占用桥端口
    let holder = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = holder.local_addr().unwrap();

    let mut cfg = config(true);
    cfg.bridge_addr = addr.to_string();
    assert!(Server::start(cfg).await.is_err());

    // holder 仍可用（没有被服务端夺走）
    drop(holder);
}

#[tokio::test]
async fn start_rejects_duplicate_client_vkey() {
    let mut cfg = config(true);
    cfg.clients.push(ClientConfig {
        id: 2,
        name: "dup".into(),
        vkey: "integration-test-key".into(),
            rate_limit: 0,
            flow_limit: 0,
            crypt: false,
            compress: false,
        });
    assert!(Server::start(cfg).await.is_err());
}

#[tokio::test]
async fn offline_client_connection_is_closed_without_panic() {
    let server = Server::start(config(true)).await.unwrap();
    let listen = server.snapshot().await.tunnels[0]
        .bound_addr
        .clone()
        .unwrap();

    // 没有 npc 上线，外部连接应立即被关闭
    let mut ext = TcpStream::connect(&listen).await.unwrap();
    let mut buf = [0u8; 8];
    let closed = tokio::time::timeout(Duration::from_secs(2), ext.read(&mut buf)).await;
    match closed {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        other => panic!("离线客户端连接未被关闭: {other:?}"),
    }

    let snap = server.snapshot().await;
    assert_eq!(snap.tunnels[0].active_connections, 0);
    assert!(snap.tunnels[0].last_error.is_some());

    // 写入也不应 panic
    let _ = ext.write_all(b"ping").await;
    server.shutdown().await;
}

/// 取一个当前空闲的本地端口（bind 后立即释放）
async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

#[tokio::test]
async fn enable_disable_releases_and_rebinds_port() {
    // 固定端口，才能验证"停用释放 / 启用重新占用同一端口"
    let port = free_port().await;
    let mut cfg = config(true);
    cfg.tunnels[0].listen_addr = format!("127.0.0.1:{port}");

    let server = Server::start(cfg).await.unwrap();
    let listen = server.snapshot().await.tunnels[0]
        .bound_addr
        .clone()
        .unwrap();
    assert_eq!(listen, format!("127.0.0.1:{port}"));

    server.set_tunnel_enabled(1, false).await.unwrap();
    assert!(!server.snapshot().await.tunnels[0].enabled);

    // 停用后端口应可重新绑定
    let holder = TcpListener::bind(&listen).await.expect("停用后端口未释放");
    drop(holder);

    // 重新启用：应重新占用同一端口
    server.set_tunnel_enabled(1, true).await.unwrap();
    assert!(server.snapshot().await.tunnels[0].enabled);
    let snap = server.snapshot().await;
    assert_eq!(snap.tunnels[0].bound_addr.as_deref(), Some(listen.as_str()));

    // 未知隧道
    assert!(server.set_tunnel_enabled(999, true).await.is_err());

    server.shutdown().await;
    // 关闭后不允许再启停
    assert!(server.set_tunnel_enabled(1, true).await.is_err());
}
