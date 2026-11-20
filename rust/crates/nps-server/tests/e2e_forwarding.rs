//! 端到端转发测试：用真实 `MuxSession` 扮演 npc，验证
//! 1) Link 帧是子流第一帧且未被吞；
//! 2) 双向数据通路与字节统计；
//! 3) 停用隧道会断开现存转发连接。

use std::net::SocketAddr;
use std::time::Duration;

use nps_legacy::mux::MuxSession;
use nps_server::{ClientConfig, Server, ServerConfig, TcpTunnelConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

const VKEY: &str = "e2e-test-key-9f2c";

fn config(target_addr: String) -> ServerConfig {
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
            name: "echo".into(),
            client_id: 1,
            listen_addr: "127.0.0.1:0".into(),
            target_addr,
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

/// 模拟老 npc 的握手字节序列，返回握手完成后的连接
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

/// 启动假 npc：main + chan，接受子流并回显；Link JSON 通过 channel 回传
async fn spawn_fake_npc(
    bridge: SocketAddr,
    ready: oneshot::Sender<()>,
    links: mpsc::UnboundedSender<String>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // signal 连接：保持打开并读走服务端可能下发的数据
        let mut main = npc_handshake(bridge, b"main").await;
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                match main.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });

        // data 连接：mux
        let chan = npc_handshake(bridge, b"chan").await;
        let mux = MuxSession::new(chan);
        let _ = ready.send(());

        while let Ok(mut stream) = mux.accept_stream().await {
            let links = links.clone();
            tokio::spawn(async move {
                // 第一帧必须是 Link（len32 LE + JSON）
                let first = match stream.recv_data().await {
                    Some(d) => d,
                    None => return,
                };
                if first.len() < 4 {
                    let _ = links.send(format!("BAD_FIRST_FRAME:{first:?}"));
                    return;
                }
                let len = i32::from_le_bytes([first[0], first[1], first[2], first[3]]) as usize;
                let link = String::from_utf8_lossy(&first[4..4 + len]).to_string();
                let _ = links.send(link);

                // 回显其余数据
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

async fn wait_online(server: &Server) {
    for _ in 0..200 {
        let snap = server.snapshot().await;
        if snap.clients[0].online {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("假 npc 未上线");
}

#[tokio::test]
async fn forwarding_keeps_link_first_frame_and_counts_bytes() {
    let (ready_tx, ready_rx) = oneshot::channel();
    let (link_tx, mut link_rx) = mpsc::unbounded_channel();
    let server = Server::start(config("127.0.0.1:2222".into()))
        .await
        .unwrap();
    let bridge = server.bridge_addr();

    let npc = tokio::spawn(spawn_fake_npc(bridge, ready_tx, link_tx));
    tokio::time::timeout(Duration::from_secs(5), ready_rx)
        .await
        .expect("npc 握手超时")
        .unwrap();
    wait_online(&server).await;

    let listen = server.snapshot().await.tunnels[0]
        .bound_addr
        .clone()
        .unwrap();

    // 外部客户端 -> 隧道 -> npc（回显）
    let mut ext = TcpStream::connect(&listen).await.unwrap();
    ext.write_all(b"hello-nps").await.unwrap();
    let mut echoed = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(5), ext.read_exact(&mut echoed))
        .await
        .expect("等待回显超时")
        .unwrap();
    assert_eq!(&echoed, b"hello-nps");

    // Link 帧是第一帧且内容正确
    let link = tokio::time::timeout(Duration::from_secs(5), link_rx.recv())
        .await
        .expect("未收到 Link 帧")
        .unwrap();
    assert!(
        link.contains("\"ConnType\":\"tcp\""),
        "Link 内容异常: {link}"
    );
    assert!(
        link.contains("\"Host\":\"127.0.0.1:2222\""),
        "Link 内容异常: {link}"
    );
    assert!(
        link.contains("\"RemoteAddr\":\"127.0.0.1:"),
        "Link 缺少 RemoteAddr: {link}"
    );

    // 字节统计
    let mut counted = false;
    for _ in 0..100 {
        let snap = server.snapshot().await;
        let t = &snap.tunnels[0];
        if t.bytes_to_client >= 9 && t.bytes_from_client >= 9 {
            assert_eq!(t.active_connections, 1);
            counted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(counted, "字节统计未更新");

    drop(ext);
    server.shutdown().await;
    npc.abort();
}

#[tokio::test]
async fn disable_closes_live_forwarded_connection() {
    let (ready_tx, ready_rx) = oneshot::channel();
    let (link_tx, _link_rx) = mpsc::unbounded_channel();
    let server = Server::start(config("127.0.0.1:3333".into()))
        .await
        .unwrap();
    let bridge = server.bridge_addr();

    let npc = tokio::spawn(spawn_fake_npc(bridge, ready_tx, link_tx));
    tokio::time::timeout(Duration::from_secs(5), ready_rx)
        .await
        .expect("npc 握手超时")
        .unwrap();
    wait_online(&server).await;

    let listen = server.snapshot().await.tunnels[0]
        .bound_addr
        .clone()
        .unwrap();
    let mut ext = TcpStream::connect(&listen).await.unwrap();
    ext.write_all(b"x").await.unwrap();
    let mut one = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(5), ext.read_exact(&mut one))
        .await
        .expect("转发未建立")
        .unwrap();

    // 停用后现存连接应被关闭（读端得到 EOF/错误）
    server.set_tunnel_enabled(1, false).await.unwrap();
    let mut buf = [0u8; 8];
    let closed = tokio::time::timeout(Duration::from_secs(5), ext.read(&mut buf)).await;
    match closed {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        other => panic!("停用后现存连接未被关闭: {other:?}"),
    }

    server.shutdown().await;
    npc.abort();
}
