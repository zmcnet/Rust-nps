//! p2p 任务登记 + `p2pm` 邀请链路的集成测试（走 `Server::start` 全接线）。
//!
//! 覆盖：
//! - conf 注册 `Mode=p2p` 任务成功，登记 md5(password) → client id；
//! - visitor 的 `p2pm` 连接收到会合地址回执，provider 的 signal 收到
//!   `udpc` 邀请帧（与真实 npc 的解析顺序一致）；
//! - 未知密码摘要的 `p2pm` 连接被关闭、无回执；
//! - 同密码重复登记幂等（npc 重连会重发同一任务）。

use std::net::SocketAddr;
use std::time::Duration;

use nps_legacy::mux::MuxSession;
use nps_server::{Server, ServerConfig};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

const VKEY: &str = "p2p-invite-vkey-3b7d1e";

fn config(conf_register: bool) -> ServerConfig {
    ServerConfig {
        bridge_addr: "127.0.0.1:0".into(),
        web_addr: "127.0.0.1:0".into(),
        clients: vec![nps_server::ClientConfig {
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
        conf_register,
        conf_listen_host: "127.0.0.1".into(),
        ..Default::default()
    }
}

async fn free_udp_triple() -> u16 {
    for _ in 0..200 {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let base = s.local_addr().unwrap().port();
        drop(s);
        if base + 2 < 65000 {
            let mut ok = true;
            let mut socks = Vec::new();
            for i in 0..3u16 {
                match std::net::UdpSocket::bind(("127.0.0.1", base + i)) {
                    Ok(u) => socks.push(u),
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                return base;
            }
        }
    }
    panic!("找不到连续三个可用 UDP 端口");
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

async fn spawn_echo_npc(bridge: SocketAddr, ready: oneshot::Sender<()>) -> tokio::task::JoinHandle<()> {
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

/// 读一个长度前缀帧
async fn read_len_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut l = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut l))
        .await
        .expect("读帧超时")
        .expect("读帧失败");
    let n = i32::from_le_bytes(l) as usize;
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await.unwrap();
    buf
}

#[tokio::test]
async fn conf_p2p_task_then_invite_chain() {
    let p2p_base = free_udp_triple().await;
    let advertise = format!("127.0.0.1:{p2p_base}");

    let mut cfg = config(true);
    cfg.p2p_listen_addr = Some(advertise.clone());
    let server = Server::start(cfg).await.unwrap();

    let (ready_tx, ready_rx) = oneshot::channel();
    let npc = spawn_echo_npc(server.bridge_addr(), ready_tx).await;
    let _ = tokio::time::timeout(Duration::from_secs(10), ready_rx).await;

    // conf 会话注册 p2p 任务
    let mut conf = npc_handshake(server.bridge_addr(), b"conf").await;
    let mut is_pub = [0u8; 1];
    conf.read_exact(&mut is_pub).await.unwrap();
    let task = json!({
        "Id": 0, "Port": 0, "ServerIp": "", "Mode": "p2p", "Status": true,
        "RunStatus": false, "Client": null, "Ports": "", "Flow": null,
        "Password": "p2p-secret-1", "Remark": "p2p-home", "TargetAddr": "",
        "NoStore": true, "LocalPath": "", "StripPre": "",
        "Target": { "TargetStr": "", "TargetArr": null, "LocalProxy": false },
        "MultiAccount": null
    });
    let raw = serde_json::to_vec(&task).unwrap();
    nps_legacy::write_flag_content(&mut conf, b"task", &raw)
        .await
        .unwrap();
    let mut ok = [0u8; 1];
    conf.read_exact(&mut ok).await.unwrap();
    assert_ne!(ok[0], 0, "p2p 任务注册应成功");

    // visitor：p2pm 连接 + md5(password)
    let md5 = nps_legacy::md5_hex("p2p-secret-1");
    let mut p2pm = npc_handshake(server.bridge_addr(), b"p2pm").await;
    p2pm.write_all(md5.as_bytes()).await.unwrap();
    let reply = read_len_frame(&mut p2pm).await;
    assert_eq!(String::from_utf8_lossy(&reply), advertise, "回执应是会合地址");

    drop(conf);
    drop(p2pm);
    server.shutdown().await;
    npc.abort();
}

/// 与上一条相同，但 main 连接由测试自己持有，断言邀请帧内容。
#[tokio::test]
async fn conf_p2p_invite_reaches_own_signal() {
    let p2p_base = free_udp_triple().await;
    let advertise = format!("127.0.0.1:{p2p_base}");

    let mut cfg = config(true);
    cfg.p2p_listen_addr = Some(advertise.clone());
    let server = Server::start(cfg).await.unwrap();

    // 测试自持 main 连接（模拟 provider 的 signal）
    let mut main_conn = npc_handshake(server.bridge_addr(), b"main").await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // conf 注册 p2p 任务
    let mut conf = npc_handshake(server.bridge_addr(), b"conf").await;
    let mut is_pub = [0u8; 1];
    conf.read_exact(&mut is_pub).await.unwrap();
    let task = json!({
        "Id": 0, "Port": 0, "ServerIp": "", "Mode": "p2p", "Status": true,
        "RunStatus": false, "Client": null, "Ports": "", "Flow": null,
        "Password": "p2p-secret-2", "Remark": "p2p-home", "TargetAddr": "",
        "NoStore": true, "LocalPath": "", "StripPre": "",
        "Target": { "TargetStr": "", "TargetArr": null, "LocalProxy": false },
        "MultiAccount": null
    });
    let raw = serde_json::to_vec(&task).unwrap();
    nps_legacy::write_flag_content(&mut conf, b"task", &raw)
        .await
        .unwrap();
    let mut ok = [0u8; 1];
    conf.read_exact(&mut ok).await.unwrap();
    assert_ne!(ok[0], 0);

    let md5 = nps_legacy::md5_hex("p2p-secret-2");
    let mut p2pm = npc_handshake(server.bridge_addr(), b"p2pm").await;
    p2pm.write_all(md5.as_bytes()).await.unwrap();

    // provider signal：udpc + len(addr) + len(md5)
    let mut flag = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), main_conn.read_exact(&mut flag))
        .await
        .expect("等待邀请帧超时")
        .expect("读邀请 flag 失败");
    assert_eq!(&flag, nps_proto::NEW_UDP_CONN.as_bytes());
    let addr = read_len_frame(&mut main_conn).await;
    assert_eq!(String::from_utf8_lossy(&addr), advertise);
    let pwd = read_len_frame(&mut main_conn).await;
    assert_eq!(pwd.len(), 32);
    assert_eq!(String::from_utf8_lossy(&pwd), md5);

    // visitor 回执
    let reply = read_len_frame(&mut p2pm).await;
    assert_eq!(String::from_utf8_lossy(&reply), advertise);

    drop(conf);
    drop(p2pm);
    server.shutdown().await;
}

/// 未知密码摘要：p2pm 连接无回执直接关闭。
#[tokio::test]
async fn unknown_p2p_password_closes_connection() {
    let p2p_base = free_udp_triple().await;
    let mut cfg = config(true);
    cfg.p2p_listen_addr = Some(format!("127.0.0.1:{p2p_base}"));
    let server = Server::start(cfg).await.unwrap();

    let mut p2pm = npc_handshake(server.bridge_addr(), b"p2pm").await;
    p2pm.write_all(nps_legacy::md5_hex("wrong").as_bytes())
        .await
        .unwrap();
    let mut buf = [0u8; 4];
    let r = tokio::time::timeout(Duration::from_secs(3), p2pm.read(&mut buf)).await;
    match r {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("未知密码不应收到 {n} 字节回执"),
        Err(_) => panic!("未知密码的连接应在关闭前不发送任何回执（超时）"),
    }
    server.shutdown().await;
}

/// 同密码重复登记（模拟 npc 重连重发任务）必须幂等成功。
#[tokio::test]
async fn duplicate_p2p_registration_is_idempotent() {
    let p2p_base = free_udp_triple().await;
    let mut cfg = config(true);
    cfg.p2p_listen_addr = Some(format!("127.0.0.1:{p2p_base}"));
    let server = Server::start(cfg).await.unwrap();

    for round in 0..2 {
        let mut conf = npc_handshake(server.bridge_addr(), b"conf").await;
        let mut is_pub = [0u8; 1];
        conf.read_exact(&mut is_pub).await.unwrap();
        let task = json!({
            "Id": 0, "Port": 0, "ServerIp": "", "Mode": "p2p", "Status": true,
            "RunStatus": false, "Client": null, "Ports": "", "Flow": null,
            "Password": "p2p-secret-3", "Remark": "p2p-home", "TargetAddr": "",
            "NoStore": true, "LocalPath": "", "StripPre": "",
            "Target": { "TargetStr": "", "TargetArr": null, "LocalProxy": false },
            "MultiAccount": null
        });
        let raw = serde_json::to_vec(&task).unwrap();
        nps_legacy::write_flag_content(&mut conf, b"task", &raw)
            .await
            .unwrap();
        let mut ok = [0u8; 1];
        conf.read_exact(&mut ok).await.unwrap();
        assert_ne!(ok[0], 0, "第 {} 次注册应成功（幂等）", round + 1);
        drop(conf);
    }
    server.shutdown().await;
}
