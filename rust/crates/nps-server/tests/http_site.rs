//! HTTP 域名代理端到端测试：真实 `MuxSession` 扮演老 npc，
//! 验证路由、请求/响应转发（含 chunked）、WebSocket 升级与各类错误码。
//!
//! 这里不依赖 `server.rs` 的接线：直接用 [`nps_legacy::Bridge`] + [`HttpSiteServer`]
//! 组装最小环境，因此测试也覆盖了"父代理把本模块接进 server"时的调用形态。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use nps_legacy::mux::MuxSession;
use nps_legacy::Bridge;
use nps_server::config::HttpSiteConfig as SiteConfig;
use nps_server::{HttpProxyConfig, HttpRoute, HttpSite, HttpSiteRouter, HttpSiteServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};

const VKEY: &str = "http-site-test-key-4a91";
const DOMAIN: &str = "site.test";

// ---------------------------------------------------------------------------
// 假 npc：握手 + mux + 作为"目标服务器"直接应答 HTTP
// ---------------------------------------------------------------------------

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

/// Link 帧里解析出的关键字段
#[derive(Debug, Clone)]
struct SeenLink {
    conn_type: String,
    host: String,
    remote_addr: String,
}

/// 启动假 npc；`links` 会收到每次建流的 Link 摘要，便于断言路由结果。
async fn spawn_fake_npc(
    bridge: SocketAddr,
    ready: oneshot::Sender<()>,
    links: mpsc::UnboundedSender<SeenLink>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
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

        let chan = npc_handshake(bridge, b"chan").await;
        let mux = MuxSession::new(chan);
        let _ = ready.send(());

        while let Ok(stream) = mux.accept_stream().await {
            let links = links.clone();
            tokio::spawn(async move {
                let mut stream = stream;
                // 第一帧：Link
                let first = match stream.recv_data().await {
                    Some(d) => d,
                    None => return,
                };
                if first.len() < 4 {
                    return;
                }
                let len = i32::from_le_bytes([first[0], first[1], first[2], first[3]]) as usize;
                let link: nps_proto::Link =
                    serde_json::from_slice(&first[4..4 + len]).expect("Link JSON");
                let _ = links.send(SeenLink {
                    conn_type: link.conn_type.clone(),
                    host: link.host.clone(),
                    remote_addr: link.remote_addr.clone(),
                });

                // 把剩余字节当作 HTTP 请求（可能不足一个完整头，继续收）
                let mut pending = first[4 + len..].to_vec();
                loop {
                    let head_end = match find_head_end(&pending) {
                        Some(idx) => idx,
                        None => match stream.recv_data().await {
                            Some(d) => {
                                pending.extend_from_slice(&d);
                                continue;
                            }
                            None => return,
                        },
                    };
                    let head = pending[..head_end].to_vec();
                    pending.drain(..head_end);

                    // 读掉请求体（Content-Length / chunked），保持流边界正确
                    let text = String::from_utf8_lossy(&head).to_ascii_lowercase();
                    if text.contains("transfer-encoding: chunked") {
                        if !drain_chunked(&mut stream, &mut pending).await {
                            return;
                        }
                    } else if let Some(cl) = content_length(&text) {
                        while pending.len() < cl {
                            match stream.recv_data().await {
                                Some(d) => pending.extend_from_slice(&d),
                                None => return,
                            }
                        }
                        pending.drain(..cl);
                    }

                    let path = request_path_of(&head);
                    match respond(&mut stream, &path).await {
                        true => {}
                        false => return,
                    }
                    // 除 /close 外都保持长连接，继续读下一个请求
                    if path == "/close" {
                        return;
                    }
                }
            });
        }
    })
}

/// 消费一个 chunked 请求体（含尾部头）
async fn drain_chunked(
    stream: &mut nps_legacy::mux::MuxStream,
    pending: &mut Vec<u8>,
) -> bool {
    loop {
        let line = match take_line(stream, pending).await {
            Some(line) => line,
            None => return false,
        };
        let text = String::from_utf8_lossy(&line).to_string();
        let size_text = text.trim_end_matches(['\r', '\n']);
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size = match usize::from_str_radix(size_text, 16) {
            Ok(size) => size,
            Err(_) => return false,
        };
        if size == 0 {
            loop {
                let line = match take_line(stream, pending).await {
                    Some(line) => line,
                    None => return false,
                };
                if line.iter().all(|b| matches!(b, b'\r' | b'\n')) {
                    return true;
                }
            }
        }
        let need = size + 2; // data + CRLF
        while pending.len() < need {
            match stream.recv_data().await {
                Some(d) => pending.extend_from_slice(&d),
                None => return false,
            }
        }
        pending.drain(..need);
    }
}

async fn take_line(
    stream: &mut nps_legacy::mux::MuxStream,
    pending: &mut Vec<u8>,
) -> Option<Vec<u8>> {
    loop {
        if let Some(idx) = pending.windows(2).position(|w| w == b"\r\n") {
            let line = pending[..idx + 2].to_vec();
            pending.drain(..idx + 2);
            return Some(line);
        }
        match stream.recv_data().await {
            Some(d) => pending.extend_from_slice(&d),
            None => return None,
        }
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn content_length(head_lower: &str) -> Option<usize> {
    for line in head_lower.split("\r\n") {
        if let Some(value) = line.strip_prefix("content-length:") {
            return value.trim().parse().ok();
        }
    }
    None
}

fn request_path_of(head: &[u8]) -> String {
    let text = String::from_utf8_lossy(head);
    let target = text
        .lines()
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .unwrap_or("/");
    let end = target.find(['?', '#']).unwrap_or(target.len());
    let path = &target[..end];
    if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    }
}

/// 假目标：按路径返回不同响应；返回 false 表示该子流应结束
async fn respond(stream: &mut nps_legacy::mux::MuxStream, path: &str) -> bool {
    // 前缀路由（/api、/api/v2）与根路径返回同一份 hello 响应
    if path == "/" || path == "/echo" || path.starts_with("/api/") || path == "/api" {
        let body = b"hello-from-http-target";
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nX-Target: fake-npc\r\n\r\n",
            body.len()
        );
        if stream.send_data(head.as_bytes()).await.is_err() {
            return false;
        }
        return stream.send_data(body).await.is_ok();
    }

    match path {
        "/chunked" => {
            let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
            if stream.send_data(head).await.is_err() {
                return false;
            }
            for part in [b"alpha".as_slice(), b"beta".as_slice(), b"gamma".as_slice()] {
                let frame = format!("{:x}\r\n", part.len());
                if stream.send_data(frame.as_bytes()).await.is_err()
                    || stream.send_data(part).await.is_err()
                    || stream.send_data(b"\r\n").await.is_err()
                {
                    return false;
                }
            }
            stream.send_data(b"0\r\n\r\n").await.is_ok()
        }
        "/big" => {
            // 1.5 MiB 响应，验证流式转发不会挂住
            let size = 1536 * 1024;
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n");
            if stream.send_data(head.as_bytes()).await.is_err() {
                return false;
            }
            let chunk = vec![b'z'; 32 * 1024];
            let mut sent = 0;
            while sent < size {
                let n = (size - sent).min(chunk.len());
                if stream.send_data(&chunk[..n]).await.is_err() {
                    return false;
                }
                sent += n;
            }
            true
        }
        "/close" => {
            let head =
                b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 4\r\n\r\nbye\n";
            stream.send_data(head).await.is_ok()
        }
        "/until-close" => {
            // 无 Content-Length、无 chunked，靠 EOF 结束
            let head = b"HTTP/1.1 200 OK\r\n\r\nuntil-close-body";
            if stream.send_data(head).await.is_err() {
                return false;
            }
            stream.close();
            true
        }
        "/drop" => {
            // 目标在建流后立刻断开：服务端应回 502
            stream.close();
            false
        }
        "/ws" => {
            // 回 101，然后 echo 后续字节（模拟 WebSocket 服务）
            let head = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: dummy\r\n\r\n";
            if stream.send_data(head).await.is_err() {
                return false;
            }
            while let Some(data) = stream.recv_data().await {
                if stream.send_data(&data).await.is_err() {
                    break;
                }
            }
            false
        }
        _ => {
            let body = b"no such path";
            let head = format!(
                "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            if stream.send_data(head.as_bytes()).await.is_err() {
                return false;
            }
            stream.send_data(body).await.is_ok()
        }
    }
}


// ---------------------------------------------------------------------------
// 测试环境
// ---------------------------------------------------------------------------

struct Harness {
    bridge_addr: SocketAddr,
    http_addr: SocketAddr,
    links: mpsc::UnboundedReceiver<SeenLink>,
    server: Arc<HttpSiteServer>,
    bridge: Bridge,
    _cancel: watch::Sender<bool>,
    _npc: tokio::task::JoinHandle<()>,
}

/// 组装：桥 + 假 npc + HTTP 站点服务
async fn harness(sites: Vec<HttpSite>, connect_npc: bool) -> Harness {
    let bridge = Bridge::new(|v: &str| {
        if v == nps_legacy::md5_hex(VKEY) {
            Some(1)
        } else {
            None
        }
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = listener.local_addr().unwrap();
    let b = bridge.clone();
    tokio::spawn(async move {
        let _ = b.serve_on(listener).await;
    });

    let (ready_tx, ready_rx) = oneshot::channel();
    let (link_tx, link_rx) = mpsc::unbounded_channel();
    let npc = if connect_npc {
        spawn_fake_npc(bridge_addr, ready_tx, link_tx).await
    } else {
        // 不连 npc：ready 立即完成（客户端离线场景）
        let _ = ready_tx.send(());
        tokio::spawn(async {})
    };
    if connect_npc {
        tokio::time::timeout(Duration::from_secs(5), ready_rx)
            .await
            .expect("假 npc 握手超时")
            .unwrap();
        // 等桥登记在线（main + chan 都要到位）
        for _ in 0..100 {
            if bridge.is_client_online(1).await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(bridge.is_client_online(1).await, "假 npc 未上线");
    }

    let http = HttpSiteServer::new(
        bridge.clone(),
        HttpProxyConfig {
            listen_addr: "127.0.0.1:0".into(),
            sites,
            idle_timeout: Duration::from_secs(10),
            max_connections: 32,
            max_head_bytes: 64 * 1024,
        },
    )
    .unwrap();

    let (cancel_tx, cancel_rx) = watch::channel(false);
    let listener = http.bind().await.unwrap();
    let http_addr = listener.local_addr().unwrap();
    let this = http.clone();
    tokio::spawn(async move {
        this.serve(listener, cancel_rx).await;
    });

    Harness {
        bridge_addr,
        http_addr,
        links: link_rx,
        server: http,
        bridge,
        _cancel: cancel_tx,
        _npc: npc,
    }
}

impl Harness {
    async fn next_link(&mut self) -> SeenLink {
        tokio::time::timeout(Duration::from_secs(5), self.links.recv())
            .await
            .expect("等待 Link 超时")
            .expect("Link 通道关闭")
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.bridge.is_closing();
    }
}

fn site(domain: &str, target: &str) -> HttpSite {
    HttpSite::new(domain, 1, target)
}

/// 发一个请求并读完整响应（按 Content-Length / chunked / EOF 判定结束）
async fn roundtrip(
    addr: SocketAddr,
    raw_request: &str,
) -> (String, Vec<u8>, bool) {
    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.write_all(raw_request.as_bytes()).await.unwrap();
    read_response(&mut sock).await
}

async fn read_response(sock: &mut TcpStream) -> (String, Vec<u8>, bool) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 16 * 1024];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), sock.read(&mut tmp))
            .await
            .expect("读响应超时")
            .unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(idx) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..idx + 4]).to_string();
            let lower = head.to_ascii_lowercase();
            let body = buf[idx + 4..].to_vec();
            if lower.contains("transfer-encoding: chunked") {
                if body.ends_with(b"0\r\n\r\n") {
                    return (head, body, false);
                }
            } else if let Some(cl) = content_length(&lower) {
                if body.len() >= cl {
                    return (head, body[..cl].to_vec(), false);
                }
            } else if lower.contains("101 switching protocols") {
                // 升级后由调用方继续读
                return (head, body, true);
            }
        }
    }
    let head_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(0);
    (
        String::from_utf8_lossy(&buf[..head_end]).to_string(),
        buf[head_end..].to_vec(),
        false,
    )
}

fn status_of(head: &str) -> u16 {
    head.lines()
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// 用例
// ---------------------------------------------------------------------------

#[tokio::test]
async fn routes_by_host_and_strips_port() {
    let mut h = harness(vec![site("Site.Test", "10.0.0.1:8080")], true).await;
    assert!(h.bridge_addr.port() > 0, "桥应已绑定");

    for host in ["site.test", "SITE.TEST", "Site.Test:1234"] {
        let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
        let (head, body, _) = roundtrip(h.http_addr, &req).await;
        assert_eq!(status_of(&head), 200, "host={host} head={head}");
        assert_eq!(body, b"hello-from-http-target");

        let link = h.next_link().await;
        assert_eq!(link.conn_type, "http");
        assert_eq!(link.host, "10.0.0.1:8080");
        assert!(link.remote_addr.starts_with("127.0.0.1:"), "{link:?}");
    }
}

#[tokio::test]
async fn longest_path_prefix_selects_target() {
    let mut h = harness(
        vec![site("site.test", "10.0.0.1:80").with_routes(vec![
            HttpRoute {
                prefix: "/api".into(),
                target_addr: "10.0.0.2:8000".into(),
            },
            HttpRoute {
                prefix: "/api/v2".into(),
                target_addr: "10.0.0.3:9000".into(),
            },
        ])],
        true,
    )
    .await;

    let cases = [("/", "10.0.0.1:80"), ("/api/x", "10.0.0.2:8000"), ("/api/v2/x", "10.0.0.3:9000")];
    for (path, expected) in cases {
        let req = format!("GET {path} HTTP/1.1\r\nHost: site.test\r\n\r\n");
        let (head, _, _) = roundtrip(h.http_addr, &req).await;
        assert_eq!(status_of(&head), 200, "path={path}");
        let link = h.next_link().await;
        assert_eq!(link.host, expected, "path={path}");
    }
}

#[tokio::test]
async fn post_with_body_is_forwarded_whole() {
    let mut h = harness(vec![site(DOMAIN, "10.0.0.1:80")], true).await;

    let payload = "x".repeat(70 * 1024); // 跨多个 mux 分片
    let req = format!(
        "POST /echo HTTP/1.1\r\nHost: {DOMAIN}\r\nContent-Length: {}\r\n\r\n{payload}",
        payload.len()
    );
    let (head, body, _) = roundtrip(h.http_addr, &req).await;
    assert_eq!(status_of(&head), 200);
    assert_eq!(body, b"hello-from-http-target");
    let _ = h.next_link().await;
}

#[tokio::test]
async fn chunked_request_body_is_forwarded() {
    let mut h = harness(vec![site(DOMAIN, "10.0.0.1:80")], true).await;
    let req = format!(
        "POST /echo HTTP/1.1\r\nHost: {DOMAIN}\r\nTransfer-Encoding: chunked\r\n\r\n\
         5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    );
    let (head, body, _) = roundtrip(h.http_addr, &req).await;
    assert_eq!(status_of(&head), 200);
    assert_eq!(body, b"hello-from-http-target");
    let _ = h.next_link().await;
}

#[tokio::test]
async fn chunked_response_is_relayed() {
    let mut h = harness(vec![site(DOMAIN, "10.0.0.1:80")], true).await;
    let req = format!("GET /chunked HTTP/1.1\r\nHost: {DOMAIN}\r\n\r\n");
    let (head, body, _) = roundtrip(h.http_addr, &req).await;
    assert_eq!(status_of(&head), 200);
    assert!(head.to_ascii_lowercase().contains("transfer-encoding: chunked"));
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("alpha") && text.contains("beta") && text.contains("gamma"), "{text}");
    assert!(text.trim_end().ends_with("0"), "缺少终止块: {text:?}");
    let _ = h.next_link().await;
}

#[tokio::test]
async fn large_response_is_streamed() {
    let mut h = harness(vec![site(DOMAIN, "10.0.0.1:80")], true).await;
    let req = format!("GET /big HTTP/1.1\r\nHost: {DOMAIN}\r\n\r\n");
    let mut sock = TcpStream::connect(h.http_addr).await.unwrap();
    sock.write_all(req.as_bytes()).await.unwrap();

    let mut total = 0usize;
    let mut buf = [0u8; 64 * 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let n = tokio::time::timeout_at(deadline, sock.read(&mut buf))
            .await
            .expect("大响应超时")
            .unwrap();
        if n == 0 {
            break;
        }
        total += n;
        if total >= 1536 * 1024 + 64 {
            break;
        }
    }
    assert!(total >= 1536 * 1024, "只收到 {total} 字节");
    let _ = h.next_link().await;
}

#[tokio::test]
async fn expect_100_continue_is_answered_before_body() {
    let mut h = harness(vec![site(DOMAIN, "10.0.0.1:80")], true).await;
    let mut sock = TcpStream::connect(h.http_addr).await.unwrap();
    let head = format!(
        "POST /echo HTTP/1.1\r\nHost: {DOMAIN}\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n"
    );
    sock.write_all(head.as_bytes()).await.unwrap();

    // 客户端在发 body 前必须收到 100 Continue
    let mut interim = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
            .await
            .expect("等待 100 Continue 超时")
            .unwrap();
        interim.extend_from_slice(&buf[..n]);
        if interim.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let interim_text = String::from_utf8_lossy(&interim);
    assert!(
        interim_text.starts_with("HTTP/1.1 100 Continue"),
        "interim={interim_text}"
    );

    sock.write_all(b"hello").await.unwrap();
    let (resp_head, body, _) = read_response(&mut sock).await;
    assert_eq!(status_of(&resp_head), 200, "head={resp_head}");
    assert_eq!(body, b"hello-from-http-target");
    let _ = h.next_link().await;
}

#[tokio::test]
async fn target_closing_before_response_returns_502() {
    let mut h = harness(vec![site(DOMAIN, "10.0.0.1:80")], true).await;
    let req = format!("GET /drop HTTP/1.1\r\nHost: {DOMAIN}\r\n\r\n");
    let (head, _, _) = roundtrip(h.http_addr, &req).await;
    assert_eq!(status_of(&head), 502, "head={head}");
    let _ = h.next_link().await;
}

#[tokio::test]
async fn websocket_upgrade_becomes_raw_stream() {
    let mut h = harness(vec![site(DOMAIN, "10.0.0.1:80")], true).await;
    let req = format!(
        "GET /ws HTTP/1.1\r\nHost: {DOMAIN}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    let mut sock = TcpStream::connect(h.http_addr).await.unwrap();
    sock.write_all(req.as_bytes()).await.unwrap();

    let (head, _, upgraded) = read_response(&mut sock).await;
    assert_eq!(status_of(&head), 101, "head={head}");
    assert!(upgraded);

    let link = h.next_link().await;
    // 升级请求必须用 tcp：npc 的 http 分支会二次解析升级后的帧
    assert_eq!(link.conn_type, "tcp", "{link:?}");

    // 双向：发两次，收两次
    for msg in [b"frame-one".as_slice(), b"frame-two".as_slice()] {
        sock.write_all(msg).await.unwrap();
        let mut echo = vec![0u8; msg.len()];
        tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut echo))
            .await
            .expect("WebSocket 回显超时")
            .unwrap();
        assert_eq!(echo, msg);
    }
}

#[tokio::test]
async fn keep_alive_reuses_client_connection_with_new_stream_each_time() {
    let mut h = harness(vec![site(DOMAIN, "10.0.0.1:80")], true).await;

    let mut sock = TcpStream::connect(h.http_addr).await.unwrap();
    for i in 0..3 {
        let req = format!("GET /?n={i} HTTP/1.1\r\nHost: {DOMAIN}\r\n\r\n");
        sock.write_all(req.as_bytes()).await.unwrap();
        let (head, body, _) = read_response(&mut sock).await;
        assert_eq!(status_of(&head), 200, "第 {i} 个请求");
        assert_eq!(body, b"hello-from-http-target");
        // 每个请求都有独立子流
        let link = h.next_link().await;
        assert_eq!(link.host, "10.0.0.1:80");
    }
    assert_eq!(h.server.served_requests(), 3, "应统计 3 个请求");
    assert_eq!(h.server.active_connections(), 1, "连接仍被复用");
}

#[tokio::test]
async fn connection_close_from_target_ends_client_connection() {
    let mut h = harness(vec![site(DOMAIN, "10.0.0.1:80")], true).await;
    let req = format!("GET /close HTTP/1.1\r\nHost: {DOMAIN}\r\n\r\n");
    let mut sock = TcpStream::connect(h.http_addr).await.unwrap();
    sock.write_all(req.as_bytes()).await.unwrap();
    let (head, body, _) = read_response(&mut sock).await;
    assert_eq!(status_of(&head), 200);
    assert_eq!(body, b"bye\n");

    // 服务端应关闭连接（读到 EOF）
    let mut extra = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut extra))
        .await
        .expect("等待关闭超时")
        .unwrap_or(0);
    assert_eq!(n, 0, "Connection: close 后仍可读");
    let _ = h.next_link().await;
}

#[tokio::test]
async fn response_ending_by_eof_is_relayed() {
    let mut h = harness(vec![site(DOMAIN, "10.0.0.1:80")], true).await;
    let req = format!("GET /until-close HTTP/1.1\r\nHost: {DOMAIN}\r\n\r\n");
    let (head, body, _) = roundtrip(h.http_addr, &req).await;
    assert_eq!(status_of(&head), 200);
    assert_eq!(body, b"until-close-body");
    let _ = h.next_link().await;
}

#[tokio::test]
async fn unmatched_host_returns_404_with_connection_close() {
    let mut h = harness(vec![site(DOMAIN, "10.0.0.1:80")], true).await;
    let req = "GET / HTTP/1.1\r\nHost: nope.local\r\n\r\n";
    let (head, _, _) = roundtrip(h.http_addr, req).await;
    assert_eq!(status_of(&head), 404);
    assert!(head.to_ascii_lowercase().contains("connection: close"), "{head}");
    // 没有建流发生
    assert!(h.links.try_recv().is_err());
}

#[tokio::test]
async fn offline_client_returns_502() {
    let h = harness(vec![site(DOMAIN, "10.0.0.1:80")], false).await;
    let req = format!("GET / HTTP/1.1\r\nHost: {DOMAIN}\r\n\r\n");
    let (head, _, _) = roundtrip(h.http_addr, &req).await;
    assert_eq!(status_of(&head), 502, "head={head}");
    assert!(head.to_ascii_lowercase().contains("connection: close"), "{head}");
    let _ = h;
}

#[tokio::test]
async fn oversized_head_returns_431() {
    let h = harness(vec![site(DOMAIN, "10.0.0.1:80")], true).await;
    let mut sock = TcpStream::connect(h.http_addr).await.unwrap();
    let big = "a".repeat(70 * 1024);
    let req = format!("GET / HTTP/1.1\r\nHost: {DOMAIN}\r\nX-Big: {big}\r\n\r\n");
    let _ = sock.write_all(req.as_bytes()).await;
    let (head, _, _) = read_response(&mut sock).await;
    assert_eq!(status_of(&head), 431, "head={head}");
}

#[tokio::test]
async fn websocket_disabled_rejects_upgrade_with_403() {
    let h = harness(
        vec![site(DOMAIN, "10.0.0.1:80").with_websocket(false)],
        true,
    )
    .await;
    let req = format!(
        "GET /ws HTTP/1.1\r\nHost: {DOMAIN}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
    );
    let (head, _, _) = roundtrip(h.http_addr, &req).await;
    assert_eq!(status_of(&head), 403, "head={head}");
}

#[tokio::test]
async fn site_concurrency_limit_returns_503() {
    let bridge = Bridge::new(|_| Some(1));
    let http = HttpSiteServer::new(
        bridge,
        HttpProxyConfig {
            listen_addr: "127.0.0.1:0".into(),
            sites: vec![site(DOMAIN, "10.0.0.1:80")],
            idle_timeout: Duration::from_secs(10),
            max_connections: 1,
            max_head_bytes: 64 * 1024,
        },
    )
    .unwrap();
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let listener = http.bind().await.unwrap();
    let addr = listener.local_addr().unwrap();
    let this = http.clone();
    tokio::spawn(async move {
        this.serve(listener, cancel_rx).await;
    });

    // 手工占用唯一槽位
    let resolved = http.router().await.resolve(DOMAIN, "/").unwrap();
    let guard = resolved.try_acquire(1).unwrap();

    let req = format!("GET / HTTP/1.1\r\nHost: {DOMAIN}\r\n\r\n");
    let (head, _, _) = roundtrip(addr, &req).await;
    assert_eq!(status_of(&head), 503, "head={head}");
    drop(guard);
    drop(cancel_tx);
}

#[tokio::test]
async fn router_api_surface_works_without_server_wiring() {
    // 父代理接线用的最小调用形态（config.rs 的 HttpSiteConfig → 本模块）
    let cfg = SiteConfig {
        id: 1,
        name: "site".into(),
        client_id: 1,
        domain: DOMAIN.into(),
        target_addr: "127.0.0.1:9000".into(),
        routes: vec![HttpRoute {
            prefix: "/api".into(),
            target_addr: "127.0.0.1:9001".into(),
        }],
        websocket: true,
        enabled: true,
        tls_mode: nps_server::config::TlsMode::Off,
        force_https: false,
    };
    let site = HttpSite::from_site_config(&cfg);
    assert_eq!(site.target, "127.0.0.1:9000");
    assert_eq!(site.routes.len(), 1);

    let router = HttpSiteRouter::new(vec![site]).unwrap();
    assert_eq!(router.len(), 1);
    assert_eq!(router.resolve(DOMAIN, "/api/x").unwrap().target, "127.0.0.1:9001");
    assert!(router.resolve("other.test", "/").is_none());
}
