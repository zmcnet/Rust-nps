//! `ConnType == "udp"` 子流：把子流的字节块当成 UDP 数据报转发到目标。
//!
//! 协议对齐 Go `client/client.go:handleChan` + `lib/conn/conn.go:CopyWaitGroup`：
//! 原版对 `"udp"` 只是 `net.DialTimeout("udp", Host)` 然后双向拷贝。子流本身走
//! `nps-mux`（可靠有序流），而目标侧是 UDP socket；Go 的 `net.Conn` 抽象让两者
//! 直接对接，副作用就是**子流侧没有数据报边界**：
//!
//! - 子流 → 目标：每次从子流读到的字节块当作**一个** UDP 数据报发送
//!   （Go `CopyBuffer` 里 `src.Read` 一次、`dst.Write` 一次，行为等价）
//! - 目标 → 子流：每个收到的数据报作为一段字节写入子流
//!
//! 因此这里**不引入任何额外的分帧格式**，否则会与原版服务端不兼容
//! （服务端 `server/proxy/udp.go` 同样是裸 `Write`/`Read`）。
//!
//! 与 Go 的差异（均为收紧，不影响互操作）：
//! - 目标 ─→ 子流方向用 64 KiB 缓冲读取，避免超过 Go `BufPoolUdp`(1672 B) 的
//!   数据报被静默截断；
//! - 子流块超过单个 UDP 数据报上限（65507 B）时记日志并结束该方向，
//!   而不是让 `send` 报 EMSGSIZE 后无声退出；
//! - 双向累计无流量超过 [`crate::tunnel::RELAY_IDLE_TIMEOUT`] 时关闭子流，
//!   对齐 Go 服务端 10 分钟读超时的语义，避免长期挂死的子流占任务。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nps_legacy::mux::MuxStream;
use nps_proto::Link;
use tokio::net::UdpSocket;
use tracing::{debug, warn};

use crate::tunnel::{
    dial_timeout, forward_chunk, normalize_host, IdleTracker, TunnelError, RELAY_IDLE_TIMEOUT,
};

/// 单个 UDP 数据报的最大载荷（65535 - 8 字节 UDP 头 - 20 字节 IP 头）。
const MAX_UDP_PAYLOAD: usize = 65507;

/// 目标 → 子流方向的读缓冲：必须不小于最大数据报，否则 `recv` 会截断。
const UDP_RECV_BUF: usize = 65535;

/// 处理一条 `"udp"` 子流。
pub async fn handle_stream(mut stream: MuxStream, link: &Link) -> Result<(), TunnelError> {
    let host = match normalize_host(&link.host) {
        Ok(host) => host,
        Err(error) => {
            warn!(host = %link.host, %error, "目标地址非法，关闭子流");
            stream.close();
            return Err(error);
        }
    };
    let timeout = dial_timeout(link);
    debug!(target = %host, timeout_ms = timeout.as_millis() as u64, "开始绑定并连接 UDP 目标");

    let target = match dial_udp(&host, timeout).await {
        Ok(target) => target,
        Err(error) => {
            stream.close();
            return Err(error);
        }
    };

    let (mut send, mut recv) = stream.into_split();
    let tracker = IdleTracker::new();
    tracker.touch();

    // 收发两个方向都要用同一个 socket；tokio 的 UdpSocket 方法都取 &self，
    // 因此用 Arc 共享即可，无需拆分。
    let socket = Arc::new(target);
    let up_total = Arc::new(AtomicU64::new(0));
    let down_total = Arc::new(AtomicU64::new(0));

    // 上行：目标 -> mux。每个数据报作为一段写入子流。
    let up_tracker = tracker.clone();
    let up_counter = up_total.clone();
    let up_socket = socket.clone();
    let mut up = tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_RECV_BUF];
        loop {
            match up_socket.recv(&mut buf).await {
                Ok(n) => {
                    up_tracker.touch();
                    if !forward_chunk(&mut send, &up_tracker, &up_counter, &buf[..n]).await {
                        break;
                    }
                }
                Err(error) => {
                    debug!(%error, "读取 UDP 目标失败，结束上行");
                    break;
                }
            }
        }
        send.close();
    });

    // 下行：mux -> 目标。每个子流字节块作为一个数据报发送。
    let down_tracker = tracker.clone();
    let down_counter = down_total.clone();
    let mut down = tokio::spawn(async move {
        while let Some(chunk) = recv.recv_data().await {
            if chunk.is_empty() {
                continue;
            }
            if !datagram_fits(&chunk) {
                warn!(
                    len = chunk.len(),
                    max = MAX_UDP_PAYLOAD,
                    "子流数据块超过单个 UDP 数据报上限，结束下行"
                );
                break;
            }
            match socket.send(&chunk).await {
                Ok(n) => {
                    down_tracker.touch();
                    down_counter.fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(error) => {
                    debug!(%error, "发送 UDP 数据报失败，结束下行");
                    break;
                }
            }
        }
    });

    let idle_tracker = tracker.clone();
    tokio::select! {
        _ = &mut up => {
            // UDP 目标方向结束（对端 socket 出错/关闭）后不会再有数据报回来，
            // 继续等下行只会挂住子流，因此一并结束。
            down.abort();
            let _ = down.await;
        }
        _ = &mut down => {
            up.abort();
            let _ = up.await;
        }
        _ = crate::tunnel::wait_idle_timeout(idle_tracker, RELAY_IDLE_TIMEOUT) => {
            warn!(target = %host, "UDP 子流空闲超时，关闭子流");
            up.abort();
            down.abort();
            let _ = up.await;
            let _ = down.await;
        }
    }

    debug!(
        target = %host,
        up_bytes = up_total.load(Ordering::Relaxed),
        down_bytes = down_total.load(Ordering::Relaxed),
        "UDP 子流转发结束"
    );
    Ok(())
}

/// 按目标地址族绑定本地任意端口并 `connect`（UDP 的 connect 只是记录对端地址，
/// 但仍可能触发 DNS 解析，因此同样受 Link 超时约束）。
///
/// 先 `lookup_host` 定地址族再绑定，避免「IPv4 通配本地端口连 IPv6 目标」失败。
async fn dial_udp(host: &str, timeout: Duration) -> Result<UdpSocket, TunnelError> {
    let connect = async {
        let target = tokio::net::lookup_host(host)
            .await
            .map_err(|error| TunnelError::Dial {
                host: host.to_owned(),
                error: format!("地址解析失败: {error}"),
            })?
            .next()
            .ok_or_else(|| TunnelError::Dial {
                host: host.to_owned(),
                error: "地址解析结果为空".to_owned(),
            })?;
        let bind = if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = UdpSocket::bind(bind).await.map_err(|error| {
            TunnelError::LocalUdp(format!("绑定本地 UDP 端口失败: {error}"))
        })?;
        socket.connect(target).await.map_err(|error| TunnelError::Dial {
            host: host.to_owned(),
            error: error.to_string(),
        })?;
        Ok::<UdpSocket, TunnelError>(socket)
    };

    match tokio::time::timeout(timeout, connect).await {
        Ok(Ok(socket)) => Ok(socket),
        Ok(Err(error)) => {
            warn!(target = %host, %error, "UDP 目标不可达，关闭子流");
            Err(error)
        }
        Err(_) => {
            warn!(target = %host, timeout_ms = timeout.as_millis() as u64, "UDP 目标解析/连接超时，关闭子流");
            Err(TunnelError::Dial {
                host: host.to_owned(),
                error: "UDP 目标连接超时".to_owned(),
            })
        }
    }
}

/// 单个数据报的收发上限校验：空或超过 65507 字节的块都不可能是合法 UDP 数据报。
pub fn datagram_fits(payload: &[u8]) -> bool {
    !payload.is_empty() && payload.len() <= MAX_UDP_PAYLOAD
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::test_support::{recv_within, session_pair, test_link, write_link};
    use crate::tunnel::handle_stream;
    use std::time::Duration;

    const WAIT: Duration = Duration::from_secs(5);

    #[test]
    fn datagram_limit_matches_udp_max_payload() {
        assert!(datagram_fits(&[0u8; 1]));
        assert!(datagram_fits(&vec![0u8; MAX_UDP_PAYLOAD]));
        assert!(!datagram_fits(&vec![0u8; MAX_UDP_PAYLOAD + 1]));
        assert!(!datagram_fits(&[]));
    }

    /// 每个子流字节块必须原样成为**一个**数据报：用一个记录数据报边界的 echo 服务验证。
    #[tokio::test]
    async fn each_chunk_becomes_single_datagram() {
        let echo = std::sync::Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let target = echo.local_addr().unwrap();
        let echo_task = echo.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_RECV_BUF];
            while let Ok((n, from)) = echo_task.recv_from(&mut buf).await {
                // 回显时加上长度前缀，便于断言边界未被合并/拆分
                let mut reply = format!("[{n}]").into_bytes();
                reply.extend_from_slice(&buf[..n]);
                if echo_task.send_to(&reply, from).await.is_err() {
                    break;
                }
            }
        });

        let (server, client) = session_pair().await;
        let mut peer = server.open_stream().await.unwrap();
        let stream = client.accept_stream().await.unwrap();
        let worker = tokio::spawn(handle_stream(stream));

        write_link(&mut peer, &test_link(nps_proto::CONN_UDP, target.to_string())).await;

        for payload in [b"a".to_vec(), b"bcd".to_vec(), vec![7u8; 1200]] {
            peer.send_data(&payload).await.unwrap();
            let mut expected = format!("[{}]", payload.len()).into_bytes();
            expected.extend_from_slice(&payload);
            // 回显可能分多块到达（子流是流），累积到长度足够
            let mut got = Vec::new();
            while got.len() < expected.len() {
                let chunk = recv_within(&mut peer, WAIT).await.expect("应收到回显");
                got.extend_from_slice(&chunk);
            }
            assert_eq!(got, expected, "数据报边界/内容必须一致");
        }

        drop(peer);
        let _ = tokio::time::timeout(WAIT, worker).await;
    }

    /// 往返大报文（接近 MTU 上限）不被截断。
    #[tokio::test]
    async fn large_datagram_roundtrip_is_not_truncated() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_RECV_BUF];
            while let Ok((n, from)) = echo.recv_from(&mut buf).await {
                if echo.send_to(&buf[..n], from).await.is_err() {
                    break;
                }
            }
        });

        let (server, client) = session_pair().await;
        let mut peer = server.open_stream().await.unwrap();
        let stream = client.accept_stream().await.unwrap();
        let worker = tokio::spawn(handle_stream(stream));
        write_link(&mut peer, &test_link(nps_proto::CONN_UDP, target.to_string())).await;

        let payload: Vec<u8> = (0..9000u32).map(|i| (i % 251) as u8).collect();
        peer.send_data(&payload).await.unwrap();

        let mut got = Vec::new();
        while got.len() < payload.len() {
            let chunk = recv_within(&mut peer, WAIT).await.expect("应收到回显");
            got.extend_from_slice(&chunk);
        }
        assert_eq!(got, payload);

        drop(peer);
        let _ = tokio::time::timeout(WAIT, worker).await;
    }

    /// 目标 UDP 端口存在但从不回包：子流应保持打开（不误判为错误），
    /// 关闭子流后任务必须能及时回收，不残留。
    #[tokio::test]
    async fn silent_target_keeps_stream_then_closes_cleanly() {
        // 绑定但不读、不回：模拟只收不发的 UDP 服务
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = silent.local_addr().unwrap();

        let (server, client) = session_pair().await;
        let mut peer = server.open_stream().await.unwrap();
        let stream = client.accept_stream().await.unwrap();
        let worker = tokio::spawn(handle_stream(stream));
        write_link(&mut peer, &test_link(nps_proto::CONN_UDP, target.to_string())).await;

        peer.send_data(b"no-reply").await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!worker.is_finished(), "无回包时子流应保持打开");

        drop(peer);
        let joined = tokio::time::timeout(WAIT, worker).await;
        assert!(joined.is_ok(), "关闭子流后任务必须及时结束");
        drop(silent);
    }
}
