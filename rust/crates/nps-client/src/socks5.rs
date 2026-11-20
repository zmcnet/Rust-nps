//! `ConnType == "udp5"` 子流：SOCKS5 UDP ASSOCIATE 的中继端。
//!
//! ## 协议事实（逐行核对 `D:\Developing\NPS\resources\nps`）
//!
//! 服务端 `server/proxy/socks5.go:handleUDP` 收到 SOCKS5 `UDP ASSOCIATE` 后：
//! 1. `net.ListenUDP(ServerIp:0)` 拿到回显 socket，把地址回给 SOCKS5 客户端；
//! 2. 向 npc 客户端拨一条 `ConnType="udp5"`、`Host=""` 的子流（目标地址不在
//!    Link 里，而在每一条数据报自带的 SOCKS5 头里）；
//! 3. **子流 → SOCKS5 客户端**：`reply.ReadFrom` 读到 SOCKS5 客户端发来的完整
//!    数据报，`target.Write(b[:n])` **裸写、无长度前缀**，一条数据报一次 `Write`；
//! 4. **SOCKS5 客户端 ← 子流 的反向**：`binary.Read(target, LE, &l)` 读
//!    `int32 LE` 长度（要求 `0 < l < common.PoolSizeUdp(1672)`），再读 `l` 字节，
//!    原样 `reply.WriteTo(..., clientAddr)` —— 所以上行帧里同样带完整 SOCKS5 头。
//!
//! 客户端 `client/client.go:handleUdp` 与之对应：绑本地 UDP socket；子流每段
//! 数据解析成 SOCKS5 数据报后按目标地址 `WriteTo`；本地收到的回包用 `recvfrom`
//! 的源地址重新封头，`conn.GetLenBytes` 加 `int32 LE` 长度前缀写回子流。
//!
//! 即「下行裸数据报、上行带长度前缀」。本实现完全按此实现，并对两处原版隐患加固。
//!
//! ## 与其他 ConnType 的差异
//! - `Link.Host` 恒为空，**不**做 `normalize_host`；
//! - `Link.Option.Timeout` 不再是拨号超时，这里只作为域名解析超时复用。
//!
//! ## 相对原版的收紧（不影响互操作）
//! - 上行单帧限制在 [`MAX_UPSTREAM_FRAME`](=1671) 内：服务端遇到 `l >= 1672`
//!   会 `return`（直接断开整条子流），原版客户端不做检查；这里改为丢包 + 日志；
//! - 域名形式 ATYP（原版 `*Addr.Decode` 支持但客户端没用）用 `lookup_host`
//!   异步解析 + 小容量缓存，失败只丢当前包；
//! - 单块上限 [`MAX_DOWNSTREAM_BLOCK`]、空闲超时 [`RELAY_IDLE_TIMEOUT`]；
//! - 任何解析失败只丢该包（对齐 Go `continue // drop silently`），不 panic、
//!   不中断子流、不泄漏任务。
//!
//! ## 已知限制（继承自原版协议，非本实现引入）
//! 下行没有长度前缀，只能靠 mux 的「一次 `Write` = 一个数据块」切分。
//! Go 服务端一次 `Write` 超 `maximumSegmentSize`(4085) 会被拆成多帧，因此
//! **大于 4085 字节的下行数据报在本协议里本就无法完整表达**。要修必须改服务端
//! 侧分帧（不在本次文件域内）。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nps_legacy::mux::MuxStream;
use nps_proto::Link;
use tokio::net::UdpSocket;
use tracing::{debug, warn};

use crate::tunnel::{
    dial_timeout, forward_chunk, IdleTracker, TunnelError, RELAY_IDLE_TIMEOUT,
};

/// SOCKS5 地址类型
pub const ATYP_IPV4: u8 = 1;
pub const ATYP_DOMAIN: u8 = 3;
pub const ATYP_IPV6: u8 = 4;

/// 上行单帧（不含 4 字节长度前缀）上限。
///
/// 服务端 `handleUDP` 里 `l >= common.PoolSizeUdp`(`1672`) 会直接 `return`，
/// 因此客户端绝不能发 ≥1672 的帧，否则整条子流被断开。
pub const MAX_UPSTREAM_FRAME: usize = 1671;

/// 下行单块上限。mux 单帧最大 4085，这里留出余量以容纳合法大块。
pub const MAX_DOWNSTREAM_BLOCK: usize = 64 * 1024;

/// 单个 UDP 数据报的最大载荷。
const MAX_UDP_PAYLOAD: usize = 65507;

/// 本地 socket 收包缓冲（必须 ≥ 最大数据报，否则 `recv_from` 会截断）。
const LOCAL_RECV_BUF: usize = 65_535;

/// 域名解析缓存条数上限（SOCKS5 客户端通常只用一个目标，够用且不会失控）。
const DNS_CACHE_LIMIT: usize = 64;

/// 数据报里的目标地址：IP 可直接使用；域名需要异步解析。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyAddr {
    Socket(SocketAddr),
    Name(String, u16),
}

impl ProxyAddr {
    /// 日志与缓存键用的可读形式。
    pub fn label(&self) -> String {
        match self {
            ProxyAddr::Socket(addr) => addr.to_string(),
            ProxyAddr::Name(host, port) => format!("{host}:{port}"),
        }
    }
}

/// 解析一条下行数据报：`RSV(2, BE) FRAG(1) ATYP ADDR PORT DATA`。
///
/// `RSV != 0` 时被原版复用为「数据精确长度」扩展语义
/// （见 `lib/common/netpackager.go:ReadUDPDatagram`）；为 0 时取本块剩余全部字节。
pub fn parse_datagram(block: &[u8]) -> Result<(ProxyAddr, &[u8]), TunnelError> {
    if block.len() < 4 {
        return Err(TunnelError::Protocol(format!(
            "udp5 数据报过短: {} 字节",
            block.len()
        )));
    }
    let rsv = u16::from_be_bytes([block[0], block[1]]);
    let frag = block[2];
    if frag != 0 {
        // 分片（FRAG != 0）在 SOCKS5 UDP 里几乎无人实现，原版也没处理
        return Err(TunnelError::Protocol(format!("udp5 不支持分片: FRAG={frag}")));
    }

    let atyp = block[3];
    let mut pos = 4usize;
    let addr = match atyp {
        ATYP_IPV4 => {
            if block.len() < pos + 4 + 2 {
                return Err(TunnelError::Protocol("udp5 IPv4 地址不完整".to_owned()));
            }
            let ip = Ipv4Addr::new(block[pos], block[pos + 1], block[pos + 2], block[pos + 3]);
            pos += 4;
            let port = u16::from_be_bytes([block[pos], block[pos + 1]]);
            pos += 2;
            ProxyAddr::Socket(SocketAddr::new(IpAddr::V4(ip), port))
        }
        ATYP_IPV6 => {
            if block.len() < pos + 16 + 2 {
                return Err(TunnelError::Protocol("udp5 IPv6 地址不完整".to_owned()));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&block[pos..pos + 16]);
            pos += 16;
            let port = u16::from_be_bytes([block[pos], block[pos + 1]]);
            pos += 2;
            ProxyAddr::Socket(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        ATYP_DOMAIN => {
            if block.len() < pos + 1 {
                return Err(TunnelError::Protocol("udp5 域名长度缺失".to_owned()));
            }
            let name_len = block[pos] as usize;
            pos += 1;
            if name_len == 0 || block.len() < pos + name_len + 2 {
                return Err(TunnelError::Protocol("udp5 域名不完整".to_owned()));
            }
            let name = std::str::from_utf8(&block[pos..pos + name_len])
                .map_err(|_| TunnelError::Protocol("udp5 域名不是 UTF-8".to_owned()))?
                .to_owned();
            pos += name_len;
            let port = u16::from_be_bytes([block[pos], block[pos + 1]]);
            pos += 2;
            ProxyAddr::Name(name, port)
        }
        other => {
            return Err(TunnelError::Protocol(format!(
                "udp5 不支持的地址类型: {other}"
            )));
        }
    };

    let data = if rsv != 0 {
        let declared = rsv as usize;
        if block.len() < pos + declared {
            return Err(TunnelError::Protocol(format!(
                "udp5 声明长度 {declared} 超过实际 {}",
                block.len().saturating_sub(pos)
            )));
        }
        &block[pos..pos + declared]
    } else {
        &block[pos..]
    };
    Ok((addr, data))
}

/// 构造一条数据报（`RSV=0` 的标准 SOCKS5 形态，与原版 `NewUDPDatagram` 一致）。
pub fn encode_datagram(addr: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 18 + data.len());
    out.extend_from_slice(&0u16.to_be_bytes()); // RSV
    out.push(0); // FRAG
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// 上行帧：`int32 LE 长度 + 数据报`（对齐 Go `conn.GetLenBytes`）。
pub fn encode_frame(addr: SocketAddr, data: &[u8]) -> Vec<u8> {
    let datagram = encode_datagram(addr, data);
    let mut out = Vec::with_capacity(4 + datagram.len());
    out.extend_from_slice(&(datagram.len() as i32).to_le_bytes());
    out.extend_from_slice(&datagram);
    out
}

/// 上行数据报长度是否可安全发送（服务端会因超长帧断开整条子流）。
pub fn upstream_frame_fits(datagram_len: usize) -> bool {
    datagram_len > 0 && datagram_len <= MAX_UPSTREAM_FRAME
}

/// 处理一条 `"udp5"` 子流。
pub async fn handle_stream(mut stream: MuxStream, link: &Link) -> Result<(), TunnelError> {
    let local = match bind_local().await {
        Ok(local) => local,
        Err(error) => {
            warn!(%error, "udp5 绑定本地 UDP 端口失败，关闭子流");
            stream.close();
            return Err(error);
        }
    };
    let resolve_timeout = dial_timeout(link);
    let local_label = local
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "<unknown>".to_owned());
    debug!(
        remote = %link.remote_addr,
        local = %local_label,
        "udp5 子流已建立，开始双向中继"
    );

    let (mut send, mut recv) = stream.into_split();
    let tracker = IdleTracker::new();
    tracker.touch();
    let up_total = Arc::new(AtomicU64::new(0));
    let down_total = Arc::new(AtomicU64::new(0));
    // 收发两个方向共用一个本地 socket（等价 Go 的同一个 `*net.UDPConn`）；
    // tokio 的 UdpSocket 方法都取 &self，用 Arc 共享即可。
    let local = Arc::new(local);

    // 上行：本地 socket 收到的回包 → 加 SOCKS5 头 + int32 LE 长度 → 子流
    let up_local = local.clone();
    let up_tracker = tracker.clone();
    let up_counter = up_total.clone();
    let mut up = tokio::spawn(async move {
        let mut buf = vec![0u8; LOCAL_RECV_BUF];
        loop {
            let (n, from) = match up_local.recv_from(&mut buf).await {
                Ok(value) => value,
                Err(error) => {
                    debug!(%error, "读取本地 UDP 回包失败，结束上行");
                    break;
                }
            };
            if n == 0 {
                continue;
            }
            let header_len = datagram_header_len(from);
            if !upstream_frame_fits(header_len + n) {
                // 超长帧会让服务端断开整条子流，宁可丢这一个包。
                warn!(
                    len = header_len + n,
                    max = MAX_UPSTREAM_FRAME,
                    target = %from,
                    "udp5 回包超过上行帧上限，丢弃"
                );
                continue;
            }
            let frame = encode_frame(from, &buf[..n]);
            if !forward_chunk(&mut send, &up_tracker, &up_counter, &frame).await {
                break;
            }
        }
        send.close();
    });

    // 下行：子流 → 解析 SOCKS5 头 → 从本地 socket 发给目标
    let down_local = local.clone();
    let down_tracker = tracker.clone();
    let down_counter = down_total.clone();
    let mut down = tokio::spawn(async move {
        let mut cache: HashMap<String, SocketAddr> = HashMap::new();
        while let Some(block) = recv.recv_data().await {
            if block.is_empty() {
                continue;
            }
            if block.len() > MAX_DOWNSTREAM_BLOCK {
                warn!(
                    len = block.len(),
                    max = MAX_DOWNSTREAM_BLOCK,
                    "udp5 下行块过大，丢弃"
                );
                continue;
            }
            let (addr, data) = match parse_datagram(&block) {
                Ok(parsed) => parsed,
                Err(error) => {
                    // 对齐 Go `continue // drop silently`：坏包不终止子流
                    debug!(%error, "udp5 下行数据报非法，丢弃");
                    continue;
                }
            };
            if data.is_empty() || data.len() > MAX_UDP_PAYLOAD {
                continue;
            }
            let target = match resolve(&addr, &mut cache, resolve_timeout).await {
                Some(target) => target,
                None => {
                    debug!(addr = %addr.label(), "udp5 目标地址解析失败，丢弃该包");
                    continue;
                }
            };
            match down_local.send_to(data, target).await {
                Ok(n) => {
                    down_tracker.touch();
                    down_counter.fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(error) => {
                    debug!(target = %target, %error, "udp5 发送失败，丢弃该包");
                }
            }
        }
    });

    let idle_tracker = tracker.clone();
    tokio::select! {
        _ = &mut up => {
            let _ = down.await;
        }
        _ = &mut down => {
            up.abort();
            let _ = up.await;
        }
        _ = crate::tunnel::wait_idle_timeout(idle_tracker, RELAY_IDLE_TIMEOUT) => {
            warn!("udp5 子流空闲超时，关闭子流");
            up.abort();
            down.abort();
            let _ = up.await;
            let _ = down.await;
        }
    }

    debug!(
        up_bytes = up_total.load(Ordering::Relaxed),
        down_bytes = down_total.load(Ordering::Relaxed),
        "udp5 子流转发结束"
    );
    Ok(())
}

/// SOCKS5 头（`RSV FRAG ATYP ADDR PORT`）长度，用于发送前判断帧是否超限。
fn datagram_header_len(addr: SocketAddr) -> usize {
    match addr.ip() {
        IpAddr::V4(_) => 4 + 4 + 2,
        IpAddr::V6(_) => 4 + 16 + 2,
    }
}

/// 绑定本地任意端口的 UDP socket（对齐 Go `net.ListenUDP("udp", nil)`）。
async fn bind_local() -> Result<UdpSocket, TunnelError> {
    UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|error| TunnelError::LocalUdp(format!("绑定本地 UDP 端口失败: {error}")))
}

/// 把 `ProxyAddr` 解析成 `SocketAddr`：IP 直通，域名走 `lookup_host` + 小缓存。
async fn resolve(
    addr: &ProxyAddr,
    cache: &mut HashMap<String, SocketAddr>,
    timeout: Duration,
) -> Option<SocketAddr> {
    match addr {
        ProxyAddr::Socket(socket) => Some(*socket),
        ProxyAddr::Name(host, port) => {
            let key = format!("{host}:{port}");
            if let Some(cached) = cache.get(&key) {
                return Some(*cached);
            }
            let lookup = tokio::net::lookup_host((host.as_str(), *port));
            let resolved = match tokio::time::timeout(timeout, lookup).await {
                Ok(Ok(addrs)) => addrs.into_iter().next(),
                Ok(Err(error)) => {
                    debug!(host = %host, %error, "udp5 域名解析失败");
                    None
                }
                Err(_) => {
                    debug!(host = %host, "udp5 域名解析超时");
                    None
                }
            };
            if let Some(socket) = resolved {
                if cache.len() < DNS_CACHE_LIMIT {
                    cache.insert(key, socket);
                }
            }
            resolved
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::handle_stream as dispatch;
    use crate::tunnel::test_support::{session_pair, test_link, write_link};
    use tokio::time::timeout;

    const WAIT: Duration = Duration::from_secs(5);

    #[test]
    fn ipv4_datagram_roundtrip() {
        let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let datagram = encode_datagram(addr, b"hello");
        let (parsed, data) = parse_datagram(&datagram).unwrap();
        assert_eq!(parsed, ProxyAddr::Socket(addr));
        assert_eq!(data, b"hello");
    }

    #[test]
    fn ipv6_datagram_roundtrip() {
        let addr: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let datagram = encode_datagram(addr, b"v6");
        let (parsed, data) = parse_datagram(&datagram).unwrap();
        assert_eq!(parsed, ProxyAddr::Socket(addr));
        assert_eq!(data, b"v6");
    }

    #[test]
    fn domain_datagram_is_parsed_as_name() {
        let mut block = vec![0, 0, 0, ATYP_DOMAIN, 9];
        block.extend_from_slice(b"localhost");
        block.extend_from_slice(&53u16.to_be_bytes());
        block.extend_from_slice(b"data");
        let (parsed, data) = parse_datagram(&block).unwrap();
        assert_eq!(parsed, ProxyAddr::Name("localhost".to_owned(), 53));
        assert_eq!(data, b"data");
    }

    #[test]
    fn rsv_acts_as_explicit_length() {
        // RSV = 5：数据精确 5 字节
        let mut block = vec![0, 5, 0, ATYP_IPV4, 127, 0, 0, 1, 0x1F, 0x90];
        block.extend_from_slice(b"12345");
        let (_, data) = parse_datagram(&block).unwrap();
        assert_eq!(data, b"12345");

        // 声明长度大于实际：报错
        let mut bad = vec![0, 9, 0, ATYP_IPV4, 127, 0, 0, 1, 0x1F, 0x90];
        bad.extend_from_slice(b"12345");
        assert!(parse_datagram(&bad).is_err());
    }

    #[test]
    fn fragments_and_unknown_atyp_are_rejected() {
        let mut frag = vec![0, 0, 1, ATYP_IPV4, 127, 0, 0, 1, 0, 80];
        frag.extend_from_slice(b"x");
        assert!(parse_datagram(&frag).is_err());

        assert!(parse_datagram(&[0, 0, 0, 9, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(parse_datagram(b"\0\0").is_err());
        assert!(parse_datagram(&[0, 0, 0, ATYP_IPV4, 127, 0]).is_err());
        assert!(parse_datagram(&[0, 0, 0, ATYP_IPV6, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn frame_limit_matches_server_constraint() {
        assert!(upstream_frame_fits(1));
        assert!(upstream_frame_fits(MAX_UPSTREAM_FRAME));
        assert!(!upstream_frame_fits(MAX_UPSTREAM_FRAME + 1));
        assert!(!upstream_frame_fits(0));

        // 长度前缀必须等于其后数据报长度
        let frame = encode_frame("127.0.0.1:9".parse().unwrap(), b"x");
        let declared = i32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
        assert_eq!(declared as usize, frame.len() - 4);
    }

    #[test]
    fn header_len_matches_encoded_datagram() {
        for addr in [
            "127.0.0.1:53".parse::<SocketAddr>().unwrap(),
            "[::1]:53".parse::<SocketAddr>().unwrap(),
        ] {
            let datagram = encode_datagram(addr, b"");
            assert_eq!(datagram.len(), datagram_header_len(addr));
        }
    }

    /// 端到端：下行数据报投递到目标；目标回包被封装成 `长度前缀 + SOCKS5 头` 写回。
    #[tokio::test]
    async fn relays_datagrams_both_directions() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, from)) = echo.recv_from(&mut buf).await {
                if echo.send_to(&buf[..n], from).await.is_err() {
                    break;
                }
            }
        });

        let (server, client) = session_pair().await;
        let mut peer = server.open_stream().await.unwrap();
        let stream = client.accept_stream().await.unwrap();
        let worker = tokio::spawn(dispatch(stream));
        write_link(&mut peer, &test_link(crate::tunnel::CONN_UDP5, "")).await;

        let payload = b"udp5-payload";
        // 下行是裸数据报（无长度前缀），一条数据报一次 send_data
        peer.send_data(&encode_datagram(echo_addr, payload)).await.unwrap();

        // 上行期望：int32 LE 长度 + SOCKS5 头（源地址 = echo_addr）+ payload
        let mut received = Vec::new();
        let deadline = tokio::time::Instant::now() + WAIT;
        let (addr, data) = loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let chunk = timeout(remaining, peer.recv_data())
                .await
                .expect("应收到回包")
                .expect("子流不应关闭");
            received.extend_from_slice(&chunk);
            if received.len() < 4 {
                continue;
            }
            let declared = i32::from_le_bytes([received[0], received[1], received[2], received[3]]);
            assert!(declared > 0, "长度前缀必须为正");
            let declared = declared as usize;
            if received.len() < 4 + declared {
                continue;
            }
            let body = &received[4..4 + declared];
            let (addr, data) = parse_datagram(body).expect("回包必须是合法 SOCKS5 数据报");
            break (addr, data.to_vec());
        };
        assert_eq!(addr, ProxyAddr::Socket(echo_addr));
        assert_eq!(data, payload);

        drop(peer);
        let _ = timeout(WAIT, worker).await;
    }

    /// 非法下行数据报只丢包，不能让整条子流报错退出。
    #[tokio::test]
    async fn malformed_downstream_datagram_is_dropped() {
        let (server, client) = session_pair().await;
        let mut peer = server.open_stream().await.unwrap();
        let stream = client.accept_stream().await.unwrap();
        let worker = tokio::spawn(dispatch(stream));
        write_link(&mut peer, &test_link(crate::tunnel::CONN_UDP5, "")).await;

        // ATYP=9 非法
        peer.send_data(b"\x00\x00\x00\x09garbage").await.unwrap();
        // 紧接着一条合法的：仍应被处理（不阻塞、不退出）
        let target: SocketAddr = "127.0.0.1:9".parse().unwrap();
        peer.send_data(&encode_datagram(target, b"after")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!worker.is_finished(), "单个坏包不应终止子流");

        drop(peer);
        let _ = timeout(WAIT, worker).await;
    }

    /// 子流关闭后任务必须被回收，不残留。
    #[tokio::test]
    async fn stream_close_reclaims_task() {
        let (server, client) = session_pair().await;
        let mut peer = server.open_stream().await.unwrap();
        let stream = client.accept_stream().await.unwrap();
        let worker = tokio::spawn(dispatch(stream));
        write_link(&mut peer, &test_link(crate::tunnel::CONN_UDP5, "")).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        drop(peer);
        assert!(
            timeout(WAIT, worker).await.is_ok(),
            "关闭子流后 udp5 任务必须及时结束"
        );
    }
}
