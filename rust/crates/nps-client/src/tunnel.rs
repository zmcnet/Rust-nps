//! 单条 mux 子流的处理：读 Link 首帧 → 按 `ConnType` 分派 → 拨号目标 → 双向转发。
//!
//! 协议对齐：
//! - 服务端在子流上的首个帧是 `int32 LE 长度 + Link JSON`（无 4 字节 flag），
//!   见 Go `bridge/bridge.go:SendLinkInfo` 与 `lib/conn/conn.go:SendInfo`。
//! - Link 的线上字段名是 Go 导出字段名（`ConnType`/`Host`/`Option.Timeout` …），
//!   由 `nps_proto::Link` 负责解析。
//! - 目标地址格式对齐 Go `common.FormatAddress`：不含 `:` 时按 127.0.0.1:<value> 处理。
//! - 分派规则对齐 Go `client/client.go:handleChan`：
//!   - `"tcp"`  → `net.DialTimeout("tcp", Host)` + 双向拷贝（本文件）
//!   - `"udp"`  → `net.DialTimeout("udp", Host)` + 双向拷贝，见 [`crate::udp`]
//!   - `"http"` → 拨 TCP 到 Host，读一个完整 HTTP 请求再双向拷贝，见 [`crate::http_proxy`]
//!   - `"udp5"` → 绑定本地 UDP 端口，子流内传 SOCKS5 UDP 数据报，见 [`crate::socks5`]
//!     其它类型（含 KCP/P2P 等新协议 flag）统一下降级为「关闭子流 + 日志」。
//!
//! 资源防护：Link 帧长度上限、拨号超时上下界、HTTP 头部缓冲上限、
//! 单连接累计缓冲上限（[`MAX_RELAY_BUFFER`]）与非 TCP 子流的空闲超时
//! （[`RELAY_IDLE_TIMEOUT`]）都集中在本文件，避免各协议各自为政。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nps_legacy::mux::{MuxRecvHalf, MuxSendHalf, MuxStream};
use nps_proto::Link;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// Link 首帧长度上限。Link 只含地址与选项，64 KiB 已远大于正常值；
/// 与 Go 健康帧上限一致，避免伪造长度导致的大内存分配。
pub const MAX_LINK_FRAME_LEN: usize = 64 * 1024;

/// 两个方向各自使用的读缓冲大小，对齐 Go `common.PoolSizeCopy = 32 KiB`。
pub(crate) const COPY_BUF: usize = 32 * 1024;

/// 单连接累计缓冲上限（1 MiB）。
///
/// 只约束「为了解析协议而必须在内存里攒起来」的字节（HTTP 头、udp5 长度前缀帧等），
/// 超过即判定为对端违约并关闭子流，避免一条子流吃光进程内存。
pub const MAX_RELAY_BUFFER: usize = 1024 * 1024;

/// 非 TCP 子流的空闲超时。
///
/// 对齐 Go 服务端 UDP 转发对客户端连接设置的 10 分钟读超时
/// （`server/proxy/udp.go` 的 `SetReadDeadline(time.Now().Add(time.Minute * 10))`）。
/// TCP 子流保持原有行为（无空闲超时），以免改变既有语义。
pub const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// 空闲看门狗的检查间隔（远小于超时本身，避免频繁唤醒）。
const IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(15);

/// Link 未给出有效 Timeout 时的拨号超时，对齐 Go `conn.defaultTimeOut = 5s`。
const DIAL_TIMEOUT_FALLBACK: Duration = Duration::from_secs(5);
/// 对端给出的拨号超时上限，避免被伪造 Link 挂住过久。
const DIAL_TIMEOUT_MAX: Duration = Duration::from_secs(60);

/// HTTP 域名代理链路类型（Go `server/proxy/http.go` 里 `conn.NewLink("http", ...)`）。
pub const CONN_HTTP: &str = "http";
/// SOCKS5 UDP ASSOCIATE 链路类型（Go `server/proxy/socks5.go` 里 `conn.NewLink("udp5", ...)`）。
pub const CONN_UDP5: &str = "udp5";

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("读取 Link 首帧失败: {0}")]
    ReadLink(String),
    #[error("Link 帧长度非法: {0}")]
    BadLinkLength(i32),
    #[error("Link JSON 解析失败: {0}")]
    LinkJson(#[from] serde_json::Error),
    #[error("子流在 Link 首帧前关闭")]
    StreamClosed,
    #[error("暂不支持的链路类型: {0}")]
    UnsupportedConnType(String),
    #[error("目标地址为空或不合法")]
    BadTarget,
    #[error("拨号目标 {host} 失败: {error}")]
    Dial { host: String, error: String },
    #[error("写入目标失败: {0}")]
    TargetWrite(String),
    #[error("子流数据不完整或已关闭")]
    StreamIo,
    #[error("子流缓冲超过上限（{0} 字节）")]
    BufferLimit(usize),
    #[error("子流空闲超时")]
    IdleTimeout,
    #[error("子流协议数据非法: {0}")]
    Protocol(String),
    #[error("绑定本地 UDP 端口失败: {0}")]
    LocalUdp(String),
}

impl From<StreamError> for TunnelError {
    fn from(error: StreamError) -> Self {
        match error {
            StreamError::Closed => TunnelError::StreamIo,
            StreamError::TooLarge => TunnelError::BufferLimit(MAX_RELAY_BUFFER),
        }
    }
}

/// 处理一条子流；所有错误都在内部降级为日志，不向上抛 panic。
pub async fn handle_stream(mut stream: MuxStream) -> Result<(), TunnelError> {
    let link = match read_link_frame(&mut stream).await {
        Ok(link) => link,
        Err(error) => {
            // 首帧不合法/超长：关闭子流，服务端会据此释放连接。
            stream.close();
            return Err(error);
        }
    };

    match link.conn_type.as_str() {
        nps_proto::CONN_TCP => handle_tcp(stream, &link).await,
        nps_proto::CONN_UDP => crate::udp::handle_stream(stream, &link).await,
        CONN_HTTP => crate::http_proxy::handle_stream(stream, &link).await,
        CONN_UDP5 => crate::socks5::handle_stream(stream, &link).await,
        other => {
            let conn_type = other.to_owned();
            warn!(
                conn_type = %conn_type,
                host = %link.host,
                "暂不支持该链路类型，关闭子流"
            );
            stream.close();
            Err(TunnelError::UnsupportedConnType(conn_type))
        }
    }
}

/// `ConnType == "tcp"`：拨号目标 → 双向对拷（既有行为，保持不变）。
async fn handle_tcp(mut stream: MuxStream, link: &Link) -> Result<(), TunnelError> {
    let host = match normalize_host(&link.host) {
        Ok(host) => host,
        Err(error) => {
            warn!(host = %link.host, %error, "目标地址非法，关闭子流");
            stream.close();
            return Err(error);
        }
    };
    let timeout = dial_timeout(link);
    debug!(target = %host, remote = %link.remote_addr, timeout_ms = timeout.as_millis() as u64, "开始拨号目标");

    let target = match dial_tcp(&host, timeout).await {
        Ok(target) => target,
        Err(error) => {
            stream.close();
            return Err(error);
        }
    };

    let (mut send, mut recv) = stream.into_split();
    let (mut tcp_reader, mut tcp_writer) = target.into_split();

    let up_total = Arc::new(AtomicU64::new(0));
    let down_total = Arc::new(AtomicU64::new(0));

    // 上行：目标 -> mux。目标 EOF 时只做半关闭（不发 muxConnClose），
    // 继续等待服务端把下行数据送完，对齐 Go `copyConnGroup` 的行为。
    let up_counter = up_total.clone();
    let mut up = tokio::spawn(async move {
        let mut buf = vec![0u8; COPY_BUF];
        loop {
            match tcp_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if send.send_data(&buf[..n]).await.is_err() {
                        break;
                    }
                    up_counter.fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(error) => {
                    debug!(%error, "读取目标失败，结束上行");
                    break;
                }
            }
        }
        send.close();
    });

    // 下行：mux -> 目标。服务端关闭子流时立即结束；写入失败也结束。
    let down_counter = down_total.clone();
    let mut down = tokio::spawn(async move {
        while let Some(chunk) = recv.recv_data().await {
            if let Err(error) = tcp_writer.write_all(&chunk).await {
                debug!(%error, "写入目标失败，结束下行");
                break;
            }
            down_counter.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        }
        let _ = tcp_writer.shutdown().await;
    });

    // 任一方向结束：
    // - 下行先结束（服务端关闭）→ 中止上行，尽快释放目标连接；
    // - 上行先结束（目标 EOF）→ 等下行自然结束，避免截断响应。
    tokio::select! {
        _ = &mut up => {
            let _ = down.await;
        }
        _ = &mut down => {
            up.abort();
            let _ = up.await;
        }
    };

    debug!(
        target = %host,
        up_bytes = up_total.load(Ordering::Relaxed),
        down_bytes = down_total.load(Ordering::Relaxed),
        "子流转发结束"
    );
    Ok(())
}

/// 读取并解析子流首帧 Link。
pub async fn read_link_frame(stream: &mut MuxStream) -> Result<Link, TunnelError> {
    let mut buffer: Vec<u8> = Vec::with_capacity(256);
    loop {
        if buffer.len() >= 4 {
            let len = i32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
            if len <= 0 || len as usize > MAX_LINK_FRAME_LEN {
                return Err(TunnelError::BadLinkLength(len));
            }
            let total = 4 + len as usize;
            if buffer.len() >= total {
                let link: Link = serde_json::from_slice(&buffer[4..total])?;
                return Ok(link);
            }
        }

        match stream.recv_data().await {
            Some(chunk) => {
                buffer.extend_from_slice(&chunk);
                if buffer.len() > 4 + MAX_LINK_FRAME_LEN {
                    return Err(TunnelError::BadLinkLength(buffer.len() as i32));
                }
            }
            None => return Err(TunnelError::StreamClosed),
        }
    }
}

/// 对齐 Go `common.FormatAddress`：含 `:` 视为完整地址，否则补 127.0.0.1。
pub fn normalize_host(host: &str) -> Result<String, TunnelError> {
    if host.is_empty() || host.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return Err(TunnelError::BadTarget);
    }
    if host.contains(':') {
        return Ok(host.to_owned());
    }
    Ok(format!("127.0.0.1:{host}"))
}

pub(crate) fn dial_timeout(link: &Link) -> Duration {
    link.option
        .timeout_duration()
        .map(|value| value.clamp(Duration::from_millis(100), DIAL_TIMEOUT_MAX))
        .unwrap_or(DIAL_TIMEOUT_FALLBACK)
}

/// 按 Link 的超时拨号 TCP 目标；失败时记录日志（调用方负责关闭子流）。
pub(crate) async fn dial_tcp(host: &str, timeout: Duration) -> Result<TcpStream, TunnelError> {
    match tokio::time::timeout(timeout, TcpStream::connect(host)).await {
        Ok(Ok(target)) => {
            let _ = target.set_nodelay(true);
            Ok(target)
        }
        Ok(Err(error)) => {
            warn!(target = %host, error = %error, "目标服务不可达，关闭子流");
            Err(TunnelError::Dial {
                host: host.to_owned(),
                error: error.to_string(),
            })
        }
        Err(_) => {
            warn!(target = %host, timeout_ms = timeout.as_millis() as u64, "目标拨号超时，关闭子流");
            Err(TunnelError::Dial {
                host: host.to_owned(),
                error: "拨号超时".to_owned(),
            })
        }
    }
}

/// 子流读取失败的原因（与 `TunnelError` 解耦，便于在公共读取逻辑里用 `?`）。
#[derive(Debug, thiserror::Error)]
pub(crate) enum StreamError {
    #[error("子流已关闭")]
    Closed,
    #[error("数据超过长度上限")]
    TooLarge,
}

/// 子流字节源：把 mux 的「块」输入抽象成可增量解析的字节流。
///
/// 生产实现是 [`StreamReader`]（包装 `MuxRecvHalf`）；单测里用内存数据实现，
/// 这样可以按任意边界切分输入，验证跨块的增量解析。
pub(crate) trait ChunkSource {
    /// 尚未消费的字节。
    fn buffered(&self) -> &[u8];
    /// 消费掉前 `n` 字节。
    fn consume(&mut self, n: usize);
    /// 取下一块数据；返回 `false` 表示子流已关闭。
    ///
    /// 用 RPITIT（`impl Future`）而非 `async fn`，这样 trait 对 dyn 不友好但
    /// 无需 `async_trait` 一类额外依赖；实现方允许写成 `async fn`。
    fn fill(&mut self) -> impl std::future::Future<Output = bool> + Send;
}

/// 带缓冲的 mux 子流读取器。
pub(crate) struct StreamReader {
    recv: MuxRecvHalf,
    buf: Vec<u8>,
    pos: usize,
}

impl StreamReader {
    pub(crate) fn new(recv: MuxRecvHalf) -> Self {
        Self {
            recv,
            buf: Vec::new(),
            pos: 0,
        }
    }

    /// 用「已读入但未被解析消费」的残留字节（例如 HTTP 流水线里下一个请求的
    /// 开头部分）构造，避免这部分字节丢在解析层。
    pub(crate) fn with_pending(recv: MuxRecvHalf, pending: Vec<u8>) -> Self {
        Self {
            recv,
            buf: pending,
            pos: 0,
        }
    }

    /// 取走「已读入但未被解析消费」的剩余字节，并归还接收半边。
    pub(crate) fn into_parts(self) -> (MuxRecvHalf, Vec<u8>) {
        (self.recv, self.buf[self.pos..].to_vec())
    }
}

impl ChunkSource for StreamReader {
    fn buffered(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn consume(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.buf.len());
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        }
    }

    async fn fill(&mut self) -> bool {
        let chunk = match self.recv.recv_data().await {
            Some(chunk) => chunk,
            None => return false,
        };
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        }
        self.buf.extend_from_slice(&chunk);
        true
    }
}

/// 读取直到 `needle` 出现（返回值包含 `needle`），单次读取上限 `limit` 字节。
pub(crate) async fn read_until<S: ChunkSource>(
    source: &mut S,
    needle: &[u8],
    limit: usize,
) -> Result<Vec<u8>, StreamError> {
    loop {
        if let Some(index) = find(source.buffered(), needle) {
            let end = index + needle.len();
            let out = source.buffered()[..end].to_vec();
            source.consume(end);
            return Ok(out);
        }
        if source.buffered().len() >= limit {
            return Err(StreamError::TooLarge);
        }
        if !source.fill().await {
            return Err(StreamError::Closed);
        }
    }
}

/// 子流里出现 `needle` 的位置。
pub(crate) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// 空闲活动追踪：任一方向有字节流动就刷新时间戳，用于非 TCP 子流的空闲超时。
pub(crate) struct IdleTracker {
    start: Instant,
    last_ms: AtomicU64,
}

impl IdleTracker {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
        })
    }

    pub(crate) fn touch(&self) {
        self.last_ms
            .store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    fn idle_for(&self) -> Duration {
        let now = self.start.elapsed().as_millis() as u64;
        Duration::from_millis(now.saturating_sub(self.last_ms.load(Ordering::Relaxed)))
    }
}

/// 等待空闲超时；返回即表示该子流应被关闭。
pub(crate) async fn wait_idle_timeout(tracker: Arc<IdleTracker>, timeout: Duration) {
    loop {
        tokio::time::sleep(IDLE_CHECK_INTERVAL).await;
        if tracker.idle_for() >= timeout {
            return;
        }
    }
}

/// 子流发送半边的一段写操作，失败即终止对应方向。
pub(crate) async fn forward_chunk(
    send: &mut MuxSendHalf,
    tracker: &IdleTracker,
    counter: &AtomicU64,
    data: &[u8],
) -> bool {
    if send.send_data(data).await.is_err() {
        return false;
    }
    tracker.touch();
    counter.fetch_add(data.len() as u64, Ordering::Relaxed);
    true
}

#[cfg(test)]
pub(crate) mod test_support {
    //! 单测工具：在内存 duplex 上建立一对真实 mux 会话，测试扮演 nps 服务端。

    use super::*;
    use nps_legacy::mux::MuxSession;
    use tokio::io::duplex;

    /// 建立一对互联的 mux 会话：(服务端侧, 客户端侧)。
    pub async fn session_pair() -> (Arc<MuxSession>, Arc<MuxSession>) {
        let (a, b) = duplex(256 * 1024);
        let server = Arc::new(MuxSession::new(a));
        let client = Arc::new(MuxSession::new(b));
        // 等两边读循环启动，避免首个 NewConn 因写入队列尚未就绪而失败。
        tokio::task::yield_now().await;
        (server, client)
    }

    /// 在子流上写一个 Link 首帧（`int32 LE 长度 + JSON`）。
    pub async fn write_link(stream: &mut MuxStream, link: &Link) {
        let json = serde_json::to_vec(link).expect("Link 可序列化");
        let mut frame = Vec::with_capacity(4 + json.len());
        frame.extend_from_slice(&(json.len() as i32).to_le_bytes());
        frame.extend_from_slice(&json);
        stream.send_data(&frame).await.expect("写入 Link 首帧");
    }

    /// 在超时内读取一段子流数据；超时或关闭返回 `None`。
    pub async fn recv_within(stream: &mut MuxStream, within: Duration) -> Option<Vec<u8>> {
        tokio::time::timeout(within, stream.recv_data())
            .await
            .ok()
            .flatten()
    }

    pub fn test_link(conn_type: &str, host: impl Into<String>) -> Link {
        Link::new(conn_type, host, false, false, "127.0.0.1:12345", false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::test_support::{
        recv_within, session_pair, test_link, write_link,
    };
    use tokio::net::TcpListener;

    const WAIT: Duration = Duration::from_secs(5);

    #[test]
    fn normalize_host_matches_go_format_address() {
        assert_eq!(normalize_host("8080").unwrap(), "127.0.0.1:8080");
        assert_eq!(normalize_host("127.0.0.1:8080").unwrap(), "127.0.0.1:8080");
        assert_eq!(normalize_host("example.com:443").unwrap(), "example.com:443");
    }

    #[test]
    fn normalize_host_rejects_empty_and_whitespace() {
        for host in ["", "  ", "127.0.0.1 :80", "a\nb", "\t"] {
            assert!(matches!(normalize_host(host), Err(TunnelError::BadTarget)), "host={host:?}");
        }
    }

    #[test]
    fn dial_timeout_uses_link_option_and_clamps() {
        let mut link = Link::tcp("127.0.0.1:1", "127.0.0.1:2");
        link.option.timeout = 1_000_000_000;
        assert_eq!(dial_timeout(&link), Duration::from_secs(1));

        link.option.timeout = 0;
        assert_eq!(dial_timeout(&link), DIAL_TIMEOUT_FALLBACK);

        link.option.timeout = i64::MAX;
        assert_eq!(dial_timeout(&link), DIAL_TIMEOUT_MAX);

        link.option.timeout = 1;
        assert_eq!(dial_timeout(&link), Duration::from_millis(100));
    }

    #[test]
    fn find_locates_needle() {
        assert_eq!(find(b"abcdef", b"cd"), Some(2));
        assert_eq!(find(b"abcdef", b"gh"), None);
        assert_eq!(find(b"ab", b""), None);
        assert_eq!(find(b"a", b"ab"), None);
    }

    /// 类型分派：tcp 走既有 TCP 逻辑，双向数据必须一致。
    #[tokio::test]
    async fn dispatch_tcp_relays_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (mut reader, mut writer) = socket.split();
            let _ = tokio::io::copy(&mut reader, &mut writer).await;
        });

        let (server, client) = session_pair().await;
        let mut peer = server.open_stream().await.unwrap();
        let stream = client.accept_stream().await.unwrap();
        let worker = tokio::spawn(handle_stream(stream));

        write_link(&mut peer, &test_link(nps_proto::CONN_TCP, target.to_string())).await;
        peer.send_data(b"hello-tcp").await.unwrap();
        let echoed = recv_within(&mut peer, WAIT).await.expect("应收到回显");
        assert_eq!(echoed, b"hello-tcp");

        drop(peer);
        let _ = tokio::time::timeout(WAIT, worker).await;
    }

    /// 类型分派：udp 子流按数据报转发，往返内容一致。
    #[tokio::test]
    async fn dispatch_udp_relays_datagrams() {
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = echo.local_addr().unwrap();
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
        let worker = tokio::spawn(handle_stream(stream));

        write_link(&mut peer, &test_link(nps_proto::CONN_UDP, target.to_string())).await;

        for payload in [&b"ping-1"[..], &b"ping-2"[..], &b"ping-3"[..]] {
            peer.send_data(payload).await.unwrap();
            let echoed = recv_within(&mut peer, WAIT).await.expect("应收到 UDP 回显");
            assert_eq!(echoed, payload);
        }

        drop(peer);
        let _ = tokio::time::timeout(WAIT, worker).await;
    }

    /// 类型分派：http 子流先透传一个完整请求，再双向拷贝响应。
    #[tokio::test]
    async fn dispatch_http_forwards_request_and_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let seen_target = seen.clone();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut request = Vec::new();
            // 读到请求头结束
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    return;
                }
                request.extend_from_slice(&buf[..n]);
            }
            *seen_target.lock().await = request.clone();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            // 保持连接，让客户端方向的下行拷贝继续
            tokio::time::sleep(Duration::from_secs(2)).await;
        });

        let (server, client) = session_pair().await;
        let mut peer = server.open_stream().await.unwrap();
        let stream = client.accept_stream().await.unwrap();
        let worker = tokio::spawn(handle_stream(stream));

        write_link(&mut peer, &test_link(CONN_HTTP, target.to_string())).await;
        peer.send_data(b"GET /probe HTTP/1.1\r\nHost: probe.test\r\n\r\n")
            .await
            .unwrap();

        let response = recv_within(&mut peer, WAIT).await.expect("应收到响应");
        assert!(response.starts_with(b"HTTP/1.1 200 OK"), "response={response:?}");
        assert!(response.ends_with(b"ok"));

        let request = seen.lock().await.clone();
        assert_eq!(
            String::from_utf8_lossy(&request),
            "GET /probe HTTP/1.1\r\nHost: probe.test\r\n\r\n"
        );

        drop(peer);
        let _ = tokio::time::timeout(WAIT, worker).await;
    }

    /// 不支持的链路类型：关闭子流并返回明确的错误，不 panic。
    #[tokio::test]
    async fn dispatch_unsupported_conn_type_closes_stream() {
        let (server, client) = session_pair().await;
        let mut peer = server.open_stream().await.unwrap();
        let stream = client.accept_stream().await.unwrap();

        let worker = tokio::spawn(handle_stream(stream));
        write_link(&mut peer, &test_link("kcp", "127.0.0.1:1")).await;

        let result = tokio::time::timeout(WAIT, worker).await.expect("应及时结束");
        match result.unwrap() {
            Err(TunnelError::UnsupportedConnType(conn_type)) => assert_eq!(conn_type, "kcp"),
            other => panic!("应返回 UnsupportedConnType，实际 {other:?}"),
        }
        // 子流应被关闭：后续读取返回 None
        assert!(
            tokio::time::timeout(WAIT, peer.recv_data()).await.unwrap().is_none(),
            "不支持的类型必须关闭子流"
        );
    }

    /// 空 Host（目标地址缺失）不应建立任何连接，直接报错并关闭子流。
    #[tokio::test]
    async fn tcp_with_bad_target_closes_stream() {
        let (server, client) = session_pair().await;
        let mut peer = server.open_stream().await.unwrap();
        let stream = client.accept_stream().await.unwrap();
        let worker = tokio::spawn(handle_stream(stream));

        write_link(&mut peer, &test_link(nps_proto::CONN_TCP, "")).await;
        let result = tokio::time::timeout(WAIT, worker).await.unwrap().unwrap();
        assert!(matches!(result, Err(TunnelError::BadTarget)));
        assert!(tokio::time::timeout(WAIT, peer.recv_data()).await.unwrap().is_none());
    }

    /// 空闲追踪：新建时立即 `touch` 则空闲时长接近 0；不 touch 会随时间增长；
    /// 再次 `touch` 必须把空闲时长重置。
    #[test]
    fn idle_tracker_resets_on_touch() {
        let tracker = IdleTracker::new();
        assert!(tracker.idle_for() < Duration::from_secs(1));
        std::thread::sleep(Duration::from_millis(60));
        assert!(tracker.idle_for() >= Duration::from_millis(50));
        tracker.touch();
        assert!(tracker.idle_for() < Duration::from_millis(50));
    }
}
