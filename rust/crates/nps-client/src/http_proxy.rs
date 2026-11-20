//! `ConnType == "http"` 子流：解析 HTTP 请求 → 透传目标 → 双向拷贝。
//!
//! 协议对齐 Go `client/client.go:handleChan` 里 `lk.ConnType == "http"` 分支：
//!
//! ```go
//! if targetConn, err := net.DialTimeout(common.CONN_TCP, lk.Host, lk.Option.Timeout); err != nil {
//!     src.Close()
//! } else {
//!     srcConn := conn.GetConn(src, ...)
//!     go func() { common.CopyBuffer(srcConn, targetConn); ... }()   // 响应方向
//!     for {
//!         if r, err := http.ReadRequest(bufio.NewReader(srcConn)); err != nil { break }
//!         r.Write(targetConn)                                       // 请求方向
//!     }
//! }
//! ```
//!
//! 即：请求方向「读一个完整请求 → 写目标」由客户端做（服务端会按 hosts 配置
//! 先把目标地址放进 Link.Host，并已完成 host/header 改写），响应方向是裸拷贝。
//! 这里保持同样的语义，但把「读一个请求」拆成 **头部一次解析 + 体流式透传**，
//! 从而既能逐条记日志，又不需要把整个请求体攒进内存：
//!
//! 1. 拨号 `lk.Host`（TCP，对齐原版 `common.CONN_TCP`）
//! 2. 读一个完整请求头（请求行 + 头，`\r\n\r\n` 结束，上限 [`MAX_HEADER_BYTES`]）
//! 3. 按头部声明流式透传请求体：
//!    - `Transfer-Encoding: chunked` → 按块边界原样透传（含块扩展与尾随头）
//!    - `Content-Length: n` → 原样透传 n 字节
//!    - 都没给 → 视为无体
//! 4. 之后同时进行：目标 → 子流裸拷贝（响应），以及子流 → 目标继续解析后续请求
//!    （HTTP 长连接 / 流水线语义）
//!
//! 与 Go 的差异（均为收紧，不影响互操作）：
//! - 不做任何请求改写（Go 的 `r.Write` 会重排头部；透明透传对目标更友好；
//!   需要改写 header 的场景由服务端 `ChangeHostAndHeader` 完成）
//! - 头部缓冲上限、chunk 行长度上限、子流空闲超时（[`RELAY_IDLE_TIMEOUT`]）；
//! - 解析失败只记日志并关闭子流，不 panic。
//!
//! 单测说明：解析逻辑通过 [`ChunkSource`] 抽象，可以用任意切分粒度的内存数据
//! 驱动，不需要真实网络即可覆盖「跨块增量解析」「chunked」「超限」等路径。

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use nps_legacy::mux::{MuxRecvHalf, MuxSendHalf, MuxStream};
use nps_proto::Link;

use crate::tunnel::{
    dial_tcp, dial_timeout, forward_chunk, normalize_host, read_until, ChunkSource, IdleTracker,
    StreamError, StreamReader, TunnelError, COPY_BUF, MAX_RELAY_BUFFER, RELAY_IDLE_TIMEOUT,
};

/// HTTP 请求头（含请求行）的字节上限，对齐 Go `net/http` 默认的 `MaxHeaderBytes`(1 MiB)。
pub const MAX_HEADER_BYTES: usize = 1024 * 1024;

/// chunk 大小行 / 尾随头单行的长度上限。
pub const MAX_CHUNK_LINE: usize = 8 * 1024;

/// 头部上限不得突破单连接缓冲总上限。
const _: () = assert!(MAX_HEADER_BYTES <= MAX_RELAY_BUFFER);

const HEADER_END: &[u8] = b"\r\n\r\n";

/// 请求体框架方式（由头部声明决定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    /// 头部没有声明体（或声明长度为 0）。
    None,
    /// `Content-Length: n`
    ContentLength(u64),
    /// `Transfer-Encoding: chunked`
    Chunked,
}

/// 已解析的请求头。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    /// 头部原始字节（请求行 + 头 + 结尾 CRLFCRLF），原样透传给目标。
    pub bytes: Vec<u8>,
    /// 请求行原文（不含 CRLF），仅用于日志。
    pub request_line: String,
    /// 方法名。
    pub method: String,
    /// 请求体框架方式。
    pub body: BodyFraming,
}

/// 处理一条 `"http"` 子流。
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
    debug!(target = %host, timeout_ms = timeout.as_millis() as u64, "开始拨号 HTTP 目标");

    let target = match dial_tcp(&host, timeout).await {
        Ok(target) => target,
        Err(error) => {
            stream.close();
            return Err(error);
        }
    };

    let (send, recv) = stream.into_split();
    match relay(send, recv, target).await {
        Ok(()) => {
            debug!(target = %host, "HTTP 子流转发结束");
            Ok(())
        }
        Err(error) => {
            warn!(target = %host, %error, "HTTP 子流转发失败，关闭子流");
            Err(error)
        }
    }
}

/// 请求 / 响应双向转发；任一方向结束或空闲超时即返回。
async fn relay(
    mut send: MuxSendHalf,
    recv: MuxRecvHalf,
    target: TcpStream,
) -> Result<(), TunnelError> {
    let (mut target_reader, mut target_writer) = target.into_split();
    let mut reader = StreamReader::new(recv);
    let tracker = IdleTracker::new();
    tracker.touch();

    // 第一阶段：读并透传首个请求。放在 select 之前，因此单独套空闲超时，
    // 防止对端只发半截请求头时永远挂住任务。
    let first = match tokio::time::timeout(RELAY_IDLE_TIMEOUT, exchange_one(&mut reader, &mut target_writer, &tracker)).await {
        Ok(result) => result?,
        Err(_) => {
            warn!("等待首个 HTTP 请求超时，关闭子流");
            return Err(TunnelError::IdleTimeout);
        }
    };
    debug!(
        method = %first.method,
        request_line = %first.request_line,
        body_bytes = first.body_bytes,
        "已透传首个 HTTP 请求"
    );

    let (rest_recv, pending) = reader.into_parts();
    let up_total = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let down_total = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

    // 上行（响应方向）：目标 -> 子流，裸字节拷贝。
    let up_tracker = tracker.clone();
    let up_counter = up_total.clone();
    let mut up = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; COPY_BUF];
        loop {
            match target_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if !forward_chunk(&mut send, &up_tracker, &up_counter, &buf[..n]).await {
                        break;
                    }
                }
                Err(error) => {
                    debug!(%error, "读取 HTTP 目标失败，结束响应方向");
                    break;
                }
            }
        }
        send.close();
    });

    // 下行（请求方向）：继续解析子流上的后续请求并透传（长连接 / 流水线）。
    let down_tracker = tracker.clone();
    let down_counter = down_total.clone();
    let mut down = tokio::spawn(async move {
        let mut reader = StreamReader::with_pending(rest_recv, pending);
        loop {
            match exchange_one(&mut reader, &mut target_writer, &down_tracker).await {
                Ok(exchange) => {
                    debug!(
                        method = %exchange.method,
                        request_line = %exchange.request_line,
                        body_bytes = exchange.body_bytes,
                        "透传后续 HTTP 请求"
                    );
                    down_counter.fetch_add(exchange.total_bytes, std::sync::atomic::Ordering::Relaxed);
                }
                Err(TunnelError::StreamIo) => break,
                Err(error) => {
                    debug!(%error, "读取后续 HTTP 请求失败，结束请求方向");
                    break;
                }
            }
        }
        let _ = target_writer.shutdown().await;
    });

    let idle_tracker = tracker.clone();
    tokio::select! {
        _ = &mut up => {
            // 响应方向 EOF：等对端把子流关掉再退出（与 TCP 子流一致）。
            // 不能在这里 abort 下行——那两个半边会立即 drop，触发 muxConnClose，
            // 而 mux 的控制帧优先于数据帧发送，可能把刚写出的响应截断。
            // 服务端在浏览器连接结束后会 connClient.Close()，下行随之返回 None。
            let _ = down.await;
        }
        _ = &mut down => {
            up.abort();
            let _ = up.await;
        }
        _ = crate::tunnel::wait_idle_timeout(idle_tracker, RELAY_IDLE_TIMEOUT) => {
            warn!("HTTP 子流空闲超时，关闭子流");
            up.abort();
            down.abort();
            let _ = up.await;
            let _ = down.await;
        }
    }

    debug!(
        up_bytes = up_total.load(std::sync::atomic::Ordering::Relaxed),
        down_bytes = down_total.load(std::sync::atomic::Ordering::Relaxed),
        "HTTP 子流双向转发结束"
    );
    Ok(())
}

/// 一次请求交换：读请求（头 + 体）并原样写入目标。
struct Exchange {
    method: String,
    request_line: String,
    body_bytes: u64,
    total_bytes: u64,
}

async fn exchange_one<S, W>(
    reader: &mut S,
    writer: &mut W,
    tracker: &IdleTracker,
) -> Result<Exchange, TunnelError>
where
    S: ChunkSource,
    W: AsyncWrite + Unpin,
{
    let head = read_request_head(reader).await?;
    tracker.touch();
    writer
        .write_all(&head.bytes)
        .await
        .map_err(|error| TunnelError::TargetWrite(error.to_string()))?;
    let body_bytes = copy_body(reader, head.body, writer, tracker).await?;
    Ok(Exchange {
        method: head.method,
        request_line: head.request_line,
        body_bytes,
        total_bytes: head.bytes.len() as u64 + body_bytes,
    })
}

/// 从子流读取并解析一个完整的 HTTP 请求头。
pub(crate) async fn read_request_head<S: ChunkSource>(source: &mut S) -> Result<RequestHead, TunnelError> {
    let bytes = read_until(source, HEADER_END, MAX_HEADER_BYTES)
        .await
        .map_err(map_stream_error)?;

    // 头部只允许 ASCII（RFC 9110 限制）；非 ASCII 视为非法请求，
    // 但单个字节 < 0x80 的合法性已足够，这里不做逐字节校验，只要求可解析。
    let text = String::from_utf8_lossy(&bytes);
    let request_line = text
        .split("\r\n")
        .next()
        .unwrap_or_default()
        .trim_end_matches('\r')
        .to_owned();
    let method = parse_request_line(&request_line)?;
    let body = body_framing(&text)?;

    Ok(RequestHead {
        bytes,
        request_line,
        method,
        body,
    })
}

/// 解析请求行，返回方法名（对齐 Go `http.ReadRequest` 的最小校验）。
fn parse_request_line(line: &str) -> Result<String, TunnelError> {
    let mut parts = line.split(' ');
    let method = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| TunnelError::Protocol("HTTP 请求行缺少方法".to_owned()))?;
    if !method.bytes().all(|byte| byte.is_ascii_uppercase() || byte == b'-') {
        return Err(TunnelError::Protocol(format!("HTTP 方法非法: {method}")));
    }
    let target = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| TunnelError::Protocol("HTTP 请求行缺少请求目标".to_owned()))?;
    let _ = target;
    if let Some(version) = parts.next() {
        if !version.starts_with("HTTP/") {
            return Err(TunnelError::Protocol(format!("HTTP 版本非法: {version}")));
        }
    }
    Ok(method.to_owned())
}

/// 依据头部判定请求体框架方式。
fn body_framing(head_text: &str) -> Result<BodyFraming, TunnelError> {
    let mut content_length: Option<u64> = None;
    let mut chunked = false;
    for line in head_text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(TunnelError::Protocol(format!("HTTP 头非法: {line:?}")));
        };
        if name.is_empty() {
            return Err(TunnelError::Protocol("HTTP 头名称为空".to_owned()));
        }
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            let length: u64 = value
                .parse()
                .map_err(|_| TunnelError::Protocol(format!("Content-Length 非法: {value:?}")))?;
            if let Some(existing) = content_length {
                if existing != length {
                    return Err(TunnelError::Protocol(format!(
                        "Content-Length 冲突: {existing} != {length}"
                    )));
                }
            }
            content_length = Some(length);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            let last = value.rsplit(',').next().unwrap_or_default().trim();
            if !last.eq_ignore_ascii_case("chunked") {
                return Err(TunnelError::Protocol(format!(
                    "不支持的 Transfer-Encoding: {value:?}"
                )));
            }
            chunked = true;
        }
    }

    if chunked {
        return Ok(BodyFraming::Chunked);
    }
    match content_length {
        Some(0) | None => Ok(BodyFraming::None),
        Some(length) => Ok(BodyFraming::ContentLength(length)),
    }
}

/// 按框架方式把请求体原样透传到目标，返回透传的字节数。
async fn copy_body<S, W>(
    source: &mut S,
    framing: BodyFraming,
    writer: &mut W,
    tracker: &IdleTracker,
) -> Result<u64, TunnelError>
where
    S: ChunkSource,
    W: AsyncWrite + Unpin,
{
    match framing {
        BodyFraming::None => Ok(0),
        BodyFraming::ContentLength(length) => {
            let copied = copy_exact(source, writer, length, tracker).await?;
            Ok(copied)
        }
        BodyFraming::Chunked => copy_chunked(source, writer, tracker).await,
    }
}

/// 原样透传恰好 `length` 字节（分块写，不整体缓冲）。
async fn copy_exact<S, W>(
    source: &mut S,
    writer: &mut W,
    length: u64,
    tracker: &IdleTracker,
) -> Result<u64, TunnelError>
where
    S: ChunkSource,
    W: AsyncWrite + Unpin,
{
    let mut remaining = length;
    let mut copied = 0u64;
    while remaining > 0 {
        if source.buffered().is_empty() && !source.fill().await {
            return Err(TunnelError::StreamIo);
        }
        let available = source.buffered().len() as u64;
        if available == 0 {
            continue;
        }
        let take = available.min(remaining) as usize;
        writer
            .write_all(&source.buffered()[..take])
            .await
            .map_err(|error| TunnelError::TargetWrite(error.to_string()))?;
        source.consume(take);
        remaining -= take as u64;
        copied += take as u64;
        tracker.touch();
    }
    Ok(copied)
}

/// 原样透传 chunked 请求体（含块扩展与尾随头），返回 payload 之外的原始字节数。
async fn copy_chunked<S, W>(
    source: &mut S,
    writer: &mut W,
    tracker: &IdleTracker,
) -> Result<u64, TunnelError>
where
    S: ChunkSource,
    W: AsyncWrite + Unpin,
{
    let mut copied = 0u64;
    loop {
        // chunk 头：<hex>[;ext]\r\n
        let line = read_until(source, b"\r\n", MAX_CHUNK_LINE)
            .await
            .map_err(map_stream_error)?;
        tracker.touch();
        writer
            .write_all(&line)
            .await
            .map_err(|error| TunnelError::TargetWrite(error.to_string()))?;
        copied += line.len() as u64;

        let size_text = std::str::from_utf8(&line[..line.len() - 2])
            .map_err(|_| TunnelError::Protocol("chunk 长度不是 ASCII".to_owned()))?;
        let size_text = size_text.split(';').next().unwrap_or_default().trim();
        let size = u64::from_str_radix(size_text, 16)
            .map_err(|_| TunnelError::Protocol(format!("chunk 长度非法: {size_text:?}")))?;

        if size == 0 {
            // 尾随头：若干 "Name: value\r\n"，以空行结束
            loop {
                let line = read_until(source, b"\r\n", MAX_CHUNK_LINE)
                    .await
                    .map_err(map_stream_error)?;
                let empty = line.len() == 2;
                writer
                    .write_all(&line)
                    .await
                    .map_err(|error| TunnelError::TargetWrite(error.to_string()))?;
                copied += line.len() as u64;
                if empty {
                    return Ok(copied);
                }
            }
        }

        copied += copy_exact(source, writer, size, tracker).await?;

        // chunk 数据后的 CRLF 原样透传
        let crlf = read_until(source, b"\r\n", MAX_CHUNK_LINE)
            .await
            .map_err(map_stream_error)?;
        if crlf != b"\r\n" {
            return Err(TunnelError::Protocol("chunk 数据后缺少 CRLF".to_owned()));
        }
        writer
            .write_all(&crlf)
            .await
            .map_err(|error| TunnelError::TargetWrite(error.to_string()))?;
        copied += 2;
        tracker.touch();
    }
}

fn map_stream_error(error: StreamError) -> TunnelError {
    match error {
        StreamError::Closed => TunnelError::StreamIo,
        StreamError::TooLarge => TunnelError::BufferLimit(MAX_HEADER_BYTES),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::test_support::{recv_within, session_pair, test_link, write_link};
    use crate::tunnel::handle_stream;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    const WAIT: Duration = Duration::from_secs(5);

    /// 带固定分块的字节源：每次 `fill` 只让 `step` 字节可见，
    /// 用来验证跨块边界的增量解析。
    struct SteppedSource {
        data: Vec<u8>,
        visible_end: usize,
        pos: usize,
        step: usize,
    }

    impl SteppedSource {
        fn new(data: &[u8], step: usize) -> Self {
            Self {
                data: data.to_vec(),
                visible_end: step.min(data.len()),
                pos: 0,
                step: step.max(1),
            }
        }
    }

    impl ChunkSource for SteppedSource {
        fn buffered(&self) -> &[u8] {
            &self.data[self.pos..self.visible_end.max(self.pos)]
        }

        fn consume(&mut self, n: usize) {
            self.pos = (self.pos + n).min(self.data.len());
        }

        async fn fill(&mut self) -> bool {
            if self.visible_end >= self.data.len() {
                return false;
            }
            self.visible_end = (self.visible_end + self.step).min(self.data.len());
            true
        }
    }

    #[test]
    fn request_line_parsing_accepts_valid_and_rejects_garbage() {
        assert_eq!(parse_request_line("GET / HTTP/1.1").unwrap(), "GET");
        assert_eq!(parse_request_line("POST /x?a=1 HTTP/1.1").unwrap(), "POST");
        assert_eq!(parse_request_line("PRI * HTTP/2.0").unwrap(), "PRI");
        assert!(parse_request_line("").is_err());
        assert!(parse_request_line("GET").is_err());
        assert!(parse_request_line("GET  / HTTP/1.1").is_err());
        assert!(parse_request_line("get / HTTP/1.1").is_err());
        assert!(parse_request_line("GET / SPDY/3").is_err());
    }

    #[test]
    fn body_framing_detects_length_and_chunked() {
        let none = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        assert_eq!(body_framing(none).unwrap(), BodyFraming::None);

        let zero = "POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(body_framing(zero).unwrap(), BodyFraming::None);

        let len = "POST / HTTP/1.1\r\nContent-Length: 42\r\n\r\n";
        assert_eq!(body_framing(len).unwrap(), BodyFraming::ContentLength(42));

        let chunked = "POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
        assert_eq!(body_framing(chunked).unwrap(), BodyFraming::Chunked);

        // chunked 优先于 Content-Length（RFC 9112 §6.3）
        let both = "POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(body_framing(both).unwrap(), BodyFraming::Chunked);

        let bad_len = "POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n";
        assert!(matches!(body_framing(bad_len), Err(TunnelError::Protocol(_))));

        let conflict = "POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n";
        assert!(matches!(body_framing(conflict), Err(TunnelError::Protocol(_))));

        let unsupported = "POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n";
        assert!(matches!(body_framing(unsupported), Err(TunnelError::Protocol(_))));
    }

    /// 请求头跨任意块边界都能解析出来。
    #[tokio::test]
    async fn parses_head_across_arbitrary_chunks() {
        let raw = b"POST /upload HTTP/1.1\r\nHost: a.test\r\nContent-Length: 11\r\n\r\n";
        for step in [1usize, 3, 7, 64, 4096] {
            let mut source = SteppedSource::new(raw, step);
            let head = read_request_head(&mut source).await.unwrap();
            assert_eq!(head.method, "POST", "step={step}");
            assert_eq!(head.bytes, raw, "step={step}: 头部必须原样保留");
            assert_eq!(head.body, BodyFraming::ContentLength(11), "step={step}");
            assert_eq!(head.request_line, "POST /upload HTTP/1.1");
        }
    }

    /// Content-Length 体按任意块边界完整透传，且不多读后续请求的字节。
    #[tokio::test]
    async fn copies_content_length_body_across_chunks() {
        let body = b"hello world".to_vec();
        let mut request = b"POST /u HTTP/1.1\r\nContent-Length: 11\r\n\r\n".to_vec();
        request.extend_from_slice(&body);
        request.extend_from_slice(b"GET /next HTTP/1.1\r\n\r\n");
        let expected_next: &[u8] = b"GET /next HTTP/1.1\r\n\r\n";

        for step in [1usize, 2, 5, 4096] {
            let mut source = SteppedSource::new(&request, step);
            let head = read_request_head(&mut source).await.unwrap();
            let mut out: Vec<u8> = Vec::new();
            let copied = copy_body(&mut source, head.body, &mut out, &IdleTracker::new())
                .await
                .unwrap();
            assert_eq!(copied, body.len() as u64, "step={step}");
            assert_eq!(out, body, "step={step}: 体必须原样透传");

            // 剩余字节属于下一个请求，不能被吞掉（step 很小时需要再 fill 才可见）
            let mut rest = source.buffered().to_vec();
            while rest.len() < expected_next.len() && source.fill().await {
                rest = source.buffered().to_vec();
            }
            assert_eq!(
                rest, expected_next,
                "step={step}: 下一个请求不能被吞掉或篡改"
            );
        }
    }

    /// chunked 体（含块扩展与尾随头）按任意边界完整透传。
    #[tokio::test]
    async fn copies_chunked_body_across_chunks() {
        let body = b"5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: yes\r\n\r\n".to_vec();
        let mut request = b"POST /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        request.extend_from_slice(&body);

        for step in [1usize, 2, 5, 17, 4096] {
            let mut source = SteppedSource::new(&request, step);
            let head = read_request_head(&mut source).await.unwrap();
            let mut out: Vec<u8> = Vec::new();
            let copied = copy_body(&mut source, head.body, &mut out, &IdleTracker::new())
                .await
                .unwrap();
            assert_eq!(copied, body.len() as u64, "step={step}");
            assert_eq!(out, body, "step={step}: chunked 体必须原样透传");
        }
    }

    /// 头部超过上限必须被拒绝（不无限攒内存）。
    #[tokio::test]
    async fn oversize_head_is_rejected() {
        let mut raw = b"GET / HTTP/1.1\r\nHost: a.test\r\nX-Big: ".to_vec();
        raw.extend(std::iter::repeat_n(b'a', MAX_HEADER_BYTES + 16));
        let mut source = SteppedSource::new(&raw, 64 * 1024);
        let result = read_request_head(&mut source).await;
        assert!(matches!(result, Err(TunnelError::BufferLimit(_))), "实际: {result:?}");
    }

    /// 子流在请求中间关闭：返回 StreamIo 而不是 panic。
    #[tokio::test]
    async fn truncated_body_reports_stream_closed() {
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nonly-part".to_vec();
        let mut source = SteppedSource::new(&raw, 8);
        let head = read_request_head(&mut source).await.unwrap();
        let mut out: Vec<u8> = Vec::new();
        let result = copy_body(&mut source, head.body, &mut out, &IdleTracker::new()).await;
        assert!(matches!(result, Err(TunnelError::StreamIo)), "实际: {result:?}");
        assert_eq!(out, b"only-part");
    }

    /// 端到端（真实 mux 会话 + 真实 TCP 目标）：请求与响应都字节一致。
    #[tokio::test]
    async fn relays_request_and_chunked_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let captured = Arc::new(tokio::sync::Mutex::new(Vec::<u8>::new()));
        let captured_target = captured.clone();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 2048];
            let mut request = Vec::new();
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    return;
                }
                request.extend_from_slice(&buf[..n]);
            }
            *captured_target.lock().await = request;
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n3\r\nefg\r\n0\r\n\r\n",
                )
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
        });

        let (server, client) = session_pair().await;
        let mut peer = server.open_stream().await.unwrap();
        let stream = client.accept_stream().await.unwrap();
        let worker = tokio::spawn(handle_stream(stream));

        write_link(&mut peer, &test_link(crate::tunnel::CONN_HTTP, target.to_string())).await;
        peer.send_data(b"PUT /x HTTP/1.1\r\nHost: x.test\r\nContent-Length: 3\r\n\r\nabc")
            .await
            .unwrap();

        let mut response = Vec::new();
        while !response.ends_with(b"0\r\n\r\n") {
            let chunk = recv_within(&mut peer, WAIT).await.expect("应收到响应");
            response.extend_from_slice(&chunk);
        }
        assert_eq!(
            String::from_utf8_lossy(&response),
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n3\r\nefg\r\n0\r\n\r\n"
        );
        assert_eq!(
            String::from_utf8_lossy(&captured.lock().await),
            "PUT /x HTTP/1.1\r\nHost: x.test\r\nContent-Length: 3\r\n\r\nabc"
        );

        drop(peer);
        let _ = tokio::time::timeout(WAIT, worker).await;
    }

    /// 目标拨号失败：返回 Dial 错误并关闭子流。
    #[tokio::test]
    async fn http_dial_failure_closes_stream() {
        let dead = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap()
        };
        let (server, client) = session_pair().await;
        let mut peer = server.open_stream().await.unwrap();
        let stream = client.accept_stream().await.unwrap();
        let worker = tokio::spawn(handle_stream(stream));
        write_link(&mut peer, &test_link(crate::tunnel::CONN_HTTP, dead.to_string())).await;

        let result = tokio::time::timeout(WAIT, worker).await.unwrap().unwrap();
        assert!(matches!(result, Err(TunnelError::Dial { .. })), "实际: {result:?}");
        assert!(tokio::time::timeout(WAIT, peer.recv_data()).await.unwrap().is_none());
    }

    /// 请求行非法：关闭子流并报协议错误。
    #[tokio::test]
    async fn malformed_request_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        });

        let (server, client) = session_pair().await;
        let mut peer = server.open_stream().await.unwrap();
        let stream = client.accept_stream().await.unwrap();
        let worker = tokio::spawn(handle_stream(stream));
        write_link(&mut peer, &test_link(crate::tunnel::CONN_HTTP, target.to_string())).await;
        peer.send_data(b"garbage without request line\r\n\r\n").await.unwrap();

        let result = tokio::time::timeout(WAIT, worker).await.unwrap().unwrap();
        assert!(
            matches!(result, Err(TunnelError::Protocol(_)) | Err(TunnelError::StreamIo)),
            "实际: {result:?}"
        );
        let _ = tokio::time::timeout(WAIT, peer.recv_data()).await;
    }

    /// 同一子流上连续两个请求都要被透传（长连接语义）。
    #[tokio::test]
    async fn pipeline_two_requests_on_one_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count_target = count.clone();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (mut reader, mut writer) = socket.into_split();
            for _ in 0..2 {
                let mut buf = vec![0u8; 1024];
                let mut request = Vec::new();
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = reader.read(&mut buf).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    request.extend_from_slice(&buf[..n]);
                }
                count_target.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                writer.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await.unwrap();
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        });

        let (server, client) = session_pair().await;
        let mut peer = server.open_stream().await.unwrap();
        let stream = client.accept_stream().await.unwrap();
        let worker = tokio::spawn(handle_stream(stream));
        write_link(&mut peer, &test_link(crate::tunnel::CONN_HTTP, target.to_string())).await;

        peer.send_data(b"GET /1 HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
        let mut got = Vec::new();
        while got.len() < 25 {
            got.extend_from_slice(&recv_within(&mut peer, WAIT).await.expect("第一个响应"));
        }
        peer.send_data(b"GET /2 HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
        let mut got2 = Vec::new();
        while got2.len() < 25 {
            got2.extend_from_slice(&recv_within(&mut peer, WAIT).await.expect("第二个响应"));
        }
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);

        drop(peer);
        let _ = tokio::time::timeout(WAIT, worker).await;
    }
}
