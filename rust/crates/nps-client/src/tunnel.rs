//! 单条 mux 子流的处理：读 Link 首帧 → 拨号目标 → 双向对拷。
//!
//! 协议对齐：
//! - 服务端在子流上的首个帧是 `int32 LE 长度 + Link JSON`（无 4 字节 flag），
//!   见 Go `bridge/bridge.go:SendLinkInfo` 与 `lib/conn/conn.go:SendInfo`。
//! - Link 的线上字段名是 Go 导出字段名（`ConnType`/`Host`/`Option.Timeout` …），
//!   由 `nps_proto::Link` 负责解析。
//! - 目标地址格式对齐 Go `common.FormatAddress`：不含 `:` 时按 127.0.0.1:<value> 处理。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nps_legacy::mux::MuxStream;
use nps_proto::Link;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// Link 首帧长度上限。Link 只含地址与选项，64 KiB 已远大于正常值；
/// 与 Go 健康帧上限一致，避免伪造长度导致的大内存分配。
pub const MAX_LINK_FRAME_LEN: usize = 64 * 1024;

/// 两个方向各自使用的读缓冲大小，对齐 Go `common.PoolSizeCopy = 32 KiB`。
const COPY_BUF: usize = 32 * 1024;

/// Link 未给出有效 Timeout 时的拨号超时，对齐 Go `conn.defaultTimeOut = 5s`。
const DIAL_TIMEOUT_FALLBACK: Duration = Duration::from_secs(5);
/// 对端给出的拨号超时上限，避免被伪造 Link 挂住过久。
const DIAL_TIMEOUT_MAX: Duration = Duration::from_secs(60);

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

    if link.conn_type != nps_proto::CONN_TCP {
        warn!(
            conn_type = %link.conn_type,
            host = %link.host,
            "本阶段只支持 tcp 链路，关闭子流"
        );
        stream.close();
        return Err(TunnelError::UnsupportedConnType(link.conn_type));
    }

    let host = normalize_host(&link.host)?;
    let timeout = dial_timeout(&link);
    debug!(target = %host, remote = %link.remote_addr, timeout_ms = timeout.as_millis() as u64, "开始拨号目标");

    let target = match tokio::time::timeout(timeout, TcpStream::connect(&host)).await {
        Ok(Ok(target)) => target,
        Ok(Err(error)) => {
            warn!(target = %host, error = %error, "目标服务不可达，关闭子流");
            stream.close();
            return Err(TunnelError::Dial {
                host,
                error: error.to_string(),
            });
        }
        Err(_) => {
            warn!(target = %host, timeout_ms = timeout.as_millis() as u64, "目标拨号超时，关闭子流");
            stream.close();
            return Err(TunnelError::Dial {
                host,
                error: "拨号超时".to_owned(),
            });
        }
    };
    let _ = target.set_nodelay(true);

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

fn dial_timeout(link: &Link) -> Duration {
    link.option
        .timeout_duration()
        .map(|value| value.clamp(Duration::from_millis(100), DIAL_TIMEOUT_MAX))
        .unwrap_or(DIAL_TIMEOUT_FALLBACK)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}