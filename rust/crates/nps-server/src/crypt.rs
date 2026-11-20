//! 子流包装：加密（crypt）与压缩（compress）。
//!
//! 对齐原版 Go 的 `lib/conn/conn.go:GetConn`：
//!
//! ```go
//! if cpt {
//!     if isServer { return rate.NewRateConn(crypt.NewTlsServerConn(conn), rt) }
//!     return rate.NewRateConn(crypt.NewTlsClientConn(conn), rt)
//! } else if snappy {
//!     return rate.NewRateConn(NewSnappyConn(conn), rt)
//! }
//! return rate.NewRateConn(conn, rt)
//! ```
//!
//! 两个要点（均从源码核实，不是猜）：
//!
//! 1. **crypt 是自签 TLS 包装**（`lib/crypt/tls.go`）：服务端 `tls.Server` 用进程内
//!    生成的自签证书，客户端 `tls.Client` 配 `InsecureSkipVerify: true`。
//!    它提供加密与完整性，**不做身份认证**——身份认证靠 vkey。
//! 2. **compress 是 snappy framed 格式**（`lib/conn/snappy.go` 用
//!    `snappy.NewBufferedWriter` / `snappy.NewReader`），每次 `Write` 后立即 `Flush`。
//!    因此 Rust 侧必须用 `snap::write::FrameEncoder` / `snap::read::FrameDecoder`，
//!    而不是 raw block 编解码。
//!
//! `crypt` 优先于 `compress`：两者同时为 true 时，原版走 `if cpt` 分支，
//! `compress` 被忽略。本模块的 [`StreamWrap::from_flags`] 保持同样语义。

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tracing::debug;

/// 子流包装类型，对应原版 `GetConn` 的三个分支
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamWrap {
    /// 不包装（默认）
    Plain,
    /// 自签 TLS（原版 `crypt=true`）
    Crypt,
    /// snappy framed 压缩（原版 `compress=true`）
    Compress,
}

impl StreamWrap {
    /// 按 Link 的 `crypt` / `compress` 标志决定包装方式。
    ///
    /// **crypt 优先**：与原版 `if cpt { ... } else if snappy { ... }` 一致，
    /// 两者同时为真时忽略 compress。
    pub fn from_flags(crypt: bool, compress: bool) -> Self {
        if crypt {
            Self::Crypt
        } else if compress {
            Self::Compress
        } else {
            Self::Plain
        }
    }

    pub fn is_plain(self) -> bool {
        matches!(self, Self::Plain)
    }
}

// ---------------------------------------------------------------------------
// crypt：自签 TLS 服务端
// ---------------------------------------------------------------------------

/// 服务端 TLS 包装器。
///
/// 证书在**首次构造时**生成一次并复用（与原版 `generateKeyPair` 在包初始化
/// 阶段生成一次的行为一致）。
pub struct CryptServer {
    acceptor: TlsAcceptor,
}

impl CryptServer {
    /// 生成进程内自签证书并构建 acceptor。
    pub fn new() -> Result<Arc<Self>> {
        let (cert_pem, key_pem) = generate_self_signed()?;
        Self::from_pem(&cert_pem, &key_pem)
    }

    /// 用给定 PEM 构建（便于测试或将来支持自定义证书）。
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Arc<Self>> {
        let certs = parse_certs(cert_pem)?;
        let key = parse_key(key_pem)?;

        // 显式指定 provider，不依赖进程级默认值（与 tls.rs 的做法一致，
        // 避免两个模块互相覆盖 rustls 的全局默认）
        let mut config = ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .context("配置 TLS 协议版本失败")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("构建 TLS 服务端配置失败（证书与私钥可能不匹配）")?;
        // 原版客户端不做 ALPN 协商；这里也不宣告任何 ALPN，
        // 避免协商出客户端不认识的协议
        config.alpn_protocols.clear();

        Ok(Arc::new(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
        }))
    }

    /// 在给定流上完成 TLS 服务端握手。
    ///
    /// 握手失败通常意味着对端并未启用 crypt（或版本/套件不兼容）——
    /// 调用方应记录并关闭子流，而不是把它当作数据继续处理。
    pub async fn accept<S>(&self, stream: S) -> Result<tokio_rustls::server::TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let tls = self
            .acceptor
            .accept(stream)
            .await
            .context("crypt: TLS 服务端握手失败")?;
        debug!("crypt: TLS 握手完成");
        Ok(tls)
    }
}

fn generate_self_signed() -> Result<(String, String)> {
    let cert = rcgen::generate_simple_self_signed(vec!["nps-crypt".to_owned()])
        .context("生成自签证书失败")?;
    let key_pem = cert.key_pair.serialize_pem();
    let cert_pem = cert.cert.pem();
    Ok((cert_pem, key_pem))
}

fn parse_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = io::BufReader::new(pem.as_bytes());
    let certs: std::result::Result<Vec<_>, _> =
        rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.context("解析 PEM 证书失败")?;
    if certs.is_empty() {
        anyhow::bail!("PEM 里没有找到任何证书");
    }
    Ok(certs)
}

fn parse_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut reader = io::BufReader::new(pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut reader)
        .context("解析 PEM 私钥失败")?
        .ok_or_else(|| anyhow::anyhow!("PEM 里没有找到私钥"))?;
    Ok(key)
}

/// 便于测试：把 PKCS#8 私钥字节直接包成 `PrivateKeyDer`
#[allow(dead_code)]
fn key_from_pkcs8(der: Vec<u8>) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der))
}

// ---------------------------------------------------------------------------
// compress：snappy framed
// ---------------------------------------------------------------------------

/// 把一条流包装成 snappy framed 压缩流（双向）。
///
/// 由于 Rust 的 `AsyncRead`/`AsyncWrite` 与 snappy 的同步 API 不匹配，
/// 这里提供一个**缓冲式**包装：读侧按需解压整块，写侧每次写一个块。
/// 对 nps 的子流场景（mux 已按 4085 分片）足够。
pub struct SnappyStream<S> {
    inner: S,
    /// 已解压、待交给调用方的数据
    read_buf: Vec<u8>,
    read_pos: usize,
    /// 从底层读到、尚未能完整解压的原始字节（framed 块可能跨多次 read）
    raw_buf: Vec<u8>,
    /// 底层是否已 EOF
    eof: bool,
}

impl<S> SnappyStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_buf: Vec::new(),
            read_pos: 0,
            raw_buf: Vec::new(),
            eof: false,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SnappyStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // 1) 有已解压数据 → 直接给
            if this.read_pos < this.read_buf.len() {
                let n = (this.read_buf.len() - this.read_pos).min(buf.remaining());
                let start = this.read_pos;
                let end = start + n;
                buf.put_slice(&this.read_buf[start..end]);
                this.read_pos = end;
                return Poll::Ready(Ok(()));
            }

            // 2) 尝试从已累积的原始字节里解出完整的 framed 块。
            //    framed 格式每块 = 4 字节头(1 type + 3 len) + payload，
            //    数据块 payload 里还有 4 字节 CRC。这里交给 FrameDecoder，
            //    但**不能** read_to_end（半块会 UnexpectedEof）——逐块解析。
            if !this.raw_buf.is_empty() {
                match decode_one_frame(&this.raw_buf) {
                    Ok(Some((decoded, consumed))) => {
                        this.raw_buf.drain(..consumed);
                        if decoded.is_empty() {
                            // 控制块（如流标识），继续尝试下一块
                            continue;
                        }
                        this.read_buf = decoded;
                        this.read_pos = 0;
                        continue;
                    }
                    Ok(None) => {
                        // 数据不够一个完整块，继续从底层读
                    }
                    Err(e) => {
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e)));
                    }
                }
            }

            // 3) 底层已 EOF 且无剩余可解数据 → 结束
            if this.eof {
                return Poll::Ready(Ok(()));
            }

            // 4) 继续从底层读
            let mut raw = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut raw);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled();
                    if filled.is_empty() {
                        this.eof = true;
                    } else {
                        this.raw_buf.extend_from_slice(filled);
                    }
                }
            }
        }
    }
}

/// 尝试从 `raw` 里解出**一个** snappy framed 块。
///
/// 返回 `Ok(Some((解压后字节, 消耗的原始字节数)))` 表示成功解出一块；
/// `Ok(None)` 表示数据还不足一个完整块；`Err` 表示格式错误。
fn decode_one_frame(raw: &[u8]) -> Result<Option<(Vec<u8>, usize)>, String> {
    if raw.len() < 4 {
        return Ok(None); // 连头都不够
    }
    let chunk_type = raw[0];
    let len = u32::from_le_bytes([raw[1], raw[2], raw[3], 0]) as usize;
    let total = 4 + len;
    if raw.len() < total {
        return Ok(None); // 半块
    }
    let payload = &raw[4..total];

    match chunk_type {
        // 0x00 = 压缩数据块（payload 含 4 字节 CRC）
        // 0x01 = 未压缩数据块（payload 含 4 字节 CRC）
        0x00 | 0x01 => {
            if payload.len() < 4 {
                return Err("snappy 数据块 payload 过短".to_owned());
            }
            let body = &payload[4..]; // 跳过 CRC
            let decoded = if chunk_type == 0x00 {
                snap::raw::Decoder::new()
                    .decompress_vec(body)
                    .map_err(|e| format!("snappy 解压失败: {e}"))?
            } else {
                body.to_vec()
            };
            Ok(Some((decoded, total)))
        }
        // 0xff = 流标识（payload = "sNaPpY"），无数据
        0xff => Ok(Some((Vec::new(), total))),
        // 0x02-0x7f 保留未压缩、0x80-0xfe 保留可压缩；跳过其 payload
        other => Err(format!("不支持的 snappy 块类型 0x{other:02x}")),
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SnappyStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut compressed = Vec::new();
        {
            use std::io::Write as _;
            let mut enc = snap::write::FrameEncoder::new(&mut compressed);
            if let Err(e) = enc.write_all(buf) {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
            }
            if let Err(e) = enc.flush() {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
            }
        }
        match Pin::new(&mut this.inner).poll_write(cx, &compressed) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn flags_prefer_crypt_over_compress() {
        assert_eq!(StreamWrap::from_flags(false, false), StreamWrap::Plain);
        assert_eq!(StreamWrap::from_flags(true, false), StreamWrap::Crypt);
        assert_eq!(StreamWrap::from_flags(false, true), StreamWrap::Compress);
        // 原版是 if cpt { } else if snappy { } —— 两者都为真时 crypt 胜出
        assert_eq!(StreamWrap::from_flags(true, true), StreamWrap::Crypt);
    }

    #[test]
    fn crypt_server_can_be_constructed() {
        let server = CryptServer::new().expect("自签证书应能生成");
        drop(server);
    }

    #[test]
    fn crypt_rejects_mismatched_key() {
        let (cert_pem, _) = generate_self_signed().unwrap();
        let (_, other_key) = generate_self_signed().unwrap();
        let err = match CryptServer::from_pem(&cert_pem, &other_key) {
            Ok(_) => panic!("证书与私钥不匹配时应报错"),
            Err(e) => e,
        };
        assert!(
            format!("{err:#}").contains("证书") || format!("{err:#}").contains("mismatch"),
            "错误信息应说明原因: {err:#}"
        );
    }

    #[tokio::test]
    async fn snappy_roundtrip_preserves_bytes() {
        // 用内存 duplex 验证压缩流能原样还原
        let (client, server) = tokio::io::duplex(64 * 1024);
        let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let expect = payload.clone();

        let writer = tokio::spawn(async move {
            let mut w = SnappyStream::new(server);
            w.write_all(&payload).await.unwrap();
            w.flush().await.unwrap();
            // 关闭写端，让读端看到 EOF
            w.shutdown().await.unwrap();
        });

        let mut r = SnappyStream::new(client);
        let mut got = Vec::new();
        let _ = r.read_to_end(&mut got).await;
        writer.await.unwrap();

        assert_eq!(got.len(), expect.len(), "解压后长度应一致");
        assert_eq!(got, expect, "解压后内容应逐字节一致");
    }
}
