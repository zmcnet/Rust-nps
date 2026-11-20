//! 客户端侧握手 —— 与 Go `client/control.go:NewConn` 的字节序列一致。
//!
//! ## 帧序（客户端视角，对齐 `bridge/bridge.go:cliProcess`）
//! ```text
//! ① 写 3 字节        CONN_TEST = "TST"
//! ② 写 len+内容       客户端核心版本 CORE_VERSION = "0.26.0"
//! ③ 写 len+内容       客户端完整版本 FULL_VERSION = "0.26.10"（仅记录）
//! ④ 读 32 字节        md5(CORE_VERSION) 十六进制
//! ⑤ 写 32 字节        md5(vkey) 十六进制（**无 len 前缀**）
//! ⑥ 读 4 字节         "sucs" 成功 / "vkey" 失败
//! ⑦ 写 4 字节         连接类型 flag："main" / "chan"
//! ```
//!
//! 本模块不持有、也不记录 vkey；所有错误信息只包含状态，不回显密钥。

use std::time::Duration;

use nps_proto::CORE_VERSION;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

/// 握手整体超时，对齐 Go 客户端 `connection.SetDeadline(10s)`。
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// 连接类型 flag，与服务端 `common.WORK_*` 常量对应。
pub const FLAG_MAIN: &[u8; 4] = b"main";
pub const FLAG_CHAN: &[u8; 4] = b"chan";
/// 配置文件模式（`WORK_CONFIG`），用于上传客户端信息与隧道。
pub const FLAG_CONF: &[u8; 4] = b"conf";
/// IP 注册模式（`WORK_REGISTER`）。
pub const FLAG_RGST: &[u8; 4] = b"rgst";

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("握手 I/O 失败: {0}")]
    Io(#[from] std::io::Error),
    #[error("握手超时（{0:?}）")]
    Timeout(Duration),
    #[error("对端提前关闭连接")]
    Closed,
    #[error("服务端版本校验串不匹配（客户端核心版本 {0}）")]
    VersionMismatch(&'static str),
    #[error("服务端拒绝了认证密钥")]
    VkeyRejected,
    #[error("服务端返回了非预期的 4 字节状态: {0:?}")]
    BadStatus([u8; 4]),
}

/// 客户端握手，成功后底层连接即可承载协议帧（main 健康帧或 chan mux 帧）。
pub async fn client_handshake<S>(
    stream: &mut S,
    vkey: &str,
    conn_flag: &[u8; 4],
) -> Result<(), HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    client_handshake_with_timeout(stream, vkey, conn_flag, HANDSHAKE_TIMEOUT).await
}

/// 带显式超时的握手（供测试复用）。
pub async fn client_handshake_with_timeout<S>(
    stream: &mut S,
    vkey: &str,
    conn_flag: &[u8; 4],
    timeout: Duration,
) -> Result<(), HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::time::timeout(timeout, handshake_inner(stream, vkey, conn_flag)).await {
        Ok(result) => result,
        Err(_) => Err(HandshakeError::Timeout(timeout)),
    }
}

async fn handshake_inner<S>(
    stream: &mut S,
    vkey: &str,
    conn_flag: &[u8; 4],
) -> Result<(), HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // ① TST
    stream
        .write_all(nps_proto::CONN_TEST.as_bytes())
        .await
        .map_err(map_io)?;

    // ② 核心版本：真实 npc 发送 version.GetVersion() = "0.26.0"
    nps_legacy::codec::write_len_content(stream, CORE_VERSION.as_bytes())
        .await
        .map_err(map_codec)?;

    // ③ 完整版本：真实 npc 发送 VERSION = "0.26.10"，服务端只记录
    nps_legacy::codec::write_len_content(stream, nps_proto::FULL_VERSION.as_bytes())
        .await
        .map_err(map_codec)?;

    // ④ 读服务端 md5(core_version)
    let mut server_digest = [0u8; 32];
    read_exact(stream, &mut server_digest).await?;
    let expected = nps_legacy::md5_hex(CORE_VERSION);
    if server_digest != expected.as_bytes() {
        return Err(HandshakeError::VersionMismatch(CORE_VERSION));
    }

    // ⑤ 写 md5(vkey)，注意没有长度前缀（Go: c.Write([]byte(common.Getverifyval(vkey)))）
    // vkey 只在本函数的栈上参与 md5，不进入日志。
    let vkey_digest = nps_legacy::md5_hex(vkey);
    stream
        .write_all(vkey_digest.as_bytes())
        .await
        .map_err(map_io)?;
    stream.flush().await.map_err(map_io)?;

    // ⑥ 读校验结果
    let mut status = [0u8; 4];
    read_exact(stream, &mut status).await?;
    if &status == nps_proto::VERIFY_EER.as_bytes() {
        return Err(HandshakeError::VkeyRejected);
    }
    if &status != nps_proto::VERIFY_SUCCESS.as_bytes() {
        return Err(HandshakeError::BadStatus(status));
    }

    // ⑦ 声明连接类型
    stream.write_all(conn_flag).await.map_err(map_io)?;
    stream.flush().await.map_err(map_io)?;

    debug!(conn_type = %String::from_utf8_lossy(conn_flag), "握手完成");
    Ok(())
}

async fn read_exact<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut [u8]) -> Result<(), HandshakeError> {
    stream.read_exact(buf).await.map(|_| ()).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            HandshakeError::Closed
        } else {
            HandshakeError::Io(error)
        }
    })
}

fn map_io(error: std::io::Error) -> HandshakeError {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        HandshakeError::Closed
    } else {
        HandshakeError::Io(error)
    }
}

fn map_codec(error: nps_proto::Error) -> HandshakeError {
    match error {
        nps_proto::Error::Io(io) => map_io(io),
        nps_proto::Error::Closed => HandshakeError::Closed,
        other => HandshakeError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            other.to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 模拟服务端 `cliProcess`：按真实字节序读取并回写。
    async fn fake_server(
        mut stream: tokio::io::DuplexStream,
        expected_vkey: &str,
        accept: bool,
    ) -> (Vec<u8>, Vec<u8>, [u8; 4]) {
        let mut tst = [0u8; 3];
        stream.read_exact(&mut tst).await.unwrap();
        assert_eq!(&tst, b"TST");

        let core = nps_legacy::codec::read_short_len_content(&mut stream)
            .await
            .unwrap();
        let full = nps_legacy::codec::read_short_len_content(&mut stream)
            .await
            .unwrap();
        assert_eq!(&core[..], CORE_VERSION.as_bytes());

        stream
            .write_all(nps_legacy::md5_hex(CORE_VERSION).as_bytes())
            .await
            .unwrap();

        let mut vkey_digest = [0u8; 32];
        stream.read_exact(&mut vkey_digest).await.unwrap();
        if accept {
            assert_eq!(&vkey_digest[..], nps_legacy::md5_hex(expected_vkey).as_bytes());
        }

        let status = if accept { b"sucs" } else { b"vkey" };
        stream.write_all(status).await.unwrap();

        let mut flag = [0u8; 4];
        if accept {
            stream.read_exact(&mut flag).await.unwrap();
        }

        (core.to_vec(), full.to_vec(), flag)
    }

    #[tokio::test]
    async fn handshake_success_matches_go_framing() {
        let (mut client, server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(fake_server(server, "secret-key", true));

        client_handshake(&mut client, "secret-key", FLAG_MAIN)
            .await
            .unwrap();

        let (core, full, flag) = server_task.await.unwrap();
        assert_eq!(core, CORE_VERSION.as_bytes());
        assert_eq!(full, nps_proto::FULL_VERSION.as_bytes());
        assert_eq!(&flag, FLAG_MAIN);
    }

    #[tokio::test]
    async fn handshake_chan_flag() {
        let (mut client, server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(fake_server(server, "k", true));

        client_handshake(&mut client, "k", FLAG_CHAN)
            .await
            .unwrap();
        let (_, _, flag) = server_task.await.unwrap();
        assert_eq!(&flag, FLAG_CHAN);
    }

    #[tokio::test]
    async fn handshake_rejects_wrong_vkey_without_echo() {
        let (mut client, server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(fake_server(server, "right-key", false));

        let error = client_handshake(&mut client, "wrong-key", FLAG_MAIN)
            .await
            .unwrap_err();
        assert!(matches!(error, HandshakeError::VkeyRejected));

        let text = format!("{error} {error:?}");
        assert!(!text.contains("wrong-key"), "错误信息泄露了 vkey: {text}");
        assert!(!text.contains(&nps_legacy::md5_hex("wrong-key")));

        let _ = server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_rejects_version_mismatch() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut tst = [0u8; 3];
            server.read_exact(&mut tst).await.unwrap();
            let _ = nps_legacy::codec::read_short_len_content(&mut server).await.unwrap();
            let _ = nps_legacy::codec::read_short_len_content(&mut server).await.unwrap();
            // 故意返回错误版本的摘要
            server
                .write_all(nps_legacy::md5_hex("0.26.10").as_bytes())
                .await
                .unwrap();
        });

        let error = client_handshake(&mut client, "k", FLAG_MAIN)
            .await
            .unwrap_err();
        assert!(matches!(error, HandshakeError::VersionMismatch(_)));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_reports_unexpected_status() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut tst = [0u8; 3];
            server.read_exact(&mut tst).await.unwrap();
            let _ = nps_legacy::codec::read_short_len_content(&mut server).await.unwrap();
            let _ = nps_legacy::codec::read_short_len_content(&mut server).await.unwrap();
            server
                .write_all(nps_legacy::md5_hex(CORE_VERSION).as_bytes())
                .await
                .unwrap();
            let mut digest = [0u8; 32];
            server.read_exact(&mut digest).await.unwrap();
            server.write_all(b"nope").await.unwrap();
        });

        let error = client_handshake(&mut client, "k", FLAG_MAIN)
            .await
            .unwrap_err();
        assert!(matches!(error, HandshakeError::BadStatus(_)));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_times_out_when_server_is_silent() {
        let (mut client, _server) = tokio::io::duplex(4096);
        let error = client_handshake_with_timeout(&mut client, "k", FLAG_MAIN, Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(matches!(error, HandshakeError::Timeout(_)));
    }

    #[tokio::test]
    async fn handshake_truncated_input_is_closed() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut tst = [0u8; 3];
            server.read_exact(&mut tst).await.unwrap();
            drop(server);
        });

        let error = client_handshake(&mut client, "k", FLAG_MAIN)
            .await
            .unwrap_err();
        assert!(matches!(error, HandshakeError::Closed));
        server_task.await.unwrap();
    }
}