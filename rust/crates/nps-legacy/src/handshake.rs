//! 握手流程（服务端侧）—— 对齐 Go `bridge/bridge.go:cliProcess`
//!
//! ## 帧序（服务端视角，对齐 `bridge/bridge.go:cliProcess`）
//! ```text
//! ① 读 3 字节        CONN_TEST = "TST"（Go: GetShortContent(3)）
//! ② 读 len+内容       客户端核心版本，须 == GetVersion() = "0.26.0"
//! ③ 读 len+内容       客户端完整版本 VERSION = "0.26.10"（仅记录）
//! ④ 写 32 字节        md5(GetVersion()) 十六进制（无 len 前缀）
//! ⑤ 读 32 字节        md5(VerifyKey) 十六进制（GetShortContent(32)）
//! ⑥ 写 4 字节         "sucs" 成功 / "vkey" 失败
//! ⑦ 读 4 字节         连接类型 flag（"main"/"chan"/"conf"...）
//! ```
//!
//! 注意：`lib/version/version.go` 中 `VERSION = "0.26.10"` 只用于展示，
//! 握手互验用的是 `GetVersion()` 返回的 **"0.26.0"**；
//! vkey 校验值为 `common.Getverifyval(vkey) = md5(vkey)` 的小写 hex。

use md5::{Digest, Md5};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

/// 握手成功后的结果
#[derive(Debug, Clone)]
pub struct HandshakeResult {
    /// 客户端 ID（由 verify 回调给出）
    pub client_id: i32,
    /// 客户端上报的完整版本
    pub client_version: String,
    /// 连接类型 flag（4 字节，`WORK_MAIN`/`WORK_CHAN` 等）
    pub conn_type: [u8; 4],
}

/// 握手错误
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("对端关闭")]
    Closed,
    #[error("探测字节不是 TST")]
    BadTestFlag,
    #[error("客户端核心版本不匹配: got={got}, expect={expect}")]
    VersionMismatch { got: String, expect: &'static str },
    #[error("客户端完整版本长度非法: {0}")]
    BadVersionLength(usize),
    #[error("vkey 校验失败")]
    VerifyFailed,
    #[error("vkey md5 非合法 hex: {0}")]
    BadVkeyHex(String),
}

impl From<nps_proto::Error> for HandshakeError {
    fn from(e: nps_proto::Error) -> Self {
        match e {
            nps_proto::Error::Io(io) => HandshakeError::Io(io),
            nps_proto::Error::Closed => HandshakeError::Closed,
            other => HandshakeError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                other.to_string(),
            )),
        }
    }
}

/// 计算 Go `crypt.Md5` 相同的结果（小写 hex）
pub fn md5_hex(s: &str) -> String {
    let mut h = Md5::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

/// 服务端侧握手。
///
/// `verify` 回调接收客户端传来的 `md5(vkey)` 十六进制，
/// 返回对应的 client id（`None` = 拒绝）。
pub async fn server_handshake<S, F>(
    stream: &mut S,
    verify: F,
) -> Result<HandshakeResult, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: Fn(&str) -> Option<i32>,
{
    // ① 读 TST
    let mut test = [0u8; 3];
    stream.read_exact(&mut test).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            HandshakeError::Closed
        } else {
            HandshakeError::Io(e)
        }
    })?;
    if &test != b"TST" {
        return Err(HandshakeError::BadTestFlag);
    }

    // ② 读核心版本（长度前缀，上限 32KiB，负值报错）
    let core = crate::codec::read_short_len_content(stream).await?;
    if core.as_ref() != nps_proto::CORE_VERSION.as_bytes() {
        let got = String::from_utf8_lossy(&core).into_owned();
        debug!("client core version mismatch: {}", got);
        return Err(HandshakeError::VersionMismatch {
            got,
            expect: nps_proto::CORE_VERSION,
        });
    }

    // ③ 读完整版本（Go 侧发 VERSION = "0.26.10"，仅记录，不参与校验）
    let full = crate::codec::read_short_len_content(stream).await?;
    if full.is_empty() {
        return Err(HandshakeError::BadVersionLength(0));
    }
    let client_version = String::from_utf8_lossy(&full).into_owned();

    // ④ 写 md5(CORE_VERSION)，32 字节无前缀
    let digest = md5_hex(nps_proto::CORE_VERSION);
    stream.write_all(digest.as_bytes()).await?;

    // ⑤ 读 32 字节 md5(vkey)
    let mut vkey_md5 = [0u8; 32];
    stream.read_exact(&mut vkey_md5).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            HandshakeError::Closed
        } else {
            HandshakeError::Io(e)
        }
    })?;
    let vkey_hex = std::str::from_utf8(&vkey_md5)
        .map_err(|_| HandshakeError::BadVkeyHex("<非UTF8>".into()))?;

    // ⑥ 验证
    let client_id = match verify(vkey_hex) {
        Some(id) => {
            stream
                .write_all(nps_proto::VERIFY_SUCCESS.as_bytes())
                .await?;
            debug!("client verified: id={}", id);
            id
        }
        None => {
            stream.write_all(nps_proto::VERIFY_EER.as_bytes()).await?;
            return Err(HandshakeError::VerifyFailed);
        }
    };

    // ⑦ 读连接类型 flag
    let conn_type = crate::codec::read_flag(stream).await?;

    Ok(HandshakeResult {
        client_id,
        client_version,
        conn_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 用一个内存 duplex 模拟完整握手：服务端跑 server_handshake，
    /// 测试侧扮演真实老 npc 的字节序列。
    #[tokio::test]
    async fn handshake_success() {
        let (mut server, mut client) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            // verify：md5("vkey123") -> client id 7
            let result = server_handshake(&mut server, |h| {
                if h == md5_hex("vkey123") {
                    Some(7)
                } else {
                    None
                }
            })
            .await
            .unwrap();
            result
        });

        // ——— 模拟客户端 ———
        // ① TST
        client.write_all(b"TST").await.unwrap();
        // ② 核心版本
        crate::codec::write_len_content(&mut client, nps_proto::CORE_VERSION.as_bytes())
            .await
            .unwrap();
        // ③ 完整版本（真实 npc 发 VERSION = 0.26.10）
        crate::codec::write_len_content(&mut client, nps_proto::FULL_VERSION.as_bytes())
            .await
            .unwrap();
        // ④ 读服务端的 md5
        let mut digest = [0u8; 32];
        client.read_exact(&mut digest).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&digest).unwrap(),
            md5_hex(nps_proto::CORE_VERSION)
        );
        // ⑤ 发 md5(vkey)
        client
            .write_all(md5_hex("vkey123").as_bytes())
            .await
            .unwrap();
        // ⑥ 读 sucs
        let mut ok = [0u8; 4];
        client.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, nps_proto::VERIFY_SUCCESS.as_bytes());
        // ⑦ 发连接类型 main
        client.write_all(b"main").await.unwrap();

        // ——— 断言服务端结果 ———
        let result = server_task.await.unwrap();
        assert_eq!(result.client_id, 7);
        assert_eq!(result.client_version, nps_proto::FULL_VERSION);
        assert_eq!(&result.conn_type, b"main");
    }

    #[tokio::test]
    async fn handshake_wrong_vkey() {
        let (mut server, mut client) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let r = server_handshake(&mut server, |_| None).await;
            r
        });
        client.write_all(b"TST").await.unwrap();
        crate::codec::write_len_content(&mut client, nps_proto::CORE_VERSION.as_bytes())
            .await
            .unwrap();
        crate::codec::write_len_content(&mut client, nps_proto::FULL_VERSION.as_bytes())
            .await
            .unwrap();
        let mut digest = [0u8; 32];
        client.read_exact(&mut digest).await.unwrap();
        client.write_all(md5_hex("wrong").as_bytes()).await.unwrap();
        let mut res = [0u8; 4];
        client.read_exact(&mut res).await.unwrap();
        assert_eq!(&res, nps_proto::VERIFY_EER.as_bytes());

        let err = server_task.await.unwrap().unwrap_err();
        assert!(matches!(err, HandshakeError::VerifyFailed));
    }

    /// 固定向量（用 `printf <str> | md5sum` 独立算出，非 roundtrip 自证）
    #[test]
    fn md5_known_vectors() {
        assert_eq!(md5_hex("0.26.0"), "89a4f3fc3c89257d6f712de6964bda8e");
        assert_eq!(md5_hex("0.26.10"), "f42608ea2519772960f25e215292668e");
        assert_eq!(md5_hex("vkey123"), "f4c92f944d33d8c361f3410eda059383");
        assert_eq!(md5_hex("testkey"), "221b368d7f5f597867f525971f28ff75");
    }

    /// 核心版本必须是 GetVersion() 的 0.26.0，而不是 VERSION 的 0.26.10。
    #[test]
    fn core_version_matches_go_get_version() {
        assert_eq!(nps_proto::CORE_VERSION, "0.26.0");
        assert_eq!(nps_proto::FULL_VERSION, "0.26.10");
        assert_ne!(nps_proto::CORE_VERSION, nps_proto::FULL_VERSION);
    }

    /// 错误的核心版本（0.26.10，即旧实现误用的值）必须被拒绝。
    #[tokio::test]
    async fn handshake_rejects_wrong_core_version() {
        let (mut server, mut client) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move { server_handshake(&mut server, |_| Some(1)).await });

        client.write_all(b"TST").await.unwrap();
        crate::codec::write_len_content(&mut client, b"0.26.10")
            .await
            .unwrap();
        crate::codec::write_len_content(&mut client, b"0.26.10")
            .await
            .unwrap();

        let err = task.await.unwrap().unwrap_err();
        match err {
            HandshakeError::VersionMismatch { got, expect } => {
                assert_eq!(got, "0.26.10");
                assert_eq!(expect, "0.26.0");
            }
            other => panic!("期望 VersionMismatch，实际 {other:?}"),
        }
    }

    /// 错误的探测字节必须被拒绝。
    #[tokio::test]
    async fn handshake_rejects_bad_test_flag() {
        let (mut server, mut client) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move { server_handshake(&mut server, |_| Some(1)).await });
        client.write_all(b"XXX").await.unwrap();
        let err = task.await.unwrap().unwrap_err();
        assert!(matches!(err, HandshakeError::BadTestFlag), "got {err:?}");
    }

    /// 超长/负长度版本字段必须报错，不能静默分配巨大内存。
    #[tokio::test]
    async fn handshake_rejects_bad_version_length() {
        // 超过 32KiB
        let (mut server, mut client) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move { server_handshake(&mut server, |_| Some(1)).await });
        client.write_all(b"TST").await.unwrap();
        client.write_all(&[0x01, 0x80, 0x00, 0x00]).await.unwrap(); // 32769
        let err = task.await.unwrap().unwrap_err();
        assert!(matches!(err, HandshakeError::Io(_)), "got {err:?}");

        // 负长度
        let (mut server, mut client) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move { server_handshake(&mut server, |_| Some(1)).await });
        client.write_all(b"TST").await.unwrap();
        client.write_all(&[0xff, 0xff, 0xff, 0xff]).await.unwrap();
        let err = task.await.unwrap().unwrap_err();
        assert!(matches!(err, HandshakeError::Io(_)), "got {err:?}");
    }

    /// 半帧 EOF（发完 TST 就断）必须报 Closed，不得当作成功。
    #[tokio::test]
    async fn handshake_truncated_input_is_closed() {
        let (mut server, mut client) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move { server_handshake(&mut server, |_| Some(1)).await });
        client.write_all(b"TST").await.unwrap();
        drop(client);
        let err = task.await.unwrap().unwrap_err();
        assert!(matches!(err, HandshakeError::Closed), "got {err:?}");
    }

    /// 非 UTF-8 的 vkey 摘要必须报错，而不是当成校验失败静默通过。
    #[tokio::test]
    async fn handshake_rejects_non_utf8_vkey() {
        let (mut server, mut client) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move { server_handshake(&mut server, |_| Some(1)).await });

        client.write_all(b"TST").await.unwrap();
        crate::codec::write_len_content(&mut client, nps_proto::CORE_VERSION.as_bytes())
            .await
            .unwrap();
        crate::codec::write_len_content(&mut client, nps_proto::FULL_VERSION.as_bytes())
            .await
            .unwrap();
        let mut digest = [0u8; 32];
        client.read_exact(&mut digest).await.unwrap();
        client.write_all(&[0xffu8; 32]).await.unwrap();

        let err = task.await.unwrap().unwrap_err();
        assert!(matches!(err, HandshakeError::BadVkeyHex(_)), "got {err:?}");
    }

    /// 空版本串必须被拒（Go 侧同样要求非空版本），且不得继续读后面的字节。
    #[tokio::test]
    async fn handshake_rejects_empty_full_version() {
        let (mut server, mut client) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move { server_handshake(&mut server, |_| Some(1)).await });

        client.write_all(b"TST").await.unwrap();
        crate::codec::write_len_content(&mut client, nps_proto::CORE_VERSION.as_bytes())
            .await
            .unwrap();
        // 完整版本长度 = 0
        crate::codec::write_len_content(&mut client, b"").await.unwrap();

        let err = task.await.unwrap().unwrap_err();
        assert!(
            matches!(err, HandshakeError::BadVersionLength(0)),
            "got {err:?}"
        );
    }

    /// 非 UTF-8 的版本内容不得 panic（Go 侧只是 byte 比较）：
    /// 必须走 `from_utf8_lossy` 的容错路径并以 VersionMismatch 结束。
    #[tokio::test]
    async fn handshake_non_utf8_core_version_does_not_panic() {
        let (mut server, mut client) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move { server_handshake(&mut server, |_| Some(1)).await });

        client.write_all(b"TST").await.unwrap();
        let garbage = [0xffu8, 0xfe, 0x80, 0x00];
        crate::codec::write_len_content(&mut client, &garbage)
            .await
            .unwrap();

        let err = task.await.unwrap().unwrap_err();
        match err {
            HandshakeError::VersionMismatch { got, expect } => {
                assert_eq!(expect, "0.26.0");
                // lossy 转换：非法字节被替换成 U+FFFD，不 panic
                assert!(got.contains('\u{FFFD}'), "got {got:?}");
            }
            other => panic!("期望 VersionMismatch，实际 {other:?}"),
        }
    }

    /// 半包：只发 2 字节长度前缀就断开 —— 必须干净地报 Closed，
    /// 不能 panic、不能把残缺长度当成有效长度。
    #[tokio::test]
    async fn handshake_half_length_prefix_then_eof_is_closed() {
        let (mut server, mut client) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move { server_handshake(&mut server, |_| Some(1)).await });

        client.write_all(b"TST").await.unwrap();
        client.write_all(&[6u8, 0u8]).await.unwrap(); // 只发了一半长度
        drop(client);

        let err = task.await.unwrap().unwrap_err();
        assert!(matches!(err, HandshakeError::Closed), "got {err:?}");
    }

    /// 半包：长度声明 6 字节，只发 2 字节内容就断开 —— 同样必须是 Closed。
    #[tokio::test]
    async fn handshake_half_content_then_eof_is_closed() {
        let (mut server, mut client) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move { server_handshake(&mut server, |_| Some(1)).await });

        client.write_all(b"TST").await.unwrap();
        client.write_all(&6i32.to_le_bytes()).await.unwrap();
        client.write_all(b"0.").await.unwrap();
        drop(client);

        let err = task.await.unwrap().unwrap_err();
        assert!(matches!(err, HandshakeError::Closed), "got {err:?}");
    }

    /// 极端长度（`i32::MAX`）必须被拒，且不能因为“按声明长度预分配”而吃内存。
    #[tokio::test]
    async fn handshake_extreme_version_length_is_rejected() {
        let (mut server, mut client) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move { server_handshake(&mut server, |_| Some(1)).await });

        client.write_all(b"TST").await.unwrap();
        client.write_all(&i32::MAX.to_le_bytes()).await.unwrap();

        let err = task.await.unwrap().unwrap_err();
        assert!(matches!(err, HandshakeError::Io(_)), "got {err:?}");
    }

    /// 上限内的最长版本串（32768 = 32KiB）不得 panic/OOM：
    /// 长度检查通过后按内容长度分配，随后因内容不匹配被拒。
    #[tokio::test]
    async fn handshake_max_allowed_version_length_is_bounded() {
        let (mut server, mut client) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(async move { server_handshake(&mut server, |_| Some(1)).await });

        client.write_all(b"TST").await.unwrap();
        client
            .write_all(&(nps_proto::MAX_SHORT_LEN as i32).to_le_bytes())
            .await
            .unwrap();
        let filler = vec![b'A'; nps_proto::MAX_SHORT_LEN];
        client.write_all(&filler).await.unwrap();

        let err = task.await.unwrap().unwrap_err();
        assert!(matches!(err, HandshakeError::VersionMismatch { .. }), "got {err:?}");
    }
}
