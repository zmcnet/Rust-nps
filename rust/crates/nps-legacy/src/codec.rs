//! 帧编解码：与老 npc 通信的字节级协议
//!
//! 对应 Go 源码 `lib/conn/conn.go`：
//! - `WriteLenContent`: 写入 `int32 LE 长度 + 内容`
//! - `GetShortLenContent`: 读取 `int32 LE 长度`（限 32KB）→ 内容
//! - `ReadFlag`: 读 4 字节字符串
//! - `SendInfo`: 写入 `4 字节 flag + int32 LE 长度 + 内容`
//!
//! 所有二进制均为 **Little Endian**（Go 侧 `binary.LittleEndian`）。

use bytes::BytesMut;
use nps_proto::{Error, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 读取一个 4 字节的 flag 字符串（`ReadFlag`）
///
/// Go: `binary.Read(s, binary.LittleEndian, &buf)` 固定读 4 字节。
pub async fn read_flag<R: AsyncRead + Unpin>(r: &mut R) -> Result<[u8; 4]> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf).await.map_err(|e| match e.kind() {
        std::io::ErrorKind::UnexpectedEof => Error::Closed,
        _ => Error::Io(e),
    })?;
    Ok(buf)
}

/// 长度前缀内容允许分配的上限。
///
/// 这是所有“读长度 → 立刻分配”路径（`read_exact_len`）的硬闸门：
/// 超过它的长度必须在**分配之前**被拒绝。否则一个 `int32::MAX` 的长度字段
/// 就能让服务端直接 `abort`（`BytesMut::zeroed(i32::MAX)` 申请 2GiB），
/// 这是最廉价的一类远程 OOM。
///
/// 取值与协议上限 `nps_proto::MAX_SHORT_LEN`（32 KiB）一致：老 nps 协议里
/// 所有带长度前缀的帧都在这个范围内（健康上报另有 64 KiB 上限，走自己的校验）。
pub const MAX_FRAME_ALLOC: usize = nps_proto::MAX_SHORT_LEN;

/// 读定长字节流（`ReadLen`），Go: `io.ReadFull(s, buf[:cLen])`
///
/// **先校验长度，后分配内存**：`len` 超过 [`MAX_FRAME_ALLOC`] 时直接返回
/// `LengthOutOfBound`，不碰 reader、不分配。这样即使调用方忘了校验，
/// 也不会因为一个伪造的 i32 长度把进程内存打爆。
pub async fn read_exact_len<R: AsyncRead + Unpin>(r: &mut R, len: usize) -> Result<BytesMut> {
    if len > MAX_FRAME_ALLOC {
        return Err(Error::LengthOutOfBound {
            got: len,
            max: MAX_FRAME_ALLOC,
        });
    }
    let mut buf = BytesMut::zeroed(len);
    r.read_exact(&mut buf).await.map_err(|e| match e.kind() {
        std::io::ErrorKind::UnexpectedEof => Error::Closed,
        _ => Error::Io(e),
    })?;
    Ok(buf)
}

/// 读取长度前缀的内容（`GetShortLenContent`）
///
/// Go: `GetLen()` 读 int32 LE → `if l < 0 || l > 32<<10 { err }` → 读内容。
/// 负长度与大长度都必须报错，不能转成巨大 usize 后静默分配。
pub async fn read_short_len_content<R: AsyncRead + Unpin>(r: &mut R) -> Result<BytesMut> {
    let raw = read_len_i32(r).await?;
    if raw < 0 {
        return Err(Error::InvalidLength(raw as usize));
    }
    let len = raw as usize;
    if len > nps_proto::MAX_SHORT_LEN {
        return Err(Error::LengthOutOfBound {
            got: len,
            max: nps_proto::MAX_SHORT_LEN,
        });
    }
    read_exact_len(r, len).await
}

/// 读取一个 int32 LE 长度值（`GetLen`，保留符号用于负长度判断）
pub async fn read_len_i32<R: AsyncRead + Unpin>(r: &mut R) -> Result<i32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b).await.map_err(|e| match e.kind() {
        std::io::ErrorKind::UnexpectedEof => Error::Closed,
        _ => Error::Io(e),
    })?;
    Ok(i32::from_le_bytes(b))
}

/// 读取一个非负长度（负值报错）
pub async fn read_len<R: AsyncRead + Unpin>(r: &mut R) -> Result<usize> {
    let raw = read_len_i32(r).await?;
    if raw < 0 {
        return Err(Error::InvalidLength(raw as usize));
    }
    Ok(raw as usize)
}

/// 写入长度前缀内容（`WriteLenContent`）
///
/// Go: `GetLenBytes(buf)` = `int32 LE len + buf`。
pub async fn write_len_content<W: AsyncWrite + Unpin>(w: &mut W, content: &[u8]) -> Result<()> {
    let len = i32::try_from(content.len()).map_err(|_| Error::InvalidLength(content.len()))?;
    debug_assert!(len >= 0);
    w.write_all(&len.to_le_bytes()).await?;
    w.write_all(content).await?;
    Ok(())
}

/// 写入一条 flag+内容 帧（`SendInfo` 的核心）
///
/// Go: `SendInfo(t, flag)` 组装 `flag(4B) + len(4B) + content`。
/// 注意：Go 侧长度是**内容长度**，不含 flag 自己的 4 字节。
pub async fn write_flag_content<W: AsyncWrite + Unpin>(
    w: &mut W,
    flag: &[u8; 4],
    content: &[u8],
) -> Result<()> {
    w.write_all(flag).await?;
    write_len_content(w, content).await?;
    Ok(())
}

/// 写入一条纯 flag 帧（如 `WORK_MAIN`/`WORK_CHAN`，无内容）
pub async fn write_flag_only<W: AsyncWrite + Unpin>(w: &mut W, flag: &[u8; 4]) -> Result<()> {
    w.write_all(flag).await?;
    Ok(())
}

/// 写入关闭标志（`WriteClose`，Go 写 `RES_CLOSE` = "clse"）
pub async fn write_close<W: AsyncWrite + Unpin>(w: &mut W) -> Result<()> {
    w.write_all(nps_proto::RES_CLOSE.as_bytes()).await?;
    Ok(())
}

/// 解码一个 4 字节 flag 到字符串（去尾 0）
pub fn flag_to_str(b: &[u8; 4]) -> &str {
    // Go 的 ReadFlag 读 4 字节原样转 string；但可控 flag 均为 4 字节精确值。
    // 这里严格按字节序转 UTF-8；若含非 ASCII 则回退空串。
    std::str::from_utf8(b).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn write_len_content_roundtrip() {
        let mut w = Vec::new();
        let content = b"hello nps";
        write_len_content(&mut w, content).await.unwrap();

        // 手动解析: int32 LE = 9
        let n = i32::from_le_bytes([w[0], w[1], w[2], w[3]]) as usize;
        assert_eq!(n, content.len());
        assert_eq!(&w[4..], content);

        // 用 read_short_len_content 正确回读
        let mut cursor = std::io::Cursor::new(&w);
        let got = read_short_len_content(&mut cursor).await.unwrap();
        assert_eq!(&got[..], content);
    }

    #[tokio::test]
    async fn read_len_zero() {
        let mut data: &[u8] = &[0, 0, 0, 0];
        let n = read_len(&mut data).await.unwrap();
        assert_eq!(n, 0);
    }

    /// 独立字节样例：Go `WriteLenContent([]byte("0.26.0"))`
    #[tokio::test]
    async fn go_wire_sample_core_version() {
        // int32 LE 6 + "0.26.0"
        let raw: &[u8] = &[6, 0, 0, 0, b'0', b'.', b'2', b'6', b'.', b'0'];
        let mut cursor = raw;
        let got = read_short_len_content(&mut cursor).await.unwrap();
        assert_eq!(&got[..], b"0.26.0");

        // 反向：我们写出的字节必须与 Go 完全一致
        let mut out = Vec::new();
        write_len_content(&mut out, b"0.26.0").await.unwrap();
        assert_eq!(out, raw);
    }

    /// 负长度必须报错（Go: `if l < 0`），不能当作巨大 usize。
    #[tokio::test]
    async fn negative_length_is_rejected() {
        let raw: &[u8] = &[0xff, 0xff, 0xff, 0xff]; // -1
        let mut cursor = raw;
        let err = read_short_len_content(&mut cursor).await.unwrap_err();
        assert!(matches!(err, Error::InvalidLength(_)), "got {err:?}");

        let mut cursor = raw;
        assert!(read_len(&mut cursor).await.is_err());
    }

    /// 超过 32KiB 的长度必须报错（Go: `l > 32<<10`）。
    #[tokio::test]
    async fn oversize_length_is_rejected() {
        // 32769 = 0x8001
        let raw: &[u8] = &[0x01, 0x80, 0x00, 0x00];
        let mut cursor = raw;
        let err = read_short_len_content(&mut cursor).await.unwrap_err();
        assert!(
            matches!(err, Error::LengthOutOfBound { got: 32769, .. }),
            "got {err:?}"
        );

        // 边界内（32768）应通过长度检查（随后因内容不足而 EOF）
        let raw: &[u8] = &[0x00, 0x80, 0x00, 0x00];
        let mut cursor = raw;
        let err = read_short_len_content(&mut cursor).await.unwrap_err();
        assert!(matches!(err, Error::Closed), "got {err:?}");
    }

    /// 长度声明超过实际数据（半帧 EOF）必须报错，不能返回部分数据。
    #[tokio::test]
    async fn truncated_content_is_eof() {
        let raw: &[u8] = &[5, 0, 0, 0, b'a', b'b'];
        let mut cursor = raw;
        let err = read_short_len_content(&mut cursor).await.unwrap_err();
        assert!(matches!(err, Error::Closed), "got {err:?}");
    }

    /// `read_flag` 只接受完整 4 字节（Go `binary.Read(..., &buf)`）。
    #[tokio::test]
    async fn read_flag_requires_four_bytes() {
        let mut ok: &[u8] = b"main";
        assert_eq!(&read_flag(&mut ok).await.unwrap(), b"main");

        let mut short: &[u8] = b"mai";
        assert!(matches!(
            read_flag(&mut short).await.unwrap_err(),
            Error::Closed
        ));
    }

    #[tokio::test]
    async fn flag_only_frame() {
        let mut w = Vec::new();
        write_flag_only(&mut w, b"main").await.unwrap();
        assert_eq!(w, b"main");
    }

    #[tokio::test]
    async fn flag_content_frame() {
        let mut w = Vec::new();
        let content = serde_json::json!({"a": 1}).to_string();
        write_flag_content(&mut w, b"task", content.as_bytes())
            .await
            .unwrap();
        // 长度：4(flag) + 4(len) + 内容
        assert_eq!(w.len(), 4 + 4 + content.len());
        assert_eq!(&w[0..4], b"task");
        let len = i32::from_le_bytes([w[4], w[5], w[6], w[7]]);
        assert_eq!(len as usize, content.len());
    }

    /// `read_exact_len` 必须在**分配之前**拒绝超限长度：
    /// 用一个空 reader，若先分配再读会退化成 `Closed`；
    /// 只有“先校验”才会直接给出 `LengthOutOfBound`。
    #[tokio::test]
    async fn read_exact_len_rejects_before_allocating() {
        let mut empty: &[u8] = &[];
        let err = read_exact_len(&mut empty, i32::MAX as usize)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                Error::LengthOutOfBound {
                    got,
                    max: MAX_FRAME_ALLOC
                } if got == i32::MAX as usize
            ),
            "got {err:?}"
        );

        // 1 字节都无法读到的 reader，配一个 `MAX_FRAME_ALLOC + 1` 的长度
        let mut empty: &[u8] = &[];
        assert!(matches!(
            read_exact_len(&mut empty, MAX_FRAME_ALLOC + 1)
                .await
                .unwrap_err(),
            Error::LengthOutOfBound { .. }
        ));

        // 上限内仍然正常工作
        let mut data: &[u8] = b"abc";
        let got = read_exact_len(&mut data, 3).await.unwrap();
        assert_eq!(&got[..], b"abc");
    }

    /// `read_short_len_content` 的极端长度（`i32::MAX`）必须被拒，
    /// 且**不消费内容字节**（否则会伪造出“已读到内容”的假象）。
    #[tokio::test]
    async fn read_short_len_content_rejects_extreme_length() {
        // i32::MAX
        let raw: &[u8] = &[0xff, 0xff, 0xff, 0x7f, b'x', b'y'];
        let mut cursor = raw;
        let err = read_short_len_content(&mut cursor).await.unwrap_err();
        assert!(
            matches!(err, Error::LengthOutOfBound { max: 32768, .. }),
            "got {err:?}"
        );
        assert_eq!(cursor.len(), 2, "越界长度不应继续消费内容");

        // i32::MIN（最小负值）
        let raw: &[u8] = &[0x00, 0x00, 0x00, 0x80];
        let mut cursor = raw;
        assert!(matches!(
            read_short_len_content(&mut cursor).await.unwrap_err(),
            Error::InvalidLength(_)
        ));
    }

    /// 纯 flag 帧（如 conn_type）不得被长度前缀逻辑误伤。
    #[tokio::test]
    async fn read_flag_then_content_frames_do_not_desync() {
        let mut buf = Vec::new();
        write_flag_only(&mut buf, b"main").await.unwrap();
        write_len_content(&mut buf, b"payload").await.unwrap();

        let mut cursor: &[u8] = &buf;
        assert_eq!(&read_flag(&mut cursor).await.unwrap(), b"main");
        let content = read_short_len_content(&mut cursor).await.unwrap();
        assert_eq!(&content[..], b"payload");
        assert!(cursor.is_empty(), "所有字节应被恰好消费一次");
    }
}
