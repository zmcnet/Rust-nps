//! `ConnType == "udp5"` 子流（SOCKS5 UDP ASSOCIATE）：**明确暂不支持**。
//!
//! ## 为什么不做
//!
//! 按 `D:\Developing\NPS\resources\nps` 逐行核对，原版两端对这个子流的封装**不对称**，
//! 属于未完成实现，照抄必然无法互通：
//!
//! | 方向 | 服务端 `server/proxy/socks5.go:handleUDP` | 客户端 `client/client.go:handleUdp` |
//! | --- | --- | --- |
//! | 客户端 → 服务端 | `binary.Read(target, LE, &l)` 读 **int32 LE 长度**，且要求 `0 < l < PoolSizeUdp(1672)` | `GetLenBytes(...)` 写 **int32 LE 长度 + 数据报** |
//! | 服务端 → 客户端 | `target.Write(b[:n])` 裸写（**无长度前缀**） | `serverConn.Read(b)` 后直接 `ReadUDPDatagram(bytes.NewReader(b[:n]))`，把「本次 Read 的全部剩余字节」当作一个数据报 |
//!
//! 数据报自身的格式（`lib/common/netpackager.go`）是
//! `RSV(2, BE) FRAG(1) ATYP ADDR PORT DATA`，其中 `RSV != 0` 被复用为「数据精确长度」
//! 扩展语义，`RSV == 0` 时退化为「读到流结束」。子流是 TCP/mux 可靠流，
//! 「读到流结束」在长连接上无意义，所以：
//!
//! - 下行没有长度前缀 → 只能靠单次 `Read` 的边界切分，多个数据报粘在一起就解析失败；
//! - 上行被服务端额外限制单帧 < 1672 字节；
//! - `udp5` 的 `Link.Host` 恒为空，目标地址只存在于每一帧的 SOCKS5 头里。
//!
//! 结论：这套流程在原版内部就自相矛盾，客户端无法与之可靠互通。
//! 要真正支持需要先修服务端（不在本次文件域内），因此这里按任务约定
//! **返回「暂不支持」并记日志、关闭子流**，绝不静默丢包或发明新分帧格式
//! （那会让客户端看起来"能用"却与原版互不兼容）。
//!
//! ## 后续实现时需要的东西（备忘）
//!
//! - `int32 LE` 长度前缀（`conn.GetLenBytes`）用于上行分帧；
//! - SOCKS5 头：`ATYP=1` IPv4(4B) / `ATYP=4` IPv6(16B) / `ATYP=3` 域名(1B 长度 + n)，
//!   端口 2 字节大端；
//! - 反向封装需要 `recv_from` 得到的真实源地址；
//! - 需要服务端侧同步修正为「双向都带长度前缀」，否则不可互通。

use nps_legacy::mux::MuxStream;
use nps_proto::Link;
use tracing::warn;

use crate::tunnel::TunnelError;

/// 链路类型字符串（与 Go `server/proxy/socks5.go` 的 `NewLink("udp5", ...)` 一致）。
pub const CONN_UDP5: &str = "udp5";

/// 处理一条 `"udp5"` 子流：记日志 + 关闭，返回 `UnsupportedConnType`。
///
/// 关闭子流（而非直接 drop）是为了让服务端立刻释放 SOCKS5 那条控制连接，
/// 避免客户端侧留下一条永不响应的 UDP ASSOCIATE。
pub async fn handle_stream(mut stream: MuxStream, link: &Link) -> Result<(), TunnelError> {
    warn!(
        conn_type = %link.conn_type,
        remote = %link.remote_addr,
        "udp5（SOCKS5 UDP ASSOCIATE）暂不支持：原版两端分帧不对称，关闭子流"
    );
    stream.close();
    Err(TunnelError::UnsupportedConnType(link.conn_type.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::handle_stream as dispatch;
    use crate::tunnel::test_support::{session_pair, test_link, write_link};
    use std::time::Duration;

    const WAIT: Duration = Duration::from_secs(5);

    /// udp5：明确返回 UnsupportedConnType 并关闭子流，不 panic、不泄漏任务。
    #[tokio::test]
    async fn udp5_reports_unsupported_and_closes_stream() {
        let (server, client) = session_pair().await;
        let mut peer = server.open_stream().await.unwrap();
        let stream = client.accept_stream().await.unwrap();
        let worker = tokio::spawn(dispatch(stream));

        write_link(&mut peer, &test_link(CONN_UDP5, "")).await;

        let result = tokio::time::timeout(WAIT, worker)
            .await
            .expect("应及时结束")
            .unwrap();
        match result {
            Err(TunnelError::UnsupportedConnType(conn_type)) => assert_eq!(conn_type, CONN_UDP5),
            other => panic!("应返回 UnsupportedConnType(\"udp5\")，实际 {other:?}"),
        }
        assert!(
            tokio::time::timeout(WAIT, peer.recv_data()).await.unwrap().is_none(),
            "udp5 必须关闭子流"
        );
    }
}
