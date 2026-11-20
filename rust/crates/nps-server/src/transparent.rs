//! `tcpTrans` 模式：透明代理（Transparent Proxy）。
//!
//! # 原版行为
//!
//! `server/proxy/transport.go`（**仅非 Windows**）：
//!
//! ```go
//! const SO_ORIGINAL_DST = 80
//!
//! func getAddress(conn net.Conn) (string, error) {
//!     // 通过 getsockopt(SO_ORIGINAL_DST) 取 iptables REDIRECT 前的原始目标
//!     ...
//! }
//!
//! func HandleTrans(c *conn.Conn, s *TunnelModeServer) error {
//!     addr, _ := getAddress(c.Conn)
//!     return s.DealClient(c, ..., addr, ...)  // 用原始目标地址当隧道目标
//! }
//! ```
//!
//! 也就是说：用户在服务端机器上用 iptables 把流量 REDIRECT 到本程序监听的端口，
//! 程序通过 `SO_ORIGINAL_DST` 反查「用户本来想连哪里」，再把这个地址交给
//! 客户端去拨号——于是客户端所在网络成为出口。
//!
//! `transport_windows.go` 是**空实现**（`return nil`）——Windows 没有
//! `SO_ORIGINAL_DST` 等价物，原版在 Windows 上 tcpTrans 不可用。
//!
//! # 本实现
//!
//! - Linux：用 `getsockopt(fd, SOL_IP, SO_ORIGINAL_DST)` 取原始目标
//! - 其它平台：`original_dst()` 返回 `Unsupported`，调用方据此拒绝并记明确原因
//!
//! **不做**任何 iptables 配置——那是运维职责，程序只消费 REDIRECT 的结果。

use std::net::SocketAddr;

/// 取原始目标地址的结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginalDst {
    /// 拿到了 iptables REDIRECT 前的目标
    Addr(SocketAddr),
    /// 该连接不是被 REDIRECT 来的（直接连到监听端口）
    NotRedirected,
    /// 当前平台不支持（Windows / macOS 等）
    Unsupported,
}

impl OriginalDst {
    pub fn describe(&self) -> String {
        match self {
            Self::Addr(a) => format!("原始目标 {a}"),
            Self::NotRedirected => "连接未经 iptables REDIRECT，无法确定原始目标".to_owned(),
            Self::Unsupported => {
                "当前平台不支持 SO_ORIGINAL_DST（tcpTrans 仅 Linux 可用）".to_owned()
            }
        }
    }
}

/// 当前平台是否支持透明代理
pub const fn supported() -> bool {
    cfg!(target_os = "linux")
}

#[cfg(target_os = "linux")]
mod imp {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::OriginalDst;

    // linux/netfilter_ipv4.h: #define SO_ORIGINAL_DST 80
    const SO_ORIGINAL_DST: libc_int = 80;
    // linux/netfilter_ipv6/ip6_tables.h: #define IP6T_SO_ORIGINAL_DST 80
    const IP6T_SO_ORIGINAL_DST: libc_int = 80;
    const SOL_IP: libc_int = 0;
    const SOL_IPV6: libc_int = 41;

    type libc_int = i32;

    extern "C" {
        fn getsockopt(
            sockfd: libc_int,
            level: libc_int,
            optname: libc_int,
            optval: *mut u8,
            optlen: *mut u32,
        ) -> libc_int;
    }

    /// 从一条已 accept 的 TCP 连接取 iptables REDIRECT 前的原始目标。
    ///
    /// `sock_fd` 是底层 socket 的文件描述符（`TcpStream::as_raw_fd()`）。
    pub fn original_dst_v4(sock_fd: libc_int) -> OriginalDst {
        // struct sockaddr_in: family(2) port(2, big-endian) addr(4) ...
        let mut buf = [0u8; 16];
        let mut len: u32 = buf.len() as u32;
        // SAFETY: buf/len 由本函数独占，getsockopt 只会写入 len 字节
        let rc = unsafe {
            getsockopt(
                sock_fd,
                SOL_IP,
                SO_ORIGINAL_DST,
                buf.as_mut_ptr(),
                &mut len,
            )
        };
        if rc != 0 || len < 8 {
            return OriginalDst::NotRedirected;
        }
        let port = u16::from_be_bytes([buf[2], buf[3]]);
        let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
        if port == 0 || ip.is_unspecified() {
            return OriginalDst::NotRedirected;
        }
        OriginalDst::Addr(SocketAddr::new(IpAddr::V4(ip), port))
    }

    /// IPv6 版本（`struct sockaddr_in6`）
    pub fn original_dst_v6(sock_fd: libc_int) -> OriginalDst {
        let mut buf = [0u8; 28];
        let mut len: u32 = buf.len() as u32;
        // SAFETY: 同上
        let rc = unsafe {
            getsockopt(
                sock_fd,
                SOL_IPV6,
                IP6T_SO_ORIGINAL_DST,
                buf.as_mut_ptr(),
                &mut len,
            )
        };
        if rc != 0 || len < 24 {
            return OriginalDst::NotRedirected;
        }
        let port = u16::from_be_bytes([buf[2], buf[3]]);
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&buf[8..24]);
        let ip = Ipv6Addr::from(octets);
        if port == 0 || ip.is_unspecified() {
            return OriginalDst::NotRedirected;
        }
        OriginalDst::Addr(SocketAddr::new(IpAddr::V6(ip), port))
    }
}

/// 从一条已 accept 的连接取原始目标（平台分发）。
#[cfg(target_os = "linux")]
pub fn original_dst(stream: &std::net::TcpStream) -> OriginalDst {
    use std::os::fd::AsRawFd;

    let fd = stream.as_raw_fd();
    match stream.local_addr() {
        Ok(SocketAddr::V6(_)) => imp::original_dst_v6(fd),
        _ => imp::original_dst_v4(fd),
    }
}

/// 非 Linux：如实返回 Unsupported（原版在 Windows 上也是空实现）。
#[cfg(not(target_os = "linux"))]
pub fn original_dst(_stream: &std::net::TcpStream) -> OriginalDst {
    OriginalDst::Unsupported
}

/// 从一条已 accept 的 **tokio** 连接取原始目标（平台分发）。
///
/// 转发路径拿到的是 `tokio::net::TcpStream`，为了取 fd 不必 `into_std()`
/// 把连接所有权换出去（那会让后续转发拿不回 async 流），这里直接读 fd。
#[cfg(target_os = "linux")]
pub fn original_dst_tokio(stream: &tokio::net::TcpStream) -> OriginalDst {
    use std::os::fd::AsRawFd;

    let fd = stream.as_raw_fd();
    match stream.local_addr() {
        Ok(SocketAddr::V6(_)) => imp::original_dst_v6(fd),
        _ => imp::original_dst_v4(fd),
    }
}

/// 非 Linux：恒为 Unsupported（原版 Windows 同样是空实现）。
#[cfg(not(target_os = "linux"))]
pub fn original_dst_tokio(_stream: &tokio::net::TcpStream) -> OriginalDst {
    OriginalDst::Unsupported
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_support_flag_matches_os() {
        assert_eq!(supported(), cfg!(target_os = "linux"));
    }

    #[test]
    fn describe_messages_are_actionable() {
        let unsupported = OriginalDst::Unsupported.describe();
        assert!(unsupported.contains("Linux"), "应说明只在 Linux 可用: {unsupported}");

        let not_redirected = OriginalDst::NotRedirected.describe();
        assert!(
            not_redirected.contains("REDIRECT"),
            "应提示需要 iptables REDIRECT: {not_redirected}"
        );

        let addr = OriginalDst::Addr("1.2.3.4:80".parse().unwrap()).describe();
        assert!(addr.contains("1.2.3.4:80"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_reports_unsupported() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let _ = listener.accept();
        });
        let client = std::net::TcpStream::connect(addr).unwrap();
        assert_eq!(original_dst(&client), OriginalDst::Unsupported);
        drop(client);
        let _ = handle.join();
    }
}
