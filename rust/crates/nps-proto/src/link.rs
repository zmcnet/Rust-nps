//! 老 nps 协议的 Link（链路信息）结构
//!
//! 对应 Go 源码 `lib/conn/link.go` 的 `Link` / `Options`。
//!
//! Go 侧结构**没有 json tag**，所以线上字段名就是 Go 的导出字段名：
//!
//! ```go
//! type Link struct {
//!     ConnType   string //连接类型
//!     Host       string //目标
//!     Crypt      bool   //加密
//!     Compress   bool
//!     LocalProxy bool
//!     RemoteAddr string
//!     Option     Options
//! }
//!
//! type Options struct {
//!     Timeout time.Duration  // 纳秒 int64
//! }
//! ```
//!
//! Rust 侧字段用 snake_case（符合命名规范），靠 `serde(rename_all = "PascalCase")`
//! 保持线格式与 Go 一致。`Timeout` 是 `time.Duration` 的纳秒整数值。

use serde::{Deserialize, Serialize};

/// 链路选项（老 npc 的 `Options`），`timeout` 为纳秒
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Options {
    /// 超时时间，单位纳秒（Go `time.Duration` 的内部表示）
    ///
    /// 缺省 5s，对齐 Go `defaultTimeOut = time.Second * 5`。
    #[serde(default = "default_timeout_ns")]
    pub timeout: i64,
}

fn default_timeout_ns() -> i64 {
    super::consts::DEFAULT_LINK_TIMEOUT_NS
}

impl Default for Options {
    fn default() -> Self {
        Self {
            timeout: default_timeout_ns(),
        }
    }
}

impl Options {
    /// 以秒为单位取超时（便于直接喂给 tokio）
    pub fn timeout_duration(&self) -> Option<std::time::Duration> {
        if self.timeout > 0 {
            Some(std::time::Duration::from_nanos(self.timeout as u64))
        } else {
            None
        }
    }
}

/// 链路信息，随握手/转发在服务端与客户端间传递
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Link {
    /// 连接类型："tcp" / "udp"（与 `CONN_TCP` / `CONN_UDP` 对应）
    #[serde(default)]
    pub conn_type: String,
    /// 目标地址，如 `"10.0.0.5:3306"`
    #[serde(default)]
    pub host: String,
    /// 是否加密（TLS 包装）
    #[serde(default)]
    pub crypt: bool,
    /// 是否压缩（snappy）
    #[serde(default)]
    pub compress: bool,
    /// 本地代理模式
    #[serde(default)]
    pub local_proxy: bool,
    /// 远端地址（客户端看到的外网连接源地址）
    #[serde(default)]
    pub remote_addr: String,
    /// 选项
    #[serde(default)]
    pub option: Options,
}

impl Link {
    /// 构造一个 tcp 链路（等价 Go `NewLink("tcp", host, false, false, remote, false)`）
    pub fn tcp(host: impl Into<String>, remote_addr: impl Into<String>) -> Self {
        Self {
            conn_type: super::consts::CONN_TCP.to_owned(),
            host: host.into(),
            crypt: false,
            compress: false,
            local_proxy: false,
            remote_addr: remote_addr.into(),
            option: Options::default(),
        }
    }

    /// 按 Go `NewLink(connType, host, crypt, compress, remoteAddr, localProxy)` 构造
    pub fn new(
        conn_type: impl Into<String>,
        host: impl Into<String>,
        crypt: bool,
        compress: bool,
        remote_addr: impl Into<String>,
        local_proxy: bool,
    ) -> Self {
        Self {
            conn_type: conn_type.into(),
            host: host.into(),
            crypt,
            compress,
            local_proxy,
            remote_addr: remote_addr.into(),
            option: Options::default(),
        }
    }

    /// 编码为老 nps 的 JSON（字段名与 Go `json.Marshal` 一致）
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("Link 结构必然可序列化")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::CONN_TCP;

    #[test]
    fn link_json_uses_go_field_names() {
        let l = Link::tcp("10.0.0.5:3306", "1.2.3.4:5678");

        let v = serde_json::to_value(&l).unwrap();
        let obj = v.as_object().unwrap();
        for key in [
            "ConnType",
            "Host",
            "Crypt",
            "Compress",
            "LocalProxy",
            "RemoteAddr",
            "Option",
        ] {
            assert!(obj.contains_key(key), "字段 {key} 缺失（Go 兼容要求）");
        }
        // 不允许出现 snake_case 泄漏
        for bad in ["conn_type", "local_proxy", "remote_addr", "option"] {
            assert!(!obj.contains_key(bad), "字段 {bad} 不应出现在线格式中");
        }
        assert_eq!(l.conn_type, CONN_TCP);
    }

    /// 反序列化真实 Go `json.Marshal` 输出（独立字节样例，非 roundtrip 自证）
    #[test]
    fn decode_go_marshaled_link() {
        // Go: json.Marshal(conn.NewLink("tcp","127.0.0.1:80",false,false,"9.9.9.9:1234",false))
        // time.Duration(5*time.Second) => 5000000000
        let raw = r#"{"ConnType":"tcp","Host":"127.0.0.1:80","Crypt":false,"Compress":false,"LocalProxy":false,"RemoteAddr":"9.9.9.9:1234","Option":{"Timeout":5000000000}}"#;
        let l: Link = serde_json::from_str(raw).unwrap();
        assert_eq!(l.conn_type, "tcp");
        assert_eq!(l.host, "127.0.0.1:80");
        assert_eq!(l.remote_addr, "9.9.9.9:1234");
        assert_eq!(l.option.timeout, 5_000_000_000);
        assert_eq!(
            l.option.timeout_duration(),
            Some(std::time::Duration::from_secs(5))
        );

        // 再序列化回去，字段名与数值必须一致
        let v: serde_json::Value = serde_json::to_value(&l).unwrap();
        assert_eq!(v["Option"]["Timeout"], 5_000_000_000i64);
    }

    #[test]
    fn default_timeout_is_go_five_seconds() {
        let l = Link::tcp("a:1", "b:2");
        assert_eq!(l.option.timeout, 5_000_000_000);
        let v = serde_json::to_value(&l).unwrap();
        assert_eq!(v["Option"]["Timeout"], 5_000_000_000i64);
    }

    #[test]
    fn missing_fields_are_tolerated() {
        // 老版本/精简报文中可能缺字段，反序列化不应失败
        let l: Link = serde_json::from_str(r#"{"ConnType":"tcp","Host":"h:1"}"#).unwrap();
        assert_eq!(l.conn_type, "tcp");
        assert!(!l.crypt);
        assert_eq!(l.option.timeout, 5_000_000_000);
    }
}
