//! 服务端配置（JSON）
//!
//! 结构是 Web 代理与管理端的固定契约：字段名不做改动，额外字段可以追加。
//!
//! 安全约定：
//! - **所有认证 vkey 必须显式配置**，不接受默认值 / 空值 / `"123"`。
//! - 顶层**不包含** `admin_token`：管理 token 由外部环境变量
//!   `NPS_ADMIN_TOKEN` 交给 Web 层，配置文件与被提交的代码里都不落库。
//!
//! ```json
//! {
//!   "bridge_addr": "127.0.0.1:8024",
//!   "web_addr": "127.0.0.1:8080",
//!   "clients": [{ "id": 1, "name": "home", "vkey": "change-me" }],
//!   "tunnels": [{
//!     "id": 1, "name": "ssh", "client_id": 1,
//!     "listen_addr": "127.0.0.1:6000", "target_addr": "127.0.0.1:22",
//!     "enabled": true
//!   }],
//!   "conf_register": false,
//!   "conf_max_tunnels": 32,
//!   "conf_listen_host": "0.0.0.0"
//! }
//! ```
//!
//! `conf_*` 三个字段是**追加**能力（老 npc 配置文件模式注册），默认关闭/保守：
//! `conf_register=false` 时收到 `conf` 连接会被立即关闭。

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// 默认桥端口（与 Go 版 `bridge_port` 一致）
pub const DEFAULT_BRIDGE_ADDR: &str = "127.0.0.1:8024";
/// 默认 Web 端口（与 Go 版 `web_port` 一致）
pub const DEFAULT_WEB_ADDR: &str = "127.0.0.1:8080";
/// 配置文件模式注册的隧道总数上限（含配置内的静态隧道）
pub const DEFAULT_CONF_MAX_TUNNELS: usize = 32;
/// 配置文件模式注册隧道的默认监听地址（对齐 Go 版 `:port`，即所有网卡）
pub const DEFAULT_CONF_LISTEN_HOST: &str = "0.0.0.0";
/// 注册隧道允许的最小监听端口：拒绝特权端口（<1024）
pub const CONF_MIN_LISTEN_PORT: u16 = 1024;

/// 明令禁止的默认 vkey（Go 版安装向导里的示例值，绝不允许继续使用）
const FORBIDDEN_VKEYS: &[&str] = &["123", "123456", "password", "vkey"];

/// 服务端配置
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    /// 老 npc 接入的桥监听地址，支持 `:0` 由系统分配
    #[serde(default = "default_bridge_addr")]
    pub bridge_addr: String,
    /// Web 管理面监听地址（本 crate 不绑定，由 Web 层使用）
    #[serde(default = "default_web_addr")]
    pub web_addr: String,
    /// 允许接入的客户端
    #[serde(default)]
    pub clients: Vec<ClientConfig>,
    /// TCP 隧道定义
    #[serde(default)]
    pub tunnels: Vec<TcpTunnelConfig>,
    /// 是否接受老 npc 的**配置文件模式**（`conf` 连接）注册隧道。
    ///
    /// 默认 `false`：`conf` 是攻击面（任意客户端可申请监听端口），
    /// 未开启时收到 `conf` 连接会被立即关闭。
    #[serde(default)]
    pub conf_register: bool,
    /// `conf` 注册的隧道总数上限（含配置内的静态隧道），默认 32。
    #[serde(default = "default_conf_max_tunnels")]
    pub conf_max_tunnels: usize,
    /// `conf` 注册隧道的监听 IP（客户端只上报端口号）。
    ///
    /// 默认 [`DEFAULT_CONF_LISTEN_HOST`]（`0.0.0.0`，与 Go 版一致）。
    #[serde(default = "default_conf_listen_host")]
    pub conf_listen_host: String,
}

fn default_bridge_addr() -> String {
    DEFAULT_BRIDGE_ADDR.to_owned()
}

fn default_web_addr() -> String {
    DEFAULT_WEB_ADDR.to_owned()
}

fn default_enabled() -> bool {
    true
}

fn default_conf_max_tunnels() -> usize {
    DEFAULT_CONF_MAX_TUNNELS
}

fn default_conf_listen_host() -> String {
    DEFAULT_CONF_LISTEN_HOST.to_owned()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bridge_addr: default_bridge_addr(),
            web_addr: default_web_addr(),
            clients: Vec::new(),
            tunnels: Vec::new(),
            conf_register: false,
            conf_max_tunnels: default_conf_max_tunnels(),
            conf_listen_host: default_conf_listen_host(),
        }
    }
}

/// 一个客户端（对应 Go 版 `file.Client` 的最小可用字段）
///
/// 注意：`Debug` 是手写的，**不会**打印 vkey —— 避免将来某处
/// `tracing::debug!("{config:?}")` 把认证密钥写进日志。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientConfig {
    pub id: i32,
    pub name: String,
    /// 认证密钥（明文仅存在于服务端配置；桥内部只比较 md5）
    pub vkey: String,
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("vkey", &"<redacted>")
            .finish()
    }
}

/// 一条 TCP 隧道
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpTunnelConfig {
    pub id: u32,
    pub name: String,
    /// 归属客户端
    pub client_id: i32,
    /// 服务端监听地址（外部入口）
    pub listen_addr: String,
    /// 客户端侧拨号目标（如 `127.0.0.1:22`）
    pub target_addr: String,
    /// 是否随 server 启动而监听；默认 true
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

impl ServerConfig {
    /// 校验配置；返回第一个发现的问题。
    ///
    /// 覆盖：地址可解析、客户端 id / vkey 唯一、vkey 非空且非默认值、
    /// 隧道 id 唯一、隧道归属客户端存在、监听地址可解析、目标地址形如 host:port、
    /// 同一监听地址不被多个启用隧道占用。
    pub fn validate(&self) -> Result<()> {
        parse_addr(&self.bridge_addr).with_context(|| {
            format!("bridge_addr 非法: {:?}（应为 host:port）", self.bridge_addr)
        })?;
        parse_addr(&self.web_addr)
            .with_context(|| format!("web_addr 非法: {:?}（应为 host:port）", self.web_addr))?;

        let mut client_ids = HashSet::new();
        let mut vkeys = HashSet::new();
        for c in &self.clients {
            if c.id <= 0 {
                bail!("客户端 id 必须为正数: {}", c.id);
            }
            if c.name.trim().is_empty() {
                bail!("客户端 {} 的 name 不能为空", c.id);
            }
            if !client_ids.insert(c.id) {
                bail!("客户端 id 重复: {}", c.id);
            }
            let vkey = c.vkey.trim();
            if vkey.is_empty() {
                bail!("客户端 {} 未配置 vkey（认证密钥必须显式配置）", c.id);
            }
            if FORBIDDEN_VKEYS.iter().any(|f| vkey.eq_ignore_ascii_case(f)) {
                bail!("客户端 {} 使用了被禁止的默认 vkey，请更换为随机密钥", c.id);
            }
            if !vkeys.insert(vkey.to_owned()) {
                bail!("客户端 {} 的 vkey 与其他客户端重复", c.id);
            }
        }

        let mut tunnel_ids = HashSet::new();
        let mut listen_addrs: HashMap<SocketAddr, u32> = HashMap::new();
        for t in &self.tunnels {
            if !tunnel_ids.insert(t.id) {
                bail!("隧道 id 重复: {}", t.id);
            }
            if !client_ids.contains(&t.client_id) {
                bail!("隧道 {} 引用了不存在的客户端 {}", t.id, t.client_id);
            }
            let listen = parse_addr(&t.listen_addr).with_context(|| {
                format!("隧道 {} 的 listen_addr 非法: {:?}", t.id, t.listen_addr)
            })?;
            if t.target_addr.trim().is_empty() {
                bail!("隧道 {} 未配置 target_addr", t.id);
            }
            validate_host_port(&t.target_addr).with_context(|| {
                format!("隧道 {} 的 target_addr 非法: {:?}", t.id, t.target_addr)
            })?;
            if t.enabled && listen.port() != 0 {
                if let Some(other) = listen_addrs.insert(listen, t.id) {
                    bail!("隧道 {} 与隧道 {} 监听了同一地址 {}", t.id, other, listen);
                }
            }
        }

        // 配置文件模式：只在开启时校验相关参数
        if self.conf_register {
            let host = self.conf_listen_host.trim();
            host.parse::<IpAddr>().with_context(|| {
                format!("conf_listen_host 非法: {host:?}（应为 IP 字面量，如 0.0.0.0）")
            })?;
            if !(1..=4096).contains(&self.conf_max_tunnels) {
                bail!(
                    "conf_max_tunnels 必须在 1..=4096 之间，当前为 {}",
                    self.conf_max_tunnels
                );
            }
        }
        Ok(())
    }

    /// id -> 客户端 的索引
    pub fn client_index(&self) -> HashMap<i32, &ClientConfig> {
        self.clients.iter().map(|c| (c.id, c)).collect()
    }

    /// vkey 的 md5 十六进制 -> client id
    ///
    /// 桥握手只拿到 md5(vkey)，因此鉴权表以 md5 为键，并让明文 vkey
    /// 不进入桥的内部状态（也不会被 `snapshot` 序列化）。
    pub fn verify_table(&self) -> HashMap<String, i32> {
        self.clients
            .iter()
            .map(|c| (nps_legacy::md5_hex(c.vkey.trim()), c.id))
            .collect()
    }
}

/// 解析 `host:port` 为 `SocketAddr`（要求 IP 字面量，避免启动时做 DNS）
pub(crate) fn parse_addr(addr: &str) -> Result<SocketAddr> {
    addr.parse::<SocketAddr>()
        .with_context(|| format!("无法解析地址 {addr:?}"))
}

/// 校验 `host:port` 形式的目标地址（host 允许域名，不做 DNS 解析）
pub(crate) fn validate_host_port(addr: &str) -> Result<()> {
    let addr = addr.trim();
    let (host, port) = addr
        .rsplit_once(':')
        .with_context(|| format!("缺少端口: {addr:?}"))?;
    if host.is_empty() {
        bail!("缺少主机名: {addr:?}");
    }
    let port: u16 = port
        .parse()
        .with_context(|| format!("端口非法: {addr:?}"))?;
    if port == 0 {
        bail!("端口不能为 0: {addr:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(id: i32, vkey: &str) -> ClientConfig {
        ClientConfig {
            id,
            name: format!("c{id}"),
            vkey: vkey.into(),
        }
    }

    fn tunnel(id: u32, client_id: i32, listen: &str) -> TcpTunnelConfig {
        TcpTunnelConfig {
            id,
            name: format!("t{id}"),
            client_id,
            listen_addr: listen.into(),
            target_addr: "127.0.0.1:22".into(),
            enabled: true,
        }
    }

    fn base() -> ServerConfig {
        ServerConfig {
            bridge_addr: "127.0.0.1:0".into(),
            web_addr: "127.0.0.1:0".into(),
            clients: vec![client(1, "s3cret-key")],
            tunnels: vec![tunnel(1, 1, "127.0.0.1:0")],
            conf_register: false,
            conf_max_tunnels: DEFAULT_CONF_MAX_TUNNELS,
            conf_listen_host: DEFAULT_CONF_LISTEN_HOST.into(),
        }
    }

    #[test]
    fn valid_config_passes() {
        base().validate().unwrap();
    }

    #[test]
    fn defaults_applied_on_partial_json() {
        let cfg: ServerConfig = serde_json::from_str(r#"{"clients":[]}"#).unwrap();
        assert_eq!(cfg.bridge_addr, DEFAULT_BRIDGE_ADDR);
        assert_eq!(cfg.web_addr, DEFAULT_WEB_ADDR);
        assert!(cfg.tunnels.is_empty());
        // enabled 默认 true
        let t: TcpTunnelConfig = serde_json::from_str(
            r#"{"id":1,"name":"t","client_id":1,"listen_addr":"127.0.0.1:1","target_addr":"a:2"}"#,
        )
        .unwrap();
        assert!(t.enabled);
    }

    #[test]
    fn duplicate_client_id_rejected() {
        let mut cfg = base();
        cfg.clients.push(client(1, "other-key"));
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("id 重复"), "{err}");
    }

    #[test]
    fn duplicate_vkey_rejected() {
        let mut cfg = base();
        cfg.clients.push(client(2, "s3cret-key"));
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("vkey"), "{err}");
    }

    #[test]
    fn default_vkey_rejected() {
        for bad in ["", "   ", "123"] {
            let mut cfg = base();
            cfg.clients[0].vkey = bad.into();
            assert!(cfg.validate().is_err(), "vkey {bad:?} 应被拒绝");
        }
    }

    #[test]
    fn tunnel_must_reference_known_client() {
        let mut cfg = base();
        cfg.tunnels.push(tunnel(2, 99, "127.0.0.1:1234"));
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("不存在的客户端"), "{err}");
    }

    #[test]
    fn duplicate_listen_addr_rejected_only_when_enabled() {
        let mut cfg = base();
        cfg.tunnels[0].listen_addr = "127.0.0.1:16000".into();
        cfg.tunnels.push(tunnel(2, 1, "127.0.0.1:16000"));
        assert!(cfg.validate().is_err());

        cfg.tunnels[1].enabled = false;
        cfg.validate().unwrap();
    }

    #[test]
    fn bad_addresses_rejected() {
        let mut cfg = base();
        cfg.bridge_addr = "not-an-addr".into();
        assert!(cfg.validate().is_err());

        let mut cfg = base();
        cfg.tunnels[0].listen_addr = "127.0.0.1".into();
        assert!(cfg.validate().is_err());

        let mut cfg = base();
        cfg.tunnels[0].target_addr = "127.0.0.1".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn verify_table_uses_md5_and_never_plaintext() {
        let table = base().verify_table();
        assert_eq!(table.get(&nps_legacy::md5_hex("s3cret-key")), Some(&1));
        assert!(!table.contains_key("s3cret-key"));
    }

    #[test]
    fn config_has_no_admin_token_field() {
        let json = serde_json::to_string(&base()).unwrap();
        assert!(!json.contains("admin_token"));
    }

    /// 配置文件模式默认关闭（攻击面），并给出保守默认值
    #[test]
    fn conf_registration_defaults_are_off() {
        let cfg: ServerConfig = serde_json::from_str(r#"{"clients":[]}"#).unwrap();
        assert!(!cfg.conf_register, "conf 注册必须默认关闭");
        assert_eq!(cfg.conf_max_tunnels, DEFAULT_CONF_MAX_TUNNELS);
        assert_eq!(cfg.conf_listen_host, DEFAULT_CONF_LISTEN_HOST);
        cfg.validate().unwrap();

        // 关闭时不校验 conf_* 参数（即使写错也不影响启动）
        let lenient: ServerConfig = serde_json::from_str(
            r#"{"clients":[],"conf_listen_host":"not-an-ip","conf_max_tunnels":0}"#,
        )
        .unwrap();
        lenient.validate().unwrap();
    }

    #[test]
    fn conf_registration_validates_limits_when_enabled() {
        let mut cfg = base();
        cfg.conf_register = true;
        cfg.conf_listen_host = "not-an-ip".into();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("conf_listen_host"), "{err}");

        let mut cfg = base();
        cfg.conf_register = true;
        cfg.conf_max_tunnels = 0;
        assert!(cfg.validate().is_err());

        let mut cfg = base();
        cfg.conf_register = true;
        cfg.conf_max_tunnels = 4097;
        assert!(cfg.validate().is_err());

        let mut cfg = base();
        cfg.conf_register = true;
        cfg.conf_listen_host = "127.0.0.1".into();
        cfg.validate().unwrap();
    }

    /// 配置结构的 `Debug` 输出不得包含 vkey（防止日志里意外落密钥）。
    #[test]
    fn debug_output_redacts_vkey() {
        let cfg = base();
        let rendered = format!("{cfg:?}");
        assert!(
            !rendered.contains("s3cret-key"),
            "Debug 泄漏了 vkey: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "未打码: {rendered}");

        // 单条记录同样打码
        let one = format!("{:?}", cfg.clients[0]);
        assert!(
            !one.contains("s3cret-key"),
            "ClientConfig Debug 泄漏了 vkey: {one}"
        );
    }
}
