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
/// UDP 来源地址的默认空闲回收时间（秒），对齐 Go 版的 10 分钟读超时
pub const DEFAULT_UDP_IDLE_SECS: u64 = 600;
/// 单条 UDP 隧道允许的最大并发来源数
pub const DEFAULT_UDP_MAX_SESSIONS: usize = 512;

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
    /// UDP 隧道定义（对应 Go 版 `mode=udp`）
    #[serde(default)]
    pub udp_tunnels: Vec<UdpTunnelConfig>,
    /// HTTP 域名站点（对应 Go 版 `Host` + `http_proxy_port`）
    #[serde(default)]
    pub http_sites: Vec<HttpSiteConfig>,
    /// SOCKS5 代理监听（对应 Go 版 `mode=socks5`）
    #[serde(default)]
    pub socks5_listeners: Vec<Socks5Config>,
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
            udp_tunnels: Vec::new(),
            http_sites: Vec::new(),
            socks5_listeners: Vec::new(),
        }
    }
}

/// 一条 UDP 隧道（对应 Go 版 `mode=udp`）
///
/// 服务端在 `listen_addr` 上监听 UDP；每个来源地址 `(ip:port)` 会建立一条
/// 独立的 mux 子流，子流内传原始 UDP 载荷。来源地址空闲超时后回收。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpTunnelConfig {
    pub id: u32,
    pub name: String,
    /// 归属客户端
    pub client_id: i32,
    /// 服务端监听地址（UDP）
    pub listen_addr: String,
    /// 客户端侧拨号目标（如 `8.8.8.8:53`）
    pub target_addr: String,
    /// 是否随 server 启动而监听；默认 true
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 单个来源地址的空闲回收时间（秒）。对齐 Go 版的 10 分钟。
    #[serde(default = "default_udp_idle_secs")]
    pub idle_timeout_secs: u64,
    /// 该隧道允许的最大并发来源数；超出后丢弃新来源的包。
    #[serde(default = "default_udp_max_sessions")]
    pub max_sessions: usize,
}

fn default_udp_idle_secs() -> u64 {
    DEFAULT_UDP_IDLE_SECS
}

fn default_udp_max_sessions() -> usize {
    DEFAULT_UDP_MAX_SESSIONS
}

/// HTTP 站点（对应 Go 版 `Host`）
///
/// 服务端按请求的 `Host` 头选站点，再按路径前缀选目标，
/// 通过 mux 子流把**原始 HTTP 字节**转发给客户端。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpSiteConfig {
    pub id: u32,
    pub name: String,
    /// 归属客户端
    pub client_id: i32,
    /// 域名（不含端口；匹配时大小写不敏感，自动剥离请求里的端口）
    pub domain: String,
    /// 默认目标（`routes` 都不匹配时使用）
    pub target_addr: String,
    /// 路径前缀分流：`/api` → `127.0.0.1:8080`。按最长前缀匹配。
    #[serde(default)]
    pub routes: Vec<HttpRoute>,
    /// 是否允许 WebSocket 升级；默认允许
    #[serde(default = "default_enabled")]
    pub websocket: bool,
    /// 是否随 server 启动而监听；默认 true
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// TLS 模式：`off`（默认）/ `upload` / `self-signed` / `acme`
    ///
    /// **默认 `off`**：程序不会自动申请证书，必须由用户在管理端显式选择。
    #[serde(default)]
    pub tls_mode: TlsMode,
    /// 是否把 HTTP 请求 301 跳到 HTTPS（仅 tls_mode != off 时有意义）
    #[serde(default = "default_enabled")]
    pub force_https: bool,
}

/// 一条路径前缀路由
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRoute {
    /// 路径前缀，必须以 `/` 开头
    pub prefix: String,
    /// 该前缀的目标地址
    pub target_addr: String,
}

/// 站点 TLS 模式。默认 `Off` —— 程序绝不擅自申请证书。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsMode {
    /// 不启用 TLS（纯 HTTP）
    #[default]
    Off,
    /// 使用用户上传的证书文件
    Upload,
    /// 启动时生成自签证书（仅测试）
    SelfSigned,
    /// 由用户显式触发 ACME 申请
    Acme,
}

/// SOCKS5 代理监听配置（对应 Go 版 `mode=socks5`）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Socks5Config {
    pub id: u32,
    pub name: String,
    /// 归属客户端
    pub client_id: i32,
    /// 服务端监听地址
    pub listen_addr: String,
    /// 用户名密码认证；为空则只允许无认证
    #[serde(default)]
    pub users: Vec<Socks5User>,
    /// 是否随 server 启动而监听；默认 true
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

/// SOCKS5 用户名密码（RFC 1929）
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Socks5User {
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for Socks5User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5User")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
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

        self.validate_udp_tunnels(&client_ids)?;
        self.validate_http_sites(&client_ids)?;
        self.validate_socks5(&client_ids)?;
        Ok(())
    }

    /// 校验 UDP 隧道
    fn validate_udp_tunnels(&self, client_ids: &HashSet<i32>) -> Result<()> {
        let mut ids = HashSet::new();
        let mut listen_addrs = HashSet::new();
        for t in &self.udp_tunnels {
            if !ids.insert(t.id) {
                bail!("UDP 隧道 id 重复: {}", t.id);
            }
            if !client_ids.contains(&t.client_id) {
                bail!("UDP 隧道 {} 引用了不存在的客户端 {}", t.id, t.client_id);
            }
            if t.name.trim().is_empty() {
                bail!("UDP 隧道 {} 的 name 不能为空", t.id);
            }
            let listen = parse_addr(&t.listen_addr).with_context(|| {
                format!("UDP 隧道 {} 的 listen_addr 非法: {:?}", t.id, t.listen_addr)
            })?;
            validate_host_port(&t.target_addr).with_context(|| {
                format!("UDP 隧道 {} 的 target_addr 非法: {:?}", t.id, t.target_addr)
            })?;
            if t.idle_timeout_secs == 0 {
                bail!("UDP 隧道 {} 的 idle_timeout_secs 不能为 0", t.id);
            }
            if t.max_sessions == 0 {
                bail!("UDP 隧道 {} 的 max_sessions 不能为 0", t.id);
            }
            if t.enabled && listen.port() != 0 && !listen_addrs.insert(listen) {
                bail!("UDP 隧道 {} 的监听地址 {listen} 与其他 UDP 隧道冲突", t.id);
            }
        }
        Ok(())
    }

    /// 校验 HTTP 站点
    fn validate_http_sites(&self, client_ids: &HashSet<i32>) -> Result<()> {
        let mut ids = HashSet::new();
        let mut domains = HashSet::new();
        for s in &self.http_sites {
            if !ids.insert(s.id) {
                bail!("HTTP 站点 id 重复: {}", s.id);
            }
            if !client_ids.contains(&s.client_id) {
                bail!("HTTP 站点 {} 引用了不存在的客户端 {}", s.id, s.client_id);
            }
            let domain = s.domain.trim();
            if domain.is_empty() {
                bail!("HTTP 站点 {} 的 domain 不能为空", s.id);
            }
            // 域名不允许带端口/协议前缀，避免匹配歧义
            if domain.contains(':') || domain.contains('/') {
                bail!("HTTP 站点 {} 的 domain 不应包含端口或路径: {domain:?}", s.id);
            }
            if !domains.insert(domain.to_ascii_lowercase()) {
                bail!("HTTP 站点 {} 的 domain 与其他站点重复: {domain}", s.id);
            }
            validate_host_port(&s.target_addr).with_context(|| {
                format!("HTTP 站点 {} 的 target_addr 非法: {:?}", s.id, s.target_addr)
            })?;
            let mut prefixes = HashSet::new();
            for r in &s.routes {
                if !r.prefix.starts_with('/') {
                    bail!("HTTP 站点 {} 的路由前缀必须以 / 开头: {:?}", s.id, r.prefix);
                }
                if !prefixes.insert(r.prefix.clone()) {
                    bail!("HTTP 站点 {} 的路由前缀重复: {}", s.id, r.prefix);
                }
                validate_host_port(&r.target_addr).with_context(|| {
                    format!(
                        "HTTP 站点 {} 路由 {} 的 target_addr 非法: {:?}",
                        s.id, r.prefix, r.target_addr
                    )
                })?;
            }
        }
        Ok(())
    }

    /// 校验 SOCKS5 监听
    fn validate_socks5(&self, client_ids: &HashSet<i32>) -> Result<()> {
        let mut ids = HashSet::new();
        let mut listen_addrs = HashSet::new();
        for s in &self.socks5_listeners {
            if !ids.insert(s.id) {
                bail!("SOCKS5 监听 id 重复: {}", s.id);
            }
            if !client_ids.contains(&s.client_id) {
                bail!("SOCKS5 监听 {} 引用了不存在的客户端 {}", s.id, s.client_id);
            }
            let listen = parse_addr(&s.listen_addr).with_context(|| {
                format!("SOCKS5 监听 {} 的 listen_addr 非法: {:?}", s.id, s.listen_addr)
            })?;
            let mut users = HashSet::new();
            for u in &s.users {
                if u.username.is_empty() || u.password.is_empty() {
                    bail!("SOCKS5 监听 {} 存在空用户名或空密码", s.id);
                }
                // RFC 1929：用户名与密码长度上限均为 255
                if u.username.len() > 255 || u.password.len() > 255 {
                    bail!("SOCKS5 监听 {} 的用户名或密码超过 255 字节", s.id);
                }
                if !users.insert(u.username.clone()) {
                    bail!("SOCKS5 监听 {} 的用户名重复: {}", s.id, u.username);
                }
            }
            if s.enabled && listen.port() != 0 && !listen_addrs.insert(listen) {
                bail!("SOCKS5 监听 {} 的地址 {listen} 与其他监听冲突", s.id);
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
            ..Default::default()
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

    // ---- UDP 隧道校验 ----

    fn udp_tunnel(id: u32, client_id: i32, listen: &str, target: &str) -> UdpTunnelConfig {
        UdpTunnelConfig {
            id,
            name: format!("udp{id}"),
            client_id,
            listen_addr: listen.to_owned(),
            target_addr: target.to_owned(),
            enabled: true,
            idle_timeout_secs: DEFAULT_UDP_IDLE_SECS,
            max_sessions: DEFAULT_UDP_MAX_SESSIONS,
        }
    }

    #[test]
    fn udp_tunnel_accepts_valid_config() {
        let mut cfg = base();
        cfg.udp_tunnels = vec![udp_tunnel(1, 1, "127.0.0.1:5353", "8.8.8.8:53")];
        cfg.validate().unwrap();
    }

    #[test]
    fn udp_tunnel_rejects_unknown_client() {
        let mut cfg = base();
        cfg.udp_tunnels = vec![udp_tunnel(1, 99, "127.0.0.1:5353", "8.8.8.8:53")];
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("不存在的客户端"), "{err}");
    }

    #[test]
    fn udp_tunnel_rejects_duplicate_id_and_listen() {
        let mut cfg = base();
        cfg.udp_tunnels = vec![
            udp_tunnel(1, 1, "127.0.0.1:5353", "8.8.8.8:53"),
            udp_tunnel(1, 1, "127.0.0.1:5354", "8.8.8.8:53"),
        ];
        assert!(cfg.validate().unwrap_err().to_string().contains("id 重复"));

        let mut cfg = base();
        cfg.udp_tunnels = vec![
            udp_tunnel(1, 1, "127.0.0.1:5353", "8.8.8.8:53"),
            udp_tunnel(2, 1, "127.0.0.1:5353", "1.1.1.1:53"),
        ];
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("监听地址"));
    }

    #[test]
    fn udp_tunnel_rejects_zero_limits() {
        let mut cfg = base();
        let mut t = udp_tunnel(1, 1, "127.0.0.1:5353", "8.8.8.8:53");
        t.idle_timeout_secs = 0;
        cfg.udp_tunnels = vec![t];
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("idle_timeout_secs"));

        let mut cfg = base();
        let mut t = udp_tunnel(1, 1, "127.0.0.1:5353", "8.8.8.8:53");
        t.max_sessions = 0;
        cfg.udp_tunnels = vec![t];
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("max_sessions"));
    }

    // ---- HTTP 站点校验 ----

    fn http_site(id: u32, domain: &str) -> HttpSiteConfig {
        HttpSiteConfig {
            id,
            name: format!("site{id}"),
            client_id: 1,
            domain: domain.to_owned(),
            target_addr: "127.0.0.1:3000".to_owned(),
            routes: Vec::new(),
            websocket: true,
            enabled: true,
            tls_mode: TlsMode::Off,
            force_https: true,
        }
    }

    #[test]
    fn http_site_accepts_valid_config() {
        let mut cfg = base();
        cfg.http_sites = vec![http_site(1, "app.example.com")];
        cfg.validate().unwrap();
    }

    #[test]
    fn http_site_rejects_domain_with_port_or_path() {
        let mut cfg = base();
        cfg.http_sites = vec![http_site(1, "app.example.com:8080")];
        assert!(cfg.validate().unwrap_err().to_string().contains("端口或路径"));

        let mut cfg = base();
        cfg.http_sites = vec![http_site(1, "app.example.com/api")];
        assert!(cfg.validate().unwrap_err().to_string().contains("端口或路径"));
    }

    #[test]
    fn http_site_rejects_duplicate_domain_case_insensitive() {
        let mut cfg = base();
        cfg.http_sites = vec![http_site(1, "App.Example.com"), http_site(2, "app.example.com")];
        assert!(cfg.validate().unwrap_err().to_string().contains("domain"));
    }

    #[test]
    fn http_site_rejects_bad_route_prefix() {
        let mut cfg = base();
        let mut site = http_site(1, "app.example.com");
        site.routes = vec![HttpRoute {
            prefix: "api".to_owned(), // 缺前导 /
            target_addr: "127.0.0.1:8080".to_owned(),
        }];
        cfg.http_sites = vec![site];
        assert!(cfg.validate().unwrap_err().to_string().contains("以 / 开头"));
    }

    #[test]
    fn http_site_tls_defaults_to_off() {
        // 默认必须是 off —— 程序绝不擅自申请证书
        let site = http_site(1, "a.example.com");
        assert_eq!(site.tls_mode, TlsMode::Off);

        // 反序列化缺省时同样是 off
        let json = r#"{
            "id": 1, "name": "s", "client_id": 1,
            "domain": "a.example.com", "target_addr": "127.0.0.1:80"
        }"#;
        let parsed: HttpSiteConfig = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.tls_mode, TlsMode::Off);
        assert!(parsed.force_https);
        assert!(parsed.websocket);
    }

    // ---- SOCKS5 校验 ----

    fn socks5(id: u32) -> Socks5Config {
        Socks5Config {
            id,
            name: format!("s5-{id}"),
            client_id: 1,
            listen_addr: "127.0.0.1:1080".to_owned(),
            users: Vec::new(),
            enabled: true,
        }
    }

    #[test]
    fn socks5_accepts_valid_config() {
        let mut cfg = base();
        cfg.socks5_listeners = vec![socks5(1)];
        cfg.validate().unwrap();
    }

    #[test]
    fn socks5_rejects_empty_credentials() {
        let mut cfg = base();
        let mut s = socks5(1);
        s.users = vec![Socks5User {
            username: "u".to_owned(),
            password: String::new(),
        }];
        cfg.socks5_listeners = vec![s];
        assert!(cfg.validate().unwrap_err().to_string().contains("空密码"));
    }

    #[test]
    fn socks5_rejects_duplicate_username() {
        let mut cfg = base();
        let mut s = socks5(1);
        s.users = vec![
            Socks5User { username: "u".into(), password: "a".into() },
            Socks5User { username: "u".into(), password: "b".into() },
        ];
        cfg.socks5_listeners = vec![s];
        assert!(cfg.validate().unwrap_err().to_string().contains("用户名重复"));
    }

    #[test]
    fn socks5_password_is_redacted_in_debug() {
        let user = Socks5User {
            username: "alice".to_owned(),
            password: "top-secret-pw".to_owned(),
        };
        let rendered = format!("{user:?}");
        assert!(!rendered.contains("top-secret-pw"), "Debug 泄漏密码: {rendered}");
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn new_sections_default_to_empty() {
        // 旧配置（无新字段）必须仍能反序列化
        let json = r#"{"bridge_addr":"127.0.0.1:8024","web_addr":"127.0.0.1:8080"}"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.udp_tunnels.is_empty());
        assert!(cfg.http_sites.is_empty());
        assert!(cfg.socks5_listeners.is_empty());
        cfg.validate().unwrap();
    }
}
