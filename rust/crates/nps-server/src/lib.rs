//! Rust-nps 服务端：配置、运行状态与转发服务。
//!
//! 定位：个人 / 小团队自部署，轻内嵌 UI，兼容老 npc（Go 版）。
//! 本 crate 只是库（二进制入口由上层组装，产物名 `rnps`），提供：
//! - [`ServerConfig`]：JSON 配置（不含 admin token；所有 vkey 必须显式配置）
//! - [`Server`]：启动 / 快照 / 单隧道启停 / 关闭
//! - 外部连接 → 老 npc 反向拨号的转发链路：TCP / UDP / HTTP(S) 域名代理 /
//!   SOCKS5 / 文件 / secret / p2p 会合信令 / conf 配置注册
//!
//! # 能力边界
//! 原版 8 个 mode 已全部实现（`tcpTrans` 仅 Linux，与原版一致），逐项证据见
//! `docs/PHASE2-ACCEPTANCE.md`。已知的实现边界：
//! - 限速 / 流量上限 / IP 白名单作用于全部转发路径（TCP / conf 注册 / UDP /
//!   SOCKS5 / HTTP(S) 站点 / file / secret），per-client 一份配额
//! - `SOCKS5` / `UDP` / `HTTP` / `secret` 路径的 Link 帧未携带客户端的
//!   crypt/compress 标志（数据按明文转发；TCP 隧道会带真值）
//! - `FlowCounter`（流量上限计数）不持久化：重启后 `flow_limit` 已用量归零
//! - `conf` 注册支持 `task`（tcp/udp/file）、`host`（站点）与 `stus` 查询；
//!   `rgst` / `p2pm` 未实现
//! - 注册隧道只存内存：重启即失效，不做持久化
//! - `crypt` 是自签 TLS（不做身份认证，身份靠 vkey），`compress` 是 snappy framed
//!
//! # 停用与关闭的连接语义
//! - `set_tunnel_enabled(id, false)`：关闭监听器（端口立即释放），并断开该隧道
//!   当前正在转发的连接。
//! - `shutdown()`：停所有隧道（含 conf 注册的）与桥，断开全部连接，
//!   等待后台任务退出；幂等。

pub mod acme;
mod conf;
pub mod p2p;
pub mod transparent;
pub mod secret;
pub mod crypt;
pub mod file_service;
pub mod flow_store;
pub mod config;
mod http_site;
mod limit;
mod server;
pub mod snapshot;
pub mod socks5;
pub mod tls;
pub mod target;
mod tunnel;
pub mod udp;

pub use config::{
    ClientConfig, HttpRoute, HttpSiteConfig, ServerConfig, Socks5Config, Socks5User,
    TcpTransTunnelConfig, TcpTunnelConfig, TlsMode, UdpTunnelConfig,
};
pub use acme::{
    AcmeClient, AcmeConfig, AcmeError, AcmeErrorKind, AcmeEvent, AcmeEvents, AcmeProvider,
    AcmeService, AcmeSettings, AcmeStage, CertificateRequest, ChallengeKind, ChallengeStore,
    DnsProvider, DnsProviderKind, DnsRecord, Http01Responder, IssuedCertificate, NetworkAudit,
    RenewalPolicy, RenewalTarget, RequestSource, TlsAlpnResponder, CHALLENGE_PATH_PREFIX,
};
pub use http_site::{
    HttpProxyConfig, HttpSite, HttpSiteRouter, HttpSiteServer, ResolvedSite, SiteGuard,
};
pub use server::{ListenerStats, Server};
pub use snapshot::{ClientSnapshot, ServerSnapshot, TunnelSnapshot};
pub use udp::{
    UdpTunnel, DEFAULT_IDLE_TIMEOUT, DEFAULT_MAX_FLOWS, DEFAULT_PER_FLOW_QUEUE, UDP_RECV_BUF,
    UDP_WRITE_CHUNK,
};
pub use tls::{
    generate_self_signed, CertInfo, CertMeta, CertSource, CertificateStore, SniResolver,
    TlsListener, TlsListenerConfig, TlsSession, ALPN_HTTP11, CERT_FILE, DEFAULT_HANDSHAKE_TIMEOUT,
    KEY_FILE, META_FILE,
};
pub use target::{
    HealthCheckConfig, HealthCheckKind, HealthChecker, HealthState, TargetError, TargetPool,
    DEFAULT_HEALTH_INTERVAL, DEFAULT_HEALTH_MAX_FAILED, DEFAULT_HEALTH_TIMEOUT,
};
pub use limit::{ClientControls, FlowCounter, IpAllowList, Throttle, TokenBucket, BYTES_PER_KB};
pub use file_service::{
    target_health_details, FileChannelRegistry, FileTunnel, FileTunnelConfig, TargetHealthDetail,
};
