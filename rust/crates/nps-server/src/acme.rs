//! ACME 证书申请（RFC 8555）——**只做用户显式触发的事**。
//!
//! # 最重要的一条约束：程序绝不擅自申请证书
//!
//! 这个模块里**没有任何**会在启动、建站、改配置时自动跑起来的 ACME 逻辑：
//! - [`AcmeClient::new`]（以及 [`AcmeService::new`]）只做本地准备：建数据目录、
//!   初始化 [`ChallengeStore`]，**零网络请求**；
//! - 只有 [`AcmeClient::request_certificate`] 会联系 CA，而它必须接收一个
//!   [`CertificateRequest`]；
//! - [`CertificateRequest`] 的每个构造函数都对应一个**明确的人类意图**
//!   （[`CertificateRequest::user`] / [`CertificateRequest::from_config`] /
//!   [`CertificateRequest::renewal`]），字段私有，外部无法凭空捏一个"看起来像
//!   用户同意"的值；
//! - 自动续期只有在 [`RenewalPolicy::enabled`] 为真且上层**显式**调用
//!   [`run_renewal_loop`] 时才会发生；关掉后该函数直接返回，绝不联系 CA。
//!
//! 也就是说，"是否联系 CA"由**类型和调用点**共同保证，而不是靠调用方自律。
//!
//! # 流程与可观测性
//!
//! ```text
//! CertificateRequest
//!   └─ 预检（纯本地，不消耗 CA 配额）
//!        ├─ DNS：域名能否解析？解析到哪？
//!        ├─ 公网 IP：解析结果是否就是用户声明的本机公网 IP？
//!        └─ 端口：验证端口是否可连（http-01 → 80 / tls-alpn-01 → 443）
//!   └─ 账户：account.key / account.json（注册一次，后续复用）
//!   └─ 下单 → 挑战 → 验证 → 签发 → 落盘
//! ```
//!
//! 每一步都会通过 [`AcmeEvents`] 推送 [`AcmeEvent`]，供管理页展示进度；
//! 失败时事件里带 `stage` 与**可操作**的原因。
//!
//! # 挑战支持现状
//!
//! | 挑战 | 状态 |
//! |---|---|
//! | `http-01` | **完整实现**：内置应答服务器 + 可挂到已有 HTTP 层的 [`ChallengeStore`] |
//! | `tls-alpn-01` | **完整实现**：ALPN `acme-tls/1` + 带 acmeIdentifier 的自签证书 |
//! | `dns-01` | 流程与 provider 扩展点已接好；Cloudflare 已实现（**未用真实令牌验证**），
//!               阿里云只返回 [`AcmeErrorKind::Unsupported`]（绝不假装成功） |
//!
//! # 与 `tls.rs` 的关系
//!
//! 本模块**不**碰 TLS 服务、不重启监听器。签发成功后把
//! `fullchain.pem` / `privkey.pem` / `meta.json` 原子写到
//! `<data_dir>/acme/certs/<domain>/`（通配符用 `_wildcard_.` 前缀、`meta.json` 的
//! `source` 为 `acme`），推送 [`AcmeEvent::Deployed`]；随后由 TLS 层加载：
//!
//! ```ignore
//! let store = CertificateStore::open(acme_client.certs_dir())?; // 见 AcmeConfig::certs_dir
//! ```
//!
//! 这套目录 / 文件名与 `tls::CertificateStore` 完全兼容，已在集成测试里用
//! `CertificateStore::open` 实际加载验证过。
//!
//! # 预检为什么不碰 CA
//!
//! 预检只用系统解析器与本地 TCP 连接（[`NetworkAudit`] 只统计发给 CA 的 HTTP
//! 请求，DNS 与端口探测不计入）。所以"域名解析不到本机"这类问题在**下单之前**
//! 就被拒绝，CA 配额不会被消耗 —— 集成测试 `preflight_failure_consumes_no_ca_quota`
//! 断言 `audit().count() == 0`。
//!
//! `manage_http_responder = false`（由上层 HTTP 服务应答）时，本模块无法判断
//! 该端口对外是否可达，因此**跳过**端口预检、也不发 `PortReachable` 事件，
//! 而不是猜一个结果。

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::{Method, Request};
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, Key, LetsEncrypt, NewAccount, NewOrder,
    RetryPolicy,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::RootCertStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::config::{HttpSiteConfig, TlsMode};

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

/// http-01 挑战的回调路径前缀（RFC 8555 §8.3）
pub const CHALLENGE_PATH_PREFIX: &str = "/.well-known/acme-challenge/";
/// ACME 数据目录名（位于 `AcmeConfig::data_dir` 之下）
pub const ACME_DIR: &str = "acme";
/// 账户私钥文件名
pub const ACCOUNT_KEY_FILE: &str = "account.key";
/// 账户凭据文件名（ACME account URL 等）
pub const ACCOUNT_CREDENTIALS_FILE: &str = "account.json";
/// 账户所属 CA 的标记文件（切换 provider 时用来判断凭据能否复用）
pub const ACCOUNT_PROVIDER_FILE: &str = "account.ca";
/// 证书落盘子目录
pub const CERTS_DIR: &str = "certs";
/// 自动续期默认提前量：到期前 30 天
pub const DEFAULT_RENEW_BEFORE_DAYS: u64 = 30;
/// 续期失败退避：1h / 6h / 24h
pub const RENEW_BACKOFF: [Duration; 3] = [
    Duration::from_secs(60 * 60),
    Duration::from_secs(6 * 60 * 60),
    Duration::from_secs(24 * 60 * 60),
];

/// Let's Encrypt / ZeroSSL / 自定义 directory URL
pub const LE_PRODUCTION_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Let's Encrypt 测试环境
pub const LE_STAGING_DIRECTORY: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
/// ZeroSSL
pub const ZEROSSL_DIRECTORY: &str = "https://acme.zerossl.com/v2/DV90";

// ---------------------------------------------------------------------------
// 错误
// ---------------------------------------------------------------------------

/// 出错阶段。事件里的 `stage` 与它是同一套词。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcmeStage {
    /// 参数 / 配置校验
    Config,
    /// 预检（DNS / 端口），此阶段**不会**访问 CA
    Preflight,
    /// 账户注册 / 复用
    Account,
    /// 下单
    Order,
    /// 挑战准备与验证
    Challenge,
    /// 签发 / 下载证书
    Issue,
    /// 落盘
    Deploy,
}

impl AcmeStage {
    /// 稳定的字符串标识（给 UI / 日志）
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Preflight => "preflight",
            Self::Account => "account",
            Self::Order => "order",
            Self::Challenge => "challenge",
            Self::Issue => "issue",
            Self::Deploy => "deploy",
        }
    }
}

impl fmt::Display for AcmeStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 错误种类。`Unsupported` 用于"这个能力还没做"——绝不返回成功。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcmeErrorKind {
    /// 配置不合法
    Config(String),
    /// 预检未通过（DNS 解析不到、端口不可达、IP 不匹配……）
    Preflight(String),
    /// 网络 / IO 失败
    Network(String),
    /// ACME 服务器返回的错误
    Protocol(String),
    /// 尚未实现的能力
    Unsupported(String),
}

impl AcmeErrorKind {
    fn message(&self) -> &str {
        match self {
            Self::Config(m) | Self::Preflight(m) | Self::Network(m) | Self::Protocol(m)
            | Self::Unsupported(m) => m,
        }
    }
}

/// ACME 模块的统一错误：带阶段 + 可直接展示给用户的中文原因。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeError {
    /// 失败阶段
    pub stage: AcmeStage,
    /// 失败种类与原因
    pub kind: AcmeErrorKind,
}

impl AcmeError {
    fn new(stage: AcmeStage, kind: AcmeErrorKind) -> Self {
        Self { stage, kind }
    }

    fn config(msg: impl Into<String>) -> Self {
        Self::new(AcmeStage::Config, AcmeErrorKind::Config(msg.into()))
    }

    fn preflight(msg: impl Into<String>) -> Self {
        Self::new(AcmeStage::Preflight, AcmeErrorKind::Preflight(msg.into()))
    }

    fn network(msg: impl Into<String>) -> Self {
        Self::new(AcmeStage::Config, AcmeErrorKind::Network(msg.into()))
    }

    fn protocol(stage: AcmeStage, msg: impl Into<String>) -> Self {
        Self::new(stage, AcmeErrorKind::Protocol(msg.into()))
    }

    fn unsupported(msg: impl Into<String>) -> Self {
        Self::new(AcmeStage::Config, AcmeErrorKind::Unsupported(msg.into()))
    }

    fn io(stage: AcmeStage, err: &std::io::Error, what: &str) -> Self {
        Self::new(stage, AcmeErrorKind::Network(format!("{what}失败：{err}")))
    }

    /// 可展示的原因（中文、可操作）
    pub fn reason(&self) -> &str {
        self.kind.message()
    }
}

impl fmt::Display for AcmeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.stage, self.reason())
    }
}

impl std::error::Error for AcmeError {}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/// ACME 服务提供方
///
/// 序列化形式可直接放进 `ServerConfig`：
/// `"letsencrypt"` / `"letsencrypt-staging"` / `"zerossl"` /
/// `{"custom": "https://ca.example/dir"}`。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AcmeProvider {
    /// Let's Encrypt 生产环境（默认）
    #[default]
    #[serde(rename = "letsencrypt")]
    LetsEncrypt,
    /// Let's Encrypt 测试环境（staging，配额宽松）
    #[serde(rename = "letsencrypt-staging")]
    LetsEncryptStaging,
    /// ZeroSSL
    #[serde(rename = "zerossl")]
    ZeroSsl,
    /// 自定义 directory URL（如 Pebble：`https://localhost:14000/dir`）
    #[serde(rename = "custom")]
    Custom(String),
}

impl AcmeProvider {
    /// 对应的 ACME directory URL
    pub fn directory_url(&self) -> &str {
        match self {
            Self::LetsEncrypt => LetsEncrypt::Production.url(),
            Self::LetsEncryptStaging => LetsEncrypt::Staging.url(),
            Self::ZeroSsl => instant_acme::ZeroSsl::Production.url(),
            Self::Custom(url) => url,
        }
    }

    /// 人类可读名称（用于事件 / 落盘元数据）
    pub fn label(&self) -> &str {
        match self {
            Self::LetsEncrypt => "letsencrypt",
            Self::LetsEncryptStaging => "letsencrypt-staging",
            Self::ZeroSsl => "zerossl",
            Self::Custom(_) => "custom",
        }
    }

    fn validate(&self) -> Result<(), AcmeError> {
        let url = self.directory_url();
        if !url.starts_with("https://") {
            return Err(AcmeError::config(format!(
                "ACME directory URL 必须是 https://（当前为 {url}）；明文 HTTP 会泄露账户签名，已拒绝"
            )));
        }
        Ok(())
    }
}

impl fmt::Display for AcmeProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// 挑战种类
// ---------------------------------------------------------------------------

/// 挑战类型
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ChallengeKind {
    /// HTTP-01：`/.well-known/acme-challenge/<token>`（默认、最通用）
    #[default]
    #[serde(rename = "http-01")]
    Http01,
    /// TLS-ALPN-01：ALPN `acme-tls/1`
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
    /// DNS-01：`_acme-challenge.<domain>` TXT（通配符证书必须用它）
    #[serde(rename = "dns-01")]
    Dns01,
}

impl ChallengeKind {
    /// 稳定标识，用于事件与 UI
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http01 => "http-01",
            Self::TlsAlpn01 => "tls-alpn-01",
            Self::Dns01 => "dns-01",
        }
    }

    fn to_acme(self) -> ChallengeType {
        match self {
            Self::Http01 => ChallengeType::Http01,
            Self::TlsAlpn01 => ChallengeType::TlsAlpn01,
            Self::Dns01 => ChallengeType::Dns01,
        }
    }

    /// http-01 / tls-alpn-01 需要在 80 / 443 上应答
    pub const fn public_port(self) -> Option<u16> {
        match self {
            Self::Http01 => Some(80),
            Self::TlsAlpn01 => Some(443),
            Self::Dns01 => None,
        }
    }
}

impl fmt::Display for ChallengeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// 事件
// ---------------------------------------------------------------------------

/// 申请进度事件。管理页可直接按顺序展示。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcmeEvent {
    /// 预检开始（此后仍然**没有**任何 CA 请求）
    PreflightStarted,
    /// 域名解析结果
    DnsResolved {
        /// 域名
        domain: String,
        /// 解析到的地址
        addrs: Vec<IpAddr>,
    },
    /// 验证端口可达性
    PortReachable {
        /// 端口
        port: u16,
        /// 是否可达
        ok: bool,
    },
    /// 账户已就绪（注册或复用）
    AccountReady,
    /// 订单已创建
    OrderCreated {
        /// 订单 URL
        order_url: String,
    },
    /// 挑战材料已就绪（token 已对外暴露）
    ChallengeReady {
        /// 挑战类型
        kind: String,
        /// 挑战 token
        token: String,
    },
    /// 等待 CA 验证
    Validating,
    /// 某个域名验证通过
    ChallengeValidated,
    /// 证书已签发
    CertificateIssued {
        /// 到期时间（RFC 3339 / UTC）
        not_after: String,
    },
    /// 证书已落盘（可被 TLS 层加载）
    Deployed,
    /// 失败
    Failed {
        /// 阶段（见 [`AcmeStage`]）
        stage: String,
        /// 可操作的中文原因
        reason: String,
    },
}

impl AcmeEvent {
    /// 便于记录/展示的一行文本
    pub fn summary(&self) -> String {
        match self {
            Self::PreflightStarted => "开始预检（不访问 CA）".into(),
            Self::DnsResolved { domain, addrs } => {
                let list = addrs
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{domain} 解析到 {list}")
            }
            Self::PortReachable { port, ok } => {
                format!("端口 {port} 可达性：{}", if *ok { "通过" } else { "失败" })
            }
            Self::AccountReady => "ACME 账户就绪".into(),
            Self::OrderCreated { order_url } => format!("订单已创建：{order_url}"),
            Self::ChallengeReady { kind, token } => {
                format!("{kind} 挑战就绪（token {token}）")
            }
            Self::Validating => "等待 CA 验证".into(),
            Self::ChallengeValidated => "域名验证通过".into(),
            Self::CertificateIssued { not_after } => format!("证书已签发，到期 {not_after}"),
            Self::Deployed => "证书已落盘".into(),
            Self::Failed { stage, reason } => format!("{stage} 阶段失败：{reason}"),
        }
    }
}

/// 事件接收器（可 clone）。默认 no-op。
#[derive(Clone, Default)]
pub struct AcmeEvents {
    sink: Option<Arc<dyn Fn(AcmeEvent) + Send + Sync>>,
}

impl AcmeEvents {
    /// 不接收任何事件
    pub fn noop() -> Self {
        Self { sink: None }
    }

    /// 自定义回调
    pub fn new<F>(f: F) -> Self
    where
        F: Fn(AcmeEvent) + Send + Sync + 'static,
    {
        Self {
            sink: Some(Arc::new(f)),
        }
    }

    /// 收集到内存里（测试、管理页轮询都方便）
    pub fn recording() -> (Self, Arc<Mutex<Vec<AcmeEvent>>>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = Arc::clone(&log);
        (
            Self::new(move |e| {
                if let Ok(mut v) = log2.lock() {
                    v.push(e);
                }
            }),
            log,
        )
    }

    fn emit(&self, event: AcmeEvent) {
        if let Some(sink) = &self.sink {
            sink(event);
        }
    }
}

impl fmt::Debug for AcmeEvents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcmeEvents")
            .field("attached", &self.sink.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// 网络审计（证明"没有发请求"）
// ---------------------------------------------------------------------------

/// ACME 网络请求计数器。
///
/// 每一次真正发给 CA 的 HTTP 请求都会记一笔。预检、构造配置、启动流程都**不**计入，
/// 因为它们根本没用这个客户端。
#[derive(Clone, Default)]
pub struct NetworkAudit {
    inner: Arc<AuditInner>,
}

#[derive(Default)]
struct AuditInner {
    count: AtomicU64,
    urls: Mutex<Vec<String>>,
}

impl NetworkAudit {
    /// 新建一个计数器
    pub fn new() -> Self {
        Self::default()
    }

    /// 已经发出的请求数
    pub fn count(&self) -> u64 {
        self.inner.count.load(Ordering::SeqCst)
    }

    /// 已发出的请求 URL（按时间顺序，最多保留若干条）
    pub fn urls(&self) -> Vec<String> {
        self.inner
            .urls
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    fn record(&self, url: String) {
        self.inner.count.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut v) = self.inner.urls.lock() {
            if v.len() < 64 {
                v.push(url);
            }
        }
    }

    /// 计数清零（测试用）
    pub fn reset(&self) {
        self.inner.count.store(0, Ordering::SeqCst);
        if let Ok(mut v) = self.inner.urls.lock() {
            v.clear();
        }
    }
}

impl fmt::Debug for NetworkAudit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkAudit")
            .field("count", &self.count())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// 挑战材料存储
// ---------------------------------------------------------------------------

/// 挑战材料：token → key authorization。
///
/// HTTP 层只要在 `/.well-known/acme-challenge/<token>` 上查这里并原样返回即可。
/// 这个类型是**唯一**把挑战材料交给外部的地方，本身不做任何决策。
#[derive(Clone, Default)]
pub struct ChallengeStore {
    inner: Arc<RwLock<HashMap<String, String>>>,
}

impl ChallengeStore {
    /// 空存储
    pub fn new() -> Self {
        Self::default()
    }

    /// 写入 / 覆盖一个 token
    pub fn insert(&self, token: impl Into<String>, key_authorization: impl Into<String>) {
        if let Ok(mut map) = self.inner.write() {
            map.insert(token.into(), key_authorization.into());
        }
    }

    /// 查询 token
    pub fn get(&self, token: &str) -> Option<String> {
        self.inner.read().ok()?.get(token).cloned()
    }

    /// 删除 token
    pub fn remove(&self, token: &str) -> Option<String> {
        self.inner.write().ok()?.remove(token)
    }

    /// 清空
    pub fn clear(&self) {
        if let Ok(mut map) = self.inner.write() {
            map.clear();
        }
    }

    /// 当前 token 数量
    pub fn len(&self) -> usize {
        self.inner.read().map(|m| m.len()).unwrap_or(0)
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 按请求路径查询：`/.well-known/acme-challenge/<token>` → key authorization。
    ///
    /// 只接受精确前缀 + 非空 token；其余路径返回 `None`（调用方应回 404）。
    pub fn lookup_path(&self, path: &str) -> Option<String> {
        let token = token_from_path(path)?;
        self.get(token)
    }
}

impl fmt::Debug for ChallengeStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChallengeStore")
            .field("tokens", &self.len())
            .finish()
    }
}

/// 从请求路径里抠出 token（校验前缀与字符集）
pub fn token_from_path(path: &str) -> Option<&str> {
    let path = path.split(['?', '#']).next().unwrap_or(path);
    let token = path.strip_prefix(CHALLENGE_PATH_PREFIX)?;
    if token.is_empty() || token.contains('/') || token.len() > 256 {
        return None;
    }
    // RFC 8555 的 token 是 base64url（不含 '=' 填充）
    if !token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    Some(token)
}

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

/// DNS-01 的 provider 选择
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnsProviderKind {
    /// Cloudflare（需要 `CF_DNS_API_TOKEN`）
    Cloudflare,
    /// 阿里云（暂未实现）
    Aliyun,
}

/// ACME 配置。全部字段都是**用户显式选择**的结果，加载它不会触发任何网络请求。
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    /// 数据根目录；账户密钥写 `<data_dir>/acme/account.key`
    pub data_dir: PathBuf,
    /// ACME 服务提供方
    pub provider: AcmeProvider,
    /// 联系邮箱（可空）
    pub contact_email: Option<String>,
    /// 使用的挑战类型，默认 `http-01`
    pub challenge: ChallengeKind,
    /// 本进程是否自己监听 http-01 应答端口；`false` 表示上层已把
    /// [`ChallengeStore`] 接到自己的 HTTP 服务上
    pub manage_http_responder: bool,
    /// http-01 应答监听地址，默认 `0.0.0.0:80`
    pub http_bind: SocketAddr,
    /// CA 侧访问的 http-01 端口（默认为 80；Pebble 是 5002）
    pub public_http_port: u16,
    /// 本进程是否自己监听 tls-alpn-01 端口
    pub manage_alpn_responder: bool,
    /// tls-alpn-01 监听地址，默认 `0.0.0.0:443`
    pub tls_alpn_bind: SocketAddr,
    /// CA 侧访问的 tls-alpn-01 端口（默认 443；Pebble 是 5001）
    pub public_tls_port: u16,
    /// 用户声明的本机公网 IP。用于预检比对（`None` 表示跳过比对）
    pub public_ip: Option<IpAddr>,
    /// 附加信任根（PEM）；用于私有 CA / Pebble 测试
    pub extra_trust_roots: Vec<PathBuf>,
    /// 是否信任系统内置的公共根证书（生产环境需要 `true`）
    pub use_public_roots: bool,
    /// 是否在预检里做端口探测
    pub preflight_port_check: bool,
    /// 单次 DNS / 端口探测超时
    pub preflight_timeout: Duration,
    /// 等待 CA 验证 / 签发的上限
    pub challenge_timeout: Duration,
    /// 自动续期策略
    pub renewal: RenewalPolicy,
    /// DNS-01 的 provider
    pub dns_provider: Option<DnsProviderKind>,
    /// dns-01：发布 TXT 记录后等待多久再让 CA 验证（默认 30 秒，给小 TTL 缓存过期）
    pub dns_propagation_delay: Duration,
}

impl AcmeConfig {
    /// 以 `data_dir` 为根，给出一份保守默认值：http-01、不自建 ALPN、
    /// 不声明公网 IP、自动续期**开启**（但不会自己跑，见 [`run_renewal_loop`]）。
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            provider: AcmeProvider::LetsEncrypt,
            contact_email: None,
            challenge: ChallengeKind::Http01,
            manage_http_responder: true,
            http_bind: SocketAddr::from(([0, 0, 0, 0], 80)),
            public_http_port: 80,
            manage_alpn_responder: true,
            tls_alpn_bind: SocketAddr::from(([0, 0, 0, 0], 443)),
            public_tls_port: 443,
            public_ip: None,
            extra_trust_roots: Vec::new(),
            use_public_roots: true,
            preflight_port_check: true,
            preflight_timeout: Duration::from_secs(5),
            challenge_timeout: Duration::from_secs(300),
            renewal: RenewalPolicy::default(),
            dns_provider: None,
            dns_propagation_delay: Duration::from_secs(30),
        }
    }

    fn acme_dir(&self) -> PathBuf {
        self.data_dir.join(ACME_DIR)
    }

    /// 证书落盘根目录（`<data_dir>/acme/certs`）。
    ///
    /// 把它交给 TLS 层即可加载本模块签发的证书：
    /// ```ignore
    /// let store = CertificateStore::open(acme_cfg.certs_dir())?;
    /// ```
    /// 目录结构与 `tls::CertificateStore` 一致（`<root>/<domain>/fullchain.pem` +
    /// `privkey.pem`，通配符域名用 `_wildcard_.` 前缀）。
    pub fn certs_dir(&self) -> PathBuf {
        self.acme_dir().join(CERTS_DIR)
    }

    fn validate(&self) -> Result<(), AcmeError> {
        self.provider.validate()?;
        match self.challenge {
            ChallengeKind::Http01 if !self.manage_http_responder => {
                debug!("http-01 由外部 HTTP 层应答（ChallengeStore 已共享）");
            }
            ChallengeKind::TlsAlpn01 if !self.manage_alpn_responder => {
                return Err(AcmeError::config(
                    "tls-alpn-01 需要本进程监听 443（ALPN acme-tls/1）；外部应答模式暂不支持该挑战，请改用 http-01",
                ));
            }
            ChallengeKind::Dns01 if self.dns_provider.is_none() => {
                return Err(AcmeError::preflight(
                    "dns-01 需要 DNS API 凭据：请配置 Cloudflare（环境变量 CF_DNS_API_TOKEN）后再试",
                ));
            }
            _ => {}
        }
        if let Some(email) = &self.contact_email {
            if email.is_empty() || email.contains(char::is_whitespace) {
                return Err(AcmeError::config("contact_email 不合法"));
            }
        }
        if self.provider == AcmeProvider::ZeroSsl && self.contact_email.is_none() {
            return Err(AcmeError::config(
                "ZeroSSL 要求提供联系邮箱（contact_email），否则账户注册会被 CA 拒绝",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 可嵌进 ServerConfig 的 JSON 形态
// ---------------------------------------------------------------------------

/// 服务端配置文件里的 `acme` 段（JSON 友好、全部可选、不触发任何网络请求）。
///
/// 父代理只需在 `ServerConfig` 里加 `#[serde(default)] pub acme: AcmeSettings`，
/// 再用 [`AcmeSettings::to_config`] 映射成 [`AcmeConfig`] 即可。
///
/// ```json
/// {
///   "acme": {
///     "provider": "letsencrypt",
///     "contact_email": "ops@example.com",
///     "challenge": "http-01",
///     "auto_renew": true,
///     "renew_before_days": 30,
///     "public_ip": "203.0.113.7",
///     "http_bind": "0.0.0.0:80",
///     "tls_bind": "0.0.0.0:443"
///   }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcmeSettings {
    /// CA
    #[serde(default)]
    pub provider: AcmeProvider,
    /// 联系邮箱
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact_email: Option<String>,
    /// 挑战类型
    #[serde(default)]
    pub challenge: ChallengeKind,
    /// 是否允许自动续期（默认 true；关掉后程序绝不主动联系 CA）
    #[serde(default = "default_true")]
    pub auto_renew: bool,
    /// 到期前多少天开始续期
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: u64,
    /// 本机公网 IP（用于预检比对；不写则跳过比对）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<IpAddr>,
    /// http-01 应答监听地址
    #[serde(default = "default_http_bind")]
    pub http_bind: SocketAddr,
    /// CA 侧访问的 http-01 端口（默认 80；Pebble 是 5002）
    #[serde(default = "default_http_port")]
    pub public_http_port: u16,
    /// tls-alpn-01 监听地址
    #[serde(default = "default_tls_bind")]
    pub tls_bind: SocketAddr,
    /// CA 侧访问的 tls-alpn-01 端口
    #[serde(default = "default_tls_port")]
    pub public_tls_port: u16,
    /// 是否由本进程监听 http-01 端口；`false` 表示上层 HTTP 层用
    /// [`ChallengeStore`] 应答
    #[serde(default = "default_true")]
    pub manage_http_responder: bool,
    /// DNS-01 provider
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_provider: Option<DnsProviderKind>,
    /// dns-01 发布记录后等待传播的秒数
    #[serde(default = "default_dns_propagation")]
    pub dns_propagation_secs: u64,
    /// 是否信任系统公共根证书
    #[serde(default = "default_true")]
    pub use_public_roots: bool,
    /// 额外信任根（PEM 路径）
    #[serde(default)]
    pub extra_trust_roots: Vec<PathBuf>,
    /// 是否做端口预检
    #[serde(default = "default_true")]
    pub preflight_port_check: bool,
    /// 单次 DNS / 端口探测超时（秒）
    #[serde(default = "default_preflight_timeout")]
    pub preflight_timeout_secs: u64,
    /// 等待 CA 验证 / 签发的上限（秒）
    #[serde(default = "default_challenge_timeout")]
    pub challenge_timeout_secs: u64,
}

fn default_true() -> bool {
    true
}

fn default_renew_before_days() -> u64 {
    DEFAULT_RENEW_BEFORE_DAYS
}

fn default_http_bind() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 80))
}

fn default_http_port() -> u16 {
    80
}

fn default_tls_bind() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 443))
}

fn default_tls_port() -> u16 {
    443
}

fn default_dns_propagation() -> u64 {
    30
}

fn default_preflight_timeout() -> u64 {
    5
}

fn default_challenge_timeout() -> u64 {
    300
}

impl Default for AcmeSettings {
    fn default() -> Self {
        Self {
            provider: AcmeProvider::default(),
            contact_email: None,
            challenge: ChallengeKind::default(),
            auto_renew: true,
            renew_before_days: DEFAULT_RENEW_BEFORE_DAYS,
            public_ip: None,
            http_bind: default_http_bind(),
            public_http_port: 80,
            tls_bind: default_tls_bind(),
            public_tls_port: 443,
            manage_http_responder: true,
            dns_provider: None,
            dns_propagation_secs: 30,
            use_public_roots: true,
            extra_trust_roots: Vec::new(),
            preflight_port_check: true,
            preflight_timeout_secs: 5,
            challenge_timeout_secs: 300,
        }
    }
}

impl AcmeSettings {
    /// 映射成运行时配置（纯数据转换，不发请求）
    pub fn to_config(&self, data_dir: impl Into<PathBuf>) -> AcmeConfig {
        AcmeConfig {
            data_dir: data_dir.into(),
            provider: self.provider.clone(),
            contact_email: self.contact_email.clone(),
            challenge: self.challenge,
            manage_http_responder: self.manage_http_responder,
            http_bind: self.http_bind,
            public_http_port: self.public_http_port,
            manage_alpn_responder: true,
            tls_alpn_bind: self.tls_bind,
            public_tls_port: self.public_tls_port,
            public_ip: self.public_ip,
            extra_trust_roots: self.extra_trust_roots.clone(),
            use_public_roots: self.use_public_roots,
            preflight_port_check: self.preflight_port_check,
            preflight_timeout: Duration::from_secs(self.preflight_timeout_secs),
            challenge_timeout: Duration::from_secs(self.challenge_timeout_secs),
            renewal: RenewalPolicy {
                enabled: self.auto_renew,
                renew_before: Duration::from_secs(self.renew_before_days * 86_400),
                backoff: RENEW_BACKOFF,
            },
            dns_provider: self.dns_provider.clone(),
            dns_propagation_delay: Duration::from_secs(self.dns_propagation_secs),
        }
    }
}

// ---------------------------------------------------------------------------
// 证书申请意图
// ---------------------------------------------------------------------------

/// 申请来源。写进证书元数据，便于审计"这次是谁触发的"。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequestSource {
    /// 用户在管理页点了"申请证书"
    User,
    /// 用户把站点的 `tls_mode` 设为 `acme` 后保存配置，并显式点击应用
    ConfigOptIn,
    /// 续期：复用最初的申请意图
    Renewal,
}

impl RequestSource {
    /// 稳定标识
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::ConfigOptIn => "config-opt-in",
            Self::Renewal => "renewal",
        }
    }
}

/// 一次证书申请意图。
///
/// 字段私有：外部只能通过 [`Self::user`] / [`Self::from_config`] / [`Self::renewal`]
/// 构造，从而在类型层面表达"这是一个明确的用户动作"。
/// 把它交给 [`AcmeClient::request_certificate`] 才会真正联系 CA。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRequest {
    domains: Vec<String>,
    challenge: ChallengeKind,
    source: RequestSource,
}

impl CertificateRequest {
    /// 用户在管理页显式发起的申请（**唯一**的默认入口）
    pub fn user(domains: impl Into<Vec<String>>) -> Result<Self, AcmeError> {
        Self::build(domains.into(), ChallengeKind::Http01, RequestSource::User)
    }

    /// 用户显式选择了挑战类型
    pub fn user_with(
        domains: impl Into<Vec<String>>,
        challenge: ChallengeKind,
    ) -> Result<Self, AcmeError> {
        Self::build(domains.into(), challenge, RequestSource::User)
    }

    /// 用户把站点 `tls_mode = acme` 保存后、显式点击"应用"时生成的待办。
    ///
    /// 仅仅构造它**不会**发出任何请求；还需要调用
    /// [`AcmeClient::request_certificate`]。
    pub fn from_config(domains: impl Into<Vec<String>>) -> Result<Self, AcmeError> {
        Self::build(domains.into(), ChallengeKind::Http01, RequestSource::ConfigOptIn)
    }

    /// 续期：复用用户最初的申请意图
    pub fn renewal(domains: impl Into<Vec<String>>, challenge: ChallengeKind) -> Result<Self, AcmeError> {
        Self::build(domains.into(), challenge, RequestSource::Renewal)
    }

    fn build(
        domains: Vec<String>,
        challenge: ChallengeKind,
        source: RequestSource,
    ) -> Result<Self, AcmeError> {
        let mut out = Vec::with_capacity(domains.len());
        for raw in domains {
            let d = raw.trim().trim_end_matches('.').to_ascii_lowercase();
            validate_domain(&d, challenge)?;
            if !out.contains(&d) {
                out.push(d);
            }
        }
        if out.is_empty() {
            return Err(AcmeError::config(
                "至少需要一个域名（例如 example.com 或 *.example.com）",
            ));
        }
        Ok(Self {
            domains: out,
            challenge,
            source,
        })
    }

    /// 申请的域名列表
    pub fn domains(&self) -> &[String] {
        &self.domains
    }

    /// 挑战类型
    pub fn challenge(&self) -> ChallengeKind {
        self.challenge
    }

    /// 申请来源
    pub fn source(&self) -> RequestSource {
        self.source
    }
}

/// 域名校验：拒绝通配符之外的 `*`、端口、URL、路径；通配符只能用 dns-01。
pub fn validate_domain(domain: &str, challenge: ChallengeKind) -> Result<(), AcmeError> {
    if domain.is_empty() || domain.len() > 253 {
        return Err(AcmeError::config(format!("域名长度不合法：{domain:?}")));
    }
    if domain.contains('/') || domain.contains(':') || domain.contains(char::is_whitespace) {
        return Err(AcmeError::config(format!(
            "域名 {domain:?} 不合法：只填主机名，不要带协议、端口或路径"
        )));
    }
    if domain.contains('*') {
        let rest = domain.strip_prefix("*.").ok_or_else(|| {
            AcmeError::config(format!("通配符只能出现在最左侧：{domain:?}"))
        })?;
        if rest.contains('*') || rest.is_empty() || !rest.contains('.') {
            return Err(AcmeError::config(format!(
                "通配符域名不合法：{domain:?}（应为 *.example.com）"
            )));
        }
        if challenge != ChallengeKind::Dns01 {
            return Err(AcmeError::config(format!(
                "通配符域名 {domain} 只能用 dns-01 验证（http-01 / tls-alpn-01 无法证明通配符）"
            )));
        }
        return validate_labels(rest, domain);
    }
    validate_labels(domain, domain)
}

fn validate_labels(host: &str, original: &str) -> Result<(), AcmeError> {
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return Err(AcmeError::config(format!(
            "域名 {original:?} 不是公网域名：ACME 只接受形如 example.com 的名称"
        )));
    }
    for label in labels {
        if label.is_empty() || label.len() > 63 {
            return Err(AcmeError::config(format!("域名 {original:?} 的标签长度不合法")));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(AcmeError::config(format!(
                "域名 {original:?} 的标签不能以 '-' 开头或结尾"
            )));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(AcmeError::config(format!(
                "域名 {original:?} 含有非法字符（只允许字母、数字、'-'、'.'）"
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 续期策略
// ---------------------------------------------------------------------------

/// 自动续期策略
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalPolicy {
    /// 是否允许自动续期。`false` ⇒ 程序**绝不**主动联系 CA。
    pub enabled: bool,
    /// 到期前多久开始续期
    pub renew_before: Duration,
    /// 失败退避（第 1 / 2 / ≥3 次失败）
    pub backoff: [Duration; 3],
}

impl Default for RenewalPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            renew_before: Duration::from_secs(DEFAULT_RENEW_BEFORE_DAYS * 24 * 60 * 60),
            backoff: RENEW_BACKOFF,
        }
    }
}

impl RenewalPolicy {
    /// 关闭自动续期（此后 [`run_renewal_loop`] 直接返回）
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }

    /// 续期窗口起点
    pub fn due_at(&self, not_after: SystemTime) -> SystemTime {
        not_after
            .checked_sub(self.renew_before)
            .unwrap_or(SystemTime::UNIX_EPOCH)
    }

    /// 下一次尝试时间；`None` 表示永不尝试（已关闭）
    ///
    /// - 未到窗口：窗口起点
    /// - 已到窗口且从未失败：立刻（返回 `now`）
    /// - 有连续失败：`now + backoff[min(failures-1, 2)]`
    pub fn next_attempt(
        &self,
        now: SystemTime,
        not_after: SystemTime,
        consecutive_failures: u32,
    ) -> Option<SystemTime> {
        if !self.enabled {
            return None;
        }
        let due = self.due_at(not_after);
        if now < due {
            // 还没进入续期窗口：先把唤醒点定在窗口起点，失败次数不影响它
            return Some(due);
        }
        if consecutive_failures == 0 {
            return Some(now);
        }
        let idx = (consecutive_failures as usize - 1).min(self.backoff.len() - 1);
        Some(now + self.backoff[idx])
    }
}

/// 续期目标：一条用户曾经明确申请过的证书
#[derive(Debug, Clone)]
pub struct RenewalTarget {
    /// 最初的申请意图
    pub request: CertificateRequest,
    /// 当前证书到期时间
    pub not_after: SystemTime,
    /// 连续失败次数
    pub failures: u32,
}

/// 计算下一次需要唤醒的时间间隔；`None` 表示不需要再等待（已关闭 / 无目标）
pub fn next_renewal_wait(
    policy: &RenewalPolicy,
    targets: &[RenewalTarget],
    now: SystemTime,
) -> Option<Duration> {
    if !policy.enabled {
        return None;
    }
    targets
        .iter()
        .filter_map(|t| policy.next_attempt(now, t.not_after, t.failures))
        .min()
        .map(|at| at.duration_since(now).unwrap_or(Duration::ZERO))
}

// ---------------------------------------------------------------------------
// 证书
// ---------------------------------------------------------------------------

/// 签发结果
#[derive(Debug, Clone)]
pub struct IssuedCertificate {
    /// 覆盖的域名
    pub domains: Vec<String>,
    /// 证书链（PEM，leaf 在前）
    pub certificate_pem: String,
    /// 私钥（PEM, PKCS#8）
    pub private_key_pem: String,
    /// 到期时间
    pub not_after: SystemTime,
    /// 挑战类型
    pub challenge: ChallengeKind,
    /// ACME directory URL
    pub directory_url: String,
    /// 落盘路径：证书链
    pub cert_path: PathBuf,
    /// 落盘路径：私钥
    pub key_path: PathBuf,
}

impl IssuedCertificate {
    /// 距离到期还有多少天（负数表示已过期）
    pub fn days_remaining(&self, now: SystemTime) -> i64 {
        match self.not_after.duration_since(now) {
            Ok(d) => (d.as_secs() / 86_400) as i64,
            Err(e) => -((e.duration().as_secs() / 86_400) as i64) - 1,
        }
    }

    /// 到期时间的 RFC 3339 文本（UTC）
    pub fn not_after_rfc3339(&self) -> String {
        format_system_time(self.not_after)
    }

    /// 用本证书构造一个续期目标（交给 [`run_renewal_loop`]）
    pub fn renewal_target(&self) -> RenewalTarget {
        RenewalTarget {
            request: CertificateRequest::renewal(self.domains.clone(), self.challenge)
                .unwrap_or_else(|_| {
                    // 域名来自已签发的证书，只可能在极端情况下失效；退化为最小集合
                    CertificateRequest::user(self.domains.clone()).expect("证书里的域名应当合法")
                }),
            not_after: self.not_after,
            failures: 0,
        }
    }
}

/// `SystemTime` → `YYYY-MM-DDTHH:MM:SSZ`
pub fn format_system_time(t: SystemTime) -> String {
    let secs = match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    };
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// 民用历换算（Howard Hinnant 算法）
fn civil_from_unix(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (
        year,
        m,
        d,
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    )
}

// ---------------------------------------------------------------------------
// 账户存储
// ---------------------------------------------------------------------------

struct AccountStore {
    dir: PathBuf,
}

impl AccountStore {
    fn new(acme_dir: &Path) -> Self {
        Self {
            dir: acme_dir.to_path_buf(),
        }
    }

    fn key_path(&self) -> PathBuf {
        self.dir.join(ACCOUNT_KEY_FILE)
    }

    fn credentials_path(&self) -> PathBuf {
        self.dir.join(ACCOUNT_CREDENTIALS_FILE)
    }

    /// 记录该账户属于哪个 CA。切换 provider 时用它判断凭据能否复用。
    fn provider_path(&self) -> PathBuf {
        self.dir.join(ACCOUNT_PROVIDER_FILE)
    }

    /// 建目录并收紧权限（acme/ 0700、文件 0600）
    fn ensure_dir(&self) -> Result<(), AcmeError> {
        fs::create_dir_all(&self.dir)
            .map_err(|e| AcmeError::io(AcmeStage::Account, &e, "创建 ACME 数据目录"))?;
        restrict_dir(&self.dir);
        Ok(())
    }

    /// 读取账户凭据。`directory_url` 必须与落盘时一致，否则视为不可复用：
    /// 换 CA 后不能拿旧 CA 的账户去签新 CA 的单。
    fn load_credentials(&self, directory_url: &str) -> Option<AccountCredentials> {
        let recorded = fs::read_to_string(self.provider_path()).ok()?;
        if recorded.trim() != directory_url {
            warn!(
                "ACME 账户属于 {}，当前配置的是 {directory_url}；将用同一把密钥在新 CA 注册",
                recorded.trim()
            );
            return None;
        }
        let raw = fs::read(self.credentials_path()).ok()?;
        match serde_json::from_slice(&raw) {
            Ok(c) => Some(c),
            Err(e) => {
                warn!("忽略损坏的 ACME 账户凭据 {}：{e}", self.credentials_path().display());
                None
            }
        }
    }

    fn save_credentials(&self, creds: &AccountCredentials, directory_url: &str) -> Result<(), AcmeError> {
        self.ensure_dir()?;
        write_private_json(&self.credentials_path(), creds)
            .map_err(|e| AcmeError::io(AcmeStage::Account, &e, "写入 ACME 账户凭据"))?;
        write_atomic(self.provider_path().as_path(), directory_url.as_bytes(), true)
            .map_err(|e| AcmeError::io(AcmeStage::Account, &e, "写入账户 CA 标记"))
    }

    /// 读账户私钥（PKCS#8 PEM），没有就生成一个。
    fn load_or_create_key(&self) -> Result<(Key, PrivateKeyDer<'static>), AcmeError> {
        self.ensure_dir()?;
        if let Ok(pem) = fs::read(self.key_path()) {
            if let Some(key) = parse_private_key_pem(&pem) {
                let instant = Key::from_pkcs8_der(match &key {
                    PrivateKeyDer::Pkcs8(p) => PrivatePkcs8KeyDer::from(p.secret_pkcs8_der().to_vec()),
                    _ => {
                        return Err(AcmeError::config(
                            "account.key 必须是 PKCS#8（BEGIN PRIVATE KEY）格式",
                        ))
                    }
                })
                .map_err(|e| AcmeError::protocol(AcmeStage::Account, format!("加载账户私钥失败：{e}")))?;
                return Ok((instant, key));
            }
            return Err(AcmeError::config(format!(
                "{} 不是合法的 PKCS#8 PEM 私钥；请删除后重新申请（会注册新账户）",
                self.key_path().display()
            )));
        }

        let (key, pkcs8) = Key::generate_pkcs8()
            .map_err(|e| AcmeError::protocol(AcmeStage::Account, format!("生成账户私钥失败：{e}")))?;
        write_private_pem(&self.key_path(), "PRIVATE KEY", pkcs8.secret_pkcs8_der())
            .map_err(|e| AcmeError::io(AcmeStage::Account, &e, "写入账户私钥"))?;
        Ok((key, PrivateKeyDer::Pkcs8(pkcs8)))
    }
}

#[cfg(unix)]
fn restrict_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_dir(_path: &Path) {
    // Windows 下目录 ACL 由部署方控制；这里不假装做了限制。
}

#[cfg(unix)]
fn restrict_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) {}

fn write_private_json(path: &Path, value: &impl serde::Serialize) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(value)?;
    write_atomic(path, &json, true)
}

fn write_private_pem(path: &Path, label: &str, der: &[u8]) -> std::io::Result<()> {
    let b64 = base64_encode(der);
    let mut out = String::with_capacity(b64.len() + label.len() * 2 + 64);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    write_atomic(path, out.as_bytes(), true)
}

/// 原子写：先写同目录临时文件再 rename，避免被读到半个文件。
fn write_atomic(path: &Path, data: &[u8], private: bool) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!(
        "{}.tmp{}",
        path.extension().and_then(|s| s.to_str()).unwrap_or(""),
        std::process::id()
    ));
    fs::write(&tmp, data)?;
    if private {
        restrict_file(&tmp);
    }
    fs::rename(&tmp, path)?;
    if private {
        restrict_file(path);
    }
    Ok(())
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn parse_private_key_pem(pem: &[u8]) -> Option<PrivateKeyDer<'static>> {
    let mut cursor = std::io::Cursor::new(pem);
    rustls_pemfile::private_key(&mut cursor).ok().flatten()
}

fn parse_cert_pem(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, AcmeError> {
    let mut cursor = std::io::Cursor::new(pem);
    let mut out = Vec::new();
    for item in rustls_pemfile::certs(&mut cursor) {
        out.push(item.map_err(|e| AcmeError::network(format!("解析 PEM 证书失败：{e}")))?);
    }
    if out.is_empty() {
        return Err(AcmeError::network("PEM 里没有找到证书"));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// HTTP 客户端（带审计 + 可替换根证书）
// ---------------------------------------------------------------------------

type HttpsConnector = hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>;
type HyperClient = hyper_util::client::legacy::Client<HttpsConnector, instant_acme::BodyWrapper<Bytes>>;

#[derive(Clone)]
struct AuditedHttp {
    inner: HyperClient,
    audit: NetworkAudit,
}

impl AuditedHttp {
    fn new(cfg: &AcmeConfig, audit: NetworkAudit) -> Result<Self, AcmeError> {
        Self::with_roots(cfg.use_public_roots, &cfg.extra_trust_roots, audit)
    }

    fn with_roots(
        use_public_roots: bool,
        extra_trust_roots: &[PathBuf],
        audit: NetworkAudit,
    ) -> Result<Self, AcmeError> {
        let mut roots = RootCertStore::empty();
        if use_public_roots {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        for path in extra_trust_roots {
            let pem = fs::read(path)
                .map_err(|e| AcmeError::io(AcmeStage::Config, &e, &format!("读取信任根 {}", path.display())))?;
            for cert in parse_cert_pem(&pem)? {
                roots
                    .add(cert)
                    .map_err(|e| AcmeError::config(format!("信任根 {} 不被接受：{e}", path.display())))?;
            }
        }
        if roots.is_empty() {
            return Err(AcmeError::config(
                "信任根为空：请启用 use_public_roots 或配置 extra_trust_roots",
            ));
        }

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| AcmeError::config(format!("初始化 TLS 失败：{e}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();

        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_only()
            .enable_http1()
            .build();

        Ok(Self {
            inner: hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(connector),
            audit,
        })
    }
}

impl instant_acme::HttpClient for AuditedHttp {
    fn request(
        &self,
        req: Request<instant_acme::BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<instant_acme::BytesResponse, instant_acme::Error>> + Send>> {
        self.audit.record(req.uri().to_string());
        let fut = self.inner.request(req);
        Box::pin(async move {
            fut.await
                .map(instant_acme::BytesResponse::from)
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))
        })
    }
}

impl fmt::Debug for AuditedHttp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditedHttp")
            .field("requests", &self.audit.count())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// http-01 应答服务器
// ---------------------------------------------------------------------------

/// 内置 http-01 应答服务器。
///
/// 只回答 `GET /.well-known/acme-challenge/<token>`，其余一律 404。
/// 如果服务端已经有 80 端口的 HTTP 服务，可以把 [`ChallengeStore`] 交给它，
/// 并把 `AcmeConfig::manage_http_responder` 设为 `false`。
pub struct Http01Responder {
    store: ChallengeStore,
    local_addr: SocketAddr,
    handle: JoinHandle<()>,
}

impl Http01Responder {
    /// 绑定并启动
    pub async fn bind(store: ChallengeStore, addr: SocketAddr) -> Result<Self, AcmeError> {
        let listener = TcpListener::bind(addr).await.map_err(|e| {
            AcmeError::preflight(format!(
                "{addr} 无法监听（{e}）；请检查端口是否被占用、是否以管理员/root 运行，或改用外部应答模式"
            ))
        })?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| AcmeError::io(AcmeStage::Preflight, &e, "读取监听地址"))?;
        let store2 = store.clone();
        let handle = tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("ACME http-01 应答接入失败：{e}");
                        continue;
                    }
                };
                let store = store2.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_challenge_conn(stream, store).await {
                        debug!("ACME http-01 应答出错（{peer}）：{e}");
                    }
                });
            }
        });
        Ok(Self {
            store,
            local_addr,
            handle,
        })
    }

    /// 实际监听地址
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// 共享的挑战材料
    pub fn challenge_store(&self) -> ChallengeStore {
        self.store.clone()
    }

    /// 停止应答
    pub fn shutdown(&self) {
        self.handle.abort();
    }
}

impl Drop for Http01Responder {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn serve_challenge_conn(mut stream: TcpStream, store: ChallengeStore) -> std::io::Result<()> {
    let fut = async {
        let mut buf = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 8192 {
                break;
            }
        }

        let text = String::from_utf8_lossy(&buf);
        let mut parts = text.lines().next().unwrap_or_default().split_whitespace();
        let method = parts.next().unwrap_or_default();
        let path = parts.next().unwrap_or_default();

        let (status, body): (&str, String) = match (method, store.lookup_path(path)) {
            ("GET", Some(key_auth)) => ("200 OK", key_auth),
            ("GET", None) | ("HEAD", None) => ("404 Not Found", "not found".to_string()),
            ("HEAD", Some(key_auth)) => ("200 OK", key_auth),
            _ => ("405 Method Not Allowed", "method not allowed".to_string()),
        };

        let head_only = method == "HEAD";
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await?;
        if !head_only {
            stream.write_all(body.as_bytes()).await?;
        }
        stream.flush().await?;
        let _ = stream.shutdown().await;
        Ok::<(), std::io::Error>(())
    };

    match tokio::time::timeout(Duration::from_secs(10), fut).await {
        Ok(r) => r,
        Err(_) => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// tls-alpn-01 应答服务器
// ---------------------------------------------------------------------------

/// 按 SNI 选择 tls-alpn-01 证书
#[derive(Default)]
struct AlpnResolver {
    certs: RwLock<HashMap<String, Arc<CertifiedKey>>>,
}

impl fmt::Debug for AlpnResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AlpnResolver")
            .field("doms", &self.certs.read().map(|m| m.len()).unwrap_or(0))
            .finish()
    }
}

impl AlpnResolver {
    fn insert(&self, domain: &str, cert: Arc<CertifiedKey>) {
        if let Ok(mut map) = self.certs.write() {
            map.insert(domain.to_ascii_lowercase(), cert);
        }
    }

    fn remove(&self, domain: &str) {
        if let Ok(mut map) = self.certs.write() {
            map.remove(&domain.to_ascii_lowercase());
        }
    }
}

impl ResolvesServerCert for AlpnResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = client_hello.server_name()?;
        self.certs.read().ok()?.get(&name.to_ascii_lowercase()).cloned()
    }
}

/// 内置 tls-alpn-01 应答服务器（ALPN `acme-tls/1`）。
///
/// 只在挑战期间打开；每个域名一张带 acmeIdentifier 扩展的临时自签证书。
pub struct TlsAlpnResponder {
    resolver: Arc<AlpnResolver>,
    local_addr: SocketAddr,
    handle: JoinHandle<()>,
}

impl TlsAlpnResponder {
    /// 绑定并启动
    pub async fn bind(addr: SocketAddr) -> Result<Self, AcmeError> {
        let resolver = Arc::new(AlpnResolver::default());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| AcmeError::config(format!("初始化 TLS 失败：{e}")))?
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());
        config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
        let config = Arc::new(config);

        let listener = TcpListener::bind(addr).await.map_err(|e| {
            AcmeError::preflight(format!(
                "{addr} 无法监听（{e}）；tls-alpn-01 需要在 443 上应答，请检查权限或改用 http-01"
            ))
        })?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| AcmeError::io(AcmeStage::Preflight, &e, "读取监听地址"))?;

        let handle = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(config);
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("ACME tls-alpn-01 接入失败：{e}");
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    // 完整握手才说明挑战应答有效；握完就关。
                    let _ = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await;
                    debug!("ACME tls-alpn-01 握手结束（{peer}）");
                });
            }
        });

        Ok(Self {
            resolver,
            local_addr,
            handle,
        })
    }

    /// 实际监听地址
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// 为某个域名准备证书
    pub fn publish(&self, domain: &str, key_authorization_digest: &[u8]) -> Result<(), AcmeError> {
        let cert = self.build_cert(domain, key_authorization_digest)?;
        self.resolver.insert(domain, cert);
        Ok(())
    }

    /// 撤销
    pub fn clear(&self, domain: &str) {
        self.resolver.remove(domain);
    }

    fn build_cert(&self, domain: &str, digest: &[u8]) -> Result<Arc<CertifiedKey>, AcmeError> {
        let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])
            .map_err(|e| AcmeError::config(format!("生成 tls-alpn 证书参数失败：{e}")))?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(digest)];
        let key = rcgen::KeyPair::generate()
            .map_err(|e| AcmeError::config(format!("生成 tls-alpn 临时私钥失败：{e}")))?;
        let cert = params
            .self_signed(&key)
            .map_err(|e| AcmeError::config(format!("生成 tls-alpn 自签证书失败：{e}")))?;
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let signing = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .map_err(|e| AcmeError::config(format!("tls-alpn 私钥不可用：{e}")))?;
        Ok(Arc::new(CertifiedKey::new(
            vec![cert.der().clone()],
            signing,
        )))
    }

    /// 停止应答
    pub fn shutdown(&self) {
        self.handle.abort();
    }
}

impl Drop for TlsAlpnResponder {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

// ---------------------------------------------------------------------------
// DNS-01 provider
// ---------------------------------------------------------------------------

/// dns-01 的记录名：`*.example.com` / `example.com` → `_acme-challenge.example.com`
pub fn dns01_record_name(domain: &str) -> String {
    format!(
        "_acme-challenge.{}",
        domain.strip_prefix("*.").unwrap_or(domain)
    )
}

/// 一条待发布的 TXT 记录
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// 记录名（`_acme-challenge.example.com`）
    pub fqdn: String,
    /// 记录值（key authorization 的 SHA-256 base64url）
    pub value: String,
}

/// DNS provider 扩展点。
///
/// 返回 `Unsupported` 的实现必须**如实**报错，不允许静默成功。
pub trait DnsProvider: Send + Sync {
    /// 发布记录，返回可用于清理的句柄
    fn present<'a>(
        &'a self,
        record: &'a DnsRecord,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<String, AcmeError>> + Send + 'a>>;

    /// 清理记录
    fn cleanup<'a>(
        &'a self,
        handle: String,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), AcmeError>> + Send + 'a>>;
}

/// 阿里云 DNS 占位实现：**未实现**，如实返回 `Unsupported`。
#[derive(Debug, Default, Clone, Copy)]
pub struct AliyunDns;

impl DnsProvider for AliyunDns {
    fn present<'a>(
        &'a self,
        _record: &'a DnsRecord,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<String, AcmeError>> + Send + 'a>> {
        Box::pin(async {
            Err(AcmeError::unsupported(
                "阿里云 DNS-01 尚未实现；请改用 http-01，或按 DnsProvider trait 自行接入",
            ))
        })
    }

    fn cleanup<'a>(
        &'a self,
        _handle: String,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), AcmeError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// 客户端
// ---------------------------------------------------------------------------

/// ACME 客户端：**唯一**能发起申请的类型。
pub struct AcmeClient {
    cfg: AcmeConfig,
    store: ChallengeStore,
    audit: NetworkAudit,
    http: AuditedHttp,
    account: AsyncMutex<Option<Account>>,
    dns_provider: Mutex<Option<Arc<dyn DnsProvider>>>,
}

impl AcmeClient {
    /// 构造客户端。只做本地校验与目录准备，**零网络请求**。
    pub fn new(cfg: AcmeConfig) -> Result<Self, AcmeError> {
        cfg.validate()?;
        let accounts = AccountStore::new(&cfg.acme_dir());
        accounts.ensure_dir()?;
        let audit = NetworkAudit::new();
        let http = AuditedHttp::new(&cfg, audit.clone())?;
        Ok(Self {
            store: ChallengeStore::new(),
            audit,
            http,
            account: AsyncMutex::new(None),
            dns_provider: Mutex::new(None),
            cfg,
        })
    }

    /// 配置快照
    pub fn config(&self) -> &AcmeConfig {
        &self.cfg
    }

    /// 证书落盘根目录（交给 TLS 层加载）
    pub fn certs_dir(&self) -> PathBuf {
        self.cfg.certs_dir()
    }

    /// 网络请求计数（用于测试 / 运维观察）
    pub fn audit(&self) -> NetworkAudit {
        self.audit.clone()
    }

    /// 共享给 HTTP 层 / 外部应答服务的挑战材料
    pub fn challenge_store(&self) -> ChallengeStore {
        self.store.clone()
    }

    /// **唯一的** CA 联系入口，必须由用户显式调用。
    ///
    /// 流程：预检（本地）→ 账户 → 下单 → 挑战 → 验证 → 签发 → 落盘。
    /// 预检失败时直接返回，**不会**产生任何 CA 请求（`self.audit().count()` 保持不变）。
    pub async fn request_certificate(
        &self,
        request: &CertificateRequest,
        events: &AcmeEvents,
    ) -> Result<IssuedCertificate, AcmeError> {
        let result = self.request_inner(request, events).await;
        if let Err(err) = &result {
            events.emit(AcmeEvent::Failed {
                stage: err.stage.to_string(),
                reason: err.reason().to_string(),
            });
        }
        result
    }

    async fn request_inner(
        &self,
        request: &CertificateRequest,
        events: &AcmeEvents,
    ) -> Result<IssuedCertificate, AcmeError> {
        if request.challenge() != self.cfg.challenge {
            return Err(AcmeError::config(format!(
                "请求使用 {} 验证，但客户端配置的是 {}；请把两者设为一致",
                request.challenge(),
                self.cfg.challenge
            )));
        }
        if request.challenge() == ChallengeKind::Http01 && !self.cfg.manage_http_responder {
            debug!("使用外部 http-01 应答（ChallengeStore 已共享给 HTTP 层）");
        }

        // ---- 1. 预检：纯本地，绝不访问 CA ----
        self.preflight(request, events).await?;

        // ---- 2. 应答服务器 ----
        let mut responders = Responders::new();
        // `None` = 本进程不对该挑战端口负责（外部 HTTP 层应答），不做端口预检：
        // 那种情况下端口由上层监听，本模块无法从 127.0.0.1 判断它是否对外可达，
        // 与其猜一个结果，不如如实跳过（事件里不会出现 PortReachable）。
        let probe_addr = match request.challenge() {
            ChallengeKind::Http01 => {
                if self.cfg.manage_http_responder {
                    let r = Http01Responder::bind(self.store.clone(), self.cfg.http_bind).await?;
                    let addr = r.local_addr();
                    responders.http = Some(r);
                    Some(addr)
                } else {
                    None
                }
            }
            ChallengeKind::TlsAlpn01 => {
                let r = TlsAlpnResponder::bind(self.cfg.tls_alpn_bind).await?;
                let addr = r.local_addr();
                responders.alpn = Some(r);
                Some(addr)
            }
            ChallengeKind::Dns01 => None,
        };

        if let Some(addr) = probe_addr {
            let port = addr.port();
            let ok = if self.cfg.preflight_port_check {
                // 监听在 0.0.0.0/[::] 时用回环地址探测
                let target = if addr.ip().is_unspecified() {
                    SocketAddr::from(([127, 0, 0, 1], port))
                } else {
                    addr
                };
                self.probe_local_port(target).await
            } else {
                true
            };
            events.emit(AcmeEvent::PortReachable { port, ok });
            if !ok {
                return Err(AcmeError::preflight(format!(
                    "{port} 端口本机不可连；请检查监听地址/防火墙，或改用其它验证方式"
                )));
            }
        }

        // ---- 3. 账户（注册一次，后续复用）----
        let account = self.ensure_account().await?;
        events.emit(AcmeEvent::AccountReady);

        // ---- 4. 下单 ----
        let identifiers: Vec<Identifier> = request
            .domains()
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|e| AcmeError::protocol(AcmeStage::Order, format!("创建 ACME 订单失败：{e}")))?;
        events.emit(AcmeEvent::OrderCreated {
            order_url: order.url().to_string(),
        });

        // ---- 5. 挑战 ----
        //
        // instant-acme 的 `AuthorizationHandle::challenge(&'a mut self)` 会把句柄借到
        // 整个授权句柄的生命周期，因此"先 set_ready 再轮询同一个句柄"过不了借用检查。
        // 这里按授权下标逐个处理，每个下标用一个独立作用域，作用域结束即释放借用。
        let challenge_kind = request.challenge();
        let mut published: Vec<(String, String)> = Vec::new(); // (domain, token)
        let authz_count = order.state().authorizations.len();
        for index in 0..authz_count {
            let mut prepared = None;
            {
                let mut stream = order.authorizations();
                let mut current = 0usize;
                while let Some(item) = stream.next().await {
                    let mut authz = item.map_err(|e| {
                        AcmeError::protocol(AcmeStage::Challenge, format!("读取授权失败：{e}"))
                    })?;
                    if current != index {
                        current += 1;
                        continue;
                    }
                    let domain = authz.identifier().to_string();
                    if authz.status == instant_acme::AuthorizationStatus::Valid {
                        break;
                    }
                    let mut challenge = authz.challenge(challenge_kind.to_acme()).ok_or_else(|| {
                        AcmeError::protocol(
                            AcmeStage::Challenge,
                            format!(
                                "CA 没有为 {domain} 提供 {challenge_kind} 挑战；请换一种验证方式"
                            ),
                        )
                    })?;
                    let token = challenge.token.clone();
                    let key_auth = challenge.key_authorization();
                    self.publish_challenge(&responders, &domain, &token, &key_auth)
                        .await?;
                    events.emit(AcmeEvent::ChallengeReady {
                        kind: challenge_kind.to_string(),
                        token: token.clone(),
                    });
                    challenge.set_ready().await.map_err(|e| {
                        AcmeError::protocol(
                            AcmeStage::Challenge,
                            format!("告知 CA 挑战就绪失败（{domain}）：{e}"),
                        )
                    })?;
                    prepared = Some((domain, token));
                    break;
                }
            }
            if let Some(item) = prepared {
                published.push(item);
            }
        }

        // 轮询每个授权直到 valid（或失败）
        events.emit(AcmeEvent::Validating);
        for index in 0..authz_count {
            let domain = order
                .state()
                .authorizations
                .get(index)
                .and_then(|a| a.state.as_ref())
                .map(|s| s.identifier().to_string())
                .unwrap_or_else(|| format!("#{index}"));
            self.wait_for_authorization(&mut order, index, &domain, events)
                .await?;
        }
        for (domain, token) in published.drain(..) {
            self.cleanup_challenge(&responders, &domain, &token);
        }


        // ---- 6. 签发 ----
        // 订单在验证后必须是 ready；否则把 CA 给的原因原样带出去
        let status = order
            .poll_ready(&RetryPolicy::new().timeout(self.cfg.challenge_timeout))
            .await
            .map_err(|e| {
                AcmeError::protocol(AcmeStage::Issue, format!("等待订单变为 ready 失败：{e}"))
            })?;
        if status != instant_acme::OrderStatus::Ready {
            let detail = order
                .state()
                .error
                .as_ref()
                .and_then(|e| e.detail.clone())
                .unwrap_or_else(|| format!("订单状态为 {status:?}"));
            return Err(AcmeError::protocol(
                AcmeStage::Issue,
                format!("订单未进入 ready：{detail}"),
            ));
        }
        let private_key_pem = order
            .finalize()
            .await
            .map_err(|e| AcmeError::protocol(AcmeStage::Issue, format!("提交 CSR / 签发失败：{e}")))?;
        let certificate_pem = order
            .poll_certificate(&RetryPolicy::new().timeout(self.cfg.challenge_timeout))
            .await
            .map_err(|e| {
                AcmeError::protocol(AcmeStage::Issue, format!("下载证书失败：{e}"))
            })?;

        let not_after = certificate_not_after(&certificate_pem).map_err(|e| {
            AcmeError::protocol(AcmeStage::Issue, format!("解析证书到期时间失败：{}", e.reason()))
        })?;
        events.emit(AcmeEvent::CertificateIssued {
            not_after: format_system_time(not_after),
        });

        // ---- 7. 落盘 ----
        let (cert_path, key_path) = self
            .write_certificate(request, &certificate_pem, &private_key_pem, not_after)
            .await?;
        events.emit(AcmeEvent::Deployed);

        // 清理本次发布过的 token（不碰并发的其它申请）
        for (domain, token) in &published {
            self.cleanup_challenge(&responders, domain, token);
        }
        Ok(IssuedCertificate {
            domains: request.domains().to_vec(),
            certificate_pem,
            private_key_pem,
            not_after,
            challenge: challenge_kind,
            directory_url: self.cfg.provider.directory_url().to_string(),
            cert_path,
            key_path,
        })
    }

    async fn preflight(
        &self,
        request: &CertificateRequest,
        events: &AcmeEvents,
    ) -> Result<(), AcmeError> {
        events.emit(AcmeEvent::PreflightStarted);
        // dns-01 只要求域名下的 TXT 记录可写，不要求 A/AAAA 记录，
        // 因此不做"必须解析到某个地址"的硬性检查。
        if request.challenge() == ChallengeKind::Dns01 {
            // 但 provider 必须在**下单之前**就能拿到（缺凭据时不要先消耗 CA 配额）
            self.dns_provider()?;
            debug!("dns-01：跳过 A/AAAA 与端口预检，DNS provider 已就绪");
            return Ok(());
        }
        for domain in request.domains() {
            let lookup_host = domain.strip_prefix("*.").unwrap_or(domain);
            let addrs = resolve_domain(lookup_host, self.cfg.preflight_timeout).await?;
            if addrs.is_empty() {
                return Err(AcmeError::preflight(format!(
                    "域名 {lookup_host} 解析不到任何 A/AAAA 记录；请检查 DNS 解析是否已生效、是否填错域名"
                )));
            }
            if let Some(expected) = self.cfg.public_ip {
                if !addrs.contains(&expected) {
                    let got = addrs
                        .iter()
                        .map(|a| a.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    return Err(AcmeError::preflight(format!(
                        "域名 {lookup_host} 解析到 {got}，不是本机公网 IP {expected}；\
                         请修改 DNS 记录，或在配置里更正本机公网 IP"
                    )));
                }
            }
            events.emit(AcmeEvent::DnsResolved {
                domain: lookup_host.to_string(),
                addrs,
            });
        }
        Ok(())
    }

    /// 探测本机能否连上某个监听地址（用来确认应答服务器真的起来了）
    async fn probe_local_port(&self, addr: SocketAddr) -> bool {
        tokio::time::timeout(self.cfg.preflight_timeout, TcpStream::connect(addr))
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false)
    }

    async fn ensure_account(&self) -> Result<Account, AcmeError> {
        let mut slot = self.account.lock().await;
        if let Some(account) = slot.as_ref() {
            return Ok(account.clone());
        }
        let store = AccountStore::new(&self.cfg.acme_dir());
        let directory_url = self.cfg.provider.directory_url().to_string();

        // 1) 已有账户凭据：直接复用（只会发一次 directory GET）
        if let Some(creds) = store.load_credentials(&directory_url) {
            match Account::builder_with_http(Box::new(self.http.clone()))
                .from_credentials(creds)
                .await
            {
                Ok(account) => {
                    info!("复用 ACME 账户 {}", account.id());
                    *slot = Some(account.clone());
                    return Ok(account);
                }
                Err(e) => {
                    // 凭据失效（例如换了 CA / 账户被吊销）：退回用本地密钥重新注册
                    warn!("复用 ACME 账户失败，将用本地密钥重新注册：{e}");
                }
            }
        }

        // 2) 本地已有账户密钥：用它注册或找回账户（不再生成新密钥）
        if store.key_path().exists() {
            let (key, pkcs8) = store.load_or_create_key()?;
            let (account, creds) = Account::builder_with_http(Box::new(self.http.clone()))
                .create_from_key((key, pkcs8), directory_url.clone())
                .await
                .map_err(|e| {
                    AcmeError::protocol(
                        AcmeStage::Account,
                        format!(
                            "用已有账户密钥注册/找回 ACME 账户失败：{e}；                             若目录 URL 已更换，请删除 {} 后重试（会注册新账户）",
                            store.key_path().display()
                        ),
                    )
                })?;
            store.save_credentials(&creds, &directory_url)?;
            info!("ACME 账户已就绪（复用本地密钥）：{}", account.id());
            *slot = Some(account.clone());
            return Ok(account);
        }

        // 3) 全新部署：首次注册。`create()` 自己生成密钥，
        //    我们把它和凭据一起落盘，后续走上面的分支复用。
        let contacts: Vec<String> = self
            .cfg
            .contact_email
            .iter()
            .map(|e| format!("mailto:{e}"))
            .collect();
        let contact_refs: Vec<&str> = contacts.iter().map(|s| s.as_str()).collect();
        let new_account = NewAccount {
            contact: &contact_refs,
            terms_of_service_agreed: true,
            only_return_existing: false,
        };
        let (account, creds) = Account::builder_with_http(Box::new(self.http.clone()))
            .create(&new_account, directory_url.clone(), None)
            .await
            .map_err(|e| {
                AcmeError::protocol(
                    AcmeStage::Account,
                    format!(
                        "ACME 账户注册失败：{e}；请检查 directory URL 是否可访问、                         联系邮箱是否被 CA 接受"
                    ),
                )
            })?;
        write_private_pem(
            &store.key_path(),
            "PRIVATE KEY",
            creds.private_key().secret_pkcs8_der(),
        )
        .map_err(|e| AcmeError::io(AcmeStage::Account, &e, "写入账户私钥"))?;
        store.save_credentials(&creds, &directory_url)?;
        info!("ACME 账户已注册：{}", account.id());
        *slot = Some(account.clone());
        Ok(account)
    }

    async fn publish_challenge(
        &self,
        responders: &Responders,
        domain: &str,
        token: &str,
        key_auth: &instant_acme::KeyAuthorization,
    ) -> Result<(), AcmeError> {
        match self.cfg.challenge {
            ChallengeKind::Http01 => {
                self.store.insert(token.to_string(), key_auth.as_str());
                Ok(())
            }
            ChallengeKind::TlsAlpn01 => {
                let responder = responders.alpn.as_ref().ok_or_else(|| {
                    AcmeError::config("tls-alpn-01 应答服务器未启动")
                })?;
                responder.publish(domain, key_auth.digest().as_ref())?;
                self.store.insert(token.to_string(), key_auth.as_str());
                Ok(())
            }
            ChallengeKind::Dns01 => {
                let provider = self.dns_provider()?;
                let record = DnsRecord {
                    fqdn: dns01_record_name(domain),
                    value: key_auth.dns_value(),
                };
                let handle = provider.present(&record).await?;
                debug!("已发布 DNS 记录 {}（handle {handle}）", record.fqdn);
                self.store.insert(token.to_string(), key_auth.as_str());
                dns_handle_put(token, handle);
                // 给 DNS 传播留时间；否则 CA 可能读到旧记录导致验证失败。
                if !self.cfg.dns_propagation_delay.is_zero() {
                    debug!(
                        "等待 DNS 传播 {}s 后再让 CA 验证",
                        self.cfg.dns_propagation_delay.as_secs()
                    );
                    tokio::time::sleep(self.cfg.dns_propagation_delay).await;
                }
                Ok(())
            }
        }
    }

    fn cleanup_challenge(&self, responders: &Responders, domain: &str, token: &str) {
        self.store.remove(token);
        if let Some(alpn) = &responders.alpn {
            alpn.clear(domain);
        }
        if let Some(handle) = dns_handle_take(token) {
            if let Ok(provider) = self.dns_provider() {
                tokio::spawn(async move {
                    if let Err(e) = provider.cleanup(handle).await {
                        warn!("清理 DNS 记录失败：{e}");
                    }
                });
            }
        }
    }

    /// 懒加载并缓存 DNS provider（凭据只在第一次用到时读环境变量）
    fn dns_provider(&self) -> Result<Arc<dyn DnsProvider>, AcmeError> {
        let mut slot = match self.dns_provider.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(provider) = slot.as_ref() {
            return Ok(Arc::clone(provider));
        }
        let provider: Arc<dyn DnsProvider> = match self.cfg.dns_provider {
            Some(DnsProviderKind::Cloudflare) => Arc::new(CloudflareDns::from_env()?),
            Some(DnsProviderKind::Aliyun) => Arc::new(AliyunDns),
            None => {
                return Err(AcmeError::preflight(
                    "dns-01 未配置 DNS provider（Cloudflare / 阿里云）",
                ));
            }
        };
        *slot = Some(Arc::clone(&provider));
        Ok(provider)
    }

    async fn wait_for_authorization(
        &self,
        order: &mut instant_acme::Order,
        index: usize,
        domain: &str,
        events: &AcmeEvents,
    ) -> Result<(), AcmeError> {
        let deadline = tokio::time::Instant::now() + self.cfg.challenge_timeout;
        let mut delay = Duration::from_millis(500);
        loop {
            // 每次轮询都重新取一遍授权句柄：`challenge()` 的借用会把句柄借到
            // 整个生命周期，不能在同一句柄上 refresh。
            let (status, detail) = {
                let mut stream = order.authorizations();
                let mut current = 0usize;
                let mut found = None;
                while let Some(item) = stream.next().await {
                    let mut authz = item.map_err(|e| {
                        AcmeError::protocol(AcmeStage::Challenge, format!("读取授权失败：{e}"))
                    })?;
                    if current == index {
                        authz.refresh().await.map_err(|e| {
                            AcmeError::protocol(
                                AcmeStage::Challenge,
                                format!("刷新授权状态失败：{e}"),
                            )
                        })?;
                        let detail = authz
                            .challenges
                            .iter()
                            .filter(|c| c.status == instant_acme::ChallengeStatus::Invalid)
                            .find_map(|c| c.error.as_ref().and_then(|e| e.detail.clone()));
                        found = Some((authz.status, detail));
                        break;
                    }
                    current += 1;
                }
                found.ok_or_else(|| {
                    AcmeError::protocol(
                        AcmeStage::Challenge,
                        "订单里找不到对应的授权（CA 返回的数据不完整）",
                    )
                })?
            };

            match status {
                instant_acme::AuthorizationStatus::Valid => {
                    events.emit(AcmeEvent::ChallengeValidated);
                    return Ok(());
                }
                instant_acme::AuthorizationStatus::Invalid => {
                    let detail = detail.unwrap_or_else(|| "CA 未给出原因".to_string());
                    return Err(AcmeError::protocol(
                        AcmeStage::Challenge,
                        format!(
                            "{domain} 验证失败：{detail}；请确认验证端口对外可达、\
                             域名解析指向本机，且没有前置代理吞掉挑战请求"
                        ),
                    ));
                }
                _ => {}
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(AcmeError::protocol(
                    AcmeStage::Challenge,
                    format!("等待 {domain} 验证超时；请检查 CA 是否能访问验证端口"),
                ));
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(5));
        }
    }

    async fn write_certificate(
        &self,
        request: &CertificateRequest,
        chain_pem: &str,
        key_pem: &str,
        not_after: SystemTime,
    ) -> Result<(PathBuf, PathBuf), AcmeError> {
        // 目录命名与 `tls::CertificateStore` 保持一致（通配符用 `_wildcard_.` 前缀），
        // 这样 `CertificateStore::open(<data_dir>/acme/certs)` 能直接加载到本模块的产物。
        let dir_name = request
            .domains()
            .first()
            .map(|d| match d.strip_prefix("*.") {
                Some(rest) => format!("_wildcard_.{rest}"),
                None => d.clone(),
            })
            .unwrap_or_else(|| "cert".to_string());
        let dir = self.cfg.acme_dir().join(CERTS_DIR).join(dir_name);
        let cert_path = dir.join("fullchain.pem");
        let key_path = dir.join("privkey.pem");
        write_atomic(&cert_path, chain_pem.as_bytes(), false)
            .map_err(|e| AcmeError::io(AcmeStage::Deploy, &e, "写入证书链"))?;
        write_atomic(&key_path, key_pem.as_bytes(), true)
            .map_err(|e| AcmeError::io(AcmeStage::Deploy, &e, "写入私钥"))?;

        // meta.json 与 `tls::CertMeta` 兼容：`source` 必须是
        // `upload` / `self-signed` / `acme` 之一，TLS 层据此在管理页标注来源。
        let meta = serde_json::json!({
            "source": "acme",
            "request_source": request.source().as_str(),
            "domains": request.domains(),
            "challenge": request.challenge().as_str(),
            "directory_url": self.cfg.provider.directory_url(),
            "not_before": certificate_not_before(chain_pem)
                .map(format_system_time)
                .unwrap_or_default(),
            "not_after": format_system_time(not_after),
            "obtained_at": format_system_time(SystemTime::now()),
        });
        write_atomic(
            &dir.join("meta.json"),
            serde_json::to_vec_pretty(&meta)
                .map_err(|e| AcmeError::network(format!("序列化证书元数据失败：{e}")))?
                .as_slice(),
            false,
        )
        .map_err(|e| AcmeError::io(AcmeStage::Deploy, &e, "写入证书元数据"))?;

        info!("证书已写入 {} / {}", cert_path.display(), key_path.display());
        Ok((cert_path, key_path))
    }
}

impl fmt::Debug for AcmeClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcmeClient")
            .field("provider", &self.cfg.provider)
            .field("challenge", &self.cfg.challenge)
            .field("audit", &self.audit.count())
            .finish()
    }
}

struct Responders {
    http: Option<Http01Responder>,
    alpn: Option<TlsAlpnResponder>,
}

impl Responders {
    fn new() -> Self {
        Self {
            http: None,
            alpn: None,
        }
    }
}

impl Drop for Responders {
    fn drop(&mut self) {
        if let Some(r) = &self.http {
            r.shutdown();
        }
        if let Some(r) = &self.alpn {
            r.shutdown();
        }
    }
}

/// dns-01 记录句柄（token → provider handle）。
///
/// 用全局表是因为 `cleanup_challenge` 可能在异步任务里清理，且 provider 句柄
/// 需要跨 `present` / `cleanup` 两次调用保存。
static DNS_HANDLES: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

fn dns_handle_put(token: &str, handle: String) {
    if let Ok(mut v) = DNS_HANDLES.lock() {
        v.push((token.to_string(), handle));
    }
}

fn dns_handle_take(token: &str) -> Option<String> {
    let mut v = DNS_HANDLES.lock().ok()?;
    let pos = v.iter().position(|(t, _)| t == token)?;
    Some(v.remove(pos).1)
}

// ---------------------------------------------------------------------------
// Cloudflare DNS（实现存在，但未用真实 token 验证过）
// ---------------------------------------------------------------------------

/// Cloudflare DNS-01 provider。
///
/// 令牌只从环境变量 `CF_DNS_API_TOKEN` 读取，绝不落配置文件。
#[derive(Debug, Clone)]
pub struct CloudflareDns {
    token: String,
    http: AuditedHttp,
}

impl CloudflareDns {
    /// 从环境变量读取令牌
    pub fn from_env() -> Result<Self, AcmeError> {
        let token = std::env::var("CF_DNS_API_TOKEN").map_err(|_| {
            AcmeError::preflight(
                "缺少环境变量 CF_DNS_API_TOKEN（Cloudflare API Token，需 Zone.DNS 编辑权限）",
            )
        })?;
        if token.trim().is_empty() {
            return Err(AcmeError::preflight("CF_DNS_API_TOKEN 为空"));
        }
        // Cloudflare API 走公共 PKI，不需要 ACME 的自定义信任根
        let http = AuditedHttp::with_roots(true, &[], NetworkAudit::new())?;
        Ok(Self { token, http })
    }

    async fn cf(&self, method: &str, path: &str, body: Option<serde_json::Value>) -> Result<serde_json::Value, AcmeError> {
        let url = format!("https://api.cloudflare.com/client/v4{path}");
        let payload = match body {
            Some(v) => Bytes::from(serde_json::to_vec(&v).map_err(|e| {
                AcmeError::network(format!("序列化 Cloudflare 请求失败：{e}"))
            })?),
            None => Bytes::new(),
        };
        let req = Request::builder()
            .method(Method::from_bytes(method.as_bytes()).map_err(|e| {
                AcmeError::network(format!("非法 HTTP 方法：{e}"))
            })?)
            .uri(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .body(instant_acme::BodyWrapper::from(payload.to_vec()))
            .map_err(|e| AcmeError::network(format!("构造 Cloudflare 请求失败：{e}")))?;

        let mut rsp = instant_acme::HttpClient::request(&self.http, req)
            .await
            .map_err(|e| AcmeError::network(format!("Cloudflare API 请求失败：{e}")))?;
        let status = rsp.parts.status;
        let body = rsp
            .body
            .into_bytes()
            .await
            .map_err(|e| AcmeError::network(format!("读取 Cloudflare 响应失败：{e}")))?;
        if !status.is_success() {
            return Err(AcmeError::protocol(
                AcmeStage::Challenge,
                format!(
                    "Cloudflare API 返回 {status}：{}",
                    String::from_utf8_lossy(&body)
                ),
            ));
        }
        serde_json::from_slice(&body)
            .map_err(|e| AcmeError::network(format!("解析 Cloudflare 响应失败：{e}")))
    }

    async fn find_zone(&self, fqdn: &str) -> Result<String, AcmeError> {
        let labels: Vec<&str> = fqdn.split('.').collect();
        for start in 0..labels.len().saturating_sub(1) {
            let candidate = labels[start..].join(".");
            let json = self.cf("GET", &format!("/zones?name={candidate}"), None).await?;
            if let Some(id) = json["result"]
                .as_array()
                .and_then(|arr| arr.first())
                .and_then(|z| z["id"].as_str())
            {
                return Ok(id.to_string());
            }
        }
        Err(AcmeError::preflight(format!(
            "在 Cloudflare 找不到 {fqdn} 对应的 zone；请确认令牌有该域名的权限"
        )))
    }
}

impl DnsProvider for CloudflareDns {
    fn present<'a>(
        &'a self,
        record: &'a DnsRecord,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<String, AcmeError>> + Send + 'a>> {
        Box::pin(async move {
            let zone = self.find_zone(&record.fqdn).await?;
            let body = serde_json::json!({
                "type": "TXT",
                "name": record.fqdn,
                "content": record.value,
                "ttl": 120,
            });
            let json = self
                .cf("POST", &format!("/zones/{zone}/dns_records"), Some(body))
                .await?;
            let id = json["result"]["id"].as_str().ok_or_else(|| {
                AcmeError::network("Cloudflare 未返回记录 ID")
            })?;
            Ok(format!("{zone}/{id}"))
        })
    }

    fn cleanup<'a>(
        &'a self,
        handle: String,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), AcmeError>> + Send + 'a>> {
        Box::pin(async move {
            let Some((zone, id)) = handle.split_once('/') else {
                return Err(AcmeError::network("Cloudflare 记录句柄格式错误"));
            };
            let _ = self
                .cf("DELETE", &format!("/zones/{zone}/dns_records/{id}"), None)
                .await?;
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// 服务门面（给上层装配用，绝不自动申请）
// ---------------------------------------------------------------------------

/// 服务门面：把配置、挑战存储、审计计数器绑在一起。
///
/// **没有**任何"开始/初始化即申请"的入口；`new` 不发请求，
/// [`Self::pending_requests`] 只把配置翻译成待办列表。
pub struct AcmeService {
    client: AcmeClient,
}

impl AcmeService {
    /// 构造服务（零网络请求）
    pub fn new(cfg: AcmeConfig) -> Result<Self, AcmeError> {
        Ok(Self {
            client: AcmeClient::new(cfg)?,
        })
    }

    /// 底层客户端
    pub fn client(&self) -> &AcmeClient {
        &self.client
    }

    /// 把站点配置里 `tls_mode = acme` 的域名翻译成待办申请。
    ///
    /// 这一步**只读配置**：不会下单、不会注册账户、不会碰到网络。
    pub fn pending_requests(&self, sites: &[HttpSiteConfig]) -> Vec<CertificateRequest> {
        let mut seen: Vec<String> = Vec::new();
        let mut out = Vec::new();
        for site in sites.iter().filter(|s| s.tls_mode == TlsMode::Acme) {
            let domain = site.domain.trim().trim_end_matches('.').to_ascii_lowercase();
            if domain.is_empty() || seen.contains(&domain) {
                continue;
            }
            match CertificateRequest::from_config(vec![domain.clone()]) {
                Ok(req) => {
                    seen.push(domain);
                    out.push(req);
                }
                Err(e) => {
                    // 通配符站点无法用 http-01；这里不静默吞掉，留给运维看到
                    warn!("站点 {} 无法生成 ACME 待办：{e}", site.domain);
                }
            }
        }
        out
    }

    /// 网络请求计数
    pub fn audit(&self) -> NetworkAudit {
        self.client.audit()
    }
}

impl fmt::Debug for AcmeService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcmeService").field("client", &self.client).finish()
    }
}

// ---------------------------------------------------------------------------
// 续期循环
// ---------------------------------------------------------------------------

/// 自动续期循环（常驻任务，只在 `targets` 清空时返回）。
///
/// - `policy.enabled == false` 时**立即返回**，不产生任何网络请求 —— 这是
///   "用户关闭自动续期后程序绝不联系 CA" 的落地点；
/// - 否则按 [`RenewalPolicy`] 计算唤醒时间（到期前 30 天起），到期后调用
///   [`AcmeClient::request_certificate`]（仍复用用户最初的申请意图）；
/// - 失败按 1h / 6h / 24h 退避，下次失败后继续用 24h。
///
/// 调用方用 `tokio::spawn` 起它，并用 abort 停止。
pub async fn run_renewal_loop(
    client: Arc<AcmeClient>,
    mut targets: Vec<RenewalTarget>,
    policy: RenewalPolicy,
    events: AcmeEvents,
) -> Result<(), AcmeError> {
    if !policy.enabled {
        info!("自动续期已关闭：不会联系任何 CA");
        return Ok(());
    }
    loop {
        let now = SystemTime::now();
        let Some(wait) = next_renewal_wait(&policy, &targets, now) else {
            return Ok(());
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        for target in &mut targets {
            let now = SystemTime::now();
            let Some(at) = policy.next_attempt(now, target.not_after, target.failures) else {
                continue;
            };
            if at > now {
                continue;
            }
            match client.request_certificate(&target.request, &events).await {
                Ok(cert) => {
                    target.not_after = cert.not_after;
                    target.failures = 0;
                }
                Err(e) => {
                    // `request_certificate` 内部已经推送过带阶段的 Failed 事件
                    target.failures = target.failures.saturating_add(1);
                    warn!("续期失败（第 {} 次）：{e}", target.failures);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 证书解析 / 校验工具
// ---------------------------------------------------------------------------

/// 从 PEM 证书链里取 leaf 的 `notAfter`
pub fn certificate_not_after(chain_pem: &str) -> Result<SystemTime, AcmeError> {
    let der = first_cert_der(chain_pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| AcmeError::network(format!("解析 X.509 失败：{e}")))?;
    let ts = cert.validity().not_after.timestamp();
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(ts.max(0) as u64))
        .ok_or_else(|| AcmeError::network("证书到期时间超出可表示范围"))
}

/// 从 PEM 证书链里取 leaf 的 `notBefore`
pub fn certificate_not_before(chain_pem: &str) -> Result<SystemTime, AcmeError> {
    let der = first_cert_der(chain_pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| AcmeError::network(format!("解析 X.509 失败：{e}")))?;
    let ts = cert.validity().not_before.timestamp();
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(ts.max(0) as u64))
        .ok_or_else(|| AcmeError::network("证书生效时间超出可表示范围"))
}

fn first_cert_der(chain_pem: &str) -> Result<Vec<u8>, AcmeError> {
    let block = x509_parser::pem::parse_x509_pem(chain_pem.as_bytes())
        .map_err(|e| AcmeError::network(format!("解析 PEM 失败：{e}")))?;
    Ok(block.1.contents)
}

/// 用真实 TLS 握手验证"这张证书 + 这把私钥 + 这条链"能被给定根证书接受，
/// 并且证书对 `server_name` 有效（SAN / 通配符 / 有效期都会被 rustls 检查）。
///
/// 会临时监听 127.0.0.1:0，握手成功后立即关闭。
pub async fn verify_chain_via_tls(
    chain_pem: &str,
    key_pem: &str,
    roots_pem: &[u8],
    server_name: &str,
) -> Result<(), AcmeError> {
    let certs = parse_cert_pem(chain_pem.as_bytes())?;
    let key = parse_private_key_pem(key_pem.as_bytes())
        .ok_or_else(|| AcmeError::config("私钥 PEM 无法解析"))?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_cfg = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| AcmeError::config(format!("TLS 服务端初始化失败：{e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| AcmeError::config(format!("证书与私钥不匹配：{e}")))?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    let mut roots = RootCertStore::empty();
    for cert in parse_cert_pem(roots_pem)? {
        roots
            .add(cert)
            .map_err(|e| AcmeError::config(format!("根证书不被接受：{e}")))?;
    }
    let mut client_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| AcmeError::config(format!("TLS 客户端初始化失败：{e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_cfg.alpn_protocols = Vec::new();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| AcmeError::io(AcmeStage::Deploy, &e, "绑定本地验证端口"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| AcmeError::io(AcmeStage::Deploy, &e, "读取验证端口"))?;

    let server = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let _ = acceptor.accept(stream).await;
        }
    });

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| AcmeError::io(AcmeStage::Deploy, &e, "连接本地验证端口"))?;
    let domain = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|e| AcmeError::config(format!("非法服务器名：{e}")))?;
    let outcome = connector.connect(domain, stream).await;
    server.abort();
    outcome
        .map(|_| ())
        .map_err(|e| AcmeError::protocol(AcmeStage::Deploy, format!("证书链校验失败：{e}")))
}

async fn resolve_domain(domain: &str, timeout: Duration) -> Result<Vec<IpAddr>, AcmeError> {
    let lookup = tokio::net::lookup_host((domain, 0));
    let result = tokio::time::timeout(timeout, lookup)
        .await
        .map_err(|_| {
            AcmeError::preflight(format!("解析 {domain} 超时（{}s）", timeout.as_secs()))
        })?;
    match result {
        Ok(iter) => {
            let mut out: Vec<IpAddr> = Vec::new();
            for addr in iter {
                if !out.contains(&addr.ip()) {
                    out.push(addr.ip());
                }
            }
            Ok(out)
        }
        Err(e) => Err(AcmeError::preflight(format!(
            "域名 {domain} 解析失败：{e}；请检查 DNS 记录是否存在"
        ))),
    }
}

// ---------------------------------------------------------------------------
// 单元测试（纯本地，无网络）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_path_parsing() {
        assert_eq!(
            token_from_path("/.well-known/acme-challenge/abc-123_XY"),
            Some("abc-123_XY")
        );
        assert_eq!(token_from_path("/.well-known/acme-challenge/"), None);
        assert_eq!(token_from_path("/.well-known/acme-challenge/a/b"), None);
        assert_eq!(token_from_path("/other"), None);
        assert_eq!(token_from_path("/.well-known/acme-challenge/a?b"), Some("a"));
    }

    #[test]
    fn challenge_store_roundtrip() {
        let store = ChallengeStore::new();
        store.insert("tok", "tok.thumb");
        assert_eq!(store.get("tok").as_deref(), Some("tok.thumb"));
        assert_eq!(
            store.lookup_path("/.well-known/acme-challenge/tok").as_deref(),
            Some("tok.thumb")
        );
        assert!(store.lookup_path("/.well-known/acme-challenge/nope").is_none());
        assert_eq!(store.remove("tok").as_deref(), Some("tok.thumb"));
        assert!(store.is_empty());
    }

    #[test]
    fn domain_validation() {
        assert!(validate_domain("example.com", ChallengeKind::Http01).is_ok());
        assert!(validate_domain("a.b.example.com", ChallengeKind::Http01).is_ok());
        assert!(validate_domain("*.example.com", ChallengeKind::Dns01).is_ok());
        assert!(validate_domain("*.example.com", ChallengeKind::Http01).is_err());
        assert!(validate_domain("example", ChallengeKind::Http01).is_err());
        assert!(validate_domain("http://example.com", ChallengeKind::Http01).is_err());
        assert!(validate_domain("example.com:8443", ChallengeKind::Http01).is_err());
        assert!(validate_domain("exa mple.com", ChallengeKind::Http01).is_err());
        assert!(validate_domain("a..b.com", ChallengeKind::Http01).is_err());
    }

    #[test]
    fn dns01_record_names() {
        assert_eq!(dns01_record_name("example.com"), "_acme-challenge.example.com");
        assert_eq!(
            dns01_record_name("*.example.com"),
            "_acme-challenge.example.com"
        );
        assert_eq!(
            dns01_record_name("a.b.example.com"),
            "_acme-challenge.a.b.example.com"
        );
    }

    #[test]
    fn acme_settings_json_roundtrip() {
        // 父代理只需在 ServerConfig 里加一个 #[serde(default)] 的 AcmeSettings 字段
        let json = r#"{
            "provider": "letsencrypt-staging",
            "contact_email": "ops@example.com",
            "challenge": "tls-alpn-01",
            "auto_renew": false,
            "renew_before_days": 21,
            "public_ip": "203.0.113.7",
            "http_bind": "0.0.0.0:8080",
            "public_http_port": 8080,
            "tls_bind": "0.0.0.0:8443",
            "public_tls_port": 8443,
            "manage_http_responder": false,
            "dns_provider": "cloudflare",
            "dns_propagation_secs": 5,
            "use_public_roots": false,
            "extra_trust_roots": ["/etc/pebble-root.pem"]
        }"#;
        let settings: AcmeSettings = serde_json::from_str(json).expect("parse");
        assert_eq!(settings.provider, AcmeProvider::LetsEncryptStaging);
        assert!(!settings.auto_renew);
        assert_eq!(settings.renew_before_days, 21);
        assert_eq!(settings.challenge, ChallengeKind::TlsAlpn01);
        assert_eq!(settings.dns_provider, Some(DnsProviderKind::Cloudflare));

        let cfg = settings.to_config("/tmp/data");
        assert!(!cfg.renewal.enabled, "auto_renew=false 必须落到 RenewalPolicy");
        assert_eq!(cfg.renewal.renew_before, Duration::from_secs(21 * 86_400));
        assert_eq!(cfg.public_http_port, 8080);
        assert!(!cfg.manage_http_responder);
        assert_eq!(cfg.dns_propagation_delay, Duration::from_secs(5));
        assert_eq!(cfg.extra_trust_roots.len(), 1);
        assert_eq!(cfg.data_dir, PathBuf::from("/tmp/data"));

        // 空对象也能解析：全部取保守默认值，且默认就是"用户没主动关闭续期"
        let empty: AcmeSettings = serde_json::from_str("{}").expect("parse empty");
        assert_eq!(empty, AcmeSettings::default());
        assert_eq!(empty.provider, AcmeProvider::LetsEncrypt);
        assert_eq!(empty.challenge, ChallengeKind::Http01);
        assert!(empty.auto_renew);

        // 自定义 directory URL
        let custom: AcmeSettings = serde_json::from_str(
            r#"{"provider":{"custom":"https://localhost:14000/dir"}}"#,
        )
        .expect("parse custom");
        assert_eq!(
            custom.provider.directory_url(),
            "https://localhost:14000/dir"
        );
    }

    #[test]
    fn auto_renew_off_maps_to_no_attempts() {
        let settings = AcmeSettings {
            auto_renew: false,
            ..AcmeSettings::default()
        };
        let cfg = settings.to_config("/tmp/x");
        let not_after = SystemTime::now() + Duration::from_secs(86_400);
        assert!(
            cfg.renewal
                .next_attempt(SystemTime::now(), not_after, 0)
                .is_none(),
            "auto_renew=false 时续期策略必须永不再触发"
        );
    }

    #[test]
    fn request_dedups_and_lowercases() {
        let req = CertificateRequest::user(vec![
            "Example.COM".to_string(),
            "example.com.".to_string(),
        ])
        .unwrap();
        assert_eq!(req.domains(), &["example.com".to_string()]);
        assert_eq!(req.source(), RequestSource::User);
    }

    #[test]
    fn renewal_schedule() {
        let policy = RenewalPolicy::default();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let not_after = now + Duration::from_secs(90 * 86_400);

        // 未到窗口：唤醒点在到期前 30 天
        let next = policy.next_attempt(now, not_after, 0).unwrap();
        assert_eq!(next, not_after - Duration::from_secs(30 * 86_400));

        // 已到期窗口：立刻
        let near = not_after - Duration::from_secs(86_400);
        assert_eq!(policy.next_attempt(near, not_after, 0).unwrap(), near);

        // 失败退避 1h / 6h / 24h
        assert_eq!(
            policy.next_attempt(near, not_after, 1).unwrap(),
            near + Duration::from_secs(3600)
        );
        assert_eq!(
            policy.next_attempt(near, not_after, 2).unwrap(),
            near + Duration::from_secs(6 * 3600)
        );
        assert_eq!(
            policy.next_attempt(near, not_after, 9).unwrap(),
            near + Duration::from_secs(24 * 3600)
        );

        // 关闭后永不唤醒
        let off = RenewalPolicy::disabled();
        assert!(off.next_attempt(near, not_after, 0).is_none());
        assert!(next_renewal_wait(&off, &[], now).is_none());
    }

    #[test]
    fn time_formatting() {
        assert_eq!(
            format_system_time(SystemTime::UNIX_EPOCH),
            "1970-01-01T00:00:00Z"
        );
        assert_eq!(
            format_system_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
            "2023-11-14T22:13:20Z"
        );
    }

    #[test]
    fn base64_matches_known_values() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn not_after_parses_generated_cert() {
        // 用 rcgen 生成一张有效期 1 小时的证书，验证解析精度
        let mut params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        let now = rcgen::date_time_ymd(2035, 1, 2);
        params.not_before = now;
        params.not_after = rcgen::date_time_ymd(2035, 1, 2);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let ts = certificate_not_after(&cert.pem()).unwrap();
        // 2035-01-02T00:00:00Z
        assert_eq!(format_system_time(ts), "2035-01-02T00:00:00Z");
    }

    #[test]
    fn config_defaults_are_conservative() {
        let cfg = AcmeConfig::new("/tmp/nps-acme-test");
        assert_eq!(cfg.challenge, ChallengeKind::Http01);
        assert_eq!(cfg.provider.directory_url(), LE_PRODUCTION_DIRECTORY);
        assert_eq!(cfg.renewal.renew_before, Duration::from_secs(30 * 86_400));
        assert!(cfg.renewal.enabled);
        // dns-01 未配置 provider → 预检阶段就拒绝
        let mut dns = cfg.clone();
        dns.challenge = ChallengeKind::Dns01;
        assert!(matches!(
            dns.validate(),
            Err(AcmeError { stage: AcmeStage::Preflight, .. })
        ));
        // 明文 directory URL 拒绝
        let mut plain = cfg.clone();
        plain.provider = AcmeProvider::Custom("http://ca.local/dir".into());
        assert!(plain.validate().is_err());
    }
}
