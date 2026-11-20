//! TLS 基础设施：证书存储、SNI 路由、热加载与 HTTPS 监听器。
//!
//! 这一层只负责 **证书 → TLS 会话**，不解析 HTTP：握手成功后的
//! [`TlsSession::stream`] 交给上层（HTTP 域名代理 / WebSocket 等）。
//!
//! # 证书目录布局
//!
//! ```text
//! <cert_dir>/<domain>/
//! ├─ cert.pem        叶子证书 + 中间证书链（leaf 在前）
//! ├─ key.pem         私钥（Unix 下 0600；绝不打日志）
//! └─ meta.json       签发者 / 有效期 / 来源（upload|self-signed|acme）/ 上次错误
//! ```
//!
//! - 为兼容 ACME 模块的落盘命名，读取时会自动回退到 `fullchain.pem` / `privkey.pem`。
//! - Windows 文件名不允许 `*`，通配域名 `*.example.com` 的目录名编码为
//!   `_wildcard_.example.com`（[`dir_name_for`] / [`domain_from_dir_name`]）。
//!
//! # 安全语义（刻意与「方便」相反）
//!
//! 1. **没有默认证书**：SNI 未匹配任何已部署域名、或客户端不发 SNI 时，
//!    [`SniResolver::resolve`] 返回 `None`，rustls 直接以 fatal alert 终止握手。
//!    这样外部无法通过「连一下看返回什么证书」探测本机部署了哪些域名。
//! 2. **私钥不外泄**：`Debug` 一律输出 `<redacted>`；[`CertInfo`] 不含任何私钥字段；
//!    `meta.json` 与错误信息都不含私钥内容。
//! 3. **加载即校验**：证书与私钥必须匹配（由 rustls `keys_match` 判定）、
//!    证书链必须连得上、有效期会被标记（过期的仍然加载，但 `expired = true`）。
//!
//! # 热加载
//!
//! 证书表是「不可变快照 + 原子替换」：`RwLock<Arc<CertTable>>`。
//! [`CertificateStore::put`] / [`CertificateStore::remove`] / [`CertificateStore::reload`]
//! 只替换快照，**不重建 `ServerConfig`、不重启监听器、不断开已有连接**；
//! 下一次握手里就能看到新证书。
//!
//! # 典型接法
//!
//! ```no_run
//! # async fn demo() -> anyhow::Result<()> {
//! use nps_server::tls::{CertificateStore, CertSource, TlsListener};
//!
//! let (cert_pem, key_pem) = ("-----BEGIN CERTIFICATE-----…", "-----BEGIN PRIVATE KEY-----…");
//! let store = CertificateStore::open("data/certs")?;
//! store.put("a.example.com", cert_pem, key_pem, CertSource::Upload)?;
//!
//! let listener = TlsListener::new(store.resolver())?;
//! let tcp = listener.bind("0.0.0.0:443").await?;
//! loop {
//!     let session = listener.accept(&tcp).await?;      // 握手失败在这里返回 Err
//!     tokio::spawn(handle_http(session.stream));       // 上层自己做 HTTP
//! }
//! # }
//! # async fn handle_http<S>(_: S) {}
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, ServerConfig};
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

/// 证书目录内的证书链文件名
pub const CERT_FILE: &str = "cert.pem";
/// 证书目录内的私钥文件名（Unix 下权限 0600）
pub const KEY_FILE: &str = "key.pem";
/// 证书目录内的元数据文件名
pub const META_FILE: &str = "meta.json";
/// 默认宣告的 ALPN 协议
pub const ALPN_HTTP11: &[u8] = b"http/1.1";
/// 默认 TLS 握手超时（防慢速握手占资源）
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// 读取时兼容 ACME 模块的落盘命名
const CERT_ALIASES: [&str; 2] = [CERT_FILE, "fullchain.pem"];
const KEY_ALIASES: [&str; 2] = [KEY_FILE, "privkey.pem"];
/// 通配域名目录名前缀（Windows 不允许文件名含 `*`）
const WILDCARD_DIR_PREFIX: &str = "_wildcard_.";

// ---------------------------------------------------------------------------
// 证书来源
// ---------------------------------------------------------------------------

/// 证书来源，写入 `meta.json` 的 `source` 字段。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertSource {
    /// 用户上传（含第三方签发）
    Upload,
    /// 本机生成的自签证书（仅测试用）
    SelfSigned,
    /// ACME 自动签发
    Acme,
}

impl CertSource {
    /// 序列化名（`upload` / `self-signed` / `acme`）
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::SelfSigned => "self-signed",
            Self::Acme => "acme",
        }
    }
}

impl fmt::Display for CertSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// 元数据与对外的证书信息
// ---------------------------------------------------------------------------

/// `meta.json` 的内容。**不含任何私钥信息。**
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertMeta {
    /// 来源
    pub source: CertSource,
    /// 签发者（DN 文本，取自证书本身）
    #[serde(default)]
    pub issuer: String,
    /// 生效时间（RFC3339）
    #[serde(default)]
    pub not_before: String,
    /// 到期时间（RFC3339）
    #[serde(default)]
    pub not_after: String,
    /// SAN 列表（DNS 名 / IP）
    #[serde(default)]
    pub san: Vec<String>,
    /// 叶子证书 SHA-256 指纹
    #[serde(default)]
    pub fingerprint_sha256: String,
    /// 上次加载 / 签发失败原因（成功加载后会被清空）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl Default for CertMeta {
    fn default() -> Self {
        Self {
            source: CertSource::Upload,
            issuer: String::new(),
            not_before: String::new(),
            not_after: String::new(),
            san: Vec::new(),
            fingerprint_sha256: String::new(),
            last_error: None,
        }
    }
}

/// 管理页展示用的证书信息。**结构与私钥无关，绝不包含私钥材料。**
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertInfo {
    /// 部署域名（通配证书形如 `*.example.com`）
    pub domain: String,
    /// 来源
    pub source: CertSource,
    /// 签发者
    pub issuer: String,
    /// 生效时间（RFC3339，UTC）
    pub not_before: String,
    /// 到期时间（RFC3339，UTC）
    pub not_after: String,
    /// 剩余天数；负数表示已过期
    pub days_remaining: i64,
    /// SAN 列表
    pub san: Vec<String>,
    /// 叶子证书 SHA-256 指纹（`AA:BB:...`），**不是私钥**
    pub fingerprint_sha256: String,
    /// 是否已过期（过期证书仍会加载，只是这个标记为 true）
    pub expired: bool,
    /// 上次加载 / 签发失败原因
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl CertInfo {
    /// 是否已过期
    pub fn is_expired(&self) -> bool {
        self.expired
    }

    /// 是否在 `days` 天内到期（含已过期）
    pub fn expires_within(&self, days: i64) -> bool {
        self.days_remaining <= days
    }
}

// ---------------------------------------------------------------------------
// 纯函数工具：域名规范化 / 目录编码 / 时间格式化 / 指纹
// ---------------------------------------------------------------------------

/// 校验并规范化「部署域名」。
///
/// 允许：普通 DNS 名、以 `*.` 开头的通配域名。
/// 拒绝：空串、路径分隔符、`..`、多余 `*`、非法字符、超长标签。
fn normalize_domain(domain: &str) -> Result<String> {
    let raw = domain.trim();
    if raw.is_empty() {
        bail!("域名不能为空");
    }
    let lower = raw.trim_end_matches('.').to_ascii_lowercase();
    if lower.is_empty() {
        bail!("域名不能为空");
    }
    if lower.len() > 253 {
        bail!("域名过长（>{lower}，最多 253 字节）");
    }
    let body = match lower.strip_prefix("*.") {
        Some(rest) => {
            if rest.split('.').count() < 2 {
                bail!("通配域名过于宽泛：{lower}（至少形如 *.example.com）");
            }
            rest
        }
        None => lower.as_str(),
    };
    if body.contains('*') {
        bail!("`*` 只能作为域名开头的 `*.` 前缀：{lower}");
    }
    for label in body.split('.') {
        if label.is_empty() {
            bail!("域名包含空标签：{lower}");
        }
        if label.len() > 63 {
            bail!("域名标签过长：{lower}");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            bail!("域名包含非法字符：{lower}");
        }
        if label.starts_with('-') || label.ends_with('-') {
            bail!("域名标签不能以 `-` 开头或结尾：{lower}");
        }
    }
    Ok(lower)
}

/// 规范化客户端送来的 SNI；不合法直接视为「不匹配」。
fn normalize_sni(server_name: &str) -> Option<String> {
    let name = server_name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    // 客户端送来的 SNI 不该带通配符
    if name.starts_with("*.") || name.contains('*') {
        return None;
    }
    let lower = name.to_ascii_lowercase();
    if lower.contains("..")
        || !lower
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
    {
        return None;
    }
    Some(lower)
}

/// 通配证书能覆盖的候选键：`a.example.com` → `*.example.com`。
///
/// 只替换**最左边一个**标签，因此 `*.example.com` 不会匹配
/// `example.com`（无标签可替换）也不会匹配 `a.b.example.com`（b 保留在后缀里）。
fn wildcard_candidate(name: &str) -> Option<String> {
    let (label, rest) = name.split_once('.')?;
    if label.is_empty() || label.contains('*') {
        return None;
    }
    Some(format!("*.{rest}"))
}

/// 域名目录名编码（Windows 文件名不能含 `*`）
fn dir_name_for(domain: &str) -> String {
    match domain.strip_prefix("*.") {
        Some(rest) => format!("{WILDCARD_DIR_PREFIX}{rest}"),
        None => domain.to_owned(),
    }
}

/// 目录名解码回域名
fn domain_from_dir_name(name: &str) -> String {
    match name.strip_prefix(WILDCARD_DIR_PREFIX) {
        Some(rest) => format!("*.{rest}"),
        None => name.to_owned(),
    }
}

/// 当前 Unix 时间戳（秒）
fn now_unix() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

/// Unix 秒 → 民用历（Howard Hinnant 算法）
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
    let hour = (rem / 3600) as u32;
    let minute = ((rem % 3600) / 60) as u32;
    let second = (rem % 60) as u32;
    (year, m, d, hour, minute, second)
}

/// Unix 秒 → `YYYY-MM-DDTHH:MM:SSZ`
fn rfc3339_from_unix(secs: i64) -> String {
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// 距离 `not_after` 还有多少整天；已过期返回负数（至少 -1）。
fn days_until(not_after: i64) -> i64 {
    let diff = not_after - now_unix();
    if diff >= 0 {
        diff / 86_400
    } else {
        // 只要过期就让结果为负，避免「刚过期 1 秒」显示 0 天
        -((-diff + 86_399) / 86_400)
    }
}

/// 叶子证书 DER 的 SHA-256 指纹，`AA:BB:...` 形式
fn fingerprint_sha256(der: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    let bytes = digest.as_ref();
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{b:02X}"));
    }
    out
}

/// 把错误信息压成可落盘的短文本：剔除 PEM 块、截断长度。
///
/// 私钥内容只可能以 PEM 形式出现，这一层是「万一有人把 PEM 拼进错误信息」的兜底。
fn sanitize_error(message: &str) -> String {
    let mut out = String::new();
    let mut in_pem = false;
    for line in message.lines() {
        let t = line.trim();
        if t.starts_with("-----BEGIN") {
            // 进入 PEM 块：标记与其后的 base64 正文全部丢弃
            in_pem = true;
            continue;
        }
        if t.starts_with("-----END") {
            in_pem = false;
            continue;
        }
        if in_pem || t.starts_with("PRIVATE KEY") {
            continue;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(t);
    }
    let trimmed = out.trim();
    let clipped: String = trimmed.chars().take(400).collect();
    if clipped.chars().count() < trimmed.chars().count() {
        format!("{clipped}…")
    } else {
        clipped
    }
}

// ---------------------------------------------------------------------------
// X.509 解析与链校验
// ---------------------------------------------------------------------------

/// 从 DER 里抽出的、校验与展示需要的最小信息集。
struct ParsedCert {
    issuer: String,
    issuer_raw: Vec<u8>,
    subject_raw: Vec<u8>,
    not_before: i64,
    not_after: i64,
    san: Vec<String>,
    is_ca: Option<bool>,
    self_issued: bool,
}

fn parse_cert_der(der: &[u8]) -> Result<ParsedCert> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|_| anyhow!("证书不是合法的 X.509 DER 编码"))?;
    let mut san = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            match name {
                x509_parser::extensions::GeneralName::DNSName(n) => san.push((*n).to_string()),
                x509_parser::extensions::GeneralName::IPAddress(bytes) => {
                    if let Some(ip) = format_ip(bytes) {
                        san.push(ip);
                    }
                }
                _ => {}
            }
        }
    }
    if san.is_empty() {
        // 没有 SAN 的老式证书退回 CN，便于管理页展示
        if let Some(cn) = cert.subject().iter_common_name().next() {
            if let Ok(text) = cn.as_str() {
                san.push(text.to_string());
            }
        }
    }
    let issuer_raw = cert.issuer().as_raw().to_vec();
    let subject_raw = cert.subject().as_raw().to_vec();
    let self_issued = issuer_raw == subject_raw;
    let is_ca = cert
        .basic_constraints()
        .ok()
        .flatten()
        .map(|ext| ext.value.ca);
    Ok(ParsedCert {
        issuer: cert.issuer().to_string(),
        issuer_raw,
        subject_raw,
        not_before: cert.tbs_certificate.validity.not_before.timestamp(),
        not_after: cert.tbs_certificate.validity.not_after.timestamp(),
        san,
        is_ca,
        self_issued,
    })
}

fn format_ip(bytes: &[u8]) -> Option<String> {
    match bytes.len() {
        4 => Some(std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()),
        16 => {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(bytes);
            Some(std::net::Ipv6Addr::from(buf).to_string())
        }
        _ => None,
    }
}

/// 链完整性校验（结构级）：
///
/// - 单张证书必须是自签的（否则就是在缺少中间证书）；
/// - 多张证书时，相邻两张必须是「子证书的签发者 == 父证书的持有者」；
/// - 链上的非叶子证书不能显式声明 `CA=false`。
///
/// 签名本身不在这里验证（我们不是信任库，信任判断交给客户端）；
/// 这里只保证「上传的链是连得上的」，避免把残缺链部署出去。
fn verify_chain_links(chain: &[ParsedCert]) -> Result<()> {
    if chain.is_empty() {
        bail!("证书链为空：{} 至少要包含叶子证书", CERT_FILE);
    }
    if chain.len() == 1 {
        if !chain[0].self_issued {
            bail!(
                "证书链不完整：叶子证书由「{}」签发，但 {} 里没有对应的中间证书（请上传 fullchain）",
                chain[0].issuer,
                CERT_FILE
            );
        }
        return Ok(());
    }
    for i in 0..chain.len() - 1 {
        let child = &chain[i];
        let parent = &chain[i + 1];
        if child.issuer_raw != parent.subject_raw {
            bail!(
                "证书链不完整或顺序错误：第 {} 张证书的签发者「{}」与第 {} 张证书的持有者不匹配",
                i + 1,
                child.issuer,
                i + 2
            );
        }
        if parent.is_ca == Some(false) {
            bail!(
                "证书链不完整：第 {} 张证书不是 CA 证书（basicConstraints CA=false）",
                i + 2
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 证书表（不可变快照）
// ---------------------------------------------------------------------------

/// 一张已加载的证书：对外信息 + rustls 需要的签名材料。
struct CertEntry {
    info: CertInfo,
    key: Arc<CertifiedKey>,
}

impl fmt::Debug for CertEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertEntry")
            .field("domain", &self.info.domain)
            .field("source", &self.info.source)
            .field("fingerprint_sha256", &self.info.fingerprint_sha256)
            // 私钥（Arc<dyn SigningKey>）永不参与 Debug 输出
            .field("private_key", &"<redacted>")
            .finish()
    }
}

/// 某个时刻的完整证书表快照（不可变，替换而非原地修改）。
#[derive(Clone, Default)]
struct CertTable {
    entries: BTreeMap<String, Arc<CertEntry>>,
}

impl CertTable {
    fn insert(&mut self, entry: Arc<CertEntry>) {
        self.entries.insert(entry.info.domain.clone(), entry);
    }

    fn remove(&mut self, domain: &str) -> bool {
        self.entries.remove(domain).is_some()
    }

    fn get(&self, domain: &str) -> Option<Arc<CertEntry>> {
        self.entries.get(domain).cloned()
    }

    /// SNI 查找：精确匹配优先，其次单标签通配。
    fn lookup_sni(&self, server_name: &str) -> Option<Arc<CertifiedKey>> {
        let name = normalize_sni(server_name)?;
        if let Some(entry) = self.entries.get(&name) {
            return Some(entry.key.clone());
        }
        let candidate = wildcard_candidate(&name)?;
        self.entries.get(&candidate).map(|entry| entry.key.clone())
    }

    fn infos(&self) -> Vec<CertInfo> {
        self.entries.values().map(|e| e.info.clone()).collect()
    }

    fn domains(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }
}

/// 热替换容器：`RwLock<Arc<CertTable>>`，与 `ArcSwap` 等价的效果但零额外依赖。
#[derive(Default)]
struct CertIndex {
    table: RwLock<Arc<CertTable>>,
}

impl CertIndex {
    fn snapshot(&self) -> Arc<CertTable> {
        match self.table.read() {
            Ok(guard) => guard.clone(),
            // 某个线程恐慌留下的中毒锁：数据本身仍是完整的，继续用
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn update(&self, mutate: impl FnOnce(&mut CertTable)) {
        let mut guard = match self.table.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut next = (**guard).clone();
        mutate(&mut next);
        *guard = Arc::new(next);
    }

    /// 只改某张证书的展示信息（不碰私钥材料）
    fn update_info(&self, domain: &str, mutate: impl FnOnce(&mut CertInfo)) {
        let mut guard = match self.table.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut next = (**guard).clone();
        if let Some(entry) = next.entries.get(domain).cloned() {
            let mut info = entry.info.clone();
            mutate(&mut info);
            next.entries.insert(
                domain.to_owned(),
                Arc::new(CertEntry {
                    info,
                    key: entry.key.clone(),
                }),
            );
            *guard = Arc::new(next);
        }
    }
}

impl fmt::Debug for CertIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertIndex")
            .field("domains", &self.snapshot().domains())
            .field("private_keys", &"<redacted>")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// SNI 路由
// ---------------------------------------------------------------------------

/// 按 ClientHello 的 SNI 选择证书。
///
/// 未匹配任何已部署域名（含客户端不发 SNI）时返回 `None`，握手被拒绝，
/// **不会退回默认证书**。
pub struct SniResolver {
    index: Arc<CertIndex>,
}

impl SniResolver {
    /// 当前部署的域名（含通配）
    pub fn domains(&self) -> Vec<String> {
        self.index.snapshot().domains()
    }

    /// 证书数量
    pub fn len(&self) -> usize {
        self.index.snapshot().entries.len()
    }

    /// 是否没有可用证书（此时任何握手都会被拒绝）
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SniResolver")
            .field("domains", &self.domains())
            .field("private_keys", &"<redacted>")
            .finish()
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let Some(server_name) = client_hello.server_name() else {
            debug!("ClientHello 未携带 SNI，拒绝握手（不提供默认证书）");
            return None;
        };
        let resolved = self.index.snapshot().lookup_sni(server_name);
        if resolved.is_none() {
            debug!(sni = %server_name, "SNI 未匹配任何已部署证书，拒绝握手");
        }
        resolved
    }
}

// ---------------------------------------------------------------------------
// 证书存储
// ---------------------------------------------------------------------------

/// 证书存储：`<root>/<domain>/{cert.pem,key.pem,meta.json}` 的读写与内存索引。
///
/// 所有方法都是**同步文件 IO**（单个证书目录只有几个小文件）。管理接口里如果
/// 在意阻塞，请在外层用 `tokio::task::spawn_blocking` 包一层。
pub struct CertificateStore {
    root: PathBuf,
    index: Arc<CertIndex>,
    io: Mutex<()>,
}

impl fmt::Debug for CertificateStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateStore")
            .field("root", &self.root)
            .field("domains", &self.domains())
            .field("private_keys", &"<redacted>")
            .finish()
    }
}

impl CertificateStore {
    /// 打开（或创建）证书根目录，并加载其中已有的全部证书。
    ///
    /// 单张证书加载失败不会中断整体加载：会打 `warn` 并把原因写进该域名的
    /// `meta.json.last_error`。
    pub fn open(root: impl Into<PathBuf>) -> Result<Arc<Self>> {
        let root = root.into();
        std::fs::create_dir_all(&root)
            .with_context(|| format!("无法创建证书目录 {}", root.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700));
        }
        let store = Arc::new(Self {
            root,
            index: Arc::new(CertIndex::default()),
            io: Mutex::new(()),
        });
        store.reload()?;
        Ok(store)
    }

    /// 证书根目录
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// 该域名对应的证书目录
    pub fn domain_dir(&self, domain: &str) -> PathBuf {
        self.root.join(dir_name_for(domain))
    }

    /// 从磁盘重建整张证书表（热替换；已有连接不受影响）。
    ///
    /// 返回成功加载的证书数量。单张证书失败只记 `last_error`，不影响其它域名。
    pub fn reload(&self) -> Result<usize> {
        let mut table = CertTable::default();
        let mut failures: Vec<(String, String)> = Vec::new();
        {
            let _guard = self.lock_io();
            let read = std::fs::read_dir(&self.root)
                .with_context(|| format!("无法读取证书目录 {}", self.root.display()))?;
            for entry in read {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(err) => {
                        warn!("遍历证书目录时出错：{err}");
                        continue;
                    }
                };
                let file_type = match entry.file_type() {
                    Ok(t) => t,
                    Err(err) => {
                        warn!("读取 {} 的类型失败：{err}", entry.path().display());
                        continue;
                    }
                };
                if !file_type.is_dir() {
                    continue;
                }
                let dir_name = entry.file_name().to_string_lossy().to_string();
                let domain = domain_from_dir_name(&dir_name);
                match self.load_entry(&domain) {
                    Ok(loaded) => table.insert(loaded),
                    Err(err) => {
                        warn!(domain = %domain, "证书加载失败：{err:#}");
                        failures.push((domain, format!("{err:#}")));
                    }
                }
            }
        }
        let count = table.entries.len();
        self.index.update(|current| *current = table);
        // 不持锁再写 meta.json（record_error 自己会取 io 锁）
        for (domain, err) in failures {
            let _ = self.record_error(&domain, &err);
        }
        Ok(count)
    }

    /// 列出所有已加载证书（按域名排序）。**不含私钥。**
    pub fn list(&self) -> Vec<CertInfo> {
        self.index.snapshot().infos()
    }

    /// 查询单个域名（支持通配域名原样查询）
    pub fn get(&self, domain: &str) -> Option<CertInfo> {
        let domain = normalize_domain(domain).ok()?;
        self.index.snapshot().get(&domain).map(|e| e.info.clone())
    }

    /// 是否已部署该域名
    pub fn contains(&self, domain: &str) -> bool {
        self.get(domain).is_some()
    }

    /// 已部署的域名列表
    pub fn domains(&self) -> Vec<String> {
        self.index.snapshot().domains()
    }

    /// 绑定到当前证书表的 SNI 解析器（`TlsListener` 用它）。
    ///
    /// 解析器与存储共享同一份索引，因此后续 `put` / `remove` 立即生效。
    pub fn resolver(&self) -> Arc<SniResolver> {
        Arc::new(SniResolver {
            index: self.index.clone(),
        })
    }

    /// 写入（或覆盖）一张证书：先校验，再落盘，最后热替换内存索引。
    ///
    /// 校验失败时磁盘与内存都不会被改动。
    pub fn put(
        &self,
        domain: &str,
        cert_pem: &str,
        key_pem: &str,
        source: CertSource,
    ) -> Result<CertInfo> {
        let domain = normalize_domain(domain)?;
        let entry = self.build_entry(
            &domain,
            cert_pem.as_bytes(),
            key_pem.as_bytes(),
            source,
            None,
        )?;
        let dir = self.domain_dir(&domain);
        let meta = CertMeta {
            source,
            issuer: entry.info.issuer.clone(),
            not_before: entry.info.not_before.clone(),
            not_after: entry.info.not_after.clone(),
            san: entry.info.san.clone(),
            fingerprint_sha256: entry.info.fingerprint_sha256.clone(),
            last_error: None,
        };
        {
            let _guard = self.lock_io();
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("无法创建证书目录 {}", dir.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            }
            // 先写私钥（0600），再写证书链，最后写元数据
            write_atomic(&dir.join(KEY_FILE), key_pem.as_bytes(), true)?;
            write_atomic(&dir.join(CERT_FILE), cert_pem.as_bytes(), false)?;
            write_atomic(
                &dir.join(META_FILE),
                &serde_json::to_vec_pretty(&meta).context("序列化 meta.json 失败")?,
                false,
            )?;
        }
        self.index.update(|table| table.insert(entry.clone()));
        info!(domain = %domain, source = %source, "证书已部署并热加载");
        Ok(entry.info.clone())
    }

    /// 从文件写入证书
    pub fn put_files(
        &self,
        domain: &str,
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
        source: CertSource,
    ) -> Result<CertInfo> {
        let cert_path = cert_path.as_ref();
        let key_path = key_path.as_ref();
        let cert_pem = std::fs::read_to_string(cert_path)
            .with_context(|| format!("读取证书失败 {}", cert_path.display()))?;
        let key_pem = std::fs::read_to_string(key_path)
            .with_context(|| format!("读取私钥失败 {}", key_path.display()))?;
        self.put(domain, &cert_pem, &key_pem, source)
    }

    /// 生成自签证书并直接部署（`source = self-signed`，仅测试用途）。
    pub fn put_self_signed(&self, domain: &str) -> Result<CertInfo> {
        let (cert_pem, key_pem) = generate_self_signed(domain)?;
        self.put(domain, &cert_pem, &key_pem, CertSource::SelfSigned)
    }

    /// 删除证书（内存 + 磁盘目录）。返回删除前是否存在。
    pub fn remove(&self, domain: &str) -> Result<bool> {
        let domain = normalize_domain(domain)?;
        let dir = self.domain_dir(&domain);
        let existed = self.index.snapshot().get(&domain).is_some();
        {
            let _guard = self.lock_io();
            if dir.exists() {
                std::fs::remove_dir_all(&dir)
                    .with_context(|| format!("删除证书目录失败 {}", dir.display()))?;
            }
        }
        self.index.update(|table| {
            table.remove(&domain);
        });
        if existed {
            info!(domain = %domain, "证书已移除");
        }
        Ok(existed)
    }

    /// 记录「上次错误」到该域名的 `meta.json`（如 ACME 续期失败）。
    ///
    /// 只更新已存在的 `meta.json`，不会凭空创建目录；**保留其它模块
    /// （如 ACME）写进去的附加字段**，只增删 `last_error`。
    pub fn record_error(&self, domain: &str, message: &str) -> Result<()> {
        let domain = normalize_domain(domain)?;
        self.patch_meta(&domain, Some(sanitize_error(message)))
    }

    /// 清除「上次错误」
    pub fn clear_error(&self, domain: &str) -> Result<()> {
        let domain = normalize_domain(domain)?;
        self.patch_meta(&domain, None)
    }

    /// 只改 `meta.json` 里的 `last_error` 字段，其余键原样保留。
    fn patch_meta(&self, domain: &str, last_error: Option<String>) -> Result<()> {
        let meta_path = self.domain_dir(domain).join(META_FILE);
        if !meta_path.exists() {
            return Ok(());
        }
        let mut value: serde_json::Value = std::fs::read(&meta_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
        let Some(map) = value.as_object_mut() else {
            return Ok(());
        };
        match &last_error {
            Some(text) => {
                if map.get("last_error").and_then(|v| v.as_str()) == Some(text.as_str()) {
                    return Ok(());
                }
                map.insert(
                    "last_error".to_owned(),
                    serde_json::Value::String(text.clone()),
                );
            }
            None => {
                if map.remove("last_error").is_none() {
                    return Ok(());
                }
            }
        }
        let bytes = serde_json::to_vec_pretty(&value).context("序列化 meta.json 失败")?;
        let _guard = self.lock_io();
        write_atomic(&meta_path, &bytes, false)?;
        self.index
            .update_info(domain, |info| info.last_error = last_error);
        Ok(())
    }

    // -- 内部实现 ----------------------------------------------------------

    fn lock_io(&self) -> std::sync::MutexGuard<'_, ()> {
        match self.io.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn read_meta(&self, domain: &str) -> CertMeta {
        let path = self.domain_dir(domain).join(META_FILE);
        std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<CertMeta>(&bytes).ok())
            .unwrap_or_default()
    }

    fn load_entry(&self, domain: &str) -> Result<Arc<CertEntry>> {
        let dir = self.domain_dir(domain);
        let cert_path = locate_file(&dir, &CERT_ALIASES)
            .with_context(|| format!("{} 里找不到证书文件（{}）", dir.display(), CERT_FILE))?;
        let key_path = locate_file(&dir, &KEY_ALIASES)
            .with_context(|| format!("{} 里找不到私钥文件（{}）", dir.display(), KEY_FILE))?;
        let cert_pem = std::fs::read(&cert_path)
            .with_context(|| format!("读取证书失败 {}", cert_path.display()))?;
        let key_pem = std::fs::read(&key_path)
            .with_context(|| format!("读取私钥失败 {}", key_path.display()))?;
        let meta = self.read_meta(domain);
        self.build_entry(domain, &cert_pem, &key_pem, meta.source, meta.last_error)
    }

    /// 解析 + 校验 + 构造签名材料。**任何错误信息都不包含私钥内容。**
    fn build_entry(
        &self,
        domain: &str,
        cert_pem: &[u8],
        key_pem: &[u8],
        source: CertSource,
        last_error: Option<String>,
    ) -> Result<Arc<CertEntry>> {
        let chain = parse_pem_chain(cert_pem).context("解析证书 PEM 失败")?;
        if chain.is_empty() {
            bail!("{} 里没有找到 PEM 证书", CERT_FILE);
        }
        let parsed = chain
            .iter()
            .map(|der| parse_cert_der(der.as_ref()))
            .collect::<Result<Vec<_>>>()?;
        verify_chain_links(&parsed)?;

        let key = parse_pem_key(key_pem).context("解析私钥 PEM 失败")?;
        let provider = crypto_provider();
        let certified =
            CertifiedKey::from_der(chain.clone(), key, &provider).map_err(|err| match err {
                rustls::Error::InconsistentKeys(_) => {
                    anyhow!("证书与私钥不匹配：私钥不属于该证书")
                }
                other => anyhow!("证书或私钥无法加载：{other}"),
            })?;

        let leaf = &parsed[0];
        let days_remaining = days_until(leaf.not_after);
        let info = CertInfo {
            domain: domain.to_owned(),
            source,
            issuer: leaf.issuer.clone(),
            not_before: rfc3339_from_unix(leaf.not_before),
            not_after: rfc3339_from_unix(leaf.not_after),
            days_remaining,
            san: leaf.san.clone(),
            fingerprint_sha256: fingerprint_sha256(chain[0].as_ref()),
            expired: days_remaining < 0,
            last_error,
        };
        if info.expired {
            warn!(domain = %domain, not_after = %info.not_after, "证书已过期，仍加载但标记为过期");
        }
        Ok(Arc::new(CertEntry {
            info,
            key: Arc::new(certified),
        }))
    }
}

fn locate_file(dir: &Path, candidates: &[&str]) -> Option<PathBuf> {
    for name in candidates {
        let path = dir.join(name);
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

fn parse_pem_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut cursor = std::io::Cursor::new(pem);
    let mut chain = Vec::new();
    for item in rustls_pemfile::certs(&mut cursor) {
        chain.push(item.context("PEM 证书解析失败")?);
    }
    Ok(chain)
}

fn parse_pem_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut cursor = std::io::Cursor::new(pem);
    match rustls_pemfile::private_key(&mut cursor).context("PEM 私钥解析失败")? {
        Some(key) => Ok(key),
        None => bail!(
            "{} 里没有找到可用的私钥（支持 PKCS#8 / PKCS#1 / SEC1）",
            KEY_FILE
        ),
    }
}

/// 显式使用 ring provider，绝不依赖进程级默认值（避免与其它模块互相覆盖）。
fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn write_atomic(path: &Path, data: &[u8], secret: bool) -> Result<()> {
    #[cfg(not(unix))]
    let _ = secret; // Windows 下没有 POSIX 权限位，退回默认 ACL
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "cert".to_owned());
    let tmp = path.with_file_name(format!(".{file_name}.tmp"));

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if secret { 0o600 } else { 0o644 });
    }
    let mut file = options
        .open(&tmp)
        .with_context(|| format!("无法创建临时文件 {}", tmp.display()))?;
    file.write_all(data)
        .with_context(|| format!("写入临时文件失败 {}", tmp.display()))?;
    file.sync_all().ok();
    drop(file);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if secret { 0o600 } else { 0o644 };
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("设置权限失败 {}", tmp.display()))?;
    }

    // Windows 上 rename 到已存在的文件会失败，先删目标
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    std::fs::rename(&tmp, path).with_context(|| format!("写入失败 {}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 自签证书生成
// ---------------------------------------------------------------------------

/// 为 `domain` 生成一张自签证书，返回 `(cert_pem, key_pem)`（PKCS#8 私钥）。
///
/// 仅用于测试 / 内网自用：写入存储时请用 [`CertSource::SelfSigned`]，
/// 管理页据此提示「浏览器会报警告」。
pub fn generate_self_signed(domain: &str) -> Result<(String, String)> {
    let domain = normalize_domain(domain)?;
    let mut params = rcgen::CertificateParams::new(vec![domain.clone()])
        .map_err(|e| anyhow!("构造自签证书参数失败：{e}"))?;

    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, domain.clone());
    params.distinguished_name = dn;
    params.is_ca = rcgen::IsCa::NoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

    let now = now_unix();
    let (y, m, d, ..) = civil_from_unix(now - 86_400);
    params.not_before = rcgen::date_time_ymd(y as i32, m as u8, d as u8);
    let (y, m, d, ..) = civil_from_unix(now + 365 * 86_400);
    params.not_after = rcgen::date_time_ymd(y as i32, m as u8, d as u8);

    let key_pair = rcgen::KeyPair::generate().map_err(|e| anyhow!("生成私钥失败：{e}"))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| anyhow!("生成自签证书失败：{e}"))?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}

// ---------------------------------------------------------------------------
// HTTPS 监听器
// ---------------------------------------------------------------------------

/// [`TlsListener`] 的可调项。
#[derive(Debug, Clone)]
pub struct TlsListenerConfig {
    /// 单次握手超时（超时即断开，防慢速握手）
    pub handshake_timeout: Duration,
    /// ALPN 宣告列表，默认只有 `http/1.1`
    pub alpn_protocols: Vec<Vec<u8>>,
}

impl Default for TlsListenerConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            alpn_protocols: vec![ALPN_HTTP11.to_vec()],
        }
    }
}

/// 一次成功握手的结果：解密后的流 + 上层做路由可能需要的信息。
pub struct TlsSession {
    /// 已解密的流（HTTP 解析在上层）
    pub stream: TlsStream<TcpStream>,
    /// 对端地址
    pub peer: std::net::SocketAddr,
    /// 协商到的 SNI（客户端没发则为 `None`；能走到这里说明已匹配到证书）
    pub server_name: Option<String>,
    /// 协商到的 ALPN
    pub alpn: Option<String>,
}

impl fmt::Debug for TlsSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsSession")
            .field("peer", &self.peer)
            .field("server_name", &self.server_name)
            .field("alpn", &self.alpn)
            .finish_non_exhaustive()
    }
}

/// HTTPS 监听器：在已绑定的 TCP 监听器上做 TLS 握手。
///
/// 握手失败的连接只影响它自己（返回 `Err` 并计数），accept 循环可以继续。
pub struct TlsListener {
    acceptor: TlsAcceptor,
    config: Arc<ServerConfig>,
    resolver: Arc<SniResolver>,
    handshake_timeout: Duration,
    accepted: AtomicU64,
    rejected: AtomicU64,
    active: Arc<AtomicU64>,
}

impl TlsListener {
    /// 用默认配置（ALPN `http/1.1`、握手超时 10s）创建
    pub fn new(resolver: Arc<SniResolver>) -> Result<Arc<Self>> {
        Self::with_config(resolver, TlsListenerConfig::default())
    }

    /// 自定义配置创建
    pub fn with_config(resolver: Arc<SniResolver>, config: TlsListenerConfig) -> Result<Arc<Self>> {
        let resolver_trait: Arc<dyn ResolvesServerCert> = resolver.clone();
        let mut server_config = ServerConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()
            .context("rustls 协议版本初始化失败")?
            .with_no_client_auth()
            .with_cert_resolver(resolver_trait);
        server_config.alpn_protocols = config.alpn_protocols;
        let server_config = Arc::new(server_config);
        Ok(Arc::new(Self {
            acceptor: TlsAcceptor::from(server_config.clone()),
            config: server_config,
            resolver,
            handshake_timeout: config.handshake_timeout,
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            active: Arc::new(AtomicU64::new(0)),
        }))
    }

    /// 底层 rustls 配置（`TlsAcceptor::from(config.clone())` 可复用）
    pub fn server_config(&self) -> Arc<ServerConfig> {
        self.config.clone()
    }

    /// 与当前证书表绑定的 SNI 解析器
    pub fn resolver(&self) -> &Arc<SniResolver> {
        &self.resolver
    }

    /// 成功握手数
    pub fn accepted_handshakes(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }

    /// 被拒绝 / 失败的握手数（未匹配 SNI、协议不兼容、超时等）
    pub fn rejected_handshakes(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }

    /// 经 [`Self::serve`] 处理中的连接数
    pub fn active_connections(&self) -> u64 {
        self.active.load(Ordering::Relaxed)
    }

    /// 绑定监听端口
    pub async fn bind<A: ToSocketAddrs>(&self, addr: A) -> Result<TcpListener> {
        let listener = TcpListener::bind(addr)
            .await
            .context("HTTPS 监听绑定失败")?;
        if let Ok(local) = listener.local_addr() {
            info!("HTTPS 监听已绑定 {local}");
        }
        Ok(listener)
    }

    /// 从已绑定的监听器接一个 TCP 连接并完成握手。
    ///
    /// 握手失败（含 SNI 未匹配）返回 `Err`，调用方据此继续 accept 即可。
    pub async fn accept(&self, listener: &TcpListener) -> Result<TlsSession> {
        let (stream, peer) = listener.accept().await.context("HTTPS accept 失败")?;
        let _ = stream.set_nodelay(true);
        match self.handshake(stream).await {
            Ok(session) => Ok(session),
            Err(err) => {
                debug!(peer = %peer, "TLS 握手未完成：{err:#}");
                Err(err)
            }
        }
    }

    /// 对一条已建立的 TCP 连接做 TLS 握手（不做 accept）。
    pub async fn handshake(&self, stream: TcpStream) -> Result<TlsSession> {
        let peer = stream.peer_addr().context("读取对端地址失败")?;
        let fut = self.acceptor.accept(stream);
        let tls = match tokio::time::timeout(self.handshake_timeout, fut).await {
            Ok(Ok(tls)) => tls,
            Ok(Err(err)) => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                bail!("TLS 握手失败：{err}");
            }
            Err(_) => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                bail!("TLS 握手超时（{:?}）", self.handshake_timeout);
            }
        };
        self.accepted.fetch_add(1, Ordering::Relaxed);
        let (_, connection) = tls.get_ref();
        let server_name = connection.server_name().map(str::to_owned);
        let alpn = connection
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned());
        Ok(TlsSession {
            stream: tls,
            peer,
            server_name,
            alpn,
        })
    }

    /// accept 循环：每条连接握手后交给 `handler`（在独立任务里跑）。
    ///
    /// 握手失败的连接不会打断循环；`cancel` 变为 `true` 时退出并等待在途任务结束。
    pub async fn serve<F, Fut>(
        self: Arc<Self>,
        listener: TcpListener,
        mut cancel: watch::Receiver<bool>,
        handler: F,
    ) where
        F: Fn(TlsSession) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let mut connections: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = cancel.changed() => break,
                _ = connections.join_next(), if !connections.is_empty() => {}
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, peer)) => {
                            let _ = stream.set_nodelay(true);
                            let this = self.clone();
                            let handler = handler.clone();
                            connections.spawn(async move {
                                match this.handshake(stream).await {
                                    Ok(session) => {
                                        this.active.fetch_add(1, Ordering::Relaxed);
                                        let _guard = ActiveGuard(this.active.clone());
                                        handler(session).await;
                                    }
                                    Err(err) => debug!(peer = %peer, "TLS 握手未完成：{err:#}"),
                                }
                            });
                        }
                        Err(err) => {
                            warn!("HTTPS accept 失败：{err}");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }
        connections.shutdown().await;
        debug!("HTTPS accept 循环退出");
    }

    /// 绑定 + 启动 accept 循环，返回实际绑定地址与任务句柄。
    pub async fn bind_and_serve<A, F, Fut>(
        self: Arc<Self>,
        addr: A,
        cancel: watch::Receiver<bool>,
        handler: F,
    ) -> Result<(std::net::SocketAddr, JoinHandle<()>)>
    where
        A: ToSocketAddrs,
        F: Fn(TlsSession) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let listener = self.bind(addr).await?;
        let bound = listener.local_addr().context("读取绑定地址失败")?;
        let task = tokio::spawn(async move {
            self.serve(listener, cancel, handler).await;
        });
        Ok((bound, task))
    }
}

impl fmt::Debug for TlsListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsListener")
            .field("resolver", &self.resolver)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("accepted", &self.accepted_handshakes())
            .field("rejected", &self.rejected_handshakes())
            .finish()
    }
}

struct ActiveGuard(Arc<AtomicU64>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// 单元测试：纯函数（握手行为在 tests/tls.rs 里做集成验证）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_candidate_only_replaces_leftmost_label() {
        assert_eq!(
            wildcard_candidate("a.example.com").as_deref(),
            Some("*.example.com")
        );
        assert_eq!(wildcard_candidate("example.com").as_deref(), Some("*.com"));
        assert_eq!(
            wildcard_candidate("a.b.example.com").as_deref(),
            Some("*.b.example.com")
        );
        assert_eq!(wildcard_candidate("localhost"), None);
        assert_eq!(wildcard_candidate(".example.com"), None);
    }

    #[test]
    fn domain_validation_rejects_traversal_and_bad_wildcards() {
        assert_eq!(normalize_domain("A.Example.COM.").unwrap(), "a.example.com");
        assert_eq!(normalize_domain("*.example.com").unwrap(), "*.example.com");
        for bad in [
            "", "../etc", "a/b", "a\\b", "a..b", "a.*.b", "*", "*.com", "-a.com", "a-.com",
            "a b.com",
        ] {
            assert!(normalize_domain(bad).is_err(), "应当拒绝 {bad:?}");
        }
    }

    #[test]
    fn sni_normalization_rejects_wildcards_and_garbage() {
        assert_eq!(
            normalize_sni("A.Example.com.").as_deref(),
            Some("a.example.com")
        );
        assert_eq!(normalize_sni("*.example.com"), None);
        assert_eq!(normalize_sni("a..b"), None);
        assert_eq!(normalize_sni("a/b"), None);
        assert_eq!(normalize_sni(""), None);
    }

    #[test]
    fn dir_name_roundtrip_for_wildcard() {
        assert_eq!(dir_name_for("a.example.com"), "a.example.com");
        assert_eq!(dir_name_for("*.example.com"), "_wildcard_.example.com");
        assert_eq!(
            domain_from_dir_name("_wildcard_.example.com"),
            "*.example.com"
        );
        assert_eq!(domain_from_dir_name("a.example.com"), "a.example.com");
    }

    #[test]
    fn rfc3339_matches_known_timestamps() {
        assert_eq!(rfc3339_from_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_from_unix(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339_from_unix(1_800_000_000), "2027-01-15T08:00:00Z");
    }

    #[test]
    fn days_until_marks_expired_as_negative() {
        let now = now_unix();
        assert_eq!(days_until(now + 86_400 * 3), 3);
        assert_eq!(days_until(now + 1), 0);
        assert_eq!(days_until(now - 1), -1);
        assert_eq!(days_until(now - 86_400 * 2), -2);
    }

    #[test]
    fn sanitize_error_strips_pem_blocks() {
        let msg =
            "renew failed\n-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----";
        let out = sanitize_error(msg);
        assert!(!out.contains("BEGIN"));
        assert!(!out.contains("MIIEvQIBADANBg"));
        assert!(out.contains("renew failed"));
    }

    #[test]
    fn self_signed_generation_roundtrips_through_store() {
        let (cert_pem, key_pem) = generate_self_signed("*.example.com").unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
        // 生成的证书必须能被解析且链校验通过
        let chain = parse_pem_chain(cert_pem.as_bytes()).unwrap();
        assert_eq!(chain.len(), 1);
        let parsed = parse_cert_der(chain[0].as_ref()).unwrap();
        assert!(parsed.self_issued);
        assert!(parsed.san.iter().any(|s| s == "*.example.com"));
        verify_chain_links(&[parsed]).unwrap();
        // 私钥可被 rustls 接受，且与证书匹配
        let key = parse_pem_key(key_pem.as_bytes()).unwrap();
        CertifiedKey::from_der(chain, key, &crypto_provider()).unwrap();
    }
}
