//! HTTP 域名代理（对齐原版 nps `mode=httpProxy` + `Host` 域名绑定）。
//!
//! # 数据通路
//! ```text
//! 浏览器 --HTTP--> nps-server:http_proxy_port
//!   ① 读请求头（上限 64 KiB）→ 按 Host 查站点 → 按路径最长前缀选目标
//!   ② bridge.get_tunnel(client_id) → mux.open_stream()
//!   ③ 子流首帧：int32 LE 长度 + Link JSON（`ConnType="http"`；升级请求用
//!      `"tcp"` 让 npc 做纯字节透传，见下）
//!   ④ 把请求行/头/体**原始字节**流式写入子流（不整体缓冲）
//!   ⑤ 读响应：解析状态行/头判定结束方式，原始字节流式回写客户端
//!   ⑥ 升级（101 + Upgrade）→ 双向裸字节转发，不再解析 HTTP
//! ```
//!
//! 老 npc 侧：`ConnType == "http"` 时它会 `http.ReadRequest` 解析请求并转发到
//! `net.DialTimeout("tcp", link.Host)` 的目标，响应方向是原始字节拷贝。因此
//! 服务端只要保证"请求字节合法 + 每个请求一条独立子流"即可。
//!
//! WebSocket 使用 `ConnType == "tcp"`：原版 npc 的 `http` 分支会把升级后的
//! WebSocket 帧当作 HTTP 请求解析，导致双向消息失败（已在真实 npc 上复现）。
//! 改用 `tcp` 后 npc 只做 `Dial + 双向拷贝`，升级握手与后续帧全部原样透传。
//!
//! # 路由
//! - `Host` 头**去端口、大小写不敏感**匹配；`*.example.com` 形式支持通配。
//! - 命中站点后按路径前缀做**最长匹配**；未配置 `routes` 时用站点默认 `target`。
//!
//! # 边界与失败语义
//! - 请求头 > [`MAX_HEAD_BYTES`]：`431`，关闭连接。
//! - 未匹配域名：`404`；客户端离线 / 建流失败 / 目标异常：`502`；
//!   站点并发超限：`503`。错误响应一律带 `Connection: close`。
//! - 请求体按 `Content-Length` / `chunked` 流式转发，不整体缓冲；
//!   响应体支持 `Content-Length` / `chunked` / 读到 EOF 三种结束方式。
//! - 客户端连接空闲 [`HttpProxyConfig::idle_timeout`] 后关闭；
//!   单个 HTTP 请求处理期间每个子流有一份超时保护，不会无限挂起。
//!
//! # 接线方式（本模块不触碰 `config.rs` / `server.rs`）
//! ```ignore
//! // 配置层已有 ServerConfig::http_sites: Vec<HttpSiteConfig>
//! let cfg = HttpProxyConfig::from_server_config(&server_config, "0.0.0.0:80");
//! let http = HttpSiteServer::new(bridge.clone(), cfg)?;
//! let (addr, task) = http.bind_and_serve(shutdown_rx).await?;
//! ```

use std::io;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use nps_legacy::mux::{MuxRecvHalf, MuxSendHalf};
use nps_legacy::Bridge;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, RwLock};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::config::{
    parse_addr, validate_host_port, HttpRoute, HttpSiteConfig as SiteConfig, TlsMode,
};

/// 请求/响应头允许的最大字节数（含终止空行）
pub const MAX_HEAD_BYTES: usize = 64 * 1024;
/// 单次转发缓冲（与 Go `common.PoolSizeCopy` 一致）
pub const COPY_BUF: usize = 32 * 1024;
/// 空闲等待下一个请求的上限
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// 读取响应头（目标处理慢）的上限
pub const RESPONSE_HEAD_TIMEOUT: Duration = Duration::from_secs(60);
/// mux 建流的上限（mux 自身是 120s，这里更早失败并返回 502）
pub const OPEN_STREAM_TIMEOUT: Duration = Duration::from_secs(15);
/// 每个站点默认的并发请求上限
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;

// `Host` 记录的路径路由直接复用 `crate::config::HttpRoute`
// （配置层已定义 `prefix` / `target_addr`），避免同一契约出现两份定义。

/// 一个 HTTP 域名站点（对应原版 `file.Host` 的可用子集）。
///
/// 字段是运行期视图：`target` 对应配置里的 `target_addr`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpSite {
    /// 域名（大小写不敏感；支持 `*.example.com` 通配）
    pub domain: String,
    /// 归属客户端 id（服务端 mux 会话按它获取）
    pub client_id: i32,
    /// 默认目标 `host:port`
    pub target: String,
    /// 路径前缀 → 目标（可多条，最长前缀优先）
    pub routes: Vec<HttpRoute>,
    /// 是否允许协议升级（WebSocket）
    pub websocket: bool,
}

impl HttpSite {
    pub fn new(domain: impl Into<String>, client_id: i32, target: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            client_id,
            target: target.into(),
            routes: Vec::new(),
            websocket: true,
        }
    }

    /// 从配置层结构转换（`target_addr` → `target`）。
    pub fn from_site_config(config: &SiteConfig) -> Self {
        Self {
            domain: config.domain.trim().to_owned(),
            client_id: config.client_id,
            target: config.target_addr.trim().to_owned(),
            routes: config.routes.clone(),
            websocket: config.websocket,
        }
    }

    /// 从服务端配置里挑出**纯 HTTP** 站点（`enabled` 且 `tls_mode == off`）。
    ///
    /// HTTPS / 证书相关站点由独立的 TLS 模块负责，本模块只做明文 HTTP。
    pub fn collect_http_sites(config: &crate::config::ServerConfig) -> Vec<HttpSite> {
        config
            .http_sites
            .iter()
            .filter(|site| site.enabled && site.tls_mode == TlsMode::Off)
            .map(HttpSite::from_site_config)
            .collect()
    }

    pub fn with_routes(mut self, routes: Vec<HttpRoute>) -> Self {
        self.routes = routes;
        self
    }

    pub fn with_websocket(mut self, websocket: bool) -> Self {
        self.websocket = websocket;
        self
    }

    /// 校验单条站点配置
    pub fn validate(&self) -> Result<()> {
        let domain = normalize_host(&self.domain);
        if domain.is_empty() || domain == "." {
            bail!("HTTP 站点的 domain 不能为空");
        }
        if self.client_id <= 0 {
            bail!("HTTP 站点 {} 的 client_id 必须为正数", self.domain);
        }
        validate_target(&self.target).with_context(|| {
            format!(
                "HTTP 站点 {} 的 target 非法: {:?}",
                self.domain, self.target
            )
        })?;
        for route in &self.routes {
            if route.prefix.trim().is_empty() {
                // 允许，但按 "/" 处理
            } else if !route.prefix.starts_with('/') {
                bail!(
                    "HTTP 站点 {} 的路由前缀必须以 '/' 开头: {:?}",
                    self.domain,
                    route.prefix
                );
            }
            validate_target(&route.target_addr).with_context(|| {
                format!(
                    "HTTP 站点 {} 的路由 {} 的 target 非法: {:?}",
                    self.domain, route.prefix, route.target_addr
                )
            })?;
        }
        Ok(())
    }
}

fn validate_target(target: &str) -> Result<()> {
    validate_host_port(target)
}

/// 一个站点的运行态：配置 + 并发计数。
#[derive(Debug)]
struct SiteEntry {
    site: HttpSite,
    active: Arc<AtomicUsize>,
}

/// 一次路由解析结果（拥有数据，便于跨 `await` 持有）。
#[derive(Debug, Clone)]
pub struct ResolvedSite {
    /// 命中的域名（配置原文）
    pub domain: String,
    pub client_id: i32,
    /// 命中的目标 `host:port`
    pub target: String,
    /// 命中的路径前缀
    pub prefix: String,
    pub websocket: bool,
    active: Arc<AtomicUsize>,
}

impl ResolvedSite {
    /// 尝试占用一个站点并发槽位；超过 `max` 返回 `None`。
    pub fn try_acquire(&self, max: usize) -> Option<SiteGuard> {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= max {
                return None;
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(SiteGuard {
                        active: self.active.clone(),
                    })
                }
                Err(actual) => current = actual,
            }
        }
    }

    /// 当前该站点的并发请求数
    pub fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

/// 站点并发槽位，Drop 时归还。
#[derive(Debug)]
pub struct SiteGuard {
    active: Arc<AtomicUsize>,
}

impl Drop for SiteGuard {
    fn drop(&mut self) {
        let _ = self
            .active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                Some(v.saturating_sub(1))
            });
    }
}

/// 服务端活跃连接计数守卫（任务被 abort 时也能正确归还）。
struct ConnCounter(Arc<AtomicU64>);

impl ConnCounter {
    fn new(counter: Arc<AtomicU64>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter)
    }
}

impl Drop for ConnCounter {
    fn drop(&mut self) {
        let _ = self
            .0
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }
}

/// 域名 → 站点 的路由表。
#[derive(Debug, Default)]
pub struct HttpSiteRouter {
    entries: Vec<SiteEntry>,
}

impl HttpSiteRouter {
    /// 用站点列表构建路由表；任何配置非法都会返回错误。
    ///
    /// 同一域名（规范化后）出现两次视为配置错误。
    pub fn new(sites: impl IntoIterator<Item = HttpSite>) -> Result<Self> {
        let mut router = Self {
            entries: Vec::new(),
        };
        for site in sites {
            router.insert(site)?;
        }
        Ok(router)
    }

    /// 追加一个站点。
    pub fn insert(&mut self, site: HttpSite) -> Result<()> {
        site.validate()?;
        let normalized = normalize_host(&site.domain);
        if self
            .entries
            .iter()
            .any(|e| normalize_host(&e.site.domain) == normalized)
        {
            bail!("HTTP 站点域名重复: {}", site.domain);
        }
        self.entries.push(SiteEntry {
            site,
            active: Arc::new(AtomicUsize::new(0)),
        });
        Ok(())
    }

    /// 插入或替换同域名站点（配置文件模式的 `host` 帧重复上报时使用）。
    ///
    /// 替换保留原有并发槽位计数，避免重连时正在转发的请求被"清零"。
    pub fn upsert(&mut self, site: HttpSite) -> Result<()> {
        site.validate()?;
        let normalized = normalize_host(&site.domain);
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| normalize_host(&e.site.domain) == normalized)
        {
            entry.site = site;
            return Ok(());
        }
        self.entries.push(SiteEntry {
            site,
            active: Arc::new(AtomicUsize::new(0)),
        });
        Ok(())
    }

    /// 移除一个域名（配置文件模式注销站点时使用）；返回是否真的存在。
    pub fn remove(&mut self, domain: &str) -> bool {
        let normalized = normalize_host(domain);
        let before = self.entries.len();
        self.entries
            .retain(|e| normalize_host(&e.site.domain) != normalized);
        self.entries.len() != before
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 已配置的域名（配置原文）
    pub fn domains(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|e| e.site.domain.as_str())
    }

    /// 按 `Host` 头 + 请求路径解析站点与目标。
    ///
    /// - `host` 会去掉端口、统一小写；
    /// - `path` 应与路由前缀同源（不含 query），未以 `/` 开头时补 `/`；
    /// - 多个规则命中时取**最长前缀**；未配置路由时回落到站点 `target`。
    pub fn resolve(&self, host: &str, path: &str) -> Option<ResolvedSite> {
        let host = normalize_host(host);
        if host.is_empty() {
            return None;
        }
        let entry = self
            .entries
            .iter()
            .find(|e| domain_matches(&e.site.domain, &host))?;

        let mut best_prefix: &str = "/";
        let mut best_target: &str = &entry.site.target;
        for route in &entry.site.routes {
            let prefix = normalize_prefix(&route.prefix);
            if path.starts_with(prefix) && prefix.len() > best_prefix.len() {
                best_prefix = prefix;
                best_target = &route.target_addr;
            }
        }

        Some(ResolvedSite {
            domain: entry.site.domain.clone(),
            client_id: entry.site.client_id,
            target: best_target.to_owned(),
            prefix: best_prefix.to_owned(),
            websocket: entry.site.websocket,
            active: entry.active.clone(),
        })
    }

    /// 当前并发总数（所有站点之和），用于指标/自检。
    pub fn active_total(&self) -> usize {
        self.entries
            .iter()
            .map(|e| e.active.load(Ordering::Acquire))
            .sum()
    }
}

/// 规范化 `Host`：去端口（含 IPv6 字面量）、去尾点、转小写。
pub fn normalize_host(host: &str) -> String {
    let host = host.trim();
    let host = if let Some(rest) = host.strip_prefix('[') {
        // IPv6 字面量：[::1]:8080 -> [::1]
        match rest.find(']') {
            Some(idx) => &host[..idx + 2],
            None => host,
        }
    } else {
        match host.rfind(':') {
            // 只剥掉最后一个冒号后的端口；裸 IPv6（多个冒号）不处理
            Some(idx) if !host[..idx].contains(':') => &host[..idx],
            _ => host,
        }
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_prefix(prefix: &str) -> &str {
    let trimmed = prefix.trim();
    if trimmed.is_empty() {
        "/"
    } else {
        trimmed
    }
}

fn domain_matches(pattern: &str, host: &str) -> bool {
    let pattern = normalize_host(pattern);
    if pattern.contains('*') {
        // 与原版 `GetInfoByHost` 一致：去掉 `*` 后做子串匹配
        let needle = pattern.replace('*', "");
        host.contains(&needle)
    } else {
        pattern == host
    }
}

/// 从请求目标里取路径（支持 absolute-form，去掉 query/fragment）。
pub fn request_path(uri: &str) -> &str {
    let rest = if let Some(after) = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"))
    {
        match after.find('/') {
            Some(idx) => &after[idx..],
            None => "/",
        }
    } else {
        uri
    };
    let end = rest.find(['?', '#']).unwrap_or(rest.len());
    let path = &rest[..end];
    if path.is_empty() {
        "/"
    } else {
        path
    }
}

/// HTTP 域名代理的运行配置。
#[derive(Debug, Clone)]
pub struct HttpProxyConfig {
    /// 监听地址（如 `0.0.0.0:80`；`127.0.0.1:0` 便于测试）
    pub listen_addr: String,
    /// 站点表
    pub sites: Vec<HttpSite>,
    /// 空闲超时（等待下一个请求）
    pub idle_timeout: Duration,
    /// 单站点并发请求上限
    pub max_connections: usize,
    /// 请求头大小上限
    pub max_head_bytes: usize,
}

impl Default for HttpProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:80".into(),
            sites: Vec::new(),
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_head_bytes: MAX_HEAD_BYTES,
        }
    }
}

impl HttpProxyConfig {
    /// 用服务端配置里的 HTTP 站点构建本模块的运行配置。
    ///
    /// `listen_addr` 对应原版 `http_proxy_ip:http_proxy_port`。
    pub fn from_server_config(
        config: &crate::config::ServerConfig,
        listen_addr: impl Into<String>,
    ) -> Self {
        Self {
            listen_addr: listen_addr.into(),
            sites: HttpSite::collect_http_sites(config),
            ..Default::default()
        }
    }

    pub fn validate(&self) -> Result<()> {
        parse_addr(&self.listen_addr)
            .with_context(|| format!("http_site listen_addr 非法: {:?}", self.listen_addr))?;
        if self.max_connections == 0 {
            bail!("http_site max_connections 必须大于 0");
        }
        if self.max_head_bytes == 0 {
            bail!("http_site max_head_bytes 必须大于 0");
        }
        let mut seen = std::collections::HashSet::new();
        for site in &self.sites {
            site.validate()?;
            let domain = normalize_host(&site.domain);
            if !seen.insert(domain.clone()) {
                bail!("HTTP 站点域名重复: {domain}");
            }
        }
        Ok(())
    }
}

/// HTTP 域名代理服务：监听端口 + 连接处理。
pub struct HttpSiteServer {
    bridge: Bridge,
    router: RwLock<HttpSiteRouter>,
    listen_addr: String,
    idle_timeout: Duration,
    max_connections: usize,
    max_head_bytes: usize,
    active_connections: Arc<AtomicU64>,
    served_requests: AtomicU64,
}

impl HttpSiteServer {
    /// 创建服务（不绑定端口）。
    pub fn new(bridge: Bridge, config: HttpProxyConfig) -> Result<Arc<Self>> {
        config.validate()?;
        let router = HttpSiteRouter::new(config.sites)?;
        Ok(Arc::new(Self {
            bridge,
            router: RwLock::new(router),
            listen_addr: config.listen_addr,
            idle_timeout: config.idle_timeout,
            max_connections: config.max_connections,
            max_head_bytes: config.max_head_bytes,
            active_connections: Arc::new(AtomicU64::new(0)),
            served_requests: AtomicU64::new(0),
        }))
    }

    /// 绑定 [`HttpProxyConfig::listen_addr`] 指定的端口。
    pub async fn bind(&self) -> Result<TcpListener> {
        let listener = TcpListener::bind(&self.listen_addr)
            .await
            .with_context(|| format!("HTTP 域名代理无法监听 {}", self.listen_addr))?;
        Ok(listener)
    }

    /// 读取当前站点表快照。
    pub async fn router(&self) -> tokio::sync::RwLockReadGuard<'_, HttpSiteRouter> {
        self.router.read().await
    }

    /// 动态插入/替换站点（配置文件模式 `host` 帧使用）。
    ///
    /// 只影响路由表；监听端口与并发限制不变。重复域名会**替换**配置，
    /// 保留原并发计数。
    pub async fn upsert_site(&self, site: HttpSite) -> Result<()> {
        let mut router = self.router.write().await;
        router.upsert(site)
    }

    /// 动态移除站点（配置文件模式注销时使用）；返回是否真的存在。
    pub async fn remove_site(&self, domain: &str) -> bool {
        let mut router = self.router.write().await;
        router.remove(domain)
    }

    /// 当前活跃连接数
    pub fn active_connections(&self) -> u64 {
        self.active_connections.load(Ordering::Relaxed)
    }

    /// 已处理的请求数（含失败）
    pub fn served_requests(&self) -> u64 {
        self.served_requests.load(Ordering::Relaxed)
    }

    /// 在已绑定的监听器上跑 accept 循环；`cancel` 变为 `true` 时退出。
    ///
    /// 退出时会 abort 所有连接任务（各自的子流随 `Drop` 收到 `ConnClose`）。
    pub async fn serve(self: Arc<Self>, listener: TcpListener, mut cancel: watch::Receiver<bool>) {
        let addr = listener.local_addr().ok();
        info!("HTTP 域名代理监听 {:?}", addr);
        let mut conns: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = cancel.changed() => break,
                _ = conns.join_next(), if !conns.is_empty() => {}
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, peer)) => {
                            let this = self.clone();
                            let counter = ConnCounter::new(self.active_connections.clone());
                            let c = cancel.clone();
                            conns.spawn(async move {
                                this.handle_client(stream, peer, c).await;
                                drop(counter);
                            });
                        }
                        Err(e) => {
                            warn!("HTTP 域名代理 accept 失败: {e}");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }
        conns.shutdown().await;
        debug!("HTTP 域名代理 accept 循环退出");
    }

    /// 绑定 + 启动（返回实际绑定地址与 accept 任务句柄）。
    pub async fn bind_and_serve(
        self: Arc<Self>,
        cancel: watch::Receiver<bool>,
    ) -> Result<(std::net::SocketAddr, JoinHandle<()>)> {
        let listener = self.bind().await?;
        let bound = listener
            .local_addr()
            .context("读取 HTTP 代理绑定地址失败")?;
        let task = tokio::spawn(async move {
            self.serve(listener, cancel).await;
        });
        Ok((bound, task))
    }

    async fn handle_client(
        self: Arc<Self>,
        stream: TcpStream,
        peer: std::net::SocketAddr,
        cancel: watch::Receiver<bool>,
    ) {
        let _ = stream.set_nodelay(true);
        let (read_half, mut write_half) = stream.into_split();
        let mut client = Buffered::new(read_half, self.idle_timeout);

        loop {
            if *cancel.borrow() {
                return;
            }
            let head = match timeout(self.idle_timeout, client.read_head(self.max_head_bytes)).await
            {
                Err(_) => {
                    debug!("HTTP 域名代理: {peer} 空闲超时");
                    return;
                }
                Ok(Ok(head)) => head,
                Ok(Err(HttpError::HeadTooLarge)) => {
                    self.served_requests.fetch_add(1, Ordering::Relaxed);
                    let _ =
                        send_error(&mut write_half, 431, "Request Header Fields Too Large").await;
                    return;
                }
                Ok(Err(HttpError::Eof)) => return,
                Ok(Err(e)) => {
                    debug!("HTTP 域名代理: {peer} 读请求头失败: {e}");
                    let _ = send_error(&mut write_half, 400, "Bad Request").await;
                    return;
                }
            };

            let request = match RequestHead::parse(&head) {
                Ok(request) => request,
                Err(reason) => {
                    debug!("HTTP 域名代理: {peer} 请求头非法: {reason}");
                    self.served_requests.fetch_add(1, Ordering::Relaxed);
                    let _ = send_error(&mut write_half, 400, "Bad Request").await;
                    return;
                }
            };

            let resolved = {
                let router = self.router.read().await;
                router.resolve(&request.host, request_path(&request.uri))
            };
            let Some(site) = resolved else {
                debug!(
                    "HTTP 域名代理: {} 未匹配到站点 (Host={:?})",
                    peer, request.host
                );
                self.served_requests.fetch_add(1, Ordering::Relaxed);
                let _ = send_error(&mut write_half, 404, "Not Found").await;
                return;
            };

            let Some(_slot) = site.try_acquire(self.max_connections) else {
                warn!(
                    "HTTP 域名代理: 站点 {} 并发超限 ({}), 拒绝 {}",
                    site.domain, self.max_connections, peer
                );
                self.served_requests.fetch_add(1, Ordering::Relaxed);
                let _ = send_error(&mut write_half, 503, "Service Unavailable").await;
                return;
            };

            self.served_requests.fetch_add(1, Ordering::Relaxed);
            let upgrade = request.is_upgrade_request();
            if upgrade && !site.websocket {
                debug!(
                    "HTTP 域名代理: 站点 {} 未开启 websocket，拒绝升级请求 (from {peer})",
                    site.domain
                );
                let _ = send_error(&mut write_half, 403, "Forbidden").await;
                return;
            }

            let outcome = self
                .serve_one(
                    &mut client,
                    &mut write_half,
                    &request,
                    &head,
                    &site,
                    peer,
                    upgrade,
                )
                .await;

            match outcome {
                Ok(Outcome {
                    keep_alive: true, ..
                }) => continue,
                Ok(_) => {
                    let _ = write_half.shutdown().await;
                    return;
                }
                Err(e) => {
                    if !e.response_started {
                        // 尚未向客户端写任何字节，可以返回明确的错误码
                        let (status, text) = match &e.kind {
                            ServeErrorKind::ClientOffline => (502, "Bad Gateway"),
                            ServeErrorKind::BadRequest(_) => (400, "Bad Request"),
                            _ => (502, "Bad Gateway"),
                        };
                        let _ = send_error(&mut write_half, status, text).await;
                    }
                    let _ = write_half.shutdown().await;
                    return;
                }
            }
        }
    }

    /// 处理单个请求（一次子流）。返回是否保持客户端连接。
    #[allow(clippy::too_many_arguments)]
    async fn serve_one(
        &self,
        client: &mut Buffered<OwnedReadHalf>,
        write_half: &mut OwnedWriteHalf,
        request: &RequestHead,
        head_bytes: &[u8],
        site: &ResolvedSite,
        peer: std::net::SocketAddr,
        upgrade: bool,
    ) -> std::result::Result<Outcome, ServeError> {
        // 升级请求用 tcp 子流：npc 只做 Dial + 双向拷贝，升级后的帧原样透传
        let conn_type = if upgrade { nps_proto::CONN_TCP } else { "http" };
        let (mut send, recv) = self
            .open_stream(site, conn_type, peer)
            .await
            .map_err(|kind| ServeError {
                kind,
                response_started: false,
            })?;

        // 请求头原样写入子流
        if send.send_data(head_bytes).await.is_err() {
            return Err(ServeError {
                kind: ServeErrorKind::TargetFailed("写请求头到子流失败".into()),
                response_started: false,
            });
        }

        // 请求体流式转发。
        //
        // `Expect: 100-continue` 时客户端会先等 100 再发 body；服务端必须先回
        // 100，否则双方互相等待直到空闲超时。目标随后可能再回一个 100，
        // 那个中间响应会被跳过（客户端已经收到过）。
        let expect_continue = header_contains_token(&request.headers, "expect", "100-continue");
        if expect_continue {
            if write_half
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
                .is_err()
            {
                return Err(ServeError {
                    kind: ServeErrorKind::ClientGone,
                    response_started: true,
                });
            }
            let _ = write_half.flush().await;
        }
        let body_framing = request.framing;
        let body_result = match body_framing {
            BodyFraming::None => Ok(()),
            BodyFraming::Length(n) => forward_length(client, &mut send, n).await,
            BodyFraming::Chunked => forward_chunked(client, &mut send).await,
        };
        if let Err(e) = body_result {
            debug!("HTTP 域名代理: 转发请求体失败: {e}");
            return Err(ServeError {
                kind: ServeErrorKind::BadRequest("请求体不完整".into()),
                response_started: false,
            });
        }

        let mut response = Buffered::new(recv, RESPONSE_HEAD_TIMEOUT);

        // 读取响应头（1xx 中间响应先转发再继续读；101 走升级分支）
        let (head, resp) = loop {
            let head = match timeout(
                RESPONSE_HEAD_TIMEOUT,
                response.read_head(self.max_head_bytes),
            )
            .await
            {
                Err(_) => {
                    debug!("HTTP 域名代理: 等待目标响应超时");
                    return Err(ServeError {
                        kind: ServeErrorKind::TargetFailed("等待响应超时".into()),
                        response_started: false,
                    });
                }
                Ok(Ok(head)) => head,
                Ok(Err(e)) => {
                    debug!("HTTP 域名代理: 读取响应头失败: {e}");
                    return Err(ServeError {
                        kind: ServeErrorKind::TargetFailed("目标未返回响应".into()),
                        response_started: false,
                    });
                }
            };
            let parsed = match ResponseHead::parse(&head) {
                Ok(parsed) => parsed,
                Err(reason) => {
                    return Err(ServeError {
                        kind: ServeErrorKind::TargetFailed(format!("响应头非法: {reason}")),
                        response_started: false,
                    });
                }
            };
            if parsed.status == 101 {
                break (head, parsed);
            }
            if (100..200).contains(&parsed.status) {
                // 中间响应：直接转发，继续等最终响应。
                // 若已经替目标回过 100-continue，就丢弃目标重复的 100。
                if parsed.status == 100 && expect_continue {
                    continue;
                }
                if write_half.write_all(&head).await.is_err() {
                    return Err(ServeError {
                        kind: ServeErrorKind::ClientGone,
                        response_started: true,
                    });
                }
                let _ = write_half.flush().await;
                continue;
            }
            break (head, parsed);
        };

        // 101：握手完成，转为双向裸字节流
        if resp.status == 101 {
            if write_half.write_all(&head).await.is_err() {
                return Err(ServeError {
                    kind: ServeErrorKind::ClientGone,
                    response_started: true,
                });
            }
            let _ = write_half.flush().await;
            relay_bidirectional(client, write_half, &mut response, &mut send).await;
            return Ok(Outcome { keep_alive: false });
        }

        if write_half.write_all(&head).await.is_err() {
            return Err(ServeError {
                kind: ServeErrorKind::ClientGone,
                response_started: true,
            });
        }

        let framing = response_framing(&resp, request.method.as_str());
        let body_ok = match framing {
            ResponseFraming::None => Ok(()),
            ResponseFraming::Length(n) => copy_exact(&mut response, write_half, n).await,
            ResponseFraming::Chunked => copy_chunked(&mut response, write_half).await,
            ResponseFraming::UntilClose => copy_until_eof(&mut response, write_half).await,
        };
        if let Err(e) = body_ok {
            debug!("HTTP 域名代理: 转发响应体失败: {e}");
            return Err(ServeError {
                kind: ServeErrorKind::ClientGone,
                response_started: true,
            });
        }
        if write_half.flush().await.is_err() {
            return Err(ServeError {
                kind: ServeErrorKind::ClientGone,
                response_started: true,
            });
        }

        // 决定客户端连接是否复用
        let keep_alive = !request.client_wants_close()
            && !resp.server_wants_close()
            && framing != ResponseFraming::UntilClose;

        // 显式关闭子流：通知 npc 结束目标连接（Drop 两边即发 ConnClose）
        drop(response);
        drop(send);

        Ok(Outcome { keep_alive })
    }

    async fn open_stream(
        &self,
        site: &ResolvedSite,
        conn_type: &str,
        peer: std::net::SocketAddr,
    ) -> std::result::Result<(MuxSendHalf, MuxRecvHalf), ServeErrorKind> {
        let mux = self
            .bridge
            .get_tunnel(site.client_id)
            .await
            .ok_or(ServeErrorKind::ClientOffline)?;
        let stream = match timeout(OPEN_STREAM_TIMEOUT, mux.open_stream()).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                debug!("HTTP 域名代理: 客户端 {} 建流失败: {e}", site.client_id);
                return Err(ServeErrorKind::ClientOffline);
            }
            Err(_) => {
                debug!("HTTP 域名代理: 客户端 {} 建流超时", site.client_id);
                return Err(ServeErrorKind::ClientOffline);
            }
        };

        let (mut send, recv) = stream.into_split();

        let mut link = nps_proto::Link::new(
            conn_type,
            site.target.clone(),
            false,
            false,
            peer.to_string(),
            false,
        );
        link.option.timeout = nps_proto::DEFAULT_LINK_TIMEOUT_NS;
        let json = serde_json::to_vec(&link)
            .map_err(|e| ServeErrorKind::TargetFailed(format!("Link 序列化失败: {e}")))?;
        let mut frame = Vec::with_capacity(4 + json.len());
        frame.extend_from_slice(&(json.len() as i32).to_le_bytes());
        frame.extend_from_slice(&json);
        if send.send_data(&frame).await.is_err() {
            return Err(ServeErrorKind::TargetFailed("发送 Link 失败".into()));
        }
        Ok((send, recv))
    }
}

#[derive(Debug)]
struct Outcome {
    keep_alive: bool,
}

#[derive(Debug)]
struct ServeError {
    kind: ServeErrorKind,
    /// 是否已经向客户端写过字节；写过就不能再改状态码
    response_started: bool,
}

#[derive(Debug)]
enum ServeErrorKind {
    ClientOffline,
    BadRequest(String),
    TargetFailed(String),
    ClientGone,
}

impl std::fmt::Display for ServeErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClientOffline => write!(f, "客户端离线或建流失败"),
            Self::BadRequest(reason) => write!(f, "请求不合法: {reason}"),
            Self::TargetFailed(reason) => write!(f, "目标失败: {reason}"),
            Self::ClientGone => write!(f, "客户端已断开"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyFraming {
    None,
    Length(u64),
    Chunked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseFraming {
    None,
    Length(u64),
    Chunked,
    UntilClose,
}

/// 解析后的请求头。
#[derive(Debug)]
struct RequestHead {
    method: String,
    uri: String,
    version: Version,
    headers: Vec<(String, String)>,
    framing: BodyFraming,
    /// 规范化后的 Host（去端口、小写）
    host: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Version {
    Http10,
    Http11,
    Other,
}

impl RequestHead {
    fn parse(head: &[u8]) -> std::result::Result<Self, &'static str> {
        let mut lines = head_lines(head).ok_or("请求头缺少终止空行")?;
        let request_line = lines.next().ok_or("缺少请求行")?;
        let mut parts = request_line.splitn(3, ' ');
        let method = parts.next().unwrap_or_default();
        let uri = parts.next().unwrap_or_default();
        let version = parts.next().unwrap_or_default();
        if method.is_empty() || uri.is_empty() || version.is_empty() {
            return Err("请求行格式非法");
        }
        if !is_token(method) {
            return Err("请求方法非法");
        }
        let version = match version {
            "HTTP/1.1" => Version::Http11,
            "HTTP/1.0" => Version::Http10,
            v if v.starts_with("HTTP/") => Version::Other,
            _ => return Err("HTTP 版本格式非法"),
        };
        let headers = parse_headers(lines)?;
        let host = header_value(&headers, "host")
            .map(normalize_host)
            .unwrap_or_default();
        let framing = request_framing(&headers)?;
        Ok(Self {
            method: method.to_owned(),
            uri: uri.to_owned(),
            version,
            headers,
            framing,
            host,
        })
    }

    fn client_wants_close(&self) -> bool {
        if header_contains_token(&self.headers, "connection", "close") {
            return true;
        }
        match self.version {
            Version::Http10 => !header_contains_token(&self.headers, "connection", "keep-alive"),
            Version::Http11 => false,
            // 未知版本：保守关闭
            Version::Other => true,
        }
    }

    fn is_upgrade_request(&self) -> bool {
        header_value(&self.headers, "upgrade").is_some()
            && header_contains_token(&self.headers, "connection", "upgrade")
    }
}

/// 解析后的响应头。
#[derive(Debug)]
struct ResponseHead {
    version: Version,
    status: u16,
    headers: Vec<(String, String)>,
}

impl ResponseHead {
    fn parse(head: &[u8]) -> std::result::Result<Self, &'static str> {
        let mut lines = head_lines(head).ok_or("响应头缺少终止空行")?;
        let status_line = lines.next().ok_or("缺少状态行")?;
        let mut parts = status_line.splitn(3, ' ');
        let version = parts.next().unwrap_or_default();
        let status = parts.next().ok_or("缺少状态码")?;
        let version = match version {
            "HTTP/1.1" => Version::Http11,
            "HTTP/1.0" => Version::Http10,
            v if v.starts_with("HTTP/") => Version::Other,
            _ => return Err("HTTP 版本格式非法"),
        };
        if status.len() != 3 || !status.bytes().all(|b| b.is_ascii_digit()) {
            return Err("状态码非法");
        }
        let status: u16 = status.parse().map_err(|_| "状态码非法")?;
        let headers = parse_headers(lines)?;
        Ok(Self {
            version,
            status,
            headers,
        })
    }

    fn server_wants_close(&self) -> bool {
        if header_contains_token(&self.headers, "connection", "close") {
            return true;
        }
        match self.version {
            Version::Http10 => !header_contains_token(&self.headers, "connection", "keep-alive"),
            _ => false,
        }
    }
}

fn head_lines(head: &[u8]) -> Option<impl Iterator<Item = &str>> {
    let text = std::str::from_utf8(head).ok()?;
    let body = text
        .strip_suffix("\r\n\r\n")
        .or_else(|| text.strip_suffix("\n\n"))?;
    Some(body.split("\r\n").flat_map(|line| line.split('\n')))
}

fn parse_headers<'a>(
    lines: impl Iterator<Item = &'a str>,
) -> std::result::Result<Vec<(String, String)>, &'static str> {
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // 拒绝 obsolete line folding（请求走私面）
            return Err("不支持的头续行");
        }
        let (name, value) = line.split_once(':').ok_or("请求头缺少冒号")?;
        if name.is_empty() || !is_token(name) {
            return Err("请求头名称非法");
        }
        headers.push((name.to_owned(), trim_ows(value).to_owned()));
    }
    Ok(headers)
}

fn trim_ows(value: &str) -> &str {
    value.trim_matches(|c| c == ' ' || c == '\t')
}

fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|b| {
            matches!(
                b,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            ) || b.is_ascii_alphanumeric()
        })
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .rev()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn header_contains_token(headers: &[(String, String)], name: &str, token: &str) -> bool {
    headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .flat_map(|(_, v)| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case(token))
}

fn request_framing(headers: &[(String, String)]) -> std::result::Result<BodyFraming, &'static str> {
    let chunked = header_contains_token(headers, "transfer-encoding", "chunked");
    if chunked {
        return Ok(BodyFraming::Chunked);
    }
    if header_value(headers, "transfer-encoding").is_some() {
        return Err("不支持的 Transfer-Encoding");
    }
    match header_value(headers, "content-length") {
        Some(value) => {
            // 多个 Content-Length 必须一致，否则按走私尝试拒绝
            for (name, other) in headers {
                if name.eq_ignore_ascii_case("content-length") && other.trim() != value.trim() {
                    return Err("Content-Length 冲突");
                }
            }
            let text = value.trim();
            if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                return Err("Content-Length 非法");
            }
            let length: u64 = text.parse().map_err(|_| "Content-Length 非法")?;
            Ok(if length == 0 {
                BodyFraming::None
            } else {
                BodyFraming::Length(length)
            })
        }
        None => Ok(BodyFraming::None),
    }
}

fn response_framing(resp: &ResponseHead, method: &str) -> ResponseFraming {
    if method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&resp.status)
        || resp.status == 204
        || resp.status == 304
    {
        return ResponseFraming::None;
    }
    if header_contains_token(&resp.headers, "transfer-encoding", "chunked") {
        return ResponseFraming::Chunked;
    }
    if let Some(value) = header_value(&resp.headers, "content-length") {
        if let Ok(length) = value.trim().parse::<u64>() {
            return if length == 0 {
                ResponseFraming::None
            } else {
                ResponseFraming::Length(length)
            };
        }
    }
    ResponseFraming::UntilClose
}

// ---------------------------------------------------------------------------
// 字节流抽象
// ---------------------------------------------------------------------------

/// 可按块读取的字节源（mux 子流 / TCP 连接）。
trait ChunkSource {
    fn next_chunk(&mut self) -> impl std::future::Future<Output = Option<Vec<u8>>> + Send + '_;
}

impl ChunkSource for OwnedReadHalf {
    // 显式写成 `impl Future + Send`（而不是 `async fn`）：trait 方法必须
    // 保证 Send，才能把连接处理放进 tokio::spawn 的多线程任务里。
    #[allow(clippy::manual_async_fn)]
    fn next_chunk(&mut self) -> impl std::future::Future<Output = Option<Vec<u8>>> + Send + '_ {
        async move {
            let mut buf = vec![0u8; COPY_BUF];
            match self.read(&mut buf).await {
                Ok(0) | Err(_) => None,
                Ok(n) => {
                    buf.truncate(n);
                    Some(buf)
                }
            }
        }
    }
}

impl ChunkSource for MuxRecvHalf {
    #[allow(clippy::manual_async_fn)]
    fn next_chunk(&mut self) -> impl std::future::Future<Output = Option<Vec<u8>>> + Send + '_ {
        async move { self.recv_data().await }
    }
}

/// 带内部缓冲的字节流：支持"读到头部为止"与按帧转发。
///
/// 每次底层读都带 `stall` 上限：一侧彻底不动（例如目标进程卡死）时，
/// 连接会在有限时间内被关闭，而不是永远挂住。
struct Buffered<S> {
    src: S,
    buf: Vec<u8>,
    pos: usize,
    stall: Duration,
}

impl<S: ChunkSource + Send + Unpin> Buffered<S> {
    fn new(src: S, stall: Duration) -> Self {
        Self {
            src,
            buf: Vec::new(),
            pos: 0,
            stall,
        }
    }

    fn available(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn compact(&mut self) {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    async fn fill(&mut self) -> bool {
        match timeout(self.stall, self.src.next_chunk()).await {
            Ok(Some(chunk)) => {
                self.compact();
                self.buf.extend_from_slice(&chunk);
                true
            }
            // 对端关闭或长时间无数据：都按"流已结束"处理
            Ok(None) | Err(_) => false,
        }
    }

    /// 读取一个完整的头（含终止空行）；返回原始字节（转发用）。
    async fn read_head(&mut self, max: usize) -> std::result::Result<Vec<u8>, HttpError> {
        loop {
            if let Some(idx) = find(&self.buf[self.pos..], b"\r\n\r\n") {
                let end = self.pos + idx + 4;
                if end - self.pos > max {
                    return Err(HttpError::HeadTooLarge);
                }
                let head = self.buf[self.pos..end].to_vec();
                self.pos = end;
                return Ok(head);
            }
            if self.available() > max {
                return Err(HttpError::HeadTooLarge);
            }
            if !self.fill().await {
                return Err(HttpError::Eof);
            }
        }
    }

    /// 取走缓冲里已到达的字节（升级为裸流转发前必须先吐出）。
    fn take_buffered(&mut self) -> Vec<u8> {
        let out = self.buf[self.pos..].to_vec();
        self.pos = self.buf.len();
        out
    }

    /// 读任意一段数据（先缓冲后来源）；返回空表示 EOF。
    async fn next_chunk(&mut self) -> Vec<u8> {
        if self.available() > 0 {
            return self.take_buffered();
        }
        self.compact();
        match timeout(self.stall, self.src.next_chunk()).await {
            Ok(Some(chunk)) => chunk,
            Ok(None) | Err(_) => Vec::new(),
        }
    }

    /// 读取一行（含 CRLF），用于 chunked 帧。
    async fn read_line(&mut self, max: usize) -> std::result::Result<Vec<u8>, HttpError> {
        loop {
            if let Some(idx) = find(&self.buf[self.pos..], b"\r\n") {
                let end = self.pos + idx + 2;
                if end - self.pos > max {
                    return Err(HttpError::Malformed("chunk 行过长"));
                }
                let line = self.buf[self.pos..end].to_vec();
                self.pos = end;
                return Ok(line);
            }
            if self.available() > max {
                return Err(HttpError::Malformed("chunk 行过长"));
            }
            if !self.fill().await {
                return Err(HttpError::Eof);
            }
        }
    }

    /// 读走 up to `n` 字节。
    async fn read_some(&mut self, n: usize) -> std::result::Result<Vec<u8>, HttpError> {
        if self.available() == 0 && !self.fill().await {
            return Err(HttpError::Eof);
        }
        let take = self.available().min(n);
        let out = self.buf[self.pos..self.pos + take].to_vec();
        self.pos += take;
        Ok(out)
    }
}

#[derive(Debug)]
enum HttpError {
    Eof,
    HeadTooLarge,
    Malformed(&'static str),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Eof => write!(f, "对端提前关闭"),
            Self::HeadTooLarge => write!(f, "头部超过大小上限"),
            Self::Malformed(reason) => write!(f, "格式非法: {reason}"),
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// ---------------------------------------------------------------------------
// 请求体 / 响应体转发
// ---------------------------------------------------------------------------

/// 按 `Content-Length` 从客户端读体并写入子流。
async fn forward_length(
    client: &mut Buffered<OwnedReadHalf>,
    send: &mut MuxSendHalf,
    length: u64,
) -> std::result::Result<(), HttpError> {
    let mut remaining = length;
    while remaining > 0 {
        let want = remaining.min(COPY_BUF as u64) as usize;
        let chunk = client.read_some(want).await?;
        if chunk.is_empty() {
            return Err(HttpError::Eof);
        }
        remaining -= chunk.len() as u64;
        if send.send_data(&chunk).await.is_err() {
            return Err(HttpError::Malformed("写子流失败"));
        }
    }
    Ok(())
}

/// 按 chunked 帧从客户端读体并**原样**写入子流（保持合法分块格式）。
async fn forward_chunked(
    client: &mut Buffered<OwnedReadHalf>,
    send: &mut MuxSendHalf,
) -> std::result::Result<(), HttpError> {
    loop {
        let line = client.read_line(8 * 1024).await?;
        let size = parse_chunk_size(&line)?;
        if send.send_data(&line).await.is_err() {
            return Err(HttpError::Malformed("写子流失败"));
        }
        if size == 0 {
            // 尾部头：逐行转发到空行为止
            loop {
                let trailer = client.read_line(MAX_HEAD_BYTES).await?;
                let empty = trailer.iter().all(|b| matches!(b, b'\r' | b'\n'));
                if send.send_data(&trailer).await.is_err() {
                    return Err(HttpError::Malformed("写子流失败"));
                }
                if empty {
                    return Ok(());
                }
            }
        }
        let mut remaining = size;
        while remaining > 0 {
            let want = remaining.min(COPY_BUF as u64) as usize;
            let chunk = client.read_some(want).await?;
            if chunk.is_empty() {
                return Err(HttpError::Eof);
            }
            remaining -= chunk.len() as u64;
            if send.send_data(&chunk).await.is_err() {
                return Err(HttpError::Malformed("写子流失败"));
            }
        }
        // chunk 数据后的 CRLF
        let crlf = client.read_line(4).await?;
        if crlf.len() > 2 {
            return Err(HttpError::Malformed("chunk 数据后缺少 CRLF"));
        }
        if send.send_data(&crlf).await.is_err() {
            return Err(HttpError::Malformed("写子流失败"));
        }
    }
}

fn parse_chunk_size(line: &[u8]) -> std::result::Result<u64, HttpError> {
    let text = std::str::from_utf8(line)
        .map_err(|_| HttpError::Malformed("chunk 大小非 ASCII"))?
        .trim_end_matches(['\r', '\n']);
    let size_text = text.split(';').next().unwrap_or("").trim();
    if size_text.is_empty() {
        return Err(HttpError::Malformed("chunk 大小为空"));
    }
    u64::from_str_radix(size_text, 16).map_err(|_| HttpError::Malformed("chunk 大小非法"))
}

/// 把 `n` 字节原样从响应子流写入客户端。
async fn copy_exact<S: ChunkSource + Send + Unpin>(
    src: &mut Buffered<S>,
    dst: &mut OwnedWriteHalf,
    length: u64,
) -> std::result::Result<(), HttpError> {
    let mut remaining = length;
    while remaining > 0 {
        let want = remaining.min(COPY_BUF as u64) as usize;
        let chunk = src.read_some(want).await?;
        if chunk.is_empty() {
            return Err(HttpError::Eof);
        }
        remaining -= chunk.len() as u64;
        if dst.write_all(&chunk).await.is_err() {
            return Err(HttpError::Malformed("写客户端失败"));
        }
    }
    Ok(())
}

/// chunked 响应：解析帧边界并原样转发。
async fn copy_chunked<S: ChunkSource + Send + Unpin>(
    src: &mut Buffered<S>,
    dst: &mut OwnedWriteHalf,
) -> std::result::Result<(), HttpError> {
    loop {
        let line = src.read_line(8 * 1024).await?;
        let size = parse_chunk_size(&line)?;
        if dst.write_all(&line).await.is_err() {
            return Err(HttpError::Malformed("写客户端失败"));
        }
        if size == 0 {
            loop {
                let trailer = src.read_line(MAX_HEAD_BYTES).await?;
                let empty = trailer.iter().all(|b| matches!(b, b'\r' | b'\n'));
                if dst.write_all(&trailer).await.is_err() {
                    return Err(HttpError::Malformed("写客户端失败"));
                }
                if empty {
                    return Ok(());
                }
            }
        }
        let mut remaining = size;
        while remaining > 0 {
            let want = remaining.min(COPY_BUF as u64) as usize;
            let chunk = src.read_some(want).await?;
            if chunk.is_empty() {
                return Err(HttpError::Eof);
            }
            remaining -= chunk.len() as u64;
            if dst.write_all(&chunk).await.is_err() {
                return Err(HttpError::Malformed("写客户端失败"));
            }
        }
        let crlf = src.read_line(4).await?;
        if crlf.len() > 2 {
            return Err(HttpError::Malformed("chunk 数据后缺少 CRLF"));
        }
        if dst.write_all(&crlf).await.is_err() {
            return Err(HttpError::Malformed("写客户端失败"));
        }
    }
}

/// 读到对端关闭（Connection: close 语义）。
async fn copy_until_eof<S: ChunkSource + Send + Unpin>(
    src: &mut Buffered<S>,
    dst: &mut OwnedWriteHalf,
) -> std::result::Result<(), HttpError> {
    loop {
        let chunk = src.next_chunk().await;
        if chunk.is_empty() {
            return Ok(());
        }
        if dst.write_all(&chunk).await.is_err() {
            return Err(HttpError::Malformed("写客户端失败"));
        }
    }
}

/// 升级为裸字节流后双向转发，直到任一方向结束。
async fn relay_bidirectional(
    client: &mut Buffered<OwnedReadHalf>,
    client_out: &mut OwnedWriteHalf,
    target: &mut Buffered<MuxRecvHalf>,
    target_out: &mut MuxSendHalf,
) {
    let up = async {
        let buffered = client.take_buffered();
        if !buffered.is_empty() && target_out.send_data(&buffered).await.is_err() {
            return;
        }
        loop {
            let chunk = client.next_chunk().await;
            if chunk.is_empty() {
                return;
            }
            if target_out.send_data(&chunk).await.is_err() {
                return;
            }
        }
    };
    let down = async {
        let buffered = target.take_buffered();
        if !buffered.is_empty() && client_out.write_all(&buffered).await.is_err() {
            return;
        }
        loop {
            let chunk = target.next_chunk().await;
            if chunk.is_empty() {
                return;
            }
            if client_out.write_all(&chunk).await.is_err() {
                return;
            }
            let _ = client_out.flush().await;
        }
    };
    tokio::select! {
        _ = up => {},
        _ = down => {},
    }
}

async fn send_error(w: &mut OwnedWriteHalf, status: u16, reason: &str) -> io::Result<()> {
    let body = format!("{status} {reason}\n");
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    w.write_all(response.as_bytes()).await?;
    w.flush().await
}

// ---------------------------------------------------------------------------
// 单元测试（路由与解析）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn site(domain: &str, target: &str) -> HttpSite {
        HttpSite::new(domain, 1, target)
    }

    fn route(prefix: &str, target: &str) -> HttpRoute {
        HttpRoute {
            prefix: prefix.into(),
            target_addr: target.into(),
        }
    }

    #[test]
    fn host_is_case_insensitive_and_port_is_stripped() {
        let router = HttpSiteRouter::new(vec![site("Test.Local", "127.0.0.1:1000")]).unwrap();
        for host in [
            "test.local",
            "TEST.LOCAL",
            "test.local:8080",
            "Test.Local.:443",
        ] {
            let resolved = router.resolve(host, "/").expect(host);
            assert_eq!(resolved.target, "127.0.0.1:1000");
        }
        assert!(router.resolve("other.local", "/").is_none());
        assert!(router.resolve("", "/").is_none());
    }

    #[test]
    fn ipv6_host_literal_keeps_brackets() {
        assert_eq!(normalize_host("[::1]:8080"), "[::1]");
        assert_eq!(normalize_host("[::1]"), "[::1]");
        assert_eq!(normalize_host("example.com:80"), "example.com");
    }

    #[test]
    fn longest_prefix_wins() {
        let router = HttpSiteRouter::new(vec![site("a.local", "127.0.0.1:1").with_routes(vec![
            route("/api", "127.0.0.1:2"),
            route("/api/v2", "127.0.0.1:3"),
        ])])
        .unwrap();

        assert_eq!(
            router.resolve("a.local", "/").unwrap().target,
            "127.0.0.1:1"
        );
        assert_eq!(
            router.resolve("a.local", "/api/x").unwrap().target,
            "127.0.0.1:2"
        );
        assert_eq!(
            router.resolve("a.local", "/api/v2/x").unwrap().target,
            "127.0.0.1:3"
        );
        assert_eq!(
            router.resolve("a.local", "/api/v2").unwrap().prefix,
            "/api/v2"
        );
    }

    #[test]
    fn wildcard_domain_matches_suffix_like_go() {
        let router = HttpSiteRouter::new(vec![site("*.example.com", "127.0.0.1:9")]).unwrap();
        assert!(router.resolve("a.example.com", "/").is_some());
        // Go `GetInfoByHost` 用子串匹配：去掉 `*` 后 host 必须包含 ".example.com"
        assert!(router.resolve("example.com", "/").is_none());
        assert!(router.resolve("badexample.com", "/").is_none());
        assert!(router.resolve("other.local", "/").is_none());
    }

    #[test]
    fn duplicate_domains_rejected() {
        assert!(HttpSiteRouter::new(vec![
            site("a.local", "127.0.0.1:1"),
            site("A.LOCAL", "127.0.0.1:2"),
        ])
        .is_err());
    }

    #[test]
    fn invalid_site_rejected() {
        assert!(HttpSite::new("", 1, "127.0.0.1:1").validate().is_err());
        assert!(HttpSite::new("a.local", 0, "127.0.0.1:1")
            .validate()
            .is_err());
        assert!(HttpSite::new("a.local", 1, "127.0.0.1").validate().is_err());
        assert!(HttpSite::new("a.local", 1, "127.0.0.1:1")
            .with_routes(vec![route("api", "127.0.0.1:2")])
            .validate()
            .is_err());
    }

    #[test]
    fn request_line_and_headers_parsed() {
        let raw = b"POST /api/x?q=1 HTTP/1.1\r\nHost: A.Local:8080\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\n";
        let req = RequestHead::parse(raw).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.uri, "/api/x?q=1");
        assert_eq!(request_path(&req.uri), "/api/x");
        assert_eq!(req.host, "a.local");
        assert_eq!(req.framing, BodyFraming::Length(5));
        assert!(!req.client_wants_close());
    }

    #[test]
    fn chunked_request_detected() {
        let raw = b"POST / HTTP/1.1\r\nHost: a.local\r\nTransfer-Encoding: chunked\r\n\r\n";
        let req = RequestHead::parse(raw).unwrap();
        assert_eq!(req.framing, BodyFraming::Chunked);
    }

    #[test]
    fn conflicting_content_length_rejected() {
        let raw =
            b"POST / HTTP/1.1\r\nHost: a.local\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n";
        assert!(RequestHead::parse(raw).is_err());
    }

    #[test]
    fn upgrade_request_detected() {
        let raw = b"GET /ws HTTP/1.1\r\nHost: a.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        let req = RequestHead::parse(raw).unwrap();
        assert!(req.is_upgrade_request());
    }

    #[test]
    fn response_framing_rules() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n";
        let resp = ResponseHead::parse(head).unwrap();
        assert_eq!(response_framing(&resp, "GET"), ResponseFraming::Length(3));
        assert_eq!(response_framing(&resp, "HEAD"), ResponseFraming::None);

        let head = b"HTTP/1.1 204 No Content\r\n\r\n";
        let resp = ResponseHead::parse(head).unwrap();
        assert_eq!(response_framing(&resp, "GET"), ResponseFraming::None);

        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let resp = ResponseHead::parse(head).unwrap();
        assert_eq!(response_framing(&resp, "GET"), ResponseFraming::Chunked);

        let head = b"HTTP/1.1 200 OK\r\n\r\n";
        let resp = ResponseHead::parse(head).unwrap();
        assert_eq!(response_framing(&resp, "GET"), ResponseFraming::UntilClose);
    }

    #[test]
    fn absolute_form_uri_path() {
        assert_eq!(request_path("http://a.local/x/y?z=1"), "/x/y");
        assert_eq!(request_path("https://a.local"), "/");
        assert_eq!(request_path("*"), "*");
    }

    #[test]
    fn site_guard_counts_and_returns_slots() {
        let router = HttpSiteRouter::new(vec![site("a.local", "127.0.0.1:1")]).unwrap();
        let resolved = router.resolve("a.local", "/").unwrap();
        let g1 = resolved.try_acquire(2).unwrap();
        let g2 = resolved.try_acquire(2).unwrap();
        assert!(resolved.try_acquire(2).is_none());
        assert_eq!(resolved.active(), 2);
        drop(g1);
        assert_eq!(resolved.active(), 1);
        drop(g2);
        assert_eq!(resolved.active(), 0);
        assert_eq!(router.active_total(), 0);
    }

    /// 配置模式重复上报同一域名时应替换配置而不是报错，且不丢并发计数。
    #[test]
    fn upsert_replaces_same_domain_and_keeps_slots() {
        let mut router = HttpSiteRouter::new(vec![site("a.local", "127.0.0.1:1")]).unwrap();
        let resolved = router.resolve("a.local", "/").unwrap();
        let guard = resolved.try_acquire(4).unwrap();
        assert_eq!(router.active_total(), 1);

        router.upsert(site("A.LOCAL", "127.0.0.1:2")).unwrap();
        assert_eq!(router.len(), 1);
        assert_eq!(
            router.resolve("a.local", "/").unwrap().target,
            "127.0.0.1:2"
        );
        assert_eq!(router.active_total(), 1, "替换不能清零并发计数");

        drop(guard);
        assert_eq!(router.active_total(), 0);
        assert!(router.remove("a.local"));
        assert!(!router.remove("a.local"));
        assert!(router.is_empty());
    }
}
