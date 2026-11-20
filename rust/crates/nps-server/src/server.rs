//! 服务端装配：配置 -> 绑定 -> 转发任务 -> 状态快照 / 启停 / 关闭。
//!
//! 启动是**原子**的：先校验配置，再绑定桥与所有启用隧道的监听端口；
//! 任一端口绑定失败都会释放此前已绑定的资源并返回 `Err`，不会留下半启动状态。
//!
//! # 隧道来源
//! 隧道表是**内存态**的单一向量，两类来源共用同一套 [`Tunnel`]：
//! 1. 配置里的静态隧道（启动时建立）
//! 2. 老 npc `conf` 连接注册的动态隧道（`conf_register=true` 时，见 [`crate::conf`]）
//!
//! 动态隧道不持久化：`rnps` 重启即失效，客户端重连后会重新注册。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use nps_legacy::Bridge;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::conf::ConfRegistry;
use crate::config::ServerConfig;
use crate::snapshot::{ClientSnapshot, ServerSnapshot};
use crate::tunnel::Tunnel;

/// 关闭时等待后台任务退出的上限
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
/// 关闭时等待 conf 注册会话退出的上限
const CONF_SESSION_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

struct ServerInner {
    bridge: Bridge,
    bridge_addr: SocketAddr,
    /// 客户端最小元信息（**不含 vkey**）
    clients: Vec<(i32, String)>,
    /// 隧道运行态：配置隧道在前，`conf` 注册的隧道追加在后
    tunnels: Arc<Mutex<Vec<Arc<Tunnel>>>>,
    /// 配置文件模式注册表；`None` = 该能力关闭
    conf: Option<Arc<ConfRegistry>>,
    /// UDP 隧道（配置里的 `udp_tunnels` + conf 动态注册的）
    ///
    /// 与 [`ServerInner::tunnels`] 同理用共享 `Arc<Mutex<..>>`，
    /// 这样 conf 注册路径 push 进来的隧道会立即出现在快照里。
    udp: Arc<Mutex<Vec<Arc<crate::udp::UdpTunnel>>>>,
    /// HTTP 域名代理；`None` = 未配置站点
    http: Option<Arc<crate::http_site::HttpSiteServer>>,
    /// HTTP 域名代理的取消信号
    http_cancel: Option<tokio::sync::watch::Sender<bool>>,
    /// HTTPS 域名代理（TLS 终止层）；None = 未配置 https_listen_addr
    https_tls: Option<Arc<crate::tls::TlsListener>>,
    /// 证书存储（管理端上传 / ACME 共用）
    certs: Option<Arc<crate::tls::CertificateStore>>,
    /// HTTPS accept 循环的取消信号
    https_cancel: Option<tokio::sync::watch::Sender<bool>>,
    /// ACME 服务。**只构造不申请** —— 申请必须由管理端显式触发。
    acme: Option<Arc<crate::acme::AcmeService>>,
    /// 健康检查任务的取消信号（所有检查器共用一个）
    health_cancel: Option<tokio::sync::watch::Sender<bool>>,
    /// 流量落盘的取消信号
    flow_cancel: Option<tokio::sync::watch::Sender<bool>>,
    /// 流量落盘任务句柄（关闭时等待它写完）
    flow_task: Mutex<Option<JoinHandle<()>>>,
    /// 文件服务隧道
    file: Arc<Mutex<Vec<Arc<crate::file_service::FileTunnel>>>>,
    /// file 通道登记表（bridge 收到的 file mux 存这里）
    file_channels: Arc<crate::file_service::FileChannelRegistry>,
    /// secret 隧道注册表（md5(password) -> 隧道）
    secrets: Arc<crate::secret::SecretRegistry>,
    /// p2p 会合服务配对计数（三端口共享）；None = 未配置
    p2p_paired: Option<Arc<AtomicU64>>,
    /// p2p 取消信号
    p2p_cancel: Option<tokio::sync::watch::Sender<bool>>,
    /// SOCKS5 监听（配置里的 `socks5_listeners`）
    socks5: Vec<Arc<crate::socks5::Socks5Server>>,
    bridge_task: Mutex<Option<JoinHandle<()>>>,
    /// 关闭流程已开始 / 已完成
    shutdown: Arc<AtomicBool>,
    shutdown_done: AtomicBool,
    /// 串行化关闭流程：并发调用者会等第一个调用真正结束再返回
    shutdown_lock: Mutex<()>,
}

/// 服务端实例。内部 `Arc`，可廉价 `Clone` 并在多处共享（Web 层持有即可）。
#[derive(Clone)]
pub struct Server {
    inner: Arc<ServerInner>,
}

/// 各监听面的运行时统计（管理端展示用，不含任何密钥）
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListenerStats {
    pub udp_tunnels: usize,
    pub udp_active_flows: u64,
    pub http_configured: bool,
    pub http_active_connections: u64,
    pub http_served_requests: u64,
    pub socks5_listeners: usize,
    pub socks5_active_connections: u64,
    /// secret 隧道数量（客户端本地监听，服务端只配对）
    pub secret_tunnels: usize,
    /// secret 配对成功/被拒累计次数
    pub secret_matched: u64,
    pub secret_rejected: u64,
    /// 文件服务隧道数量
    pub file_tunnels: usize,
    /// p2p 会合服务是否启用 / 配对成功次数
    pub p2p_enabled: bool,
    pub p2p_paired: u64,
}

impl Server {
    /// 校验配置、绑定端口并启动桥与隧道转发。
    ///
    /// 失败时不会留下监听端口或后台任务。
    pub async fn start(config: ServerConfig) -> Result<Self> {
        config.validate()?;

        // ---- 1. 先绑定全部端口（失败即整体回滚）----
        let bridge_listener = TcpListener::bind(&config.bridge_addr)
            .await
            .with_context(|| format!("桥端口绑定失败: {}", config.bridge_addr))?;
        let bridge_addr = bridge_listener
            .local_addr()
            .context("读取桥实际绑定地址失败")?;

        // ---- 按客户端组装流控（同一客户端的所有隧道共享一份配额）----
        let ip_allow = Arc::new(
            crate::limit::IpAllowList::new(&config.ip_limit)
                .context("ip_limit 配置非法")?,
        );
        let mut client_wraps: HashMap<i32, crate::crypt::StreamWrap> = HashMap::new();
        for c in &config.clients {
            let wrap = crate::crypt::StreamWrap::from_flags(c.crypt, c.compress);
            if !wrap.is_plain() {
                info!("客户端 {} 子流包装: {:?}", c.id, wrap);
            }
            client_wraps.insert(c.id, wrap);
        }
        let mut client_rates: HashMap<i32, Arc<crate::limit::TokenBucket>> = HashMap::new();
        let mut client_flows: HashMap<i32, Arc<crate::limit::FlowCounter>> = HashMap::new();
        for c in &config.clients {
            if c.rate_limit > 0 {
                client_rates.insert(c.id, Arc::new(crate::limit::TokenBucket::new(c.rate_limit)));
            }
            if c.flow_limit > 0 {
                client_flows.insert(c.id, Arc::new(crate::limit::FlowCounter::new(c.flow_limit)));
            }
        }
        for c in config.clients.iter().filter(|c| c.rate_limit > 0) {
            info!("客户端 {} 限速 {} KB/s", c.id, c.rate_limit);
        }
        for c in config.clients.iter().filter(|c| c.flow_limit > 0) {
            info!("客户端 {} 流量上限 {} KB", c.id, c.flow_limit);
        }
        if !config.ip_limit.is_empty() {
            info!("来源 IP 白名单已启用（{} 条）", config.ip_limit.len());
        }

        // ---- 目标池 + 健康检查 ----
        //
        // 关键：每个隧道**只有一个** TargetPool，健康检查与转发共用它。
        // 若各自建池，健康检查摘除的目标对转发不可见（曾经的 bug）。
        let (health_cancel, target_pools) = {
            let (tx, rx) = tokio::sync::watch::channel(false);
            let mut pools: HashMap<u32, Arc<crate::target::TargetPool>> = HashMap::new();

            for cfg in &config.tunnels {
                // 多目标优先：target_addrs 非空时忽略单目标 target_addr
                let spec = if cfg.target_addrs.is_empty() {
                    cfg.target_addr.clone()
                } else {
                    cfg.target_addrs.join("
")
                };
                let pool = crate::target::TargetPool::parse(&spec)
                    .map(Arc::new)
                    .unwrap_or_else(|_| Arc::new(crate::target::TargetPool::single(&spec)));
                pools.insert(cfg.id, pool);
            }

            // 健康检查：检查器与隧道共用同一个池实例
            for cfg in &config.tunnels {
                let Some(hc) = &cfg.health_check else { continue };
                let Some(pool) = pools.get(&cfg.id).cloned() else {
                    continue;
                };
                let hc_cfg = crate::target::HealthCheckConfig {
                    timeout: std::time::Duration::from_secs(hc.timeout_secs),
                    max_failed: hc.max_failed,
                    interval: std::time::Duration::from_secs(hc.interval_secs),
                    kind: crate::target::HealthCheckKind::from_config(&hc.kind, &hc.http_url),
                };
                let checker = Arc::new(crate::target::HealthChecker::new(pool, hc_cfg));
                let rx = rx.clone();
                tokio::spawn(async move { checker.run(rx).await });
                info!(
                    "隧道 {} 健康检查已启用：间隔 {}s，失败 {} 次摘除",
                    cfg.id, hc.interval_secs, hc.max_failed
                );
            }
            (Some(tx), pools)
        };

        let static_tunnels: Vec<Arc<Tunnel>> = config
            .tunnels
            .iter()
            .map(|cfg| {
                let pool = target_pools
                    .get(&cfg.id)
                    .cloned()
                    .unwrap_or_else(|| Arc::new(crate::target::TargetPool::single(&cfg.target_addr)));
                let wrap = client_wraps
                    .get(&cfg.client_id)
                    .copied()
                    .unwrap_or(crate::crypt::StreamWrap::Plain);
                Arc::new(Tunnel::with_controls(
                    cfg.clone(),
                    pool,
                    client_rates.get(&cfg.client_id).cloned(),
                    client_flows.get(&cfg.client_id).cloned(),
                    ip_allow.clone(),
                    wrap,
                ))
            })
            .collect();

        // 动态隧道 id 从静态隧道最大 id + 1 起分配，避免与管理端可见 id 冲突
        let first_dynamic_id = match static_tunnels.iter().map(|t| t.id()).max() {
            Some(u32::MAX) => {
                if config.conf_register {
                    bail!("隧道 id 已用尽（u32::MAX），无法启用配置文件模式");
                }
                1
            }
            Some(max) => max + 1,
            None => 1,
        };
        let tunnels = Arc::new(Mutex::new(static_tunnels.clone()));

        // 已绑定的监听器先攒着，全部成功后再启动任务
        let mut bound: Vec<(Arc<Tunnel>, TcpListener)> = Vec::new();
        for t in &static_tunnels {
            if !t.cfg.enabled {
                continue;
            }
            match t.bind().await {
                Ok(listener) => bound.push((t.clone(), listener)),
                Err(e) => {
                    // bridge_listener 与已绑定端口随作用域释放
                    drop(bound);
                    drop(bridge_listener);
                    return Err(e);
                }
            }
        }

        // ---- 2. 构建桥与注册表 ----
        let verify = Arc::new(config.verify_table());
        let verify_for_bridge = verify.clone();
        let bridge =
            Bridge::new(move |md5_hex_vkey: &str| verify_for_bridge.get(md5_hex_vkey).copied());

        // ---- file 通道登记表 ----
        let file_channels = Arc::new(crate::file_service::FileChannelRegistry::new());
        let file_tunnels_for_conf: Arc<Mutex<Vec<Arc<crate::file_service::FileTunnel>>>> =
            Arc::new(Mutex::new(Vec::new()));
        bridge.set_file_handler(Arc::new(FileChannelSink {
            registry: file_channels.clone(),
        }));

        // ---- secret 隧道注册表（md5(password) -> 隧道）----
        let secrets = Arc::new(crate::secret::SecretRegistry::from_passwords(
            config
                .secret_tunnels
                .iter()
                .filter(|t| t.enabled)
                .map(|t| {
                    (
                        t.password.clone(),
                        crate::secret::SecretTarget {
                            id: t.id,
                            name: t.name.clone(),
                            client_id: t.client_id,
                            target_addr: t.target_addr.clone(),
                        },
                    )
                }),
        ));
        if !secrets.is_empty() {
            info!("secret 隧道已启用 {} 条（客户端本地监听，服务端按密码配对）", secrets.len());
        }
        bridge.set_secret_handler(Arc::new(SecretSink {
            bridge: bridge.clone(),
            registry: secrets.clone(),
        }));

        // ---- p2p 会合服务（仅信令；原版需要**三个连续端口**）----
        let (p2p_paired, p2p_cancel) = match config.p2p_listen_addr.as_deref() {
            Some(addr) => {
                let listen: SocketAddr = addr
                    .trim()
                    .parse()
                    .with_context(|| format!("p2p_listen_addr 非法: {addr}"))?;
                let (bound, tx, paired) = crate::p2p::spawn_three(listen)
                    .await
                    .context("p2p 会合服务启动失败")?;
                info!("p2p 会合端口: {:?}", bound);
                (Some(paired), Some(tx))
            }
            None => (None, None),
        };

        // ---- 3. HTTP 域名代理（先于 conf 创建：conf 的 host 帧要 upsert 进来）----
        //
        // 只要配置了 `http_listen_addr` 就创建（站点表可为空），
        // 因为 `conf` 的 host 帧会在运行时动态 upsert 站点。
        //
        // 注意：只配 `https_listen_addr` 时也必须创建解析器 ——
        // HTTPS 路径复用同一个 `HttpSiteServer`，只是不监听 80 端口。
        let (http, http_cancel) = if config.http_sites.is_empty() && config.http_listen_addr.is_none()
        {
            (None, None)
        } else {
            let listen_for_cfg = config
                .http_listen_addr
                .clone()
                .unwrap_or_else(|| "127.0.0.1:0".to_owned());
            let proxy_cfg =
                crate::http_site::HttpProxyConfig::from_server_config(&config, &listen_for_cfg);
            let server = crate::http_site::HttpSiteServer::new(bridge.clone(), proxy_cfg)?;

            match config.http_listen_addr.as_deref() {
                Some(addr) => {
                    let listener = tokio::net::TcpListener::bind(addr)
                        .await
                        .with_context(|| format!("HTTP 域名代理无法监听 {addr}"))?;
                    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
                    let s = server.clone();
                    tokio::spawn(async move { s.serve(listener, cancel_rx).await });
                    (Some(server), Some(cancel_tx))
                }
                None => (Some(server), None),
            }
        };

        // ---- 3.4 ACME 服务：只构造，绝不申请 ----
        //
        // 构造只建目录、初始化挑战表，**零网络请求**。
        // 真正申请必须由管理端调用 ，
        // 这是「程序绝不擅自申请证书」的落点。
        let acme = {
            let data_dir = config
                .data_dir
                .clone()
                .unwrap_or_else(|| ".".to_owned());
            let acme_cfg = config.acme.to_config(&data_dir);
            match crate::acme::AcmeService::new(acme_cfg) {
                Ok(service) => {
                    info!(
                        "ACME 服务已初始化（不自动申请；证书目录 {}）",
                        service.client().certs_dir().display()
                    );
                    Some(Arc::new(service))
                }
                Err(e) => {
                    warn!("ACME 服务初始化失败，证书申请功能不可用: {e}");
                    None
                }
            }
        };

        // ---- 3.5 HTTPS 域名代理（TLS 终止 + SNI 路由）----
        //
        // 只在显式配置 https_listen_addr 时启用。证书来自 cert_dir，
        // 程序**不会**自动申请证书；tls_mode=SelfSigned 的站点在此生成自签证书，
        // Upload / Acme 需要用户先通过管理端或 ACME 流程放好证书。
        let (certs, https_tls, https_cancel) = match config.https_listen_addr.as_deref() {
            Some(addr) => {
                let cert_root = config
                    .cert_dir
                    .clone()
                    .unwrap_or_else(|| "certs".to_owned());
                let store = crate::tls::CertificateStore::open(&cert_root).with_context(|| {
                    format!("证书目录无法使用: {cert_root}（可用 cert_dir 指定其它位置）")
                })?;

                // 自签证书是「用户选择 self-signed」的显式意图，可以在此生成；
                // Upload / Acme 一律不自动生成，缺证书就在握手时拒绝该域名。
                for site in config
                    .http_sites
                    .iter()
                    .filter(|s| s.tls_mode == crate::config::TlsMode::SelfSigned)
                {
                    if store.get(&site.domain).is_none() {
                        store.put_self_signed(&site.domain).with_context(|| {
                            format!("为 {} 生成自签证书失败", site.domain)
                        })?;
                        info!("已为 {} 生成自签证书（仅测试用途）", site.domain);
                    }
                }

                let tls = crate::tls::TlsListener::new(store.resolver())?;
                let listener = tls.bind(addr).await?;
                let bound = listener.local_addr().ok();
                let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

                // 握手成功后把解密流交给 HTTP 层复用同一套解析逻辑。
                // 每个连接共享 accept 循环的取消信号，shutdown 时一并退出。
                let http_for_tls = http.clone();
                let tls_task = tls.clone();
                let conn_cancel = cancel_tx.subscribe();
                tokio::spawn(async move {
                    tls_task
                        .serve(listener, cancel_rx, move |session| {
                            let http = http_for_tls.clone();
                            let cancel = conn_cancel.clone();
                            async move {
                                match http {
                                    Some(http) => {
                                        let peer = session.peer;
                                        http.serve_stream(session.stream, peer, cancel).await;
                                    }
                                    None => {
                                        warn!("收到 HTTPS 连接但未配置 HTTP 域名代理，已丢弃");
                                    }
                                }
                            }
                        })
                        .await;
                });
                info!("HTTPS 域名代理监听 {:?}（证书目录 {}）", bound, cert_root);
                (Some(store), Some(tls), Some(cancel_tx))
            }
            None => (None, None, None),
        };

        // ---- 4. 配置文件模式（默认关闭）----
        let shutdown = Arc::new(AtomicBool::new(false));
        let udp_tunnels_shared: Arc<Mutex<Vec<Arc<crate::udp::UdpTunnel>>>> =
            Arc::new(Mutex::new(Vec::new()));
        let conf = if config.conf_register {
            let listen_host = config
                .conf_listen_host
                .trim()
                .parse()
                .context("conf_listen_host 非法")?;
            let registry = Arc::new(ConfRegistry::new(
                tunnels.clone(),
                udp_tunnels_shared.clone(),
                http.clone(),
                Arc::new(client_wraps.clone()),
                file_tunnels_for_conf.clone(),
                file_channels.clone(),
                verify,
                listen_host,
                config.conf_max_tunnels,
                first_dynamic_id,
                shutdown.clone(),
            ));
            bridge.set_conf_handler(registry.clone());
            info!(
                "配置文件模式（conf）已开启：listen_host={}, 隧道上限={}；注册的隧道仅存内存，重启即失效",
                config.conf_listen_host.trim(),
                config.conf_max_tunnels
            );
            Some(registry)
        } else {
            None
        };

        // ---- 4. 启动桥 accept 循环 ----
        let bridge_for_task = bridge.clone();
        let bridge_task = tokio::spawn(async move {
            if let Err(e) = bridge_for_task.serve_on(bridge_listener).await {
                warn!("bridge accept 循环异常退出: {e}");
            }
        });

        // ---- 5. 启动隧道转发 ----
        for (t, listener) in bound {
            let guard = t.lock_op().await;
            t.start_with_listener(bridge.clone(), listener).await;
            drop(guard);
        }

        // ---- 6. UDP 隧道：先全部绑定，失败则整体回滚 ----
        let mut udp_bound: Vec<(Arc<crate::udp::UdpTunnel>, tokio::net::UdpSocket)> = Vec::new();
        for cfg in config.udp_tunnels.iter().filter(|t| t.enabled) {
            let t = Arc::new(crate::udp::UdpTunnel::new(cfg.clone()));
            match t.bind().await {
                Ok(socket) => udp_bound.push((t, socket)),
                Err(e) => {
                    drop(udp_bound);
                    return Err(e.context(format!(
                        "UDP 隧道 {} ({}) 绑定失败",
                        cfg.id, cfg.listen_addr
                    )));
                }
            }
        }
        for (t, socket) in udp_bound {
            let bound_addr = t
                .start_with_socket(bridge.clone(), socket)
                .await
                .with_context(|| format!("UDP 隧道 {} 启动失败", t.id()))?;
            info!("UDP 隧道 {} 监听 {}", t.id(), bound_addr);
            udp_tunnels_shared.lock().await.push(t);
        }
        let udp_tunnels: Vec<Arc<crate::udp::UdpTunnel>> =
            udp_tunnels_shared.lock().await.clone();


        // ---- 8. SOCKS5：先全部绑定，失败则整体回滚 ----
        let mut socks5_servers: Vec<Arc<crate::socks5::Socks5Server>> = Vec::new();
        let mut socks5_bound: Vec<(
            Arc<crate::socks5::Socks5Server>,
            TcpListener,
        )> = Vec::new();
        for cfg in config.socks5_listeners.iter().filter(|s| s.enabled) {
            let s = Arc::new(crate::socks5::Socks5Server::new(cfg.clone(), bridge.clone()));
            match s.bind().await {
                Ok(listener) => socks5_bound.push((s, listener)),
                Err(e) => {
                    drop(socks5_bound);
                    drop(udp_tunnels);
                    if let Some(c) = &http_cancel {
                        let _ = c.send(true);
                    }
                    return Err(anyhow::Error::from(e).context(format!(
                        "SOCKS5 监听 {} ({}) 绑定失败",
                        cfg.id, cfg.listen_addr
                    )));
                }
            }
        }
        for (s, listener) in socks5_bound {
            let this = s.clone();
            tokio::spawn(async move {
                if let Err(e) = this.serve_on(listener).await {
                    warn!("SOCKS5 accept 循环异常退出: {e}");
                }
            });
            socks5_servers.push(s);
        }

        // ---- 9. 文件服务隧道：先全部绑定，失败则整体回滚 ----
        let file_tunnels_shared = file_tunnels_for_conf.clone();
        let mut file_bound: Vec<(
            Arc<crate::file_service::FileTunnel>,
            tokio::net::TcpListener,
        )> = Vec::new();
        for cfg in config.file_tunnels.iter().filter(|t| t.enabled) {
            let t = Arc::new(crate::file_service::FileTunnel::with_registry(
                cfg.clone(),
                file_channels.clone(),
            ));
            match t.bind().await {
                Ok(listener) => file_bound.push((t, listener)),
                Err(e) => {
                    return Err(e.context(format!(
                        "文件隧道 {} ({}) 绑定失败",
                        cfg.id, cfg.listen_addr
                    )));
                }
            }
        }
        for (t, listener) in file_bound {
            let bound = t
                .start_with_listener(bridge.clone(), listener)
                .await
                .with_context(|| format!("文件隧道 {} 启动失败", t.id()))?;
            info!("文件隧道 {} 监听 {}", t.id(), bound);
            file_tunnels_shared.lock().await.push(t);
        }

        let clients = config
            .clients
            .iter()
            .map(|c| (c.id, c.name.clone()))
            .collect();
        // 在 drop(config) 之前取出流量持久化需要的两个值
        let config_data_dir = config
            .data_dir
            .clone()
            .unwrap_or_else(|| ".".to_owned());
        let flow_store_interval = config.flow_store_interval;
        // config 在此释放：明文 vkey 不进入任何长期存活的服务器状态
        drop(config);

        // ---- 流量持久化：读回旧值 + 启动定时落盘 ----
        let data_dir = config_data_dir.clone();
        let flow_store = crate::flow_store::FlowStore::new(
            std::path::Path::new(&data_dir).join("flow.json"),
        );
        let restored = flow_store.load();
        let mut restored_count = 0usize;
        for t in &static_tunnels {
            if let Some(rec) = restored.tunnels.get(&t.id()) {
                t.restore_bytes(rec.bytes_to_client, rec.bytes_from_client);
                restored_count += 1;
            }
        }
        if restored_count > 0 {
            info!(
                "已从 {} 恢复 {} 条隧道的累计流量",
                flow_store.path().display(),
                restored_count
            );
        }

        let (flow_cancel, flow_rx) = tokio::sync::watch::channel(false);
        let flow_cancel = Some(flow_cancel);
        let tunnels_for_flow = tunnels.clone();
        let flow_task = {
            let store = flow_store.clone();
            tokio::spawn(crate::flow_store::run_flow_store_loop(
                store,
                flow_store_interval,
                flow_rx,
                move || {
                    let mut snap = crate::flow_store::FlowSnapshot::default();
                    if let Ok(list) = tunnels_for_flow.try_lock() {
                        for t in list.iter() {
                            let (to_c, from_c) = t.bytes();
                            snap.tunnels.insert(
                                t.id(),
                                crate::flow_store::FlowRecord {
                                    bytes_to_client: to_c,
                                    bytes_from_client: from_c,
                                },
                            );
                        }
                    }
                    snap
                },
            ))
        };

        info!("Rust-nps 服务端启动完成，桥监听 {}", bridge_addr);

        Ok(Self {
            inner: Arc::new(ServerInner {
                bridge,
                bridge_addr,
                clients,
                tunnels,
                conf,
                udp: udp_tunnels_shared,
                http,
                http_cancel,
                https_tls,
                certs,
                https_cancel,
                acme,
                health_cancel,
                flow_cancel,
                flow_task: Mutex::new(Some(flow_task)),
                file: file_tunnels_shared,
                file_channels,
                secrets,
                p2p_paired,
                p2p_cancel,
                socks5: socks5_servers,
                bridge_task: Mutex::new(Some(bridge_task)),
                shutdown,
                shutdown_done: AtomicBool::new(false),
                shutdown_lock: Mutex::new(()),
            }),
        })
    }

    /// 桥实际绑定地址（`bridge_addr` 配 `:0` 时返回系统分配的端口）
    pub fn bridge_addr(&self) -> SocketAddr {
        self.inner.bridge_addr
    }

    /// 各监听面的运行时统计（供管理端展示；不含任何密钥）。
    pub fn listeners(&self) -> ListenerStats {
        ListenerStats {
            udp_tunnels: self.inner.udp.try_lock().map(|v| v.len()).unwrap_or(0),
            udp_active_flows: self
                .inner
                .udp
                .try_lock()
                .map(|v| v.iter().map(|t| t.active_flows()).sum())
                .unwrap_or(0),
            http_configured: self.inner.http.is_some(),
            http_active_connections: self
                .inner
                .http
                .as_ref()
                .map(|h| h.active_connections())
                .unwrap_or(0),
            http_served_requests: self
                .inner
                .http
                .as_ref()
                .map(|h| h.served_requests())
                .unwrap_or(0),
            secret_tunnels: self.inner.secrets.len(),
            secret_matched: self.inner.secrets.matched(),
            secret_rejected: self.inner.secrets.rejected(),
            file_tunnels: self.inner.file.try_lock().map(|v| v.len()).unwrap_or(0),
            p2p_enabled: self.inner.p2p_paired.is_some(),
            p2p_paired: self
                .inner
                .p2p_paired
                .as_ref()
                .map(|p| p.load(Ordering::Relaxed))
                .unwrap_or(0),
            socks5_listeners: self.inner.socks5.len(),
            socks5_active_connections: self
                .inner
                .socks5
                .iter()
                .map(|s| s.active_connections())
                .sum(),
        }
    }

    /// 生成状态快照。**不含 vkey / 密文 / token**。
    pub async fn snapshot(&self) -> ServerSnapshot {
        let mut clients = Vec::with_capacity(self.inner.clients.len());
        for (id, name) in &self.inner.clients {
            let (online, version) = self.inner.bridge.client_status(*id).await;
            clients.push(ClientSnapshot {
                id: *id,
                name: name.clone(),
                online,
                version,
            });
        }

        // 先克隆一层 Arc 再逐个快照：避免在整个快照期间持锁（注册路径会被挡住）
        let list = self.inner.tunnels.lock().await.clone();
        let mut tunnels = Vec::with_capacity(list.len());
        for t in &list {
            tunnels.push(t.snapshot().await);
        }
        // UDP 隧道复用同一快照契约（字段一致）
        let udp_list = self.inner.udp.lock().await.clone();
        for t in &udp_list {
            tunnels.push(t.snapshot().await);
        }
        // 文件服务隧道
        let file_list = self.inner.file.lock().await.clone();
        for t in &file_list {
            tunnels.push(t.snapshot().await);
        }

        ServerSnapshot {
            bridge_addr: self.inner.bridge_addr.to_string(),
            clients,
            tunnels,
        }
    }

    /// 启停某条隧道。停止会关闭监听器并断开该隧道现存转发连接。
    ///
    /// 竞态处理：每次操作在 `op` 锁内串行，且**拿到锁之后**再确认一次服务端
    /// 未关闭——否则"检查关闭 → 等待锁 → 关闭完成 → 绑定端口"会留下
    /// shutdown 之后的孤儿监听器。关闭后调用返回明确错误，不 panic。
    pub async fn set_tunnel_enabled(&self, id: u32, enabled: bool) -> Result<()> {
        // 只持锁取出 Arc，后续操作不占隧道表锁（注册路径也用它，避免互相阻塞）
        let tunnel = {
            let list = self.inner.tunnels.lock().await;
            list.iter().find(|t| t.id() == id).cloned()
        }
        .with_context(|| format!("隧道 {id} 不存在"))?;

        let _guard = tunnel.lock_op().await;
        if self.is_shutdown() {
            bail!("服务端已关闭，无法更改隧道 {id} 的状态");
        }
        if enabled {
            tunnel
                .enable(self.inner.bridge.clone())
                .await
                .with_context(|| format!("启用隧道 {id} 失败"))?;
            info!("隧道 {id} 已启用");
        } else {
            tunnel.disable().await;
            info!("隧道 {id} 已停用");
        }
        Ok(())
    }

    /// 关闭服务端：停所有隧道、关闭桥、等待后台任务退出。
    ///
    /// 幂等且可并发：`shutdown_lock` 保证第一个调用完整执行关闭流程，
    /// 后续/并发的调用等待它结束后直接返回（不会看到"半关闭"状态）。
    /// 关闭完成后 `snapshot()` 仍可安全调用。
    pub async fn shutdown(&self) {
        let _serial = self.inner.shutdown_lock.lock().await;
        if self.inner.shutdown_done.load(Ordering::Acquire) {
            return;
        }
        // 先置"关闭中"标志：此后 `set_tunnel_enabled` 会在 op 锁内被拒绝
        self.inner.shutdown.store(true, Ordering::Release);

        // 与 conf 注册串行：避免"注册刚 push、关闭已取完列表"导致 shutdown 返回后
        // 仍留下一条监听器。持锁期间注册路径会看到关闭标志并放弃。
        let _register_guard = match &self.inner.conf {
            Some(conf) => Some(conf.lock_register().await),
            None => None,
        };

        // 先停隧道（关闭监听器与现存连接）
        let list = self.inner.tunnels.lock().await.clone();
        for t in &list {
            let _guard = t.lock_op().await;
            t.disable().await;
        }
        drop(_register_guard);

        // 停 UDP 隧道（关闭 socket 并回收全部来源映射）
        let udp_list = self.inner.udp.lock().await.clone();
        for t in &udp_list {
            t.shutdown().await;
        }

        // 停 HTTP 域名代理（广播取消，accept 循环退出后 abort 连接任务）
        if let Some(cancel) = &self.inner.http_cancel {
            let _ = cancel.send(true);
        }

        // 停 HTTPS 域名代理
        if let Some(cancel) = &self.inner.https_cancel {
            let _ = cancel.send(true);
        }

        // 停健康检查
        if let Some(cancel) = &self.inner.health_cancel {
            let _ = cancel.send(true);
        }

        // 停 p2p 会合服务
        if let Some(cancel) = &self.inner.p2p_cancel {
            let _ = cancel.send(true);
        }

        // 停流量落盘（它会在退出前再写一次）
        if let Some(cancel) = &self.inner.flow_cancel {
            let _ = cancel.send(true);
        }
        let flow_task = self.inner.flow_task.lock().await.take();
        if let Some(task) = flow_task {
            match tokio::time::timeout(Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!("流量落盘任务 join 失败: {e}"),
                Err(_) => warn!("流量落盘任务退出超时"),
            }
        }

        // 停 SOCKS5 监听
        for s in &self.inner.socks5 {
            s.shutdown().await;
        }

        // 停文件服务隧道
        let file_list = self.inner.file.lock().await.clone();
        for t in &file_list {
            t.shutdown().await;
        }
        self.inner.file_channels.clear();

        // 再关桥（同时通过 closing 广播让 conf 注册会话退出）
        self.inner.bridge.shutdown().await;
        if let Some(conf) = &self.inner.conf {
            let deadline = tokio::time::Instant::now() + CONF_SESSION_SHUTDOWN_TIMEOUT;
            while conf.active_sessions() > 0 && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            if conf.active_sessions() > 0 {
                warn!("仍有 {} 个 conf 会话未退出", conf.active_sessions());
            }
        }
        let task = self.inner.bridge_task.lock().await.take();
        if let Some(h) = task {
            match tokio::time::timeout(SHUTDOWN_TIMEOUT, h).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!("bridge 任务 join 失败: {e}"),
                Err(_) => warn!("bridge 任务关闭超时"),
            }
        }
        self.inner.shutdown_done.store(true, Ordering::Release);
        info!("Rust-nps 服务端已关闭");
    }

    /// 证书存储（管理端上传 / 查询 / ACME 部署共用）。未启用 HTTPS 时为 None。
    pub fn certificate_store(&self) -> Option<Arc<crate::tls::CertificateStore>> {
        self.inner.certs.clone()
    }

    /// HTTPS 监听器（用于读取握手统计）。未启用时为 None。
    pub fn https_listener(&self) -> Option<Arc<crate::tls::TlsListener>> {
        self.inner.https_tls.clone()
    }

    /// 列出当前生效的站点（管理端展示用；不含任何密钥）。
    pub async fn list_sites(&self) -> Vec<crate::http_site::HttpSite> {
        match &self.inner.http {
            Some(http) => http.router().await.sites().to_vec(),
            None => Vec::new(),
        }
    }

    /// 新增或更新一个站点（按域名）。立即生效，无需重启。
    ///
    /// 返回  表示域名非法或与已有站点冲突。
    pub async fn upsert_site(&self, site: crate::http_site::HttpSite) -> Result<()> {
        let http = self
            .inner
            .http
            .as_ref()
            .context("域名代理未启用（需配置 http_listen_addr 或 https_listen_addr）")?;
        if self.is_shutdown() {
            bail!("服务端已关闭，无法修改站点");
        }
        http.upsert_site(site).await
    }

    /// 删除一个站点（按域名）。返回是否真的删掉了。
    pub async fn remove_site(&self, domain: &str) -> Result<bool> {
        let Some(http) = self.inner.http.as_ref() else {
            return Ok(false);
        };
        Ok(http.remove_site(domain).await)
    }

    /// ACME 服务（管理端用来触发申请/查询待办）。
    ///
    /// **拿到它不会产生任何网络请求**；只有显式调用
    /// `request_certificate` 才会联系 CA。
    pub fn acme(&self) -> Option<Arc<crate::acme::AcmeService>> {
        self.inner.acme.clone()
    }

    pub fn is_shutdown(&self) -> bool {
        self.inner.shutdown.load(Ordering::Acquire)
    }
}

/// 把桥收到的 `file` 通道登记进 `FileChannelRegistry`。
struct FileChannelSink {
    registry: Arc<crate::file_service::FileChannelRegistry>,
}

impl nps_legacy::bridge::FileChannelHandler for FileChannelSink {
    fn handle(&self, client_id: i32, mux: Arc<nps_legacy::mux::MuxSession>) {
        self.registry.register_and_watch(client_id, mux);
    }
}

/// 把桥收到的 `sert` 连接交给 secret 隧道处理。
struct SecretSink {
    bridge: Bridge,
    registry: Arc<crate::secret::SecretRegistry>,
}

impl nps_legacy::bridge::SecretHandler for SecretSink {
    fn handle(
        &self,
        client_id: i32,
        password_md5: String,
        stream: tokio::net::TcpStream,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        let bridge = self.bridge.clone();
        let registry = self.registry.clone();
        Box::pin(async move {
            crate::secret::handle_secret_connection(
                bridge,
                registry,
                client_id,
                password_md5,
                stream,
            )
            .await;
        })
    }
}
