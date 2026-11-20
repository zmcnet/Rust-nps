//! SOCKS5 代理（RFC 1928）与用户名密码认证（RFC 1929）。
//!
//! 对齐 Go `server/proxy/socks5.go` 的行为：
//! - 服务端在 `listen_addr` 上监听，自己完成 SOCKS5 握手/认证/请求解析，
//!   然后把目标地址通过 mux 子流交给老 npc 去拨号（`ConnType="tcp"`）。
//! - 客户端（npc）**不需要**任何额外配置：`mode=socks5` 完全在服务端实现，
//!   npc 只按 Link 里的 `Host` 拨号并透传字节。
//!
//! ```text
//! SOCKS5 客户端 --TCP--> nps-server(Socks5Server)
//!   ├─ 握手：VER=5, NMETHODS, METHODS[]      -> 选 0x00 或 0x02
//!   ├─ 认证：VER=1, ULEN, UNAME, PLEN, PASSWD -> VER=1, STATUS
//!   ├─ 请求：VER=5, CMD, RSV, ATYP, ADDR, PORT
//!   ├─ bridge.get_tunnel(client_id) -> mux.open_stream()
//!   ├─ 写首帧：int32 LE 长度 + Link JSON（ConnType="tcp"）
//!   ├─ 回 REP=0（VER=5, REP, RSV=0, ATYP, BND.ADDR, BND.PORT）
//!   └─ 双向字节流（两条独立泵，避免全双工死锁）
//! ```
//!
//! # 能力与边界
//! - **CONNECT**：完整实现。
//! - **BIND**：如实返回 `REP=7`（command not supported），不假装支持。
//! - **UDP ASSOCIATE**：已实现（`ConnType="udp5"`，子流内为 Go 的
//!   `int32 LE 长度 + SOCKS5 UDP 报文` 帧，上行方向按 Go 原版写裸报文）。
//! - 目标不可达的判定边界与 Go 原版一致：协议里没有"拨号结果"的确认帧，
//!   因此**服务端只能在两种情况下给出失败码**：
//!   * 客户端离线 / mux 建流被拒 -> `REP=1`（general failure）
//!   * mux 建流失败（会话已死）-> `REP=4`（host unreachable）
//!   目标主机本身连不上时，npc 会直接关闭子流，服务端此时已回过 `REP=0`，
//!   客户端表现为"连接建立后立即 EOF"——这与 Go 原版 `DealClient` 完全一致。
//!
//! # 安全
//! - 认证失败立即关闭，不重试；日志不打印用户名/密码。
//! - 密码比较为常量时间（避免按字节短路）。
//! - 握手（含认证与请求头）整体 10s 超时；域名长度上限 255。
//! - 并发连接数上限（默认 [`DEFAULT_MAX_CONNECTIONS`]），超限直接关闭。
//! - UDP ASSOCIATE 只接受来自首个报文来源地址的后续报文（RFC 1928 要求）。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nps_legacy::mux::{MuxRecvHalf, MuxSendHalf};
use nps_legacy::Bridge;
use nps_proto::{Link, CONN_TCP};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{watch, Mutex};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, info, trace, warn};

use crate::config::Socks5Config;

/// SOCKS 协议版本
pub const SOCKS_VERSION: u8 = 0x05;
/// 用户名密码认证子协议版本（RFC 1929）
pub const AUTH_VERSION: u8 = 0x01;
/// 无认证
pub const METHOD_NO_AUTH: u8 = 0x00;
/// 用户名密码认证
pub const METHOD_USERPASS: u8 = 0x02;
/// 没有可接受的方法
pub const METHOD_UNACCEPTABLE: u8 = 0xFF;

/// CONNECT
pub const CMD_CONNECT: u8 = 0x01;
/// BIND
pub const CMD_BIND: u8 = 0x02;
/// UDP ASSOCIATE
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// IPv4 地址
pub const ATYP_IPV4: u8 = 0x01;
/// 域名（首字节是长度）
pub const ATYP_DOMAIN: u8 = 0x03;
/// IPv6 地址
pub const ATYP_IPV6: u8 = 0x04;

/// 握手（greeting + 认证 + 请求头）的整体超时。
///
/// 只覆盖协商阶段；CONNECT 建立后的双向转发是长连接，不受此限制。
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 默认并发连接上限（单进程、个人/小团队场景足够）。
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;
/// 域名长度上限（RFC 1928 的 ATYP=3 用 1 字节表示长度，即 255）。
pub const MAX_DOMAIN_LEN: usize = 255;
/// 单次转发缓冲（与 Go `common.PoolSizeCopy` 一致，只影响 read 粒度）。
const COPY_BUF: usize = 32 * 1024;
/// UDP 报文长度上限。
///
/// 对齐 Go 原版 `common.PoolSizeUdp = 1672` 与
/// `if err != nil || l >= common.PoolSizeUdp || l <= 0` 的校验：
/// 合法的子流帧长度是 `1..=1671`。
pub const MAX_UDP_PAYLOAD: usize = 1671;
/// UDP 子流的 ConnType（Go: `conn.NewLink("udp5", ...)`）
pub const CONN_UDP5: &str = "udp5";
/// 关闭时等待 accept 任务退出的上限
const STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// SOCKS5 应答码（REP）
pub mod reply {
    /// 成功
    pub const SUCCEEDED: u8 = 0x00;
    /// 一般性失败（本实现用于"客户端离线 / mux 建流被拒"）
    pub const GENERAL_FAILURE: u8 = 0x01;
    /// 规则不允许
    pub const NOT_ALLOWED: u8 = 0x02;
    /// 网络不可达
    pub const NETWORK_UNREACHABLE: u8 = 0x03;
    /// 主机不可达（本实现用于"mux 会话已死，无法建流"）
    pub const HOST_UNREACHABLE: u8 = 0x04;
    /// 连接被拒绝
    pub const CONNECTION_REFUSED: u8 = 0x05;
    /// TTL 过期
    pub const TTL_EXPIRED: u8 = 0x06;
    /// 命令不支持（BIND / 未知 CMD）
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    /// 地址类型不支持
    pub const ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

/// 客户端请求里的目标地址
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    /// IPv4 / IPv6 字面量
    Ip(SocketAddr),
    /// 域名 + 端口（域名长度 1..=255，且不含 `:`）
    Domain(String, u16),
}

impl TargetAddr {
    /// 转成老 npc 能直接 `net.Dial` 的 `host:port`。
    ///
    /// IPv6 必须加方括号，否则 `::1:80` 会被解析成非法地址
    /// （Go 用 `net.JoinHostPort` 做同样的事）。
    pub fn to_host_port(&self) -> String {
        match self {
            TargetAddr::Ip(addr) => match addr.ip() {
                IpAddr::V4(ip) => format!("{ip}:{}", addr.port()),
                IpAddr::V6(ip) => format!("[{ip}]:{}", addr.port()),
            },
            TargetAddr::Domain(host, port) => format!("{host}:{port}"),
        }
    }
}

/// 解析后的 SOCKS5 请求
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksRequest {
    /// CMD（1=CONNECT / 2=BIND / 3=UDP ASSOCIATE）
    pub cmd: u8,
    /// 目标地址
    pub target: TargetAddr,
    /// 原始 ATYP（便于日志/测试）
    pub atyp: u8,
}

/// 协商阶段的三种结局
enum Outcome {
    /// 可以进入命令处理
    Ready(SocksRequest),
    /// 需要回一个 REP 后关闭（地址类型不支持等）
    Reply(u8),
    /// 静默关闭（版本不对、无可用认证方法、认证失败）
    Close,
}

/// 计数器守卫：任何退出路径（含 panic / abort）都会归还并发计数。
struct ActiveGuard(Arc<Socks5Server>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        let _ = self
            .0
            .active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                Some(v.saturating_sub(1))
            });
    }
}

/// SOCKS5 代理服务实例。
///
/// 内部状态用 `Arc` 包裹的原子量 / `Mutex`，可 `Clone` 出 `Arc<Self>` 在多任务间共享。
pub struct Socks5Server {
    cfg: Socks5Config,
    bridge: Bridge,
    /// 账号表：username -> password。空表 = 只允许无认证。
    users: Arc<HashMap<String, String>>,
    max_connections: usize,
    handshake_timeout: Duration,
    active: AtomicU64,
    closing: AtomicBool,
    bound_addr: Mutex<Option<SocketAddr>>,
    close_tx: watch::Sender<bool>,
    /// 常驻接收端：`watch::Sender::send` 在没有接收端时会失败且不保存值，
    /// 保留一个接收端保证 `shutdown()` 任何时刻调用都能生效。
    _close_keepalive: watch::Receiver<bool>,
    accept_task: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for Socks5Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5Server")
            .field("id", &self.cfg.id)
            .field("name", &self.cfg.name)
            .field("client_id", &self.cfg.client_id)
            .field("listen_addr", &self.cfg.listen_addr)
            .field("auth_users", &format_args!("{}（密码 <redacted>）", self.users.len()))
            .field("max_connections", &self.max_connections)
            .field("active_connections", &self.active.load(Ordering::Relaxed))
            .finish()
    }
}

impl Socks5Server {
    /// 用配置里的账号表构建（`cfg.users` 为空则只允许无认证）。
    pub fn new(cfg: Socks5Config, bridge: Bridge) -> Self {
        let users = cfg
            .users
            .iter()
            .map(|u| (u.username.clone(), u.password.clone()))
            .collect();
        Self::with_users(cfg, bridge, users)
    }

    /// 用显式账号表构建（`username -> password`）。
    ///
    /// 空表 = 只允许无认证；非空 = 强制用户名密码认证。
    pub fn with_users(
        cfg: Socks5Config,
        bridge: Bridge,
        users: HashMap<String, String>,
    ) -> Self {
        let (close_tx, close_keepalive) = watch::channel(false);
        Self {
            cfg,
            bridge,
            users: Arc::new(users),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            handshake_timeout: HANDSHAKE_TIMEOUT,
            active: AtomicU64::new(0),
            closing: AtomicBool::new(false),
            bound_addr: Mutex::new(None),
            close_tx,
            _close_keepalive: close_keepalive,
            accept_task: Mutex::new(None),
        }
    }

    /// 设置并发连接上限（`0` 会被钳成 1，避免"永远拒绝"的配置）。
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max.max(1);
        self
    }

    /// 覆盖握手超时（主要给测试用；生产默认 [`HANDSHAKE_TIMEOUT`]）。
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// 配置中的监听地址
    pub fn listen_addr(&self) -> &str {
        &self.cfg.listen_addr
    }

    /// 实际绑定地址（`listen_addr` 配 `:0` 时是系统分配的端口）
    pub async fn bound_addr(&self) -> Option<SocketAddr> {
        *self.bound_addr.lock().await
    }

    /// 当前活跃连接数
    pub fn active_connections(&self) -> u64 {
        self.active.load(Ordering::Relaxed)
    }

    /// 是否已进入关闭流程
    pub fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Acquire)
    }

    /// 绑定 `cfg.listen_addr`（供上层做"先全部绑定再启动"的原子启动）。
    pub async fn bind(&self) -> std::io::Result<TcpListener> {
        TcpListener::bind(&self.cfg.listen_addr).await
    }

    /// 在已绑定的 listener 上启动 accept 循环。
    ///
    /// 直到 [`Socks5Server::shutdown`] 被调用才返回；返回时关闭所有活跃会话。
    pub async fn serve_on(self: &Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
        let local = listener.local_addr().ok();
        *self.bound_addr.lock().await = local;
        info!(
            "SOCKS5 代理 {}（clientId {}）监听 {:?}",
            self.cfg.name, self.cfg.client_id, local
        );

        let mut close_rx = self.close_tx.subscribe();
        if *close_rx.borrow() {
            return Ok(());
        }

        let mut conns: JoinSet<()> = JoinSet::new();
        loop {
            tokio::select! {
                _ = close_rx.changed() => break,
                _ = conns.join_next(), if !conns.is_empty() => {}
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, peer)) => {
                            if self.is_closing() {
                                break;
                            }
                            let this = self.clone();
                            conns.spawn(async move {
                                this.handle_conn(stream, peer).await;
                            });
                        }
                        Err(e) => {
                            // 单次 accept 失败不致命（如 fd 耗尽），退避后继续
                            warn!("SOCKS5 accept 失败: {e}");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }
        // 关闭所有活跃会话（泵任务会随 select 的 close 广播退出）
        conns.shutdown().await;
        debug!("SOCKS5 代理 {} accept 循环退出", self.cfg.name);
        Ok(())
    }

    /// 绑定并启动（返回实际监听地址）。accept 任务由本实例持有，`shutdown` 会等它退出。
    pub async fn start(self: &Arc<Self>) -> std::io::Result<SocketAddr> {
        let listener = self.bind().await?;
        let addr = listener.local_addr()?;
        let this = self.clone();
        let task = tokio::spawn(async move {
            if let Err(e) = this.serve_on(listener).await {
                warn!("SOCKS5 accept 循环异常退出: {e}");
            }
        });
        *self.accept_task.lock().await = Some(task);
        Ok(addr)
    }

    /// 关闭：停止 accept、断开所有活跃会话。幂等。
    pub async fn shutdown(&self) {
        self.closing.store(true, Ordering::Release);
        let _ = self.close_tx.send(true);
        let task = self.accept_task.lock().await.take();
        if let Some(task) = task {
            match tokio::time::timeout(STOP_TIMEOUT, task).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!("SOCKS5 accept 任务 join 失败: {e}"),
                Err(_) => warn!("SOCKS5 accept 任务关闭超时"),
            }
        }
    }

    // ------------------------------------------------------------------
    // 单条连接
    // ------------------------------------------------------------------

    async fn handle_conn(self: Arc<Self>, mut stream: TcpStream, peer: SocketAddr) {
        if self.is_closing() {
            return;
        }
        // 并发上限：超限直接关闭（对齐 Go `CheckFlowAndConnNum` 的拒绝语义）
        let prev = self.active.fetch_add(1, Ordering::AcqRel);
        if prev as usize >= self.max_connections {
            let _ = self
                .active
                .try_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                    Some(v.saturating_sub(1))
                });
            warn!(
                "SOCKS5 并发连接已达上限 {}，拒绝 {}",
                self.max_connections, peer
            );
            let _ = stream.shutdown().await;
            return;
        }
        let _guard = ActiveGuard(self.clone());

        let mut close_rx = self.close_tx.subscribe();
        let negotiated = tokio::select! {
            _ = close_rx.changed() => return,
            r = tokio::time::timeout(self.handshake_timeout, self.negotiate(&mut stream)) => r,
        };

        let outcome = match negotiated {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(e)) => {
                debug!("SOCKS5 协商读取失败 (from {peer}): {e}");
                return;
            }
            Err(_) => {
                debug!("SOCKS5 握手超时 (from {peer})");
                return;
            }
        };

        let request = match outcome {
            Outcome::Ready(req) => req,
            Outcome::Reply(rep) => {
                let bnd = local_bnd(&stream);
                if let Err(e) = write_reply(&mut stream, rep, bnd).await {
                    debug!("SOCKS5 写失败应答出错 (from {peer}): {e}");
                    return;
                }
                // 先 FIN 再读净残留请求字节，避免 RST 吞掉应答
                finish_reply(stream).await;
                return;
            }
            Outcome::Close => {
                // 静默关闭：不发任何应答（版本不符 / 无可用方法 / 认证失败）
                let _ = stream.shutdown().await;
                return;
            }
        };

        match request.cmd {
            CMD_CONNECT => {
                self.do_connect(stream, request, peer, close_rx).await;
            }
            CMD_BIND => {
                debug!("SOCKS5 BIND 不支持 (from {peer})，返回 REP=7");
                let bnd = local_bnd(&stream);
                if let Err(e) = write_reply(&mut stream, reply::COMMAND_NOT_SUPPORTED, bnd).await {
                    debug!("SOCKS5 写 REP=7 失败 (from {peer}): {e}");
                    return;
                }
                finish_reply(stream).await;
            }
            CMD_UDP_ASSOCIATE => {
                self.do_udp_associate(stream, request, peer, close_rx).await;
            }
            other => {
                debug!("SOCKS5 未知 CMD {other} (from {peer})，返回 REP=7");
                let bnd = local_bnd(&stream);
                if let Err(e) = write_reply(&mut stream, reply::COMMAND_NOT_SUPPORTED, bnd).await {
                    debug!("SOCKS5 写 REP=7 失败 (from {peer}): {e}");
                    return;
                }
                finish_reply(stream).await;
            }
        }
    }

    /// 握手：greeting →（可选）认证 → 请求头。
    async fn negotiate(&self, stream: &mut TcpStream) -> std::io::Result<Outcome> {
        // ---- greeting ----
        let mut head = [0u8; 2];
        stream.read_exact(&mut head).await?;
        if head[0] != SOCKS_VERSION {
            trace!("SOCKS5 版本不是 5（{}），关闭", head[0]);
            return Ok(Outcome::Close);
        }
        let nmethods = head[1] as usize;
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await?;

        let want_auth = !self.users.is_empty();
        let chosen = if want_auth {
            if methods.contains(&METHOD_USERPASS) {
                METHOD_USERPASS
            } else {
                METHOD_UNACCEPTABLE
            }
        } else if methods.contains(&METHOD_NO_AUTH) {
            METHOD_NO_AUTH
        } else {
            METHOD_UNACCEPTABLE
        };
        stream.write_all(&[SOCKS_VERSION, chosen]).await?;
        if chosen == METHOD_UNACCEPTABLE {
            trace!("SOCKS5 客户端未提供可接受的认证方法");
            return Ok(Outcome::Close);
        }

        // ---- 认证 ----
        if chosen == METHOD_USERPASS && !self.authenticate(stream).await? {
            // 失败应答已在 authenticate 里发出；立即关闭，不重试
            return Ok(Outcome::Close);
        }

        // ---- 请求 ----
        let mut req = [0u8; 4];
        stream.read_exact(&mut req).await?;
        if req[0] != SOCKS_VERSION {
            return Ok(Outcome::Close);
        }
        let cmd = req[1];
        let atyp = req[3];
        if req[2] != 0x00 {
            // RSV 必须为 0
            return Ok(Outcome::Close);
        }

        let target = match atyp {
            ATYP_IPV4 => {
                let mut ip = [0u8; 4];
                stream.read_exact(&mut ip).await?;
                let port = read_port(stream).await?;
                TargetAddr::Ip(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(ip)),
                    port,
                ))
            }
            ATYP_IPV6 => {
                let mut ip = [0u8; 16];
                stream.read_exact(&mut ip).await?;
                let port = read_port(stream).await?;
                TargetAddr::Ip(SocketAddr::new(IpAddr::V6(ip.into()), port))
            }
            ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let len = len[0] as usize;
                if len == 0 || len > MAX_DOMAIN_LEN {
                    return Ok(Outcome::Reply(reply::ADDRESS_TYPE_NOT_SUPPORTED));
                }
                let mut host = vec![0u8; len];
                stream.read_exact(&mut host).await?;
                let port = read_port(stream).await?;
                // 域名必须是合法 UTF-8 且不含 ':'（否则 host:port 拼接会歧义）
                let host = match std::str::from_utf8(&host) {
                    Ok(h) if !h.contains(':') => h.to_owned(),
                    _ => return Ok(Outcome::Reply(reply::ADDRESS_TYPE_NOT_SUPPORTED)),
                };
                TargetAddr::Domain(host, port)
            }
            _ => return Ok(Outcome::Reply(reply::ADDRESS_TYPE_NOT_SUPPORTED)),
        };

        Ok(Outcome::Ready(SocksRequest { cmd, target, atyp }))
    }

    /// RFC 1929 用户名密码认证。返回 `Ok(true)` 表示通过。
    ///
    /// 失败时已向客户端写 `[VER=1, STATUS=1]`；日志**不打印**任何凭据。
    async fn authenticate(&self, stream: &mut TcpStream) -> std::io::Result<bool> {
        let mut head = [0u8; 2];
        stream.read_exact(&mut head).await?;
        if head[0] != AUTH_VERSION {
            debug!("SOCKS5 认证子协议版本不是 1（{}）", head[0]);
            let _ = stream.write_all(&[AUTH_VERSION, 1]).await;
            return Ok(false);
        }
        let ulen = head[1] as usize;
        let mut user = vec![0u8; ulen];
        stream.read_exact(&mut user).await?;

        let mut plen = [0u8; 1];
        stream.read_exact(&mut plen).await?;
        let mut pass = vec![0u8; plen[0] as usize];
        stream.read_exact(&mut pass).await?;

        // 遍历整表（不提前 return），配合常量时间比较，避免通过耗时侧信道
        // 逐字节/逐账号试探。
        let mut matched = false;
        for (u, p) in self.users.iter() {
            let user_ok = ct_eq(u.as_bytes(), &user);
            let pass_ok = ct_eq(p.as_bytes(), &pass);
            matched |= user_ok && pass_ok;
        }

        if matched {
            stream.write_all(&[AUTH_VERSION, 0x00]).await?;
            trace!("SOCKS5 用户名密码认证通过");
            Ok(true)
        } else {
            stream.write_all(&[AUTH_VERSION, 0x01]).await?;
            // 只记录"失败"这一事实，绝不打印用户名或密码
            warn!("SOCKS5 用户名密码认证失败，关闭连接");
            Ok(false)
        }
    }

    // ------------------------------------------------------------------
    // CONNECT
    // ------------------------------------------------------------------

    async fn do_connect(
        self: Arc<Self>,
        mut stream: TcpStream,
        request: SocksRequest,
        peer: SocketAddr,
        close_rx: watch::Receiver<bool>,
    ) {
        let target = request.target.to_host_port();
        let bnd = local_bnd(&stream);

        // 1. 取该客户端的 mux 会话：离线 -> REP=1
        let mux = match self.bridge.get_tunnel(self.cfg.client_id).await {
            Some(mux) => mux,
            None => {
                warn!(
                    "SOCKS5: 客户端 {} 离线，拒绝 {} -> {}（REP=1）",
                    self.cfg.client_id, peer, target
                );
                let _ = write_reply(&mut stream, reply::GENERAL_FAILURE, bnd).await;
                return;
            }
        };

        // 2. 建子流：失败 -> REP=4
        let mux_stream = match mux.open_stream().await {
            Ok(s) => s,
            Err(e) => {
                warn!("SOCKS5: mux 建流失败（{e}），{} -> {}（REP=4）", peer, target);
                let _ = write_reply(&mut stream, reply::HOST_UNREACHABLE, bnd).await;
                return;
            }
        };

        let (mut send, recv) = mux_stream.into_split();

        // 3. 子流首帧：int32 LE 长度 + Link JSON（对齐 Go `SendInfo(link, "")`）
        let link = Link::new(
            CONN_TCP,
            target.clone(),
            false,
            false,
            peer.to_string(),
            false,
        );
        match encode_link_frame(&link) {
            Ok(frame) => {
                if let Err(e) = send.send_data(&frame).await {
                    warn!("SOCKS5: 发送 Link 失败（{e}），{} -> {}（REP=4）", peer, target);
                    let _ = write_reply(&mut stream, reply::HOST_UNREACHABLE, bnd).await;
                    return;
                }
            }
            Err(e) => {
                // 理论上不会发生（Link 是纯数据）；按一般性失败处理
                warn!("SOCKS5: Link 序列化失败（{e}）");
                let _ = write_reply(&mut stream, reply::GENERAL_FAILURE, bnd).await;
                return;
            }
        }

        // 4. 回 REP=0 后才开始转发（顺序与 Go 一致：先 SendLinkInfo，再 f()）
        if let Err(e) = write_reply(&mut stream, reply::SUCCEEDED, bnd).await {
            debug!("SOCKS5: 写成功应答失败（{e}），放弃 {peer} -> {target}");
            send.close();
            return;
        }
        debug!("SOCKS5: {} -> {} 已建立", peer, target);

        // 5. 双向转发：两个独立泵，任一结束即终止另一侧
        let (rd, wr) = stream.into_split();
        let mut up = tokio::spawn(pump_client_to_mux(rd, send, close_rx.clone()));
        let mut down = tokio::spawn(pump_mux_to_client(recv, wr, close_rx));

        // 任一方向结束即终止另一方向。注意：`select!` 已经把先完成的那一侧
        // poll 到结束，**不能再 await 它**（JoinHandle 完成后重复 poll 会 panic），
        // 只 abort + await 另一侧。
        let up_first = tokio::select! {
            _ = &mut up => true,
            _ = &mut down => false,
        };
        if up_first {
            down.abort();
            let _ = (&mut down).await;
        } else {
            up.abort();
            let _ = (&mut up).await;
        }
        debug!("SOCKS5: {} -> {} 连接结束", peer, target);
    }

    // ------------------------------------------------------------------
    // UDP ASSOCIATE
    // ------------------------------------------------------------------

    /// UDP ASSOCIATE。
    ///
    /// 子流方向（与 Go `server/proxy/socks5.go` + `client/client.go` 对齐）：
    /// - 客户端 → 服务端（TCP 上行）：裸 SOCKS5 UDP 报文
    ///   `RSV(2) FRAG(1) ATYP ADDR PORT DATA`，每条报文一次 mux 写入；
    /// - 服务端 → 客户端（下行）：`int32 LE 长度 + SOCKS5 UDP 报文`。
    ///
    /// TCP 控制连接关闭即结束整个关联（RFC 1928）。
    async fn do_udp_associate(
        self: Arc<Self>,
        mut stream: TcpStream,
        _request: SocksRequest,
        peer: SocketAddr,
        close_rx: watch::Receiver<bool>,
    ) {
        // 1. 本地 UDP socket。BND.ADDR 用 TCP 连接的本端 IP（对齐 Go 的
        //    `common.GetServerIpByClientIp`），端口用系统分配的 UDP 端口。
        let udp = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                warn!("SOCKS5 UDP: 绑定本地 UDP 端口失败: {e}");
                let bnd = local_bnd(&stream);
                let _ = write_reply(&mut stream, reply::GENERAL_FAILURE, bnd).await;
                return;
            }
        };
        let udp_port = match udp.local_addr() {
            Ok(a) => a.port(),
            Err(e) => {
                warn!("SOCKS5 UDP: 读取本地 UDP 地址失败: {e}");
                let bnd = local_bnd(&stream);
                let _ = write_reply(&mut stream, reply::GENERAL_FAILURE, bnd).await;
                return;
            }
        };
        let bnd_ip = stream
            .local_addr()
            .map(|a| a.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let bnd = SocketAddr::new(bnd_ip, udp_port);

        // 2. 取 mux 并建流（先回 REP 会误导客户端，这里先建流；失败给明确 REP）
        let mux = match self.bridge.get_tunnel(self.cfg.client_id).await {
            Some(mux) => mux,
            None => {
                warn!(
                    "SOCKS5 UDP: 客户端 {} 离线，拒绝 {}（REP=1）",
                    self.cfg.client_id, peer
                );
                let bnd = local_bnd(&stream);
                let _ = write_reply(&mut stream, reply::GENERAL_FAILURE, bnd).await;
                return;
            }
        };
        let mux_stream = match mux.open_stream().await {
            Ok(s) => s,
            Err(e) => {
                warn!("SOCKS5 UDP: mux 建流失败（{e}）（REP=4）");
                let bnd = local_bnd(&stream);
                let _ = write_reply(&mut stream, reply::HOST_UNREACHABLE, bnd).await;
                return;
            }
        };
        let (mut send, recv) = mux_stream.into_split();

        // 3. Link：ConnType="udp5"，Host 为空（由每条报文的头部决定目标）
        let link = Link::new(
            CONN_UDP5,
            "",
            false,
            false,
            peer.to_string(),
            false,
        );
        let frame = match encode_link_frame(&link) {
            Ok(f) => f,
            Err(e) => {
                warn!("SOCKS5 UDP: Link 序列化失败（{e}）");
                let bnd = local_bnd(&stream);
                let _ = write_reply(&mut stream, reply::GENERAL_FAILURE, bnd).await;
                return;
            }
        };
        if let Err(e) = send.send_data(&frame).await {
            warn!("SOCKS5 UDP: 发送 Link 失败（{e}）");
            let bnd = local_bnd(&stream);
            let _ = write_reply(&mut stream, reply::HOST_UNREACHABLE, bnd).await;
            return;
        }

        // 4. 回 REP=0 + BND（客户端据此知道往哪个 UDP 端口发数据）
        if let Err(e) = write_reply(&mut stream, reply::SUCCEEDED, bnd).await {
            debug!("SOCKS5 UDP: 写成功应答失败（{e}）");
            send.close();
            return;
        }
        info!("SOCKS5 UDP: {} 关联已建立，本地 UDP 端口 {}", peer, udp_port);

        // 5. 三条通路：UDP→mux、mux→UDP、TCP 控制连接存活探测
        let udp = Arc::new(udp);
        let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
        let mut up = tokio::spawn(pump_udp_to_mux(
            udp.clone(),
            client_addr.clone(),
            send,
            close_rx.clone(),
        ));
        let mut down = tokio::spawn(pump_mux_to_udp(
            recv,
            udp,
            client_addr,
            close_rx.clone(),
        ));

        // TCP 控制连接：任何数据都丢弃（Go 同样丢弃），EOF/错误即结束关联。
        // `select!` 会把先完成的那一侧 poll 到结束，因此下面只能 abort 另一侧。
        let mut ctrl = close_rx;
        let mut sink = [0u8; 512];
        let finished = loop {
            tokio::select! {
                _ = &mut up => break "up",
                _ = &mut down => break "down",
                _ = ctrl.changed() => break "close",
                r = stream.read(&mut sink) => match r {
                    Ok(0) | Err(_) => break "ctrl",
                    Ok(_) => {}
                },
            }
        };
        match finished {
            "up" => {
                down.abort();
                let _ = (&mut down).await;
            }
            "down" => {
                up.abort();
                let _ = (&mut up).await;
            }
            _ => {
                up.abort();
                down.abort();
                let _ = (&mut up).await;
                let _ = (&mut down).await;
            }
        }
        let _ = stream.shutdown().await;
        debug!("SOCKS5 UDP: {} 关联结束", peer);
    }
}

// ----------------------------------------------------------------------
// 转发泵
// ----------------------------------------------------------------------

/// 客户端 TCP -> mux（CONNECT 上行）
async fn pump_client_to_mux(
    mut reader: OwnedReadHalf,
    mut send: MuxSendHalf,
    mut close_rx: watch::Receiver<bool>,
) {
    let mut buf = vec![0u8; COPY_BUF];
    loop {
        if *close_rx.borrow() {
            break;
        }
        let n = tokio::select! {
            _ = close_rx.changed() => break,
            r = reader.read(&mut buf) => match r {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            },
        };
        if send.send_data(&buf[..n]).await.is_err() {
            break;
        }
    }
    // 半关闭：只停止本端发送，接收方向仍可继续（对齐 Go `copyConns`）
    send.close();
}

/// mux -> 客户端 TCP（CONNECT 下行）
async fn pump_mux_to_client(
    mut recv: MuxRecvHalf,
    mut writer: OwnedWriteHalf,
    mut close_rx: watch::Receiver<bool>,
) {
    loop {
        if *close_rx.borrow() {
            break;
        }
        let data = tokio::select! {
            _ = close_rx.changed() => break,
            d = recv.recv_data() => match d {
                Some(d) => d,
                None => break,
            },
        };
        if writer.write_all(&data).await.is_err() {
            break;
        }
        let _ = writer.flush().await;
    }
    let _ = writer.shutdown().await;
}

/// SOCKS5 UDP -> mux（上行：裸报文，每条一次 `send_data`）
async fn pump_udp_to_mux(
    udp: Arc<UdpSocket>,
    client_addr: Arc<Mutex<Option<SocketAddr>>>,
    mut send: MuxSendHalf,
    mut close_rx: watch::Receiver<bool>,
) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        if *close_rx.borrow() {
            break;
        }
        let received = tokio::select! {
            _ = close_rx.changed() => break,
            r = udp.recv_from(&mut buf) => r,
        };
        let (n, src) = match received {
            Ok(v) => v,
            Err(e) => {
                debug!("SOCKS5 UDP: 读取客户端报文失败: {e}");
                break;
            }
        };
        // 首个报文确定客户端地址；之后只接受同一来源（RFC 1928 要求）
        let mut guard = client_addr.lock().await;
        match *guard {
            None => {
                *guard = Some(src);
                trace!("SOCKS5 UDP: 客户端 UDP 地址登记为 {src}");
            }
            Some(expected) if expected != src => {
                debug!("SOCKS5 UDP: 丢弃非客户端来源 {src} 的报文（期望 {expected}）");
                continue;
            }
            Some(_) => {}
        }
        drop(guard);

        if n == 0 {
            continue;
        }
        if n > MAX_UDP_PAYLOAD {
            // Go 的客户端用 1672 字节缓冲读子流，超长会截断并解析失败
            debug!("SOCKS5 UDP: 报文 {n} 字节超过上限 {MAX_UDP_PAYLOAD}，丢弃");
            continue;
        }
        if send.send_data(&buf[..n]).await.is_err() {
            break;
        }
    }
    send.close();
}

/// mux -> SOCKS5 UDP（下行：`int32 LE 长度 + 报文` 帧）
async fn pump_mux_to_udp(
    mut recv: MuxRecvHalf,
    udp: Arc<UdpSocket>,
    client_addr: Arc<Mutex<Option<SocketAddr>>>,
    mut close_rx: watch::Receiver<bool>,
) {
    let mut buf: Vec<u8> = Vec::with_capacity(4 * 1024);
    loop {
        if *close_rx.borrow() {
            break;
        }
        // 先尝试从已缓冲的字节里切出一帧
        match take_len_frame(&mut buf) {
            FrameStep::Payload(payload) => {
                let dest = *client_addr.lock().await;
                match dest {
                    Some(dest) => {
                        if let Err(e) = udp.send_to(&payload, dest).await {
                            debug!("SOCKS5 UDP: 回写客户端失败: {e}");
                            break;
                        }
                    }
                    None => {
                        // 客户端还没发过任何报文，不知道往哪回
                        trace!("SOCKS5 UDP: 尚未登记客户端地址，丢弃下行报文");
                    }
                }
                continue;
            }
            FrameStep::NeedMore => {}
            FrameStep::Invalid => {
                // 长度字段非法（<=0 或超上限）：无法再对齐帧边界，终止关联
                debug!("SOCKS5 UDP: 下行帧长度非法，终止关联");
                break;
            }
        }
        let data = tokio::select! {
            _ = close_rx.changed() => break,
            d = recv.recv_data() => match d {
                Some(d) => d,
                None => break,
            },
        };
        buf.extend_from_slice(&data);
        // 允许多帧粘连：上限按"若干帧"给，而不是单帧上限，
        // 否则两个小报文合并到一次读里就会被误判为超限。
        if buf.len() > 4 + MAX_UDP_PAYLOAD * 8 {
            debug!("SOCKS5 UDP: 下行缓冲超过上限，终止关联");
            break;
        }
    }
}

/// 从缓冲区头部切帧的结果
enum FrameStep {
    /// 切出一帧完整载荷
    Payload(Vec<u8>),
    /// 数据不足，等待更多字节
    NeedMore,
    /// 长度字段非法（`<=0` 或超过 [`MAX_UDP_PAYLOAD`]）
    Invalid,
}

/// 从缓冲区头部切出 `int32 LE 长度 + 载荷` 的一帧。
///
/// 长度必须在 `1..=MAX_UDP_PAYLOAD`（对齐 Go 的
/// `l >= common.PoolSizeUdp || l <= 0` 校验）。
fn take_len_frame(buf: &mut Vec<u8>) -> FrameStep {
    if buf.len() < 4 {
        return FrameStep::NeedMore;
    }
    let len = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if len <= 0 || len as usize > MAX_UDP_PAYLOAD {
        buf.clear();
        return FrameStep::Invalid;
    }
    let len = len as usize;
    if buf.len() < 4 + len {
        return FrameStep::NeedMore;
    }
    let payload = buf[4..4 + len].to_vec();
    buf.drain(..4 + len);
    FrameStep::Payload(payload)
}

// ----------------------------------------------------------------------
// 小工具
// ----------------------------------------------------------------------

/// 常量时间字节比较（长度不同直接 false）。
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn read_port(stream: &mut TcpStream) -> std::io::Result<u16> {
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(u16::from_be_bytes(port))
}

/// 应答里的 BND.ADDR：用 TCP 连接本端地址（对齐 Go `c.LocalAddr()`）。
fn local_bnd(stream: &TcpStream) -> SocketAddr {
    stream.local_addr().unwrap_or_else(|_| {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    })
}

/// 编码 SOCKS5 应答：`VER, REP, RSV=0, ATYP, BND.ADDR, BND.PORT`。
///
/// Go 原版固定用 ATYP=1（IPv4）；这里对 IPv6 本端地址正确回 ATYP=4，
/// 避免像 Go 那样产生截断报文。
pub fn encode_reply(rep: u8, bnd: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 16 + 2);
    out.push(SOCKS_VERSION);
    out.push(rep);
    out.push(0x00);
    match bnd.ip() {
        IpAddr::V4(ip) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&bnd.port().to_be_bytes());
    out
}

async fn write_reply(
    stream: &mut TcpStream,
    rep: u8,
    bnd: SocketAddr,
) -> std::io::Result<()> {
    stream.write_all(&encode_reply(rep, bnd)).await?;
    stream.flush().await
}

/// 写完最后一个应答后优雅收尾。
///
/// 直接 `drop` 一个还有未读入站数据的 socket，在 Windows/BSD 上会触发 RST，
/// 可能把刚写出的应答一起丢掉（客户端看到 `ConnectionReset` 而不是 `REP=8`）。
/// 因此先 `shutdown(Write)` 发 FIN，再把残留请求字节读干净（有界超时），
/// 让对端先看到应答、再看到正常的 EOF。
async fn finish_reply(mut stream: TcpStream) {
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
    let mut sink = [0u8; 512];
    let _ = tokio::time::timeout(Duration::from_millis(300), async {
        loop {
            match stream.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;
}

/// 编码子流首帧：`int32 LE 长度 + Link JSON`。
fn encode_link_frame(link: &Link) -> Result<Vec<u8>, serde_json::Error> {
    let json = serde_json::to_vec(link)?;
    let mut frame = Vec::with_capacity(4 + json.len());
    frame.extend_from_slice(&(json.len() as i32).to_le_bytes());
    frame.extend_from_slice(&json);
    Ok(frame)
}

// 让 `MuxStream` 类型在文档里可见（`do_connect` 内部使用 `into_split`）

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Socks5Config {
        Socks5Config {
            id: 1,
            name: "s5".into(),
            client_id: 1,
            listen_addr: "127.0.0.1:0".into(),
            users: Vec::new(),
            enabled: true,
        }
    }

    fn bridge() -> Bridge {
        Bridge::new(|_| Some(1))
    }

    #[test]
    fn reply_encoding_ipv4_matches_rfc1928() {
        let bytes = encode_reply(
            reply::SUCCEEDED,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1080),
        );
        assert_eq!(
            bytes,
            vec![5, 0, 0, 1, 127, 0, 0, 1, 0x04, 0x38],
            "应答必须是 VER,REP,RSV,ATYP,ADDR,PORT"
        );
    }

    #[test]
    fn reply_encoding_ipv6_uses_atyp_4() {
        let ip = std::net::Ipv6Addr::LOCALHOST;
        let bytes = encode_reply(reply::HOST_UNREACHABLE, SocketAddr::new(IpAddr::V6(ip), 1));
        assert_eq!(bytes[0], 5);
        assert_eq!(bytes[1], reply::HOST_UNREACHABLE);
        assert_eq!(bytes[2], 0);
        assert_eq!(bytes[3], ATYP_IPV6);
        assert_eq!(bytes.len(), 4 + 16 + 2);
        assert_eq!(&bytes[4..20], &ip.octets());
        assert_eq!(&bytes[20..22], &[0, 1]);
    }

    #[test]
    fn target_host_port_brackets_ipv6() {
        let v6 = TargetAddr::Ip(SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 80));
        assert_eq!(v6.to_host_port(), "[::1]:80");

        let v4 = TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 22));
        assert_eq!(v4.to_host_port(), "127.0.0.1:22");

        let d = TargetAddr::Domain("example.com".into(), 443);
        assert_eq!(d.to_host_port(), "example.com:443");
    }

    #[test]
    fn link_frame_is_len32_le_prefixed_json() {
        let link = Link::new(CONN_TCP, "1.2.3.4:80", false, false, "5.6.7.8:9", false);
        let frame = encode_link_frame(&link).unwrap();
        let len = i32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(len, frame.len() - 4);
        let json: serde_json::Value = serde_json::from_slice(&frame[4..]).unwrap();
        assert_eq!(json["ConnType"], "tcp");
        assert_eq!(json["Host"], "1.2.3.4:80");
        assert_eq!(json["RemoteAddr"], "5.6.7.8:9");
        assert_eq!(json["LocalProxy"], false);
        // Go 用 net.DialTimeout(..., lk.Option.Timeout) 消费该字段
        assert_eq!(json["Option"]["Timeout"], 5_000_000_000i64);
    }

    #[test]
    fn udp5_link_has_empty_host() {
        let link = Link::new(CONN_UDP5, "", false, false, "1.2.3.4:5", false);
        let frame = encode_link_frame(&link).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&frame[4..]).unwrap();
        assert_eq!(json["ConnType"], "udp5");
        assert_eq!(json["Host"], "");
    }

    #[test]
    fn len_frame_parsing_handles_split_and_coalesced_frames() {
        let mut buf = Vec::new();
        // 一帧被拆成两次到达
        buf.extend_from_slice(&5i32.to_le_bytes());
        buf.extend_from_slice(b"he");
        assert!(matches!(take_len_frame(&mut buf), FrameStep::NeedMore));
        buf.extend_from_slice(b"llo");
        assert_eq!(
            expect_payload(take_len_frame(&mut buf)),
            b"hello".to_vec()
        );

        // 两帧粘在一起
        let mut two = Vec::new();
        two.extend_from_slice(&2i32.to_le_bytes());
        two.extend_from_slice(b"ab");
        two.extend_from_slice(&3i32.to_le_bytes());
        two.extend_from_slice(b"cde");
        assert_eq!(expect_payload(take_len_frame(&mut two)), b"ab".to_vec());
        assert_eq!(expect_payload(take_len_frame(&mut two)), b"cde".to_vec());
        assert!(matches!(take_len_frame(&mut two), FrameStep::NeedMore));
    }

    fn expect_payload(step: FrameStep) -> Vec<u8> {
        match step {
            FrameStep::Payload(p) => p,
            FrameStep::NeedMore => panic!("期望完整帧，实际数据不足"),
            FrameStep::Invalid => panic!("期望完整帧，实际长度非法"),
        }
    }

    #[test]
    fn len_frame_rejects_non_positive_and_oversize() {
        let mut zero = 0i32.to_le_bytes().to_vec();
        assert!(matches!(take_len_frame(&mut zero), FrameStep::Invalid));
        let mut negative = (-1i32).to_le_bytes().to_vec();
        assert!(matches!(take_len_frame(&mut negative), FrameStep::Invalid));
        // Go: `l >= PoolSizeUdp(1672)` 非法
        let mut too_big = (MAX_UDP_PAYLOAD as i32 + 1).to_le_bytes().to_vec();
        too_big.extend(std::iter::repeat(0u8).take(2000));
        assert!(matches!(take_len_frame(&mut too_big), FrameStep::Invalid));
        // 边界值 1671 合法
        let mut edge = (MAX_UDP_PAYLOAD as i32).to_le_bytes().to_vec();
        edge.extend(std::iter::repeat(b'x').take(MAX_UDP_PAYLOAD));
        assert_eq!(expect_payload(take_len_frame(&mut edge)).len(), MAX_UDP_PAYLOAD);
    }

    #[test]
    fn constant_time_eq_behaves_like_eq() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(b"ab", b"abc"));
    }

    #[test]
    fn debug_output_redacts_passwords() {
        let mut users = HashMap::new();
        users.insert("alice".to_string(), "s3cret-pass".to_string());
        let server = Socks5Server::with_users(cfg(), bridge(), users);
        let rendered = format!("{server:?}");
        assert!(
            !rendered.contains("s3cret-pass"),
            "Debug 泄漏了密码: {rendered}"
        );
        assert!(!rendered.contains("alice"), "Debug 不应列出账号名: {rendered}");
        assert!(rendered.contains("<redacted>"), "未打码: {rendered}");
        assert!(rendered.contains("auth_users: 1"), "应报告账号数: {rendered}");
    }

    #[test]
    fn max_connections_zero_is_clamped_to_one() {
        let server = Socks5Server::new(cfg(), bridge()).with_max_connections(0);
        assert_eq!(server.max_connections, 1);
    }

    #[test]
    fn default_limits_are_sane() {
        assert_eq!(DEFAULT_MAX_CONNECTIONS, 256);
        assert_eq!(HANDSHAKE_TIMEOUT, Duration::from_secs(10));
        assert_eq!(MAX_DOMAIN_LEN, 255);
        assert_eq!(MAX_UDP_PAYLOAD, 1671);
    }
}
