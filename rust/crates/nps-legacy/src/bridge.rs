//! 桥（bridge）：服务端监听桥端口，接受老 npc 连接并分发。
//!
//! 对齐 Go `bridge/bridge.go` 的职责：
//! - 监听桥端口（默认 8024），接受 TCP 连接
//! - 对每条连接执行握手（限时 10s，对齐 Go 的 5s 读超时语义）
//! - 按连接 flag 分发：
//!   - `WORK_MAIN("main")` → 控制面（signal）。持续读取健康上报帧，直到 EOF
//!   - `WORK_CHAN("chan")` → 数据面 mux 会话
//!   - `WORK_CONFIG("conf")` → 配置文件模式注册会话。协议实现由上层通过
//!     [`Bridge::set_conf_handler`] 注入（本 crate 不依赖 `nps-server`）；
//!     **未注入时立即关闭连接**（默认关闭，不挂起）
//!   - 其他 → P0 仅记录日志
//! - 按来源 IP 的 vkey 防爆破：握手失败记账 + 冷却期拒绝（见 [`crate::ip_guard`]）
//!
//! ## 相对原型的修复
//! 1. **signal 生命周期**：不再用 `readable()` 当断开信号。改为持续读取
//!    长度前缀的健康上报帧（`lib/conn/conn.go:GetHealthInfo`），并限制单帧
//!    长度（Go `BufPoolMax` = 64KB），任何读错误 / EOF / 非法长度即视为断开。
//! 2. **重复登录**：每条连接分配单调递增的 generation。旧连接的读循环退出时，
//!    只有 state 仍指向自己这一代时才清理，避免旧连接把新连接清掉。替换时主动
//!    丢弃旧 socket（等价 Go 的 `WriteClose` + 断开），旧 npc 会自动重连。
//! 3. **tunnel 在线状态**：`chan` 会话后台等待 `MuxSession::wait_closed()`，
//!    关闭时按 generation 清理并实时更新在线状态。
//! 4. **资源收尾**：`Bridge::shutdown()` 关闭 accept 循环、停止所有读循环、
//!    关闭所有 mux 会话并清空注册表。
//!
//! ## 注册表
//! `client_id -> ClientState`。每个 `ClientState` 同时保存 signal 与 tunnel，
//! 在线判定为「signal 存在 && tunnel 存在且未关闭」（与 Go `ping()` 一致）。

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch, Mutex};
use tracing::{debug, info, trace, warn};

use crate::handshake::{HandshakeError, HandshakeResult};
use crate::ip_guard::{normalize_peer_ip, FailureOutcome, GuardConfig, IpGuard};
use crate::mux::MuxSession;

/// 握手超时。Go 在写完服务端版本后 `SetReadDeadlineBySecond(5)`，
/// 这里对整段握手统一限制，避免半开连接长期占用任务。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// 健康上报单帧长度上限。对齐 Go `common.BufPoolMax`（64KB）与
/// `Conn.ReadLen` 的 `cLen <= len(buf)` 校验。
const MAX_HEALTH_FRAME_LEN: usize = 64 * 1024;

/// 单条连接的取消把手。
///
/// 持有它代表连接"存活"；`stop()` / `Drop` 会丢弃 oneshot sender，
/// 从而唤醒对应读循环的 `select!`，令其退出并释放 socket。
struct ConnGuard {
    stop: Option<oneshot::Sender<()>>,
}

impl ConnGuard {
    fn stop(&mut self) {
        self.stop.take();
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.stop.take();
    }
}

fn stop_channel() -> (ConnGuard, oneshot::Receiver<()>) {
    let (tx, rx) = oneshot::channel();
    (ConnGuard { stop: Some(tx) }, rx)
}

/// 配置文件模式（`conf`）会话上下文。
///
/// 由 [`Bridge`] 在握手与 vkey 鉴权完成后构造并交给上层注入的
/// [`ConfSessionHandler`]；`stream` 的所有权一并移交，处理器返回后连接关闭。
///
/// 上下文中**不包含** vkey 或 md5(vkey)：鉴权已在握手阶段完成，处理器只需要
/// 客户端 id。
pub struct ConfSession {
    /// 已通过 vkey 鉴权的客户端 id
    pub client_id: i32,
    /// 客户端上报的完整版本（仅展示/日志）
    pub client_version: String,
    /// 对端地址（仅日志）
    pub peer: String,
    /// 已完成握手的 TCP 连接（从 `conf` flag 之后的第一个字节开始）
    pub stream: TcpStream,
    /// 桥句柄：注册成功的隧道用它取该客户端的 mux 会话转发数据
    pub bridge: Bridge,
    /// 桥关闭信号（值为 `true` 表示服务端关闭）。处理器应尽快退出
    pub closing: watch::Receiver<bool>,
}

/// `conf` 会话处理器（对齐 Go `bridge/bridge.go:getConfig` 的职责）。
///
/// 实现放在上层（`nps-server`），避免兼容层反向依赖服务端 crate。
pub trait ConfSessionHandler: Send + Sync {
    /// 处理一个 `conf` 会话；返回即关闭连接。
    fn handle(&self, session: ConfSession) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// `file`（WORK_FILE）通道处理器：桥把已建好的 mux 会话交给上层登记。
///
/// 原版 `bridge.go` 的 `WORK_FILE` 分支把这条 mux 存为客户端独立的 `file`
/// 通道（与 `chan` 平行），文件服务隧道从它开子流。
pub trait FileChannelHandler: Send + Sync {
    fn handle(&self, client_id: i32, mux: std::sync::Arc<crate::mux::MuxSession>);
}

/// `secret`（WORK_SECRET）通道处理器。
///
/// 原版 `bridge.go` 的 `WORK_SECRET` 分支：读 32 字节 md5(password)，
/// 投到 `SecretChan`，由上层按 md5 查任务并 `DealClient`。
/// 这里把「已读完 md5 的连接」交给上层，避免 legacy 层依赖任务表。
pub trait SecretHandler: Send + Sync {
    /// `password_md5` 是客户端发来的 32 字节 md5 十六进制字符串。
    fn handle(&self, client_id: i32, password_md5: String, stream: tokio::net::TcpStream)
        -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;
}

/// `p2p`（WORK_P2P，"p2pm"）请求处理器。
///
/// 原版 `bridge.go` 的 `WORK_P2P` 分支：请求方（visitor）连桥并发 32 字节
/// md5(password)，服务端按 md5 查 p2p 任务、给**任务归属客户端**（provider）
/// 的 signal 连接推 `NEW_UDP_CONN`（"udpc"）+ 会合地址 + md5 三段帧，
/// 再把会合地址回写到这条 p2pm 连接上（visitor 从这里读到会合地址）。
/// 之后双方各自去 UDP 会合端口 punch，服务端不参与传输。
///
/// 查任务表属于上层职责：这里把「已读完 md5 的连接」整条交给上层，
/// 连接所有权一并移交（上层写完回执后连接即被丢弃）。
pub trait P2pRequestHandler: Send + Sync {
    fn handle(&self, client_id: i32, password_md5: String, stream: tokio::net::TcpStream)
        -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;
}

/// signal（main）连接的一代
struct SignalState {
    gen: u64,
    guard: ConnGuard,
    /// 服务端 → 客户端的写半边（p2p 邀请帧从这里写）。
    ///
    /// `main` 连接与其它通道不同：npc 会在**同一条连接**上继续读服务端
    /// 主动推送的帧（`udpc` 邀请），因此不能把整条 stream 消耗在读循环里，
    /// 读写半边要分开保管。
    write: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
}

/// tunnel（chan）连接的一代
struct TunnelState {
    gen: u64,
    mux: Arc<MuxSession>,
}

/// 客户端运行状态。字段对外不透明，仅供 [`Bridge`] 内部维护。
pub struct ClientState {
    /// 客户端 id（与配置一致）
    pub id: i32,
    version: String,
    signal: Option<SignalState>,
    tunnel: Option<TunnelState>,
}

impl ClientState {
    fn empty(id: i32) -> Self {
        Self {
            id,
            version: String::new(),
            signal: None,
            tunnel: None,
        }
    }

    /// 在线 = signal 存在 且 tunnel 存在且未关闭（对齐 Go `ping()` 判定）
    fn is_online(&self) -> bool {
        matches!((&self.signal, &self.tunnel), (Some(_), Some(t)) if !t.mux.is_closed())
    }
}

/// 桥内部共享状态（`Arc` 持有）
struct BridgeShared {
    /// 客户端注册表
    clients: Mutex<HashMap<i32, ClientState>>,
    /// vkey 校验：接收 md5(vkey) 十六进制，返回 client id
    verify: Box<dyn Fn(&str) -> Option<i32> + Send + Sync>,
    /// generation 分配器
    gen_counter: AtomicU64,
    /// 是否已进入关闭流程
    closing: AtomicBool,
    /// 关闭广播（值为 true 即关闭）
    close_tx: watch::Sender<bool>,
    /// 配置文件模式（`conf`）会话处理器。
    ///
    /// 默认未设置：收到 `conf` 连接直接关闭（该能力默认不对外开放）。
    /// `file` 通道处理器（文件服务用）。未设置时收到 `file` 连接直接关闭。
    file_handler: std::sync::OnceLock<std::sync::Arc<dyn FileChannelHandler>>,
    /// `secret` 通道处理器（加密隧道用）。未设置时收到 `sert` 连接直接关闭。
    secret_handler: std::sync::OnceLock<std::sync::Arc<dyn SecretHandler>>,
    /// `p2p` 请求处理器（打洞用）。未设置时收到 `p2pm` 连接直接关闭。
    p2p_handler: std::sync::OnceLock<std::sync::Arc<dyn P2pRequestHandler>>,
    /// vkey 防爆破：按来源 IP 的握手失败记账（策略见 [`crate::ip_guard`]）。
    ///
    /// 用 std `Mutex` 而非 tokio `Mutex`：临界区内没有任何 await，纯内存
    /// 读写，std 锁更轻量。
    ip_guard: std::sync::Mutex<IpGuard>,
    /// 只在启动阶段由上层设置一次，因此用 `OnceLock` 而不是 `Mutex`。
    conf_handler: OnceLock<Arc<dyn ConfSessionHandler>>,
    /// 常驻接收端。
    ///
    /// tokio 的 `watch::Sender::send` 在没有任何接收端时**会失败且不保存值**。
    /// 这里保留一个接收端，保证 `shutdown()` 无论何时调用都能把关闭状态写入通道，
    /// 之后才 subscribe 的 accept 循环也能立刻看到 `true`。
    _close_keepalive: watch::Receiver<bool>,
}

/// 桥：管理客户端注册表 + 对外监听。
///
/// 内部为 `Arc<BridgeShared>`，因此 `Bridge` 可廉价 `Clone`，
/// 任意 clone 都可调用 [`Bridge::shutdown`]。
#[derive(Clone)]
pub struct Bridge {
    shared: Arc<BridgeShared>,
}

impl Bridge {
    /// 新建桥。`verify` 由上层注入（读取配置/数据库）。
    ///
    /// vkey 防爆破默认开启：握手失败按来源 IP 记账，滑动窗口内失败达到
    /// 阈值即进入冷却期（新连接直接关闭、不再进握手）。默认参数与理由见
    /// [`crate::ip_guard::GuardConfig`]。
    pub fn new(verify: impl Fn(&str) -> Option<i32> + Send + Sync + 'static) -> Self {
        Self::build(verify, GuardConfig::default())
    }

    fn build(
        verify: impl Fn(&str) -> Option<i32> + Send + Sync + 'static,
        guard_cfg: GuardConfig,
    ) -> Self {
        let (close_tx, close_keepalive) = watch::channel(false);
        Self {
            shared: Arc::new(BridgeShared {
                clients: Mutex::new(HashMap::new()),
                verify: Box::new(verify),
                gen_counter: AtomicU64::new(1),
                closing: AtomicBool::new(false),
                close_tx,
                conf_handler: OnceLock::new(),
                file_handler: OnceLock::new(),
                secret_handler: OnceLock::new(),
                p2p_handler: OnceLock::new(),
                ip_guard: std::sync::Mutex::new(IpGuard::new(guard_cfg)),
                _close_keepalive: close_keepalive,
            }),
        }
    }

    /// 测试专用构造：自定义防爆破参数（阈值/窗口/冷却/上限）。
    /// 生产路径一律走 [`Bridge::new`]（默认参数、防护开启）。
    #[cfg(test)]
    fn with_guard_config(
        verify: impl Fn(&str) -> Option<i32> + Send + Sync + 'static,
        guard_cfg: GuardConfig,
    ) -> Self {
        Self::build(verify, guard_cfg)
    }

    fn next_gen(&self) -> u64 {
        self.shared.gen_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// 安装配置文件模式（`conf`）会话处理器。
    ///
    /// 必须在 `serve_on` / `serve` 之前调用。未安装时收到 `conf` 连接会立即
    /// 关闭（干净 FIN，不读写、不挂起）——这是默认行为，因为该能力是攻击面。
    ///
    /// 只在首次设置生效；重复设置会被忽略并记录告警。
    pub fn set_conf_handler(&self, handler: Arc<dyn ConfSessionHandler>) {
        if self.shared.conf_handler.set(handler).is_err() {
            warn!("conf 会话处理器已设置，忽略重复设置");
        }
    }

    /// 是否已安装 `conf` 会话处理器
    /// 设置 `secret` 通道处理器（加密隧道用）。只允许设置一次。
    pub fn set_secret_handler(&self, handler: Arc<dyn SecretHandler>) {
        if self.shared.secret_handler.set(handler).is_err() {
            tracing::warn!("secret 通道处理器已设置，忽略重复设置");
        }
    }

    /// 设置 `file` 通道处理器（文件服务用）。只允许设置一次。
    pub fn set_file_handler(&self, handler: Arc<dyn FileChannelHandler>) {
        if self.shared.file_handler.set(handler).is_err() {
            tracing::warn!("file 通道处理器已设置，忽略重复设置");
        }
    }

    /// 设置 `p2p` 请求处理器（打洞用）。只允许设置一次。
    pub fn set_p2p_handler(&self, handler: Arc<dyn P2pRequestHandler>) {
        if self.shared.p2p_handler.set(handler).is_err() {
            tracing::warn!("p2p 请求处理器已设置，忽略重复设置");
        }
    }

    /// 向某客户端的 signal（main）连接推一条 p2p 邀请帧。
    ///
    /// 字节序对齐原版 `bridge.go` WORK_P2P 分支：
    /// `"udpc"`（4 字节裸写，不带长度前缀）→ `WriteLenContent(会合地址)`
    /// → `WriteLenContent(md5(password))`。npc 的 signal 读循环按
    /// 「4 字节 flag = udpc → 两个长度前缀内容」解析（client.go TRPClient）。
    ///
    /// 客户端不在线 / signal 已断 / 写失败时返回 `false`（调用方据此关闭
    /// 请求方的 p2pm 连接）。
    pub async fn send_p2p_invite(
        &self,
        client_id: i32,
        rendezvous_addr: &str,
        password_md5: &str,
    ) -> bool {
        // 先取出写半边的 Arc 再放锁：写盘不持有 clients 锁
        let write = {
            let clients = self.shared.clients.lock().await;
            clients.get(&client_id).and_then(|st| {
                st.signal.as_ref().map(|s| s.write.clone())
            })
        };
        let Some(write) = write else {
            debug!("p2p 邀请失败：clientId {client_id} 不在线（无 signal 连接）");
            return false;
        };
        let mut w = write.lock().await;
        if w.write_all(nps_proto::NEW_UDP_CONN.as_bytes()).await.is_err() {
            debug!("p2p 邀请失败：clientId {client_id} signal 写入 flag 失败");
            return false;
        }
        if crate::codec::write_len_content(&mut *w, rendezvous_addr.as_bytes())
            .await
            .is_err()
        {
            debug!("p2p 邀请失败：clientId {client_id} signal 写入地址失败");
            return false;
        }
        if crate::codec::write_len_content(&mut *w, password_md5.as_bytes())
            .await
            .is_err()
        {
            debug!("p2p 邀请失败：clientId {client_id} signal 写入密码失败");
            return false;
        }
        debug!("已向 clientId {client_id} 推送 p2p 邀请（会合地址 {rendezvous_addr}）");
        true
    }

    pub fn has_conf_handler(&self) -> bool {
        self.shared.conf_handler.get().is_some()
    }

    /// 锁住防爆破账本。
    ///
    /// 毒化时直接取走内部数据继续工作：账本只影响防护强度，不能因某次
    /// panic 让整座桥拒绝服务。
    fn guard(&self) -> std::sync::MutexGuard<'_, IpGuard> {
        self.shared
            .ip_guard
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// 握手失败是否记入防爆破账本。
    ///
    /// 记：vkey 校验不过、探测字节/版本/摘要格式等协议错——都是主动的
    /// 异常行为，是 vkey 穷举的直接信号；超时同理（对端故意拖慢/半开
    /// 连接试探）。不记：对端主动断开与 IO 错误——负载均衡健康检查、
    /// 随机端口扫描都会「连上就断」，计入会把无辜来源误伤进冷却期，
    /// 且这类行为推进不了 vkey 穷举。
    fn count_handshake_failure(e: &HandshakeError) -> bool {
        !matches!(e, HandshakeError::Closed | HandshakeError::Io(_))
    }

    /// 握手失败的日志类别。只记类别，绝不记 vkey / md5(vkey) 的值。
    fn failure_category(e: &HandshakeError) -> &'static str {
        match e {
            HandshakeError::Closed => "对端关闭",
            HandshakeError::Io(_) => "io 错误",
            HandshakeError::BadTestFlag => "探测字节非法",
            HandshakeError::VersionMismatch { .. } => "核心版本不匹配",
            HandshakeError::BadVersionLength(_) => "版本长度非法",
            HandshakeError::VerifyFailed => "vkey 校验失败",
            HandshakeError::BadVkeyHex(_) => "vkey 摘要格式非法",
        }
    }

    /// 处理一条新接入的桥连接：防爆破闸门 → 握手 → 按 flag 分发。
    async fn handle_conn(&self, mut stream: tokio::net::TcpStream) {
        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "<unknown>".into());
        // 防爆破按 IP 归因；取不到对端地址时无法记账，只能放行
        let peer_ip = stream.peer_addr().ok().map(|a| normalize_peer_ip(a.ip()));

        // 防爆破第一道闸：冷却期内的来源直接关闭，不进握手、不写任何
        // 响应字节（正常客户端永远走不到这条分支，原版协议字节序不受
        // 影响）。被拒的尝试本身也记一次失败：冷却期顺延，持续重试者
        // 出不了冷却期。
        if let Some(ip) = &peer_ip {
            // 账本锁只在同步决策的内层块里存活：rustc 对 async 生成器的存活
            // 分析在「guard 作用域覆盖 await 点」时按类型整体判非 Send——
            // 即使 await 前已显式 drop 也不行。锁出块、await 留在块外。
            let blocked = {
                let mut g = self.guard();
                if !g.is_blocked(Instant::now(), ip) {
                    false
                } else {
                    if matches!(
                        g.record_failure(Instant::now(), ip),
                        FailureOutcome::CooldownExtended
                    ) {
                        debug!("来源 {ip} 冷却期内重试，直接关闭并顺延冷却期");
                    }
                    true
                }
            };
            if blocked {
                let _ = stream.shutdown().await;
                return;
            }
        }

        // 握手（限时）
        //
        // vkey 校验一通过就立即清零该 IP 的失败记录——清零点在 verify 回调里，
        // 而不是等整个握手成功。理由：防爆破记账的对象是「猜测 vkey」，vkey
        // 已被证明正确后的任何后续失败（例如客户端在读 conn_type 前断开）都
        // 不再具备穷举信号；若等到 `server_handshake` 返回，合法客户端在握手
        // 末段断开会被继续累计，且成功记录也清不掉。
        let verify = |v: &str| {
            let id = (self.shared.verify)(v);
            if id.is_some() {
                if let Some(ip) = &peer_ip {
                    // 同步临界区，不含 await
                    self.guard().clear(ip);
                }
            }
            id
        };
        let handshake = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            crate::handshake::server_handshake(&mut stream, verify),
        )
        .await;

        let hs = match handshake {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                debug!("握手失败 (from {peer}): {e}");
                // 记账与日志只含来源 IP 与失败类别，不含 vkey / md5(vkey)
                if Self::count_handshake_failure(&e) {
                    if let Some(ip) = &peer_ip {
                        let mut g = self.guard();
                        match g.record_failure(Instant::now(), ip) {
                            FailureOutcome::CooldownStarted => {
                                warn!("来源 {ip} 滑动窗口内握手失败达到阈值，进入冷却期");
                            }
                            FailureOutcome::CooldownExtended => {
                                debug!("来源 {ip} 冷却期内再次失败，冷却期顺延");
                            }
                            FailureOutcome::Counted => {
                                debug!(
                                    "来源 {ip} 握手失败已记账 ({})",
                                    Self::failure_category(&e)
                                );
                            }
                        }
                    }
                }
                return;
            }
            Err(_) => {
                debug!("握手超时 (from {peer})");
                if let Some(ip) = &peer_ip {
                    let mut g = self.guard();
                    if matches!(
                        g.record_failure(Instant::now(), ip),
                        FailureOutcome::CooldownStarted
                    ) {
                        warn!("来源 {ip} 滑动窗口内握手失败达到阈值，进入冷却期");
                    }
                }
                return;
            }
        };

        // 注意：该 IP 的失败记录已在上面 verify 回调里随校验成功清零，
        // 这里不再重复清理。

        let client_id = hs.client_id;
        let conn_type = hs.conn_type;
        info!(
            "clientId {client_id} 连接 {:?} 成功 (from {peer})",
            String::from_utf8_lossy(&conn_type)
        );

        match &conn_type {
            b"main" => self.handle_main(stream, hs, peer).await,
            b"chan" => self.handle_chan(stream, hs, peer).await,
            b"conf" => match self.shared.conf_handler.get() {
                Some(handler) => {
                    let session = ConfSession {
                        client_id,
                        client_version: hs.client_version.clone(),
                        peer,
                        stream,
                        bridge: self.clone(),
                        closing: self.shared.close_tx.subscribe(),
                    };
                    handler.handle(session).await;
                }
                None => {
                    // 默认关闭：不读不写，直接关闭（干净 FIN）
                    debug!("配置文件模式未启用，关闭 conf 连接 (clientId {client_id} from {peer})");
                    let _ = stream.shutdown().await;
                }
            },
            b"file" => match self.shared.file_handler.get() {
                Some(handler) => {
                    // 文件通道是独立的 mux 会话（与 chan 平行）
                    let mux = std::sync::Arc::new(crate::mux::MuxSession::new(stream));
                    handler.handle(client_id, mux);
                }
                None => {
                    debug!(
                        "file 通道未启用，关闭 file 连接 (clientId {client_id} from {peer})"
                    );
                    let _ = stream.shutdown().await;
                }
            },
            b"sert" => match self.shared.secret_handler.get() {
                Some(handler) => {
                    // 原版：客户端紧接着发 32 字节 md5(password)（无长度前缀）
                    let mut digest = [0u8; 32];
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut digest),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {
                            let password_md5 = String::from_utf8_lossy(&digest).to_string();
                            handler.handle(client_id, password_md5, stream).await;
                        }
                        Ok(Err(e)) => {
                            debug!("secret 通道读取密码失败 (clientId {client_id}): {e}");
                        }
                        Err(_) => {
                            debug!("secret 通道读取密码超时 (clientId {client_id})");
                        }
                    }
                }
                None => {
                    debug!("secret 通道未启用，关闭连接 (clientId {client_id} from {peer})");
                    let _ = stream.shutdown().await;
                }
            },
            b"p2pm" => match self.shared.p2p_handler.get() {
                Some(handler) => {
                    // 原版：读 32 字节 md5(password)（GetShortContent(32)，无长度前缀）
                    let mut digest = [0u8; 32];
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut digest),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {
                            let password_md5 = String::from_utf8_lossy(&digest).to_string();
                            handler.handle(client_id, password_md5, stream).await;
                        }
                        Ok(Err(e)) => {
                            debug!("p2p 通道读取密码失败 (clientId {client_id}): {e}");
                        }
                        Err(_) => {
                            debug!("p2p 通道读取密码超时 (clientId {client_id})");
                        }
                    }
                }
                None => {
                    debug!("p2p 未启用，关闭 p2pm 连接 (clientId {client_id} from {peer})");
                    let _ = stream.shutdown().await;
                }
            },
            b"rgst" => {
                // 动态客户端注册（原版 public_vkey 流程）：如实告知未支持
                debug!("连接类型 \"rgst\" 暂未支持 (clientId {client_id})，关闭");
                let _ = stream.shutdown().await;
            }
            other => {
                warn!("未知连接类型 {other:?}，关闭 (clientId {client_id})");
            }
        }
    }

    /// 处理 control 面（main）连接：注册/替换 signal，然后持续读取健康上报。
    async fn handle_main(
        &self,
        stream: tokio::net::TcpStream,
        hs: HandshakeResult,
        peer: String,
    ) {
        let id = hs.client_id;
        let gen = self.next_gen();
        let (guard, stop_rx) = stop_channel();

        // main 连接要同时支持「服务端主动推帧」（p2p 邀请）与「读健康上报」，
        // 因此读写半边分开保管：写半边进 SignalState（send_p2p_invite 用），
        // 读半边留给健康上报循环。
        let (mut read_half, write_half) = stream.into_split();
        let write = Arc::new(Mutex::new(write_half));

        {
            let mut clients = self.shared.clients.lock().await;
            let st = clients.entry(id).or_insert_with(|| ClientState::empty(id));
            let old = st.signal.replace(SignalState { gen, guard, write });
            st.version = hs.client_version.clone();
            if let Some(mut old) = old {
                // 丢弃旧 sender → 旧读循环退出 → 旧 socket 关闭
                old.guard.stop();
                info!("clientId {id} 重复登录，已替换旧 signal 连接 (from {peer})");
            }
        }

        // 持续读取健康上报帧，直到对端关闭 / 超长帧 / 被替换
        let reason = Self::read_health_loop(&mut read_half, stop_rx).await;
        debug!("clientId {id} main 读循环结束: {reason}");

        // 仅当 state 仍指向本代连接时才清理（避免误伤新连接）
        let mut clients = self.shared.clients.lock().await;
        let mut remove = false;
        if let Some(st) = clients.get_mut(&id) {
            if st.signal.as_ref().map(|s| s.gen) == Some(gen) {
                st.signal = None;
                remove = st.tunnel.is_none();
            }
        }
        if remove {
            clients.remove(&id);
        }
    }

    /// 读健康上报帧：`int32 LE 长度 + 内容`，内容形如 `"<target>*#*<0|1>"`。
    ///
    /// 对齐 Go `Conn.GetHealthInfo`：长度必须落在 `0 < len <= 64KB`，
    /// 否则视为协议错误并断开（Go 侧返回 error 后 `DelClient`）。
    /// 返回结束原因，仅用于日志。
    async fn read_health_loop(
        stream: &mut tokio::net::tcp::OwnedReadHalf,
        mut stop_rx: oneshot::Receiver<()>,
    ) -> &'static str {
        let mut len_buf = [0u8; 4];
        loop {
            let read_len = tokio::select! {
                _ = &mut stop_rx => return "replaced",
                r = stream.read_exact(&mut len_buf) => r,
            };
            if read_len.is_err() {
                return "closed";
            }
            let len = i32::from_le_bytes(len_buf);
            if len <= 0 || len as usize > MAX_HEALTH_FRAME_LEN {
                debug!("health frame 长度非法: {len}");
                return "bad-length";
            }
            let len = len as usize;
            let mut buf = vec![0u8; len];
            let read_body = tokio::select! {
                _ = &mut stop_rx => return "replaced",
                r = stream.read_exact(&mut buf) => r,
            };
            if read_body.is_err() {
                return "closed";
            }

            // P0 只校验格式并记录；健康检查路由到具体 target 的后续实现。
            match std::str::from_utf8(&buf) {
                Ok(s) => {
                    let mut parts = s.split(nps_proto::CONN_DATA_SEQ);
                    match (parts.next(), parts.next()) {
                        (Some(target), Some(status)) => {
                            trace!("client health: {target} status={status}");
                        }
                        _ => debug!("收到无法解析的健康上报，忽略"),
                    }
                }
                Err(_) => debug!("健康上报非 UTF-8，忽略"),
            }
        }
    }

    /// 处理 data 面（chan）连接：创建 mux 会话并监视其生命周期。
    async fn handle_chan(&self, stream: tokio::net::TcpStream, hs: HandshakeResult, peer: String) {
        let id = hs.client_id;
        let gen = self.next_gen();
        let mux = Arc::new(MuxSession::new(stream));

        {
            let mut clients = self.shared.clients.lock().await;
            let st = clients.entry(id).or_insert_with(|| ClientState::empty(id));
            let old = st.tunnel.replace(TunnelState {
                gen,
                mux: mux.clone(),
            });
            if st.version.is_empty() {
                st.version = hs.client_version.clone();
            }
            if let Some(old) = old {
                old.mux.close();
                info!("clientId {id} 旧 tunnel 被新连接替换 (from {peer})");
            }
        }

        // 后台等待 mux 关闭，按 generation 清理在线状态
        let this = self.clone();
        let watch_mux = mux.clone();
        tokio::spawn(async move {
            watch_mux.wait_closed().await;
            let mut clients = this.shared.clients.lock().await;
            let mut remove = false;
            if let Some(st) = clients.get_mut(&id) {
                if st.tunnel.as_ref().map(|t| t.gen) == Some(gen) {
                    st.tunnel = None;
                    debug!("clientId {id} tunnel 已断开，在线状态已更新");
                    remove = st.signal.is_none();
                }
            }
            if remove {
                clients.remove(&id);
            }
        });
    }

    /// 在已绑定的 listener 上启动 accept 循环（供 `:0` 场景与测试使用）。
    ///
    /// 直到 [`Bridge::shutdown`] 被调用才返回。
    pub async fn serve_on(&self, listener: TcpListener) -> std::io::Result<()> {
        let addr = listener.local_addr().ok();
        info!("bridge listening on {:?}", addr);

        let mut close_rx = self.shared.close_tx.subscribe();
        if *close_rx.borrow() {
            return Ok(());
        }

        loop {
            tokio::select! {
                _ = close_rx.changed() => break,
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, _peer)) => {
                            if self.shared.closing.load(Ordering::Acquire) {
                                break;
                            }
                            let this = self.clone();
                            tokio::spawn(async move {
                                this.handle_conn(stream).await;
                            });
                        }
                        Err(e) => {
                            // 单次 accept 失败不致命（如 fd 耗尽），退避后继续
                            warn!("bridge accept error: {e}");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }
        debug!("bridge accept loop exit");
        Ok(())
    }

    /// 绑定并启动桥监听（`bridge_addr` 如 `127.0.0.1:8024`）。
    pub async fn serve(&self, bridge_addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(bridge_addr).await?;
        self.serve_on(listener).await
    }

    /// 关闭桥：停止 accept、停止所有读循环、关闭所有 mux 会话、清空注册表。
    pub async fn shutdown(&self) {
        if self.shared.closing.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = self.shared.close_tx.send(true);

        let mut clients = self.shared.clients.lock().await;
        for st in clients.values_mut() {
            if let Some(sig) = st.signal.as_mut() {
                sig.guard.stop();
            }
            if let Some(t) = st.tunnel.as_ref() {
                t.mux.close();
            }
        }
        clients.clear();
        debug!("bridge 已关闭，全部连接已释放");
    }

    /// 是否已进入关闭流程
    pub fn is_closing(&self) -> bool {
        self.shared.closing.load(Ordering::Acquire)
    }

    /// 查询某客户端是否在线（signal + 未关闭的 tunnel）
    pub async fn is_client_online(&self, id: i32) -> bool {
        let clients = self.shared.clients.lock().await;
        clients
            .get(&id)
            .map(ClientState::is_online)
            .unwrap_or(false)
    }

    /// 返回 (在线, 版本)
    pub async fn client_status(&self, id: i32) -> (bool, String) {
        let clients = self.shared.clients.lock().await;
        match clients.get(&id) {
            Some(st) => (st.is_online(), st.version.clone()),
            None => (false, String::new()),
        }
    }

    /// 返回客户端上报的版本号（可能为空）
    pub async fn client_version(&self, id: i32) -> Option<String> {
        let clients = self.shared.clients.lock().await;
        clients.get(&id).map(|st| st.version.clone())
    }

    /// 取某客户端的 tunnel mux 会话（用于开子流转发数据）。
    ///
    /// tunnel 已关闭时返回 `None`。
    pub async fn get_tunnel(&self, id: i32) -> Option<Arc<MuxSession>> {
        let clients = self.shared.clients.lock().await;
        clients.get(&id).and_then(|st| {
            st.tunnel
                .as_ref()
                .map(|t| t.mux.clone())
                .filter(|m| !m.is_closed())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::write_len_content;
    use crate::handshake::md5_hex;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    /// 建一个只认 vkey-test -> id 1 的桥
    fn test_bridge() -> Arc<Bridge> {
        Arc::new(Bridge::new(|v| {
            if v == md5_hex("vkey-test") {
                Some(1)
            } else {
                None
            }
        }))
    }

    /// 模拟老 npc：connect + 握手 + 发 conn_type flag
    async fn npc_handshake(
        addr: std::net::SocketAddr,
        vkey: &str,
        conn_type: &[u8; 4],
    ) -> TcpStream {
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(b"TST").await.unwrap();
        write_len_content(&mut c, nps_proto::CORE_VERSION.as_bytes())
            .await
            .unwrap();
        write_len_content(&mut c, b"0.26.10").await.unwrap();
        let mut digest = [0u8; 32];
        c.read_exact(&mut digest).await.unwrap();
        assert_eq!(&digest, md5_hex(nps_proto::CORE_VERSION).as_bytes());
        c.write_all(md5_hex(vkey).as_bytes()).await.unwrap();
        let mut ok = [0u8; 4];
        c.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, nps_proto::VERIFY_SUCCESS.as_bytes());
        c.write_all(conn_type).await.unwrap();
        c
    }

    async fn start_bridge(bridge: &Arc<Bridge>) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let b = bridge.clone();
        tokio::spawn(async move {
            let _ = b.serve_on(listener).await;
        });
        addr
    }

    async fn wait_online(bridge: &Bridge, expected: bool) {
        for _ in 0..100 {
            if bridge.is_client_online(1).await == expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("等待在线状态 {expected} 超时");
    }

    #[tokio::test]
    async fn main_and_chan_lifecycle() {
        let bridge = test_bridge();
        let addr = start_bridge(&bridge).await;

        let main_conn = npc_handshake(addr, "vkey-test", b"main").await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        // 只有 signal，无 tunnel → 不在线
        assert!(!bridge.is_client_online(1).await);

        let chan_conn = npc_handshake(addr, "vkey-test", b"chan").await;
        wait_online(&bridge, true).await;

        // tunnel 断开 → 在线状态实时更新
        drop(chan_conn);
        wait_online(&bridge, false).await;

        drop(main_conn);
        bridge.shutdown().await;
    }

    #[tokio::test]
    async fn duplicate_main_replaces_old_and_keeps_new() {
        let bridge = test_bridge();
        let addr = start_bridge(&bridge).await;

        let main1 = npc_handshake(addr, "vkey-test", b"main").await;
        let chan = npc_handshake(addr, "vkey-test", b"chan").await;
        wait_online(&bridge, true).await;

        // 同 id 再登录：服务端应关闭旧 main，新 main 保留
        let main2 = npc_handshake(addr, "vkey-test", b"main").await;

        // 旧 main 应被服务端关闭（读到 EOF 或错误）
        let mut buf = [0u8; 1];
        let mut old_main = main1;
        let old_closed =
            tokio::time::timeout(Duration::from_secs(2), old_main.read(&mut buf)).await;
        match old_closed {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            other => panic!("旧 main 未被关闭: {other:?}"),
        }

        // 新 main + chan 仍在线
        wait_online(&bridge, true).await;

        drop(main2);
        drop(chan);
        bridge.shutdown().await;
    }

    #[tokio::test]
    async fn health_frames_consumed_and_bad_length_disconnects() {
        let bridge = test_bridge();
        let addr = start_bridge(&bridge).await;

        let mut main = npc_handshake(addr, "vkey-test", b"main").await;
        let chan = npc_handshake(addr, "vkey-test", b"chan").await;
        wait_online(&bridge, true).await;

        // 正常健康上报：len32LE + "target*#*1"
        let payload = b"127.0.0.1:80*#*1";
        main.write_all(&(payload.len() as i32).to_le_bytes())
            .await
            .unwrap();
        main.write_all(payload).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(bridge.is_client_online(1).await);

        // 超长长度 → 服务端断开 signal → 在线状态变为 false
        main.write_all(&i32::MAX.to_le_bytes()).await.unwrap();
        wait_online(&bridge, false).await;

        drop(chan);
        bridge.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_releases_listener_and_state() {
        let bridge = test_bridge();
        let addr = start_bridge(&bridge).await;

        let _main = npc_handshake(addr, "vkey-test", b"main").await;
        let _chan = npc_handshake(addr, "vkey-test", b"chan").await;
        wait_online(&bridge, true).await;

        bridge.shutdown().await;
        assert!(bridge.is_closing());
        assert!(!bridge.is_client_online(1).await);

        // accept 任务退出后端口应释放（轮询等待任务真正结束）
        let mut rebound = false;
        for _ in 0..50 {
            if TcpListener::bind(addr).await.is_ok() {
                rebound = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(rebound, "shutdown 后 bridge 端口未释放");

        // 幂等
        bridge.shutdown().await;
    }

    /// 握手超时：只连不发数据，服务端应在超时后关闭连接。
    #[tokio::test]
    async fn handshake_times_out() {
        let bridge = test_bridge();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let b = bridge.clone();
        tokio::spawn(async move {
            let _ = b.serve_on(listener).await;
        });

        let mut c = TcpStream::connect(addr).await.unwrap();
        // 不发任何握手字节，等待服务端超时（HANDSHAKE_TIMEOUT = 10s）。
        // 这里用稍长的等待避免竞态；服务端超时后直接丢弃 socket。
        let mut buf = [0u8; 1];
        let r = tokio::time::timeout(HANDSHAKE_TIMEOUT + Duration::from_secs(2), c.read(&mut buf))
            .await;
        match r {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {}
            Ok(Ok(n)) => panic!("握手超时后仍可读: {n}"),
        }
        bridge.shutdown().await;
    }

    // ---- vkey 防爆破（集成）----

    /// 防爆破测试桥：3 次失败 / 60s 窗口 / 1s 冷却 / 上限 100。
    /// 冷却取 1s 而非更短：给「冷却期内被拒」的断言留出足够时间余量，
    /// 避免慢机器上测试窗口滑出冷却期造成偶发失败。
    fn guard_test_bridge() -> Arc<Bridge> {
        Arc::new(Bridge::with_guard_config(
            |v| {
                if v == md5_hex("vkey-test") {
                    Some(1)
                } else {
                    None
                }
            },
            crate::ip_guard::GuardConfig {
                window: Duration::from_secs(60),
                max_failures: 3,
                cooldown: Duration::from_secs(1),
                max_ips: 100,
            },
        ))
    }

    /// 模拟老 npc：connect + 握手前半段（发到 md5(vkey) 为止），
    /// 校验结果由调用方自行读取（"sucs"=通过 / "vkey"=拒绝）。
    async fn npc_handshake_to_verify(addr: std::net::SocketAddr, vkey: &str) -> TcpStream {
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(b"TST").await.unwrap();
        write_len_content(&mut c, nps_proto::CORE_VERSION.as_bytes())
            .await
            .unwrap();
        write_len_content(&mut c, b"0.26.10").await.unwrap();
        let mut digest = [0u8; 32];
        c.read_exact(&mut digest).await.unwrap();
        assert_eq!(&digest, md5_hex(nps_proto::CORE_VERSION).as_bytes());
        c.write_all(md5_hex(vkey).as_bytes()).await.unwrap();
        c
    }

    /// 读服务端对 md5(vkey) 的 4 字节校验响应
    async fn read_verify_result(c: &mut TcpStream) -> [u8; 4] {
        let mut res = [0u8; 4];
        c.read_exact(&mut res).await.unwrap();
        res
    }

    /// 达到失败阈值后：冷却期内即使 vkey 正确的新连接也被直接关闭
    /// （不进握手、无响应字节）；冷却结束后重新放行。
    #[tokio::test]
    async fn brute_force_threshold_blocks_then_cooldown_releases() {
        let bridge = guard_test_bridge();
        let addr = start_bridge(&bridge).await;

        // 3 次错误 vkey：原版兼容行为不变——每次都收到 "vkey" 拒绝响应
        for _ in 0..3 {
            let mut c = npc_handshake_to_verify(addr, "wrong").await;
            assert_eq!(
                read_verify_result(&mut c).await,
                nps_proto::VERIFY_EER.as_bytes()
            );
            drop(c);
        }
        // 等服务端完成 3 次失败记账（记账在校验响应写出之后）
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 第 4 条连接：服务端不回任何握手字节，直接关闭 → 读到 EOF/错误
        let mut c = TcpStream::connect(addr).await.unwrap();
        let r = tokio::time::timeout(Duration::from_secs(2), c.read(&mut [0u8; 1])).await;
        match r {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            other => panic!("冷却期内的连接未被直接关闭: {other:?}"),
        }

        // 被拒的连接顺延了冷却期；等 1.2s 让冷却彻底结束后重新放行
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let mut c = npc_handshake_to_verify(addr, "vkey-test").await;
        assert_eq!(
            read_verify_result(&mut c).await,
            nps_proto::VERIFY_SUCCESS.as_bytes()
        );
        drop(c);
        bridge.shutdown().await;
    }

    /// 校验成功立即清零失败记录：失败 + 成功 + 失败的累计不触发冷却。
    #[tokio::test]
    async fn successful_handshake_clears_failure_record() {
        let bridge = guard_test_bridge();
        let addr = start_bridge(&bridge).await;

        // 2 次失败
        for _ in 0..2 {
            let mut c = npc_handshake_to_verify(addr, "wrong").await;
            assert_eq!(
                read_verify_result(&mut c).await,
                nps_proto::VERIFY_EER.as_bytes()
            );
            drop(c);
        }
        // 成功登录（清零）
        let mut c = npc_handshake_to_verify(addr, "vkey-test").await;
        assert_eq!(
            read_verify_result(&mut c).await,
            nps_proto::VERIFY_SUCCESS.as_bytes()
        );
        drop(c);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 清零后再失败 2 次：不到阈值，正确 vkey 依然可用
        for _ in 0..2 {
            let mut c = npc_handshake_to_verify(addr, "wrong").await;
            assert_eq!(
                read_verify_result(&mut c).await,
                nps_proto::VERIFY_EER.as_bytes()
            );
            drop(c);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut c = npc_handshake_to_verify(addr, "vkey-test").await;
        assert_eq!(
            read_verify_result(&mut c).await,
            nps_proto::VERIFY_SUCCESS.as_bytes()
        );
        drop(c);
        bridge.shutdown().await;
    }

    /// 协议错（探测字节非法）同样计入失败，达到阈值后进入冷却期。
    #[tokio::test]
    async fn protocol_errors_count_toward_cooldown() {
        let bridge = guard_test_bridge();
        let addr = start_bridge(&bridge).await;

        // 3 次「连上就发非 TST 字节」：服务端无响应、直接关闭
        for _ in 0..3 {
            let mut c = TcpStream::connect(addr).await.unwrap();
            c.write_all(b"XXX").await.unwrap();
            let r = tokio::time::timeout(Duration::from_secs(2), c.read(&mut [0u8; 1])).await;
            match r {
                Ok(Ok(0)) | Ok(Err(_)) => {}
                other => panic!("协议错连接未被关闭: {other:?}"),
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 达到阈值：正确 vkey 的新连接也被拒（EOF，无握手字节）
        let mut c = TcpStream::connect(addr).await.unwrap();
        let r = tokio::time::timeout(Duration::from_secs(2), c.read(&mut [0u8; 1])).await;
        match r {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            other => panic!("达到阈值后的连接未被直接关闭: {other:?}"),
        }
        bridge.shutdown().await;
    }

    /// 测试用 p2p 处理器：调 send_p2p_invite 后把会合地址回写给请求连接
    struct TestP2pHandler {
        bridge: Arc<Bridge>,
        rendezvous: std::sync::Mutex<Option<String>>,
    }

    impl crate::bridge::P2pRequestHandler for TestP2pHandler {
        fn handle(
            &self,
            _client_id: i32,
            password_md5: String,
            mut stream: TcpStream,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
            let bridge = self.bridge.clone();
            let addr = self.rendezvous.lock().unwrap().clone().unwrap();
            Box::pin(async move {
                assert!(bridge.send_p2p_invite(1, &addr, &password_md5).await);
                let _ = crate::codec::write_len_content(&mut stream, addr.as_bytes()).await;
            })
        }
    }

    /// p2pm 全链路：visitor 发 md5 → 处理器邀请 provider（signal 收到
    /// `udpc` + 地址 + md5 三段帧）→ p2pm 连接收到会合地址回执。
    #[tokio::test]
    async fn p2pm_invite_reaches_provider_signal_and_replies_visitor() {
        let bridge = test_bridge();
        let addr = start_bridge(&bridge).await;

        // provider：main 连接先建立（invite 要写到它的 signal 上）
        let mut provider_main = npc_handshake(addr, "vkey-test", b"main").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let rendezvous = "127.0.0.1:34567";
        let handler = Arc::new(TestP2pHandler {
            bridge: bridge.clone(),
            rendezvous: std::sync::Mutex::new(Some(rendezvous.to_owned())),
        });
        bridge.set_p2p_handler(handler);

        // visitor：以 p2pm 连入并发 md5(password)
        let md5 = crate::handshake::md5_hex("p2p-pass");
        let mut p2pm = npc_handshake(addr, "vkey-test", b"p2pm").await;
        p2pm.write_all(md5.as_bytes()).await.unwrap();

        // visitor 应收到 len(addr) 回执
        let mut len_buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), p2pm.read_exact(&mut len_buf))
            .await
            .expect("等待回执超时")
            .expect("读取回执长度失败");
        let n = i32::from_le_bytes(len_buf) as usize;
        let mut buf = vec![0u8; n];
        p2pm.read_exact(&mut buf).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&buf), rendezvous);

        // provider 的 signal 应收到 udpc + len(addr) + len(md5)
        let mut flag = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), provider_main.read_exact(&mut flag))
            .await
            .expect("等待邀请帧超时")
            .expect("读取邀请 flag 失败");
        assert_eq!(&flag, nps_proto::NEW_UDP_CONN.as_bytes());

        let mut l1 = [0u8; 4];
        provider_main.read_exact(&mut l1).await.unwrap();
        let n1 = i32::from_le_bytes(l1) as usize;
        let mut a = vec![0u8; n1];
        provider_main.read_exact(&mut a).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&a), rendezvous);

        let mut l2 = [0u8; 4];
        provider_main.read_exact(&mut l2).await.unwrap();
        let n2 = i32::from_le_bytes(l2) as usize;
        assert_eq!(n2, 32, "第二段应是 32 字节 md5");
        let mut m = vec![0u8; n2];
        provider_main.read_exact(&mut m).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&m), md5);

        bridge.shutdown().await;
    }

    /// 未安装 p2p 处理器时，p2pm 连接被直接关闭（干净 FIN）。
    #[tokio::test]
    async fn p2pm_closed_when_handler_absent() {
        let bridge = test_bridge();
        let addr = start_bridge(&bridge).await;

        let mut c = npc_handshake(addr, "vkey-test", b"p2pm").await;
        c.write_all(&[0u8; 32]).await.unwrap();
        let r = tokio::time::timeout(Duration::from_secs(3), c.read(&mut [0u8; 1])).await;
        match r {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            other => panic!("未安装处理器的 p2pm 连接未被关闭: {other:?}"),
        }
        bridge.shutdown().await;
    }
}
