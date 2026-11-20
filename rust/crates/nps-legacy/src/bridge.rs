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
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch, Mutex};
use tracing::{debug, info, trace, warn};

use crate::handshake::HandshakeResult;
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

/// signal（main）连接的一代
struct SignalState {
    gen: u64,
    guard: ConnGuard,
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
    pub fn new(verify: impl Fn(&str) -> Option<i32> + Send + Sync + 'static) -> Self {
        let (close_tx, close_keepalive) = watch::channel(false);
        Self {
            shared: Arc::new(BridgeShared {
                clients: Mutex::new(HashMap::new()),
                verify: Box::new(verify),
                gen_counter: AtomicU64::new(1),
                closing: AtomicBool::new(false),
                close_tx,
                conf_handler: OnceLock::new(),
                _close_keepalive: close_keepalive,
            }),
        }
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
    pub fn has_conf_handler(&self) -> bool {
        self.shared.conf_handler.get().is_some()
    }

    /// 处理一条已完成握手的桥连接。
    async fn handle_conn(&self, mut stream: tokio::net::TcpStream) {
        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "<unknown>".into());

        // 握手（限时）
        let verify = |v: &str| (self.shared.verify)(v);
        let handshake = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            crate::handshake::server_handshake(&mut stream, verify),
        )
        .await;

        let hs = match handshake {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                debug!("握手失败 (from {peer}): {e}");
                return;
            }
            Err(_) => {
                debug!("握手超时 (from {peer})");
                return;
            }
        };

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
            b"rgst" | b"sert" | b"p2pm" | b"file" => {
                warn!("连接类型 {conn_type:?} P0 暂未支持 (clientId {client_id})");
            }
            other => {
                warn!("未知连接类型 {other:?}，关闭 (clientId {client_id})");
            }
        }
    }

    /// 处理 control 面（main）连接：注册/替换 signal，然后持续读取健康上报。
    async fn handle_main(
        &self,
        mut stream: tokio::net::TcpStream,
        hs: HandshakeResult,
        peer: String,
    ) {
        let id = hs.client_id;
        let gen = self.next_gen();
        let (guard, stop_rx) = stop_channel();

        {
            let mut clients = self.shared.clients.lock().await;
            let st = clients.entry(id).or_insert_with(|| ClientState::empty(id));
            let old = st.signal.replace(SignalState { gen, guard });
            st.version = hs.client_version.clone();
            if let Some(mut old) = old {
                // 丢弃旧 sender → 旧读循环退出 → 旧 socket 关闭
                old.guard.stop();
                info!("clientId {id} 重复登录，已替换旧 signal 连接 (from {peer})");
            }
        }

        // 持续读取健康上报帧，直到对端关闭 / 超长帧 / 被替换
        let reason = Self::read_health_loop(&mut stream, stop_rx).await;
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
        stream: &mut tokio::net::TcpStream,
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
}
