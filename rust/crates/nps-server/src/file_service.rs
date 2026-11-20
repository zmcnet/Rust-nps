//! 文件服务隧道（原版 nps `mode=file`）。
//!
//! 数据流与 Go 版完全一致（`server/proxy/tcp.go:Start` + `bridge/bridge.go:SendLinkInfo`）：
//! ```text
//! 外部 HTTP 客户端 --TCP--> nps-server 监听器
//!   ├─ file 通道（每条 npc 连接的独立 mux 会话，见下文）
//!   ├─ mux.open_stream()                  申请子流（等对端 NewConnOk）
//!   ├─ **不发任何帧**                     子流上第一个字节就是外部客户端的 HTTP 请求
//!   └─ 双向独立转发（两条互不阻塞的读/写泵）
//! npc 侧：`nps_mux.NewMux(conn)` + `http.Server{Handler: StripPrefix(..., FileServer(Dir(local_path)))}.Serve(mux)`
//! ```
//!
//! # 与 TCP 隧道的两点关键差异
//!
//! 1. **数据面走独立的 `file` mux**，不是 `chan` mux。Go `bridge/bridge.go`：
//!    ```go
//!    case common.WORK_FILE:
//!        muxConn := nps_mux.NewMux(c.Conn, s.tunnelType, s.disconnectTime)
//!        if v, ok := s.Client.LoadOrStore(id, NewClient(nil, muxConn, nil, vs)); ok {
//!            v.(*Client).file = muxConn
//!        }
//!    ```
//!    因此 [`FileChannelRegistry`] 按 `client_id` 维护「该客户端的 file 通道」，
//!    `bridge` 收到 `file` 连接后登记进来即可（补丁见交付报告）。
//!
//! 2. **不发 Link 首帧**。Go `bridge/bridge.go:SendLinkInfo` 在 `mode == "file"` 时
//!    `tunnel.NewConn()` 之后直接返回：
//!    ```go
//!    if target, err = tunnel.NewConn(); err != nil { return }
//!    if t != nil && t.Mode == "file" {
//!        //TODO if t.mode is file ,not use crypt or compress
//!        link.Crypt = false
//!        link.Compress = false
//!        return              // ← 没有 conn.NewConn(target).SendInfo(link, "")
//!    }
//!    ```
//!    npc 侧把每个子流直接当作一条 TCP 连接交给 `http.Server`；只要我们在子流前面
//!    多写 4 字节长度 + Link JSON，HTTP 请求行就会解析失败（400）。本模块因此
//!    **只做裸字节转发**，且不透传 crypt / compress。
//!
//! # 运行态约定（与 [`crate::tunnel`] 保持一致）
//! - `active_connections` 只由 [`ActiveGuard`] 增减，任何路径（提前返回、写入失败、
//!   任务被 abort）都由 Drop 归还；停用/关闭**不**强行清零。
//! - `runtime` 同时承载「是否在监听」与「实际绑定地址」，快照不会看到
//!   「已启用但没有监听器」的中间态。
//! - 转发泵放在 [`Pump`] 里，父任务被 abort 时一并 abort，不留孤儿任务。
//!
//! # 能力边界
//! - 服务端**不解析 HTTP**，也不做目录/路径校验：`local_path`、`strip_pre` 只在
//!   npc 侧生效，服务端仅用于展示。
//! - 不做目标健康检查（文件模式没有「目标列表」；健康状态见
//!   [`target_health_details`]，供通用 `TunnelSnapshot.targets` 使用）。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use nps_legacy::mux::{MuxRecvHalf, MuxSendHalf, MuxSession};
use nps_legacy::Bridge;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, info, warn};

use crate::snapshot::{TargetHealth, TunnelSnapshot};
use crate::target::{HealthChecker, TargetPool};

/// 单次读写缓冲（与 Go `common.PoolSizeCopy = 32 KiB` 对齐）。
const COPY_BUF: usize = 32 * 1024;
/// 停用隧道时等待 accept 任务退出的上限；超时后强制 abort。
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
/// 停用后等待连接计数归零的上限（只等待，不清零）。
const DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

/// 文件隧道配置。
///
/// 字段对应 Go `file.Tunnel` 在 `mode=file` 下真正用到的部分：
/// - `listen_addr` ← 服务端 `server_ip:server_port`
/// - `client_id`   ← 注册该任务的客户端 id
/// - `local_path` / `strip_pre` ← 客户端侧 `http.FileServer` + `StripPrefix` 参数，
///   **仅用于快照/日志**，服务端不访问这些路径。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileTunnelConfig {
    pub id: u32,
    #[serde(default)]
    pub name: String,
    pub client_id: i32,
    /// 服务端监听地址，支持 `:0` 由系统分配。
    pub listen_addr: String,
    /// 是否随 server 启动而监听；默认 true（与 `TcpTunnelConfig.enabled` 同语义）。
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 目标地址。文件模式下原版不使用（npc 直接在自己的 `local_path` 上服务），
    /// 保留字段仅为快照/运维展示统一。
    #[serde(default)]
    pub target_addr: String,
    /// 客户端本地目录（`local_path`），仅展示。
    #[serde(default)]
    pub local_path: String,
    /// 客户端 URL 前缀（`strip_pre`），仅展示。
    #[serde(default)]
    pub strip_pre: String,
}

impl FileTunnelConfig {
    /// 快照里的 `target_addr`：文件模式下「目标」是客户端本地目录。
    ///
    /// `local_path` 为空时回退到 `-`，避免管理端出现空白单元格。
    fn target_display(&self) -> String {
        if !self.local_path.is_empty() {
            self.local_path.clone()
        } else if !self.target_addr.is_empty() {
            self.target_addr.clone()
        } else {
            "-".to_owned()
        }
    }
}

// ---------------------------------------------------------------------------
// 配置辅助
// ---------------------------------------------------------------------------

/// `enabled` 的 serde 默认值（与 `config.rs` 的 `default_enabled` 一致）。
fn default_enabled() -> bool {
    true
}

// ---------------------------------------------------------------------------
// file 通道注册表
// ---------------------------------------------------------------------------

fn lock<T>(m: &StdMutex<T>) -> MutexGuard<'_, T> {
    // 注册表没有可被中断的共享不变量：中毒时继续用内部值，比在转发路径 panic 更安全。
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// `client_id -> file mux 会话` 的登记表。
///
/// 每个老 npc 用 `WORK_FILE`（`"file"`）单独拨一条连接，并在其上建一条独立的 mux
/// 会话（与 `chan` 平行）。谁的 `bridge` 收到了这条连接，谁就应该把它登记进来：
///
/// ```ignore
/// // bridge.rs 的 `file` 分支（补丁见交付报告）
/// let mux = Arc::new(MuxSession::new(stream));
/// registry.register_and_watch(client_id, mux).await;
/// ```
///
/// 用 `std::sync::Mutex`：临界区全是 O(1) 的 HashMap 操作、不含 `await`。
#[derive(Default)]
pub struct FileChannelRegistry {
    inner: StdMutex<HashMap<i32, Arc<MuxSession>>>,
}

impl FileChannelRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// 登记（或替换）某客户端的 file 通道，返回被替换掉的旧会话。
    ///
    /// 旧会话由调用方决定是否 `close()`；同名重复登记（npc 重连）是正常路径。
    pub fn register(&self, client_id: i32, mux: Arc<MuxSession>) -> Option<Arc<MuxSession>> {
        lock(&self.inner).insert(client_id, mux)
    }

    /// 取某客户端的 file 通道；不存在或 mux 已关闭时返回 `None`。
    ///
    /// 顺手清理已关闭的残留项，避免 npc 断线后表里一直挂着死会话。
    pub fn get(&self, client_id: i32) -> Option<Arc<MuxSession>> {
        let mut map = lock(&self.inner);
        match map.get(&client_id) {
            Some(mux) if !mux.is_closed() => Some(mux.clone()),
            Some(_) => {
                map.remove(&client_id);
                None
            }
            None => None,
        }
    }

    /// 是否已有可用的 file 通道。
    pub fn is_registered(&self, client_id: i32) -> bool {
        self.get(client_id).is_some()
    }

    /// 移除并返回某客户端的 file 通道。
    pub fn remove(&self, client_id: i32) -> Option<Arc<MuxSession>> {
        lock(&self.inner).remove(&client_id)
    }

    /// 仅当当前登记的就是 `mux` 时移除（旧连接关闭时不会误删新连接）。
    ///
    /// 返回值 `true` 表示确实移除了。
    pub fn remove_if_same(&self, client_id: i32, mux: &Arc<MuxSession>) -> bool {
        let mut map = lock(&self.inner);
        match map.get(&client_id) {
            Some(current) if Arc::ptr_eq(current, mux) => {
                map.remove(&client_id);
                true
            }
            _ => false,
        }
    }

    /// 当前登记数（含尚未被 `get` 清理的死会话，仅供观测）。
    pub fn len(&self) -> usize {
        lock(&self.inner).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 已登记的客户端 id（无序）。
    pub fn client_ids(&self) -> Vec<i32> {
        lock(&self.inner).keys().copied().collect()
    }

    /// 清空全部登记并**关闭**每条 mux 会话（服务端关闭时使用）。
    pub fn clear(&self) {
        let sessions: Vec<Arc<MuxSession>> = {
            let mut map = lock(&self.inner);
            map.drain().map(|(_, mux)| mux).collect()
        };
        for mux in sessions {
            mux.close();
        }
    }

    /// 登记并在会话关闭后自动摘除（旧会话关闭不会误删新会话）。
    ///
    /// 必须在 tokio runtime 内调用（内部 `tokio::spawn`）。
    pub fn register_and_watch(self: &Arc<Self>, client_id: i32, mux: Arc<MuxSession>) {
        let replaced = self.register(client_id, mux.clone());
        if let Some(old) = replaced {
            // 与 Go `v.(*Client).file = muxConn` 的差异：Go 直接覆盖、旧 mux 悬挂
            // 到对端断开为止；这里显式关闭，避免双 mux 同时往同一 client 开流。
            warn!("客户端 {client_id} 的 file 通道被新连接替换，关闭旧会话");
            old.close();
        }
        let this = self.clone();
        tokio::spawn(async move {
            mux.wait_closed().await;
            if this.remove_if_same(client_id, &mux) {
                debug!("客户端 {client_id} 的 file 通道已断开关闭，登记已清除");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// 运行态
// ---------------------------------------------------------------------------

/// 计数器自增/自减的 RAII 守卫，保证任何退出路径都不漏减。
struct ActiveGuard(Arc<FileTunnel>);

impl ActiveGuard {
    fn new(t: Arc<FileTunnel>) -> Self {
        t.active_connections.fetch_add(1, Ordering::Relaxed);
        Self(t)
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        // 饱和自减：即便外部误把计数清零，也只会停在 0，不会回绕成 u64::MAX
        let _ = self
            .0
            .active_connections
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }
}

/// 转发泵的取消守卫：本函数被 abort 时一并 abort 读/写泵，不留孤儿任务。
struct Pump {
    task: JoinHandle<()>,
}

impl Pump {
    fn new(task: JoinHandle<()>) -> Self {
        Self { task }
    }
}

impl Drop for Pump {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// 运行中的监听任务
struct FileRun {
    cancel: watch::Sender<bool>,
    task: JoinHandle<()>,
    bound_addr: SocketAddr,
}

/// 一条文件服务隧道的运行态
pub struct FileTunnel {
    pub cfg: FileTunnelConfig,
    /// 各客户端的 file 通道（由 bridge 的 `WORK_FILE` 分支登记）
    channels: Arc<FileChannelRegistry>,
    active_connections: Arc<AtomicU64>,
    bytes_to_client: Arc<AtomicU64>,
    bytes_from_client: Arc<AtomicU64>,
    last_error: Arc<Mutex<Option<String>>>,
    /// 串行化 start/disable
    op: Mutex<()>,
    /// `Some` 即「已启用」，内含实际绑定地址
    runtime: Mutex<Option<FileRun>>,
    /// 限速（与同客户端其它隧道共享）
    rate: Option<Arc<crate::limit::TokenBucket>>,
    /// 流量上限（与同客户端其它隧道共享）
    flow: Option<Arc<crate::limit::FlowCounter>>,
    /// 来源 IP 白名单
    ip_allow: Arc<crate::limit::IpAllowList>,
    /// 已 shutdown：不再允许启动（幂等关闭）
    closed: AtomicBool,
}

impl FileTunnel {
    /// 自带一份 [`FileChannelRegistry`]（独立使用 / 测试）。
    ///
    /// 生产环境请用 [`FileTunnel::with_registry`] 与桥共享同一份登记表。
    pub fn new(cfg: FileTunnelConfig) -> Self {
        Self::with_registry(cfg, Arc::new(FileChannelRegistry::new()))
    }

    /// 使用外部共享的 file 通道登记表（`server.rs` 接线用）。
    pub fn with_registry(cfg: FileTunnelConfig, channels: Arc<FileChannelRegistry>) -> Self {
        Self::with_controls(
            cfg,
            channels,
            None,
            None,
            Arc::new(crate::limit::IpAllowList::default()),
        )
    }

    /// 带流控 / 白名单构造（与 [`crate::tunnel::Tunnel::with_controls`] 语义一致）。
    pub fn with_controls(
        cfg: FileTunnelConfig,
        channels: Arc<FileChannelRegistry>,
        rate: Option<Arc<crate::limit::TokenBucket>>,
        flow: Option<Arc<crate::limit::FlowCounter>>,
        ip_allow: Arc<crate::limit::IpAllowList>,
    ) -> Self {
        Self {
            cfg,
            channels,
            active_connections: Arc::new(AtomicU64::new(0)),
            bytes_to_client: Arc::new(AtomicU64::new(0)),
            bytes_from_client: Arc::new(AtomicU64::new(0)),
            last_error: Arc::new(Mutex::new(None)),
            op: Mutex::new(()),
            runtime: Mutex::new(None),
            rate,
            flow,
            ip_allow,
            closed: AtomicBool::new(false),
        }
    }

    pub fn id(&self) -> u32 {
        self.cfg.id
    }

    pub fn config(&self) -> &FileTunnelConfig {
        &self.cfg
    }

    /// 与桥共享的 file 通道登记表（`server.rs` 用它接 bridge 的 `WORK_FILE` 分支）。
    pub fn channels(&self) -> &Arc<FileChannelRegistry> {
        &self.channels
    }

    /// 当前正在转发的外部连接数。
    pub fn active_connections(&self) -> u64 {
        self.active_connections.load(Ordering::Relaxed)
    }

    /// `(外部->客户端, 客户端->外部)` 累计字节。
    pub fn bytes(&self) -> (u64, u64) {
        (
            self.bytes_to_client.load(Ordering::Relaxed),
            self.bytes_from_client.load(Ordering::Relaxed),
        )
    }

    async fn set_error(&self, msg: impl Into<String>) {
        *self.last_error.lock().await = Some(msg.into());
    }

    async fn clear_error(&self) {
        *self.last_error.lock().await = None;
    }

    /// 绑定监听器（`listen_addr` 支持 `:0`）。
    pub async fn bind(&self) -> Result<TcpListener> {
        TcpListener::bind(&self.cfg.listen_addr)
            .await
            .with_context(|| {
                format!(
                    "文件隧道 {} ({}) 无法监听 {}",
                    self.cfg.id, self.cfg.name, self.cfg.listen_addr
                )
            })
    }

    /// 绑定并启动，返回实际绑定地址。
    pub async fn start(self: &Arc<Self>, bridge: Bridge) -> Result<SocketAddr> {
        let listener = self.bind().await?;
        self.start_with_listener(bridge, listener).await
    }

    /// 用已绑定的监听器启动转发循环，返回实际绑定地址。
    ///
    /// 先起任务、再登记 runtime：登记完成即代表「已启用」，此前 `snapshot`
    /// 看到的仍是未启用状态，不会出现「已启用但监听器还没跑」的假象。
    pub async fn start_with_listener(
        self: &Arc<Self>,
        bridge: Bridge,
        listener: TcpListener,
    ) -> Result<SocketAddr> {
        let bound_addr = listener
            .local_addr()
            .context("读取文件隧道实际绑定地址失败")?;
        let _serial = self.op.lock().await;
        if self.closed.load(Ordering::Acquire) {
            bail!("文件隧道 {} 已关闭，不能再次启动", self.cfg.id);
        }
        let (cancel, cancel_rx) = watch::channel(false);
        let this = self.clone();
        let task = tokio::spawn(async move {
            this.accept_loop(bridge, listener, cancel_rx).await;
        });
        let stale = self.runtime.lock().await.replace(FileRun {
            cancel,
            task,
            bound_addr,
        });
        if let Some(previous) = stale {
            warn!("文件隧道 {} 发现残留监听任务，取消旧实例", self.cfg.id);
            let _ = previous.cancel.send(true);
            previous.task.abort();
        }
        info!(
            "文件隧道 {} ({}) 监听 {}（客户端 {} 的 file 通道，本地目录 {}，前缀 {:?}）",
            self.cfg.id,
            self.cfg.name,
            bound_addr,
            self.cfg.client_id,
            self.cfg.local_path,
            self.cfg.strip_pre
        );
        Ok(bound_addr)
    }

    /// 当前是否有**活跃**的监听任务（accept 任务异常退出时为 false）。
    pub async fn is_listening(&self) -> bool {
        let runtime = self.runtime.lock().await;
        runtime
            .as_ref()
            .is_some_and(|run| !run.task.is_finished())
    }

    /// 停用：关闭监听器（端口立即释放），并断开该隧道现存转发连接。
    ///
    /// 幂等；不强行清零 `active_connections`（计数由守卫拥有）。
    pub async fn disable(&self) {
        let _serial = self.op.lock().await;
        self.stop().await;
    }

    /// 关闭：`disable` + 标记不可再启动（幂等）。
    ///
    /// 不会关闭客户端的 file 通道（可能被同客户端其它文件隧道共用）。
    pub async fn shutdown(&self) {
        self.closed.store(true, Ordering::Release);
        self.disable().await;
    }

    /// 是否已 shutdown。
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    async fn stop(&self) {
        let run = self.runtime.lock().await.take();
        if let Some(run) = run {
            let _ = run.cancel.send(true);
            let mut task = run.task;
            match tokio::time::timeout(STOP_TIMEOUT, &mut task).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!("文件隧道 {} accept 任务异常: {e}", self.cfg.id),
                Err(_) => {
                    warn!("文件隧道 {} accept 任务停止超时，强制终止", self.cfg.id);
                    task.abort();
                    let _ = task.await;
                }
            }
        }
        // 有界等待计数归零，让「停用返回时计数为 0」成为可依赖的语义
        let deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;
        while self.active_connections.load(Ordering::Relaxed) != 0 {
            if tokio::time::Instant::now() >= deadline {
                warn!(
                    "文件隧道 {} 停用后仍有 {} 条连接未退出（计数保持真实值，不强行清零）",
                    self.cfg.id,
                    self.active_connections.load(Ordering::Relaxed)
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// 快照（复用 [`TunnelSnapshot`] 契约）。
    pub async fn snapshot(&self) -> TunnelSnapshot {
        let (enabled, bound_addr) = {
            let runtime = self.runtime.lock().await;
            match runtime.as_ref() {
                Some(run) => (true, Some(run.bound_addr.to_string())),
                None => (false, None),
            }
        };
        TunnelSnapshot {
            id: self.cfg.id,
            name: self.cfg.name.clone(),
            client_id: self.cfg.client_id,
            listen_addr: self.cfg.listen_addr.clone(),
            target_addr: self.cfg.target_display(),
            enabled,
            active_connections: self.active_connections(),
            bytes_to_client: self.bytes_to_client.load(Ordering::Relaxed),
            bytes_from_client: self.bytes_from_client.load(Ordering::Relaxed),
            last_error: self.last_error.lock().await.clone(),
            bound_addr,
            // 文件模式没有目标列表 / 健康检查：契约要求「非多目标时为空」
            targets: Vec::new(),
        }
    }

    /// accept 循环：退出时关闭所有在跑的转发连接。
    async fn accept_loop(
        self: Arc<Self>,
        bridge: Bridge,
        listener: TcpListener,
        mut cancel: watch::Receiver<bool>,
    ) {
        let mut conns: JoinSet<()> = JoinSet::new();
        loop {
            tokio::select! {
                _ = cancel.changed() => break,
                _ = conns.join_next(), if !conns.is_empty() => {}
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, peer)) => {
                            // 桥已进入关闭流程：不再为新的外部连接建流
                            if bridge.is_closing() {
                                continue;
                            }
                            let t = self.clone();
                            let b = bridge.clone();
                            let c = cancel.clone();
                            conns.spawn(async move {
                                t.handle_external(b, stream, peer, c).await;
                            });
                        }
                        Err(e) => {
                            warn!("文件隧道 {} accept 失败: {e}", self.cfg.id);
                            self.set_error(format!("accept 失败: {e}")).await;
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }
        conns.shutdown().await;
        debug!("文件隧道 {} accept 循环退出", self.cfg.id);
    }

    /// 处理一条外部连接
    async fn handle_external(
        self: Arc<Self>,
        bridge: Bridge,
        stream: TcpStream,
        peer: SocketAddr,
        cancel: watch::Receiver<bool>,
    ) {
        let _guard = ActiveGuard::new(self.clone());
        if *cancel.borrow() {
            return;
        }

        // ---- 准入检查：IP 白名单 → 流量上限（与 TCP 隧道一致）----
        if !self.ip_allow.allows(peer.ip()) {
            debug!("文件隧道 {}: 拒绝未授权来源 IP {}", self.cfg.id, peer.ip());
            return;
        }
        if let Some(flow) = &self.flow {
            if flow.exceeded() {
                self.set_error("客户端流量已超限").await;
                warn!(
                    "文件隧道 {}: 客户端 {} 流量超限，拒绝来自 {} 的连接",
                    self.cfg.id, self.cfg.client_id, peer
                );
                return;
            }
        }

        // 取该客户端的 file 通道（与 chan 通道平行的一条独立 mux）
        let mux = match self.channels.get(self.cfg.client_id) {
            Some(mux) => mux,
            None => {
                let (online, _) = bridge.client_status(self.cfg.client_id).await;
                let hint = if online {
                    "在线，但未建立 file 通道（需要 bridge 处理 WORK_FILE 连接）"
                } else {
                    "离线"
                };
                self.set_error(format!(
                    "客户端 {} {hint}，无法建立文件隧道连接",
                    self.cfg.client_id
                ))
                .await;
                debug!(
                    "文件隧道 {}: 客户端 {} {hint}，拒绝来自 {} 的连接",
                    self.cfg.id, self.cfg.client_id, peer
                );
                return;
            }
        };

        let mux_stream = match mux.open_stream().await {
            Ok(s) => s,
            Err(e) => {
                self.set_error(format!("file 通道建流失败: {e}")).await;
                warn!("文件隧道 {}: file 通道建流失败: {e}", self.cfg.id);
                return;
            }
        };
        let (send, recv) = mux_stream.into_split();

        // **不发 Link 首帧**：见模块文档 / Go `bridge.SendLinkInfo` 的 mode=file 分支。
        // npc 侧 `http.Server.Serve(mux)` 会直接把子流当 TCP 连接解析 HTTP。
        self.clear_error().await;
        debug!("文件隧道 {}: {} -> 客户端 {} 的 file 通道 已建立", self.cfg.id, peer, self.cfg.client_id);

        let (ext_r, ext_w) = stream.into_split();
        // 两个方向各自独立任务推进，避免全双工会死锁；任一方向结束即终止另一方向
        // （与 Go `copyConnGroup` 一致）。泵由 `Pump` 持有，父任务被 abort 时一并 abort。
        let mut up = Pump::new(tokio::spawn(Self::pump_ext_to_mux(
            ext_r,
            send,
            self.clone(),
            cancel.clone(),
        )));
        let mut down = Pump::new(tokio::spawn(Self::pump_mux_to_ext(
            recv,
            ext_w,
            self.clone(),
            cancel.clone(),
        )));
        let up_finished_first = tokio::select! {
            _ = &mut up.task => true,
            _ = &mut down.task => false,
        };
        if up_finished_first {
            down.task.abort();
            let _ = (&mut down.task).await;
        } else {
            up.task.abort();
            let _ = (&mut up.task).await;
        }
        debug!("文件隧道 {}: {} 连接结束", self.cfg.id, peer);
    }

    /// 外部 -> mux（计入 `bytes_to_client`）
    async fn pump_ext_to_mux(
        mut reader: OwnedReadHalf,
        mut send: MuxSendHalf,
        tunnel: Arc<FileTunnel>,
        mut cancel: watch::Receiver<bool>,
    ) {
        let mut buf = vec![0u8; COPY_BUF];
        loop {
            if *cancel.borrow() {
                break;
            }
            let n = tokio::select! {
                _ = cancel.changed() => break,
                r = reader.read(&mut buf) => match r {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        debug!("文件隧道 {}: 读取外部连接失败: {e}", tunnel.cfg.id);
                        break;
                    }
                },
            };
            // 限速：与 cancel 竞争，避免低速配置下停用隧道要等一整个配额周期
            if let Some(rate) = &tunnel.rate {
                tokio::select! {
                    _ = cancel.changed() => break,
                    _ = rate.acquire(n) => {}
                }
            }
            if send.send_data(&buf[..n]).await.is_err() {
                debug!("文件隧道 {}: 写 file 通道失败（客户端可能已断开）", tunnel.cfg.id);
                break;
            }
            tunnel
                .bytes_to_client
                .fetch_add(n as u64, Ordering::Relaxed);
            if let Some(flow) = &tunnel.flow {
                flow.add(n as u64, 0);
            }
        }
        send.close();
    }

    /// mux -> 外部（计入 `bytes_from_client`）
    async fn pump_mux_to_ext(
        mut recv: MuxRecvHalf,
        mut writer: OwnedWriteHalf,
        tunnel: Arc<FileTunnel>,
        mut cancel: watch::Receiver<bool>,
    ) {
        loop {
            if *cancel.borrow() {
                break;
            }
            let data = tokio::select! {
                _ = cancel.changed() => break,
                d = recv.recv_data() => match d {
                    Some(d) => d,
                    None => break,
                },
            };
            if let Some(rate) = &tunnel.rate {
                tokio::select! {
                    _ = cancel.changed() => break,
                    _ = rate.acquire(data.len()) => {}
                }
            }
            if writer.write_all(&data).await.is_err() {
                debug!("文件隧道 {}: 写外部连接失败", tunnel.cfg.id);
                break;
            }
            tunnel
                .bytes_from_client
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            if let Some(flow) = &tunnel.flow {
                flow.add(0, data.len() as u64);
            }
            let _ = writer.flush().await;
        }
        let _ = writer.shutdown().await;
    }
}

// ---------------------------------------------------------------------------
// 目标健康状态（供通用 TunnelSnapshot.targets 使用）
// ---------------------------------------------------------------------------

/// 单个目标的健康视图（含连续失败次数）。
///
/// 快照契约 [`TargetHealth`] 目前只有 `healthy`；`failures` 是这里补的字段，
/// 父代理在 `snapshot.rs` 加上该字段后，`to_snapshot` 直接透传即可（补丁见报告）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetHealthDetail {
    pub target: String,
    pub healthy: bool,
    /// 连续失败次数（探测成功即清零；未启用健康检查时恒为 0）
    pub failures: u32,
}

impl TargetHealthDetail {
    /// 转成快照契约类型。
    pub fn to_snapshot(&self) -> TargetHealth {
        TargetHealth {
            target: self.target.clone(),
            healthy: self.healthy,
        }
    }
}

/// 汇总目标池的逐目标健康状态（配置顺序）。
///
/// - `healthy` = 未被健康检查摘除（`TargetPool::is_offline` 取反）；
/// - `failures` = `HealthChecker::state_of().consecutive_failures`，未启用检查时为 0。
///
/// `Tunnel::snapshot()` 里按同样口径填充 `TunnelSnapshot.targets`（见报告）。
pub fn target_health_details(
    pool: &TargetPool,
    checker: Option<&HealthChecker>,
) -> Vec<TargetHealthDetail> {
    pool.all_targets()
        .into_iter()
        .map(|target| {
            let healthy = !pool.is_offline(&target);
            let failures = checker
                .and_then(|c| c.state_of(&target))
                .map(|s| s.consecutive_failures)
                .unwrap_or(0);
            TargetHealthDetail {
                target,
                healthy,
                failures,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nps_legacy::mux::MuxSession;

    fn cfg() -> FileTunnelConfig {
        FileTunnelConfig {
            id: 7,
            name: "files".into(),
            client_id: 1,
            listen_addr: "127.0.0.1:0".into(),
            enabled: true,
            target_addr: String::new(),
            local_path: "/srv/share".into(),
            strip_pre: "/files".into(),
        }
    }

    /// 文件模式的快照目标地址是客户端本地目录（而不是空串）。
    #[test]
    fn target_display_prefers_local_path() {
        assert_eq!(cfg().target_display(), "/srv/share");

        let mut c = cfg();
        c.local_path.clear();
        c.target_addr = "10.0.0.2:80".into();
        assert_eq!(c.target_display(), "10.0.0.2:80");

        c.target_addr.clear();
        assert_eq!(c.target_display(), "-");
    }

    /// 配置可序列化（父代理把它放进 ServerConfig 时可直接复用）。
    #[test]
    fn config_json_roundtrip_with_defaults() {
        let json = r#"{"id":3,"client_id":1,"listen_addr":"0.0.0.0:9001"}"#;
        let c: FileTunnelConfig = serde_json::from_str(json).unwrap();
        assert_eq!(c.id, 3);
        assert_eq!(c.name, "");
        assert_eq!(c.local_path, "");
        assert_eq!(c.strip_pre, "");
        let back = serde_json::to_string(&c).unwrap();
        assert!(back.contains("\"listen_addr\":\"0.0.0.0:9001\""));
    }

    /// 替换登记时返回旧会话；`remove_if_same` 不会误删新会话。
    #[tokio::test]
    async fn registry_replace_and_stale_removal() {
        let registry = FileChannelRegistry::new();
        let (a1, _a2) = tokio::io::duplex(8 * 1024);
        let (b1, _b2) = tokio::io::duplex(8 * 1024);
        let first = Arc::new(MuxSession::new(a1));
        let second = Arc::new(MuxSession::new(b1));

        assert!(registry.register(1, first.clone()).is_none());
        let replaced = registry.register(1, second.clone()).expect("应返回被替换的旧会话");
        assert!(Arc::ptr_eq(&replaced, &first));

        // 旧会话关闭后走 remove_if_same：不能把新会话摘掉
        assert!(!registry.remove_if_same(1, &first));
        assert!(registry.is_registered(1));
        assert!(registry.remove_if_same(1, &second));
        assert!(!registry.is_registered(1));
    }

    /// 关闭的 mux 不出现在 `get()` 里（顺手清理残留）。
    #[tokio::test]
    async fn registry_get_skips_closed_session() {
        let registry = FileChannelRegistry::new();
        let (a1, _a2) = tokio::io::duplex(8 * 1024);
        let mux = Arc::new(MuxSession::new(a1));
        registry.register(1, mux.clone());
        assert!(registry.is_registered(1));
        mux.close();
        assert!(!registry.is_registered(1));
        assert_eq!(registry.len(), 0, "关闭的会话应被清理");
    }
}
