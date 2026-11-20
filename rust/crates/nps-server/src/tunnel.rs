//! TCP 隧道转发：外部 socket -> mux 子流 -> 老 npc 拨号内网目标。
//!
//! 单条连接的数据流与 Go `server/proxy/tcp.go` + `bridge.SendLinkInfo` 对齐：
//! ```text
//! 外部客户端 --TCP--> nps-server 监听器
//!   ├─ bridge.get_tunnel(client_id)       取该 client 的 chan mux 会话
//!   ├─ mux.open_stream()                  申请子流（等对端 NewConnOk）
//!   ├─ 发送 int32 LE 长度 + Link JSON     对齐 Go `SendInfo(link, "")`，无 flag
//!   └─ 双向独立转发（两条互不阻塞的读/写泵）
//! 老 npc 收到 Link 后按 Host 拨号目标，然后透传数据。
//! ```
//!
//! 每条连接的两个方向各用独立任务（`pump_ext_to_mux` / `pump_mux_to_ext`），
//! 避免在同一个 `select!` 里做阻塞式写入而导致全双工死锁。
//!
//! ## 运行态约定
//! - `active_connections` 只由 [`ActiveGuard`] 增减，任何路径（提前返回、
//!   写入失败、任务被 abort）都由 Drop 归还；停用/关闭**不**强行清零，
//!   避免与守卫的并发递减相撞产生下溢。
//! - `runtime` 同时承载「是否在监听」与「实际绑定地址」，对外快照不会
//!   看到"已启用但无监听器"或反之的中间态。
//! - 转发泵放在 [`Pump`] 里，父任务被 abort 时一并 abort，不留孤儿任务。

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use nps_legacy::mux::{MuxRecvHalf, MuxSendHalf};
use nps_legacy::Bridge;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, info, warn};

use crate::config::TcpTunnelConfig;
use crate::snapshot::TunnelSnapshot;

/// 单次读写缓冲。
///
/// 与 Go `common.PoolSizeCopy = 32 << 10`（32 KiB）对齐：老 npc 侧
/// `common.CopyBuffer` 用它做 `io.CopyBuffer` 的缓冲区。该值只影响单次
/// `read` 的粒度，不影响正确性（mux 仍按 4085 字节分片）。
const COPY_BUF: usize = 32 * 1024;
/// 停用隧道时等待 accept 任务退出的上限；超时后强制 abort，避免遗留监听器
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
/// 下发给老 npc 的目标拨号超时（Go `conn.defaultTimeOut = 5s`）。
///
/// 老 npc 会把它直接交给 `net.DialTimeout(..., lk.Option.Timeout)`
/// （`client/client.go`），因此该值随 Link JSON 生效。
const TARGET_DIAL_TIMEOUT_NS: i64 = nps_proto::DEFAULT_LINK_TIMEOUT_NS;

/// 计数器自增/自减的 RAII 守卫，保证任何退出路径都不漏减。
struct ActiveGuard(Arc<Tunnel>);

impl ActiveGuard {
    fn new(t: Arc<Tunnel>) -> Self {
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

/// 转发泵的取消守卫。
///
/// `handle_external` 可能被上层 `JoinSet::shutdown` abort；裸 `JoinHandle`
/// 被 Drop 后任务是**分离**而不是取消，读写泵会变成孤儿任务继续持有
/// mux 半边。这里在 Drop 时显式 abort，保证停用/关闭后没有残留任务。
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

/// 把 mux 子流的两个半边合成一个 `AsyncRead + AsyncWrite`，
/// 供 crypt/compress 包装层使用。
///
/// # 为什么不用「每次 poll 新建 future」
///
/// `recv_data` / `send_data` 是 async fn。如果每次 `poll_read` 都新建一个
/// future 再 poll，waker 会注册在**临时** future 上；下次 poll 时旧 future
/// 已被丢弃，注册的唤醒丢失 → 永久挂起（实测表现为传输超时）。
///
/// 这里的做法：把 in-flight future **存起来**，poll 时复用同一个；
/// future 完成后再把 `send`/`recv` 取回。为避免借用冲突，用 `Option::take`。
struct MuxDuplex {
    send: Option<nps_legacy::mux::MuxSendHalf>,
    recv: Option<nps_legacy::mux::MuxRecvHalf>,
    /// 已从子流取出、尚未交给调用方的数据
    pending: Vec<u8>,
    pending_pos: usize,
    read_fut: Option<std::pin::Pin<Box<dyn Future<Output = (nps_legacy::mux::MuxRecvHalf, Option<Vec<u8>>)> + Send>>>,
    write_fut: Option<std::pin::Pin<Box<dyn Future<Output = (nps_legacy::mux::MuxSendHalf, std::io::Result<()>)> + Send>>>,
}

impl MuxDuplex {
    fn new(send: nps_legacy::mux::MuxSendHalf, recv: nps_legacy::mux::MuxRecvHalf) -> Self {
        Self {
            send: Some(send),
            recv: Some(recv),
            pending: Vec::new(),
            pending_pos: 0,
            read_fut: None,
            write_fut: None,
        }
    }
}

impl tokio::io::AsyncRead for MuxDuplex {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.pending_pos < self.pending.len() {
            let n = (self.pending.len() - self.pending_pos).min(buf.remaining());
            let start = self.pending_pos;
            let end = start + n;
            buf.put_slice(&self.pending[start..end]);
            self.pending_pos = end;
            return std::task::Poll::Ready(Ok(()));
        }

        if self.read_fut.is_none() {
            let Some(mut recv) = self.recv.take() else {
                // recv 已被永久取走（EOF 之后），视为流结束
                return std::task::Poll::Ready(Ok(()));
            };
            self.read_fut = Some(Box::pin(async move {
                let data = recv.recv_data().await;
                (recv, data)
            }));
        }

        let fut = self.read_fut.as_mut().expect("刚刚设置");
        match fut.as_mut().poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready((recv, data)) => {
                self.read_fut = None;
                match data {
                    None => {
                        // EOF：不再放回 recv
                        std::task::Poll::Ready(Ok(()))
                    }
                    Some(data) => {
                        self.recv = Some(recv);
                        let n = data.len().min(buf.remaining());
                        buf.put_slice(&data[..n]);
                        if n < data.len() {
                            self.pending = data;
                            self.pending_pos = n;
                        }
                        std::task::Poll::Ready(Ok(()))
                    }
                }
            }
        }
    }
}

impl tokio::io::AsyncWrite for MuxDuplex {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.write_fut.is_none() {
            let Some(mut send) = self.send.take() else {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "mux send half closed",
                )));
            };
            let owned = buf.to_vec();
            self.write_fut = Some(Box::pin(async move {
                let r = send.send_data(&owned).await;
                (send, r)
            }));
        }

        let fut = self.write_fut.as_mut().expect("刚刚设置");
        match fut.as_mut().poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready((send, result)) => {
                self.write_fut = None;
                self.send = Some(send);
                match result {
                    Ok(()) => std::task::Poll::Ready(Ok(buf.len())),
                    Err(e) => std::task::Poll::Ready(Err(e)),
                }
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(send) = self.send.as_mut() {
            send.close();
        }
        std::task::Poll::Ready(Ok(()))
    }
}

/// 运行中的监听任务
struct TunnelRun {
    cancel_tx: watch::Sender<bool>,
    accept_task: JoinHandle<()>,
    bound_addr: Option<std::net::SocketAddr>,
}

/// 一条 TCP 隧道的运行态
pub(crate) struct Tunnel {
    pub cfg: TcpTunnelConfig,
    active_connections: AtomicU64,
    bytes_to_client: AtomicU64,
    bytes_from_client: AtomicU64,
    last_error: Mutex<Option<String>>,
    /// 串行化 enable/disable 操作
    op: Mutex<()>,
    /// 当前运行中的监听任务；`Some` 即"已启用"，内含实际绑定地址
    runtime: Mutex<Option<TunnelRun>>,
    /// 多目标轮询池（含健康检查状态）
    targets: Arc<crate::target::TargetPool>,
    /// 限速（与同客户端其它隧道共享）
    rate: Option<Arc<crate::limit::TokenBucket>>,
    /// 流量上限（与同客户端其它隧道共享）
    flow: Option<Arc<crate::limit::FlowCounter>>,
    /// 来源 IP 白名单
    ip_allow: Arc<crate::limit::IpAllowList>,
    /// crypt 用的 TLS 服务端（启用 crypt 时才有）
    crypt_server: Option<Arc<crate::crypt::CryptServer>>,
    /// 子流包装方式（从**客户端**配置继承，对应原版 `client.Cnf.Crypt/Compress`）
    wrap: crate::crypt::StreamWrap,
}

impl Tunnel {
    /// 简易构造（仅测试用；生产路径走 `with_controls` 以携带流控与包装配置）。
    #[cfg(test)]
    pub fn new(cfg: TcpTunnelConfig) -> Self {
        let spec = cfg.target_addr.clone();
        Self {
            cfg,
            active_connections: AtomicU64::new(0),
            bytes_to_client: AtomicU64::new(0),
            bytes_from_client: AtomicU64::new(0),
            last_error: Mutex::new(None),
            op: Mutex::new(()),
            runtime: Mutex::new(None),
            // 解析失败时退化为单目标池（配置校验已保证 target_addr 合法）
            targets: Arc::new(
                crate::target::TargetPool::parse(&spec)
                    .unwrap_or_else(|_| crate::target::TargetPool::single(&spec)),
            ),
            rate: None,
            flow: None,
            ip_allow: Arc::new(crate::limit::IpAllowList::default()),
            crypt_server: None,
            wrap: crate::crypt::StreamWrap::Plain,
        }
    }

    /// 带上流控与多目标配置构造（由 `server.rs` 使用）。
    pub fn with_controls(
        cfg: TcpTunnelConfig,
        targets: Arc<crate::target::TargetPool>,
        rate: Option<Arc<crate::limit::TokenBucket>>,
        flow: Option<Arc<crate::limit::FlowCounter>>,
        ip_allow: Arc<crate::limit::IpAllowList>,
        wrap: crate::crypt::StreamWrap,
    ) -> Self {
        Self {
            cfg,
            active_connections: AtomicU64::new(0),
            bytes_to_client: AtomicU64::new(0),
            bytes_from_client: AtomicU64::new(0),
            last_error: Mutex::new(None),
            op: Mutex::new(()),
            runtime: Mutex::new(None),
            targets,
            rate,
            flow,
            ip_allow,
            crypt_server: if matches!(wrap, crate::crypt::StreamWrap::Crypt) {
                crate::crypt::CryptServer::new().ok()
            } else {
                None
            },
            wrap,
        }
    }

    pub fn id(&self) -> u32 {
        self.cfg.id
    }

    /// 记录最近错误（只留文本，不含密钥）
    async fn set_error(&self, msg: impl Into<String>) {
        *self.last_error.lock().await = Some(msg.into());
    }

    async fn clear_error(&self) {
        *self.last_error.lock().await = None;
    }

    /// 用持久化的累计流量初始化计数器（启动时调用，只应调用一次）。
    ///
    /// 计数器后续用 `fetch_add` 累加，恢复初值后新流量会自然叠加。
    pub fn restore_bytes(&self, to_client: u64, from_client: u64) {
        self.bytes_to_client.store(to_client, Ordering::Relaxed);
        self.bytes_from_client.store(from_client, Ordering::Relaxed);
    }

    /// 当前累计流量 `(to_client, from_client)`，用于持久化。
    pub fn bytes(&self) -> (u64, u64) {
        (
            self.bytes_to_client.load(Ordering::Relaxed),
            self.bytes_from_client.load(Ordering::Relaxed),
        )
    }

    pub(crate) async fn snapshot(&self) -> TunnelSnapshot {
        // 一次持锁读出「是否监听 + 实际地址」，避免两次读取之间的状态漂移
        let (enabled, bound_addr) = {
            let runtime = self.runtime.lock().await;
            match runtime.as_ref() {
                Some(run) => (true, run.bound_addr.map(|a| a.to_string())),
                None => (false, None),
            }
        };
        TunnelSnapshot {
            id: self.cfg.id,
            name: self.cfg.name.clone(),
            client_id: self.cfg.client_id,
            listen_addr: self.cfg.listen_addr.clone(),
            target_addr: self.cfg.target_addr.clone(),
            enabled,
            active_connections: self.active_connections.load(Ordering::Relaxed),
            bytes_to_client: self.bytes_to_client.load(Ordering::Relaxed),
            bytes_from_client: self.bytes_from_client.load(Ordering::Relaxed),
            targets: self
                .targets
                .all_targets()
                .into_iter()
                .map(|t| {
                    let healthy = !self.targets.is_offline(&t);
                    crate::snapshot::TargetHealth { target: t, healthy }
                })
                .collect(),
            last_error: self.last_error.lock().await.clone(),
            bound_addr,
        }
    }

    /// 当前是否有**活跃**的监听任务（供配置文件模式的状态查询使用）。
    ///
    /// accept 任务异常自行退出时返回 false（与快照口径一致）。
    pub(crate) async fn is_listening(&self) -> bool {
        let runtime = self.runtime.lock().await;
        runtime
            .as_ref()
            .is_some_and(|run| !run.accept_task.is_finished())
    }

    /// 绑定监听器。绑定失败不影响既有状态（调用方负责顺序）。
    pub(crate) async fn bind(&self) -> Result<TcpListener> {
        TcpListener::bind(&self.cfg.listen_addr)
            .await
            .with_context(|| {
                format!(
                    "隧道 {} ({}) 无法监听 {}",
                    self.cfg.id, self.cfg.name, self.cfg.listen_addr
                )
            })
    }

    /// 用已绑定的监听器启动转发循环（调用方需持有 `op` 锁）。
    ///
    /// 先起任务、再登记 runtime：登记完成即代表"已启用"，此前 `snapshot`
    /// 看到的仍是未启用状态，不会出现"已启用但监听器还没跑"的假象。
    async fn run_with(self: &Arc<Self>, bridge: Bridge, listener: TcpListener) {
        let bound_addr = listener.local_addr().ok();
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let this = self.clone();
        let accept_task = tokio::spawn(async move {
            this.accept_loop(bridge, listener, cancel_rx).await;
        });
        // 防御：正常路径上 `enable` 已先 `stop()`，但若仍有残留运行项，
        // 必须取消它，否则会留下两个监听循环（端口重复绑定 / 双入口）。
        let stale = self.runtime.lock().await.replace(TunnelRun {
            cancel_tx,
            accept_task,
            bound_addr,
        });
        if let Some(previous) = stale {
            warn!("隧道 {} 发现残留监听任务，取消旧实例", self.cfg.id);
            let _ = previous.cancel_tx.send(true);
            previous.accept_task.abort();
        }
        if let Some(a) = bound_addr {
            info!("隧道 {} ({}) 监听 {}", self.cfg.id, self.cfg.name, a);
        }
    }

    /// 停止监听：关闭监听器，并关闭该隧道现存转发连接。
    ///
    /// `runtime` 先摘除再等待任务退出：期间 `is_enabled()` 立刻为 false，
    /// 端口在 accept 任务真正退出后释放。若等待超时则显式 abort，
    /// 保证不会遗留孤儿监听器。
    async fn stop(&self) {
        let run = self.runtime.lock().await.take();
        if let Some(run) = run {
            // receiver 可能已随任务退出而消失，忽略发送错误
            let _ = run.cancel_tx.send(true);
            let mut accept_task = run.accept_task;
            match tokio::time::timeout(STOP_TIMEOUT, &mut accept_task).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!("隧道 {} accept 任务异常: {e}", self.cfg.id),
                Err(_) => {
                    // 超时：任务可能卡在某个不响应取消的步骤。显式 abort 并等它
                    // 落地，确保监听器与连接任务都被回收（不会留下孤儿监听器）。
                    warn!("隧道 {} accept 任务停止超时，强制终止", self.cfg.id);
                    accept_task.abort();
                    let _ = accept_task.await;
                }
            }
        }
        // 注意：**不**在这里把 active_connections 清零。
        // 计数由 ActiveGuard 拥有，强行清零会与守卫的并发自减相撞导致下溢。
        // 连接任务的 JoinSet 在 accept_loop 退出时已 shutdown，计数会自然归零；
        // 这里做一次有界等待，让"停用返回时计数为 0"成为可依赖的语义。
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            let active = self.active_connections.load(Ordering::Relaxed);
            if active == 0 {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                warn!(
                    "隧道 {} 停用后仍有 {active} 条连接未退出（计数保持真实值，不强行清零）",
                    self.cfg.id
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// accept 循环。退出时关闭所有在跑的转发连接。
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
                            let t = self.clone();
                            let b = bridge.clone();
                            let c = cancel.clone();
                            conns.spawn(async move {
                                t.handle_external(b, stream, peer, c).await;
                            });
                        }
                        Err(e) => {
                            warn!("隧道 {} accept 失败: {e}", self.cfg.id);
                            self.set_error(format!("accept 失败: {e}")).await;
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }
        // 关闭该隧道现存连接
        conns.shutdown().await;
        debug!("隧道 {} accept 循环退出", self.cfg.id);
    }

    /// 处理一条外部连接
    async fn handle_external(
        self: Arc<Self>,
        bridge: Bridge,
        stream: TcpStream,
        peer: std::net::SocketAddr,
        cancel: watch::Receiver<bool>,
    ) {
        let _guard = ActiveGuard::new(self.clone());
        if *cancel.borrow() {
            return;
        }

        // ---- 准入检查：IP 白名单 → 流量上限 ----
        // 必须在建 mux 流之前做，否则超限请求会白白消耗 npc 侧的目标连接。
        if !self.ip_allow.allows(peer.ip()) {
            debug!("隧道 {}: 拒绝未授权来源 IP {}", self.cfg.id, peer.ip());
            return;
        }
        if let Some(flow) = &self.flow {
            if flow.exceeded() {
                self.set_error("客户端流量已超限").await;
                warn!(
                    "隧道 {}: 客户端 {} 流量超限，拒绝来自 {} 的连接",
                    self.cfg.id, self.cfg.client_id, peer
                );
                return;
            }
        }

        // 目标客户端离线 → 直接关闭外部连接，记录原因，不 panic
        let mux = match bridge.get_tunnel(self.cfg.client_id).await {
            Some(m) => m,
            None => {
                self.set_error(format!(
                    "客户端 {} 离线，无法建立隧道连接",
                    self.cfg.client_id
                ))
                .await;
                debug!(
                    "隧道 {}: 客户端 {} 离线，拒绝来自 {} 的连接",
                    self.cfg.id, self.cfg.client_id, peer
                );
                return;
            }
        };

        let mux_stream = match mux.open_stream().await {
            Ok(s) => s,
            Err(e) => {
                self.set_error(format!("mux 建流失败: {e}")).await;
                warn!("隧道 {}: mux 建流失败: {e}", self.cfg.id);
                return;
            }
        };

        let (mut send, recv) = mux_stream.into_split();

        // 发送 Link 信息：int32 LE 长度 + JSON（对齐 Go `SendInfo(link, "")`）。
        // Link 帧是本次子流的第一帧，随后立即开始双向转发，不插入其他帧，
        // 因此不会吞掉首帧数据。
        // 多目标轮询：全离线时直接关闭外部连接（对应原版
        // `all inward-bending targets are offline`）
        let target = match self.targets.next() {
            Ok(target) => target,
            Err(e) => {
                self.set_error(format!("无可用目标: {e}")).await;
                warn!("隧道 {}: 无可用目标（{e}），拒绝来自 {} 的连接", self.cfg.id, peer);
                return;
            }
        };
        let mut link = nps_proto::Link::tcp(target, peer.to_string());
        link.option.timeout = TARGET_DIAL_TIMEOUT_NS;
        // crypt 优先于 compress（对齐 Go GetConn 的 if/else if）
        let wrap = self.wrap;
        link.crypt = matches!(wrap, crate::crypt::StreamWrap::Crypt);
        link.compress = matches!(wrap, crate::crypt::StreamWrap::Compress);
        let link_json = match serde_json::to_vec(&link) {
            Ok(v) => v,
            Err(e) => {
                self.set_error(format!("Link 序列化失败: {e}")).await;
                send.close();
                return;
            }
        };
        let mut frame = Vec::with_capacity(4 + link_json.len());
        frame.extend_from_slice(&(link_json.len() as i32).to_le_bytes());
        frame.extend_from_slice(&link_json);
        if let Err(e) = send.send_data(&frame).await {
            self.set_error(format!("发送 Link 失败: {e}")).await;
            warn!("隧道 {}: 发送 Link 失败: {e}", self.cfg.id);
            send.close();
            return;
        }

        self.clear_error().await;
        debug!(
            "隧道 {}: {} -> {} 已建立（wrap={:?}）",
            self.cfg.id, peer, self.cfg.target_addr, wrap
        );

        // ---- 子流包装 ----
        //
        // 顺序很重要：Link 首帧必须**以明文**发出（npc 先读 Link 再决定
        // 是否建包装层），包装只作用于其后的业务数据。
        match wrap {
            crate::crypt::StreamWrap::Crypt => {
                let Some(server) = &self.crypt_server else {
                    self.set_error("crypt 已启用但 TLS 服务端不可用").await;
                    warn!("隧道 {}: crypt 已启用但 TLS 服务端未初始化", self.cfg.id);
                    send.close();
                    return;
                };
                // 服务端是 TLS server，npc 是 TLS client
                debug!("隧道 {}: 开始 crypt TLS 握手", self.cfg.id);
                let tls = match server.accept(MuxDuplex::new(send, recv)).await {
                    Ok(tls) => tls,
                    Err(e) => {
                        self.set_error(format!("crypt 握手失败: {e:#}")).await;
                        warn!("隧道 {}: crypt 握手失败: {e:#}", self.cfg.id);
                        return;
                    }
                };
                debug!("隧道 {}: crypt 握手完成，开始转发", self.cfg.id);
                self.run_wrapped(stream, tls, cancel).await;
                return;
            }
            crate::crypt::StreamWrap::Compress => {
                let io = crate::crypt::SnappyStream::new(MuxDuplex::new(send, recv));
                self.run_wrapped(stream, io, cancel).await;
                return;
            }
            crate::crypt::StreamWrap::Plain => {}
        }

        let (ext_r, ext_w) = stream.into_split();
        // 两个方向各自独立任务推进，避免全双工会死锁。
        //
        // 连接生命周期对齐 Go 原版 `copyConnGroup`：任一方向结束即终止另一方向，
        // 最后一个半边 Drop 时向 npc 发 `ConnClose`，npc 才会关闭它到目标的连接并
        // 释放整条子流。Go 的 `CopyBuffer` 在源端 EOF 时返回 `io.EOF`（非 nil），
        // `copyConnGroup` 因此关闭 mux 与外部两端——不发 ConnClose 会让对端目标
        // 连接永久悬挂，外部连接计数无法归零。
        //
        // 注意：旧协议没有独立的半关闭帧，因此这里放弃了「外部 EOF 后继续等响应」
        // 的优化；真正的 TCP 半关闭留给后续新协议。
        //
        // 泵用 `Pump` 持有：即便本函数被 abort（停用/关闭时的 JoinSet::shutdown），
        // 两个任务也会被 Drop 时 abort，不会变成孤儿继续占用 mux 半边。
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
        // 每个 JoinHandle 只 poll 一次：先找出先结束的一侧，abort 另一侧并等它
        // 落地（被 abort 的不会留下继续读写 mux 的孤儿任务）。两侧的
        // `MuxSendHalf` / `MuxRecvHalf` 因此都在本函数返回前 Drop，
        // `StreamState::drop` 才有机会向 npc 发出 ConnClose。
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
        debug!("隧道 {}: {} 连接结束", self.cfg.id, peer);
    }

    /// 在已包装的子流上跑双向转发。
    ///
    /// # 为什么用「单任务 select!」而不是 `tokio::io::split` + 两个 spawn
    ///
    /// `tokio::io::split` 内部用 `BiLock`：读半与写半共享同一把锁。
    /// 对 `TlsStream` 这种「读时要能写、写时要能读」的协议（TLS 有握手/告警帧、
    /// snappy 有块边界）会互相阻塞。实测表现为：TLS 握手成功，
    /// 但之后 30 秒内双向零字节（死锁），随后连接超时被关。
    ///
    /// 改为单任务内 `select!` 双向推进：读外部 → 写包装流，读包装流 → 写外部。
    /// 两个方向都在同一任务里，不存在锁竞争。
    async fn run_wrapped<W>(
        self: Arc<Self>,
        stream: TcpStream,
        mut wrapped: W,
        mut cancel: watch::Receiver<bool>,
    ) where
        W: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (mut ext_r, mut ext_w) = stream.into_split();
        let mut ext_buf = vec![0u8; COPY_BUF];
        let mut wrap_buf = vec![0u8; COPY_BUF];
        let mut ext_open = true;
        let mut wrap_open = true;

        loop {
            if *cancel.borrow() {
                break;
            }

            tokio::select! {
                biased;

                _ = cancel.changed() => break,

                // 上行：外部 -> 包装流（仅在外部仍开时读）
                r = ext_r.read(&mut ext_buf), if ext_open => {
                    match r {
                        Ok(0) => {
                            ext_open = false;
                            // 外部 EOF：半关闭包装流的写侧
                            let _ = wrapped.shutdown().await;
                            if !wrap_open { break; }
                        }
                        Ok(n) => {
                            if let Some(rate) = &self.rate {
                                rate.acquire(n).await;
                            }
                            if wrapped.write_all(&ext_buf[..n]).await.is_err() {
                                break;
                            }
                            let _ = wrapped.flush().await;
                            self.bytes_to_client.fetch_add(n as u64, Ordering::Relaxed);
                            if let Some(flow) = &self.flow {
                                flow.add(n as u64, 0);
                            }
                        }
                        Err(_) => {
                            ext_open = false;
                            if !wrap_open { break; }
                        }
                    }
                }

                // 下行：包装流 -> 外部（仅在包装流仍开时读）
                r = wrapped.read(&mut wrap_buf), if wrap_open => {
                    match r {
                        Ok(0) => {
                            wrap_open = false;
                            if !ext_open { break; }
                        }
                        Ok(n) => {
                            if let Some(rate) = &self.rate {
                                rate.acquire(n).await;
                            }
                            if ext_w.write_all(&wrap_buf[..n]).await.is_err() {
                                break;
                            }
                            let _ = ext_w.flush().await;
                            self.bytes_from_client.fetch_add(n as u64, Ordering::Relaxed);
                            if let Some(flow) = &self.flow {
                                flow.add(0, n as u64);
                            }
                        }
                        Err(_) => {
                            wrap_open = false;
                            if !ext_open { break; }
                        }
                    }
                }
            }
        }

        let _ = ext_w.shutdown().await;
        debug!("隧道 {}: 包装连接结束", self.cfg.id);
    }

    /// 外部 -> mux（计入 `bytes_to_client`）
    async fn pump_ext_to_mux(
        mut reader: OwnedReadHalf,
        mut send: MuxSendHalf,
        tunnel: Arc<Tunnel>,
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
                        debug!("隧道 {}: 读取外部连接失败: {e}", tunnel.cfg.id);
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
                debug!("隧道 {}: 写 mux 失败（客户端可能已断开）", tunnel.cfg.id);
                break;
            }
            tunnel
                .bytes_to_client
                .fetch_add(n as u64, Ordering::Relaxed);
            if let Some(flow) = &tunnel.flow {
                flow.add(n as u64, 0);
            }
        }
        // 半关闭：告知 npc 外部不再发送数据
        send.close();
    }

    /// mux -> 外部（计入 `bytes_from_client`）
    async fn pump_mux_to_ext(
        mut recv: MuxRecvHalf,
        mut writer: OwnedWriteHalf,
        tunnel: Arc<Tunnel>,
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
                debug!("隧道 {}: 写外部连接失败", tunnel.cfg.id);
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

    /// 用已绑定的监听器启动转发循环（server::start 原子启动阶段使用）
    pub(crate) async fn start_with_listener(
        self: &Arc<Self>,
        bridge: Bridge,
        listener: TcpListener,
    ) {
        self.run_with(bridge, listener).await;
    }

    /// 启用（调用方需持有 `op` 锁）。
    ///
    /// 幂等：已在运行时直接返回。绑定失败会记录 `last_error` 并把错误返回给
    /// 调用方；监听器在失败时随作用域释放，不会留下半开端口。
    pub(crate) async fn enable(self: &Arc<Self>, bridge: Bridge) -> Result<()> {
        // 已有一个**仍在运行**的 accept 任务：幂等返回，绝不重复绑定端口。
        let running = {
            let runtime = self.runtime.lock().await;
            runtime
                .as_ref()
                .is_some_and(|run| !run.accept_task.is_finished())
        };
        if running {
            return Ok(());
        }
        // accept 任务已自行退出（异常）时 runtime 可能是残留项：先清理，
        // 否则会留下"显示已启用、实际没有监听器"的假状态。
        self.stop().await;

        let listener = match self.bind().await {
            Ok(listener) => listener,
            Err(e) => {
                self.set_error(format!("监听失败: {e}")).await;
                return Err(e);
            }
        };
        self.run_with(bridge, listener).await;
        Ok(())
    }

    /// 停用（调用方需持有 `op` 锁）
    pub(crate) async fn disable(&self) {
        self.stop().await;
    }

    pub(crate) async fn lock_op(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.op.lock().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TcpTunnelConfig;

    fn cfg() -> TcpTunnelConfig {
        TcpTunnelConfig {
            id: 1,
            name: "t".into(),
            client_id: 1,
            listen_addr: "127.0.0.1:0".into(),
            target_addr: "127.0.0.1:22".into(),
            enabled: true,
            target_addrs: Vec::new(),
            health_check: None,
        }
    }

    /// 连接计数完全由守卫驱动：100 次增减后必须归零。
    #[test]
    fn active_guard_returns_to_zero_after_100_cycles() {
        let t = Arc::new(Tunnel::new(cfg()));
        for _ in 0..100 {
            let _g = ActiveGuard::new(t.clone());
        }
        assert_eq!(t.active_connections.load(Ordering::Relaxed), 0);
    }

    /// 即便有人在守卫存活期间误清零，递减也只能停在 0（旧实现会回绕成
    /// u64::MAX）；这条用例锁住饱和语义。
    #[test]
    fn active_guard_saturates_at_zero_and_never_underflows() {
        let t = Arc::new(Tunnel::new(cfg()));
        let g = ActiveGuard::new(t.clone());
        t.active_connections.store(0, Ordering::Relaxed);
        drop(g);
        assert_eq!(t.active_connections.load(Ordering::Relaxed), 0);
    }

    /// 下发给 npc 的拨号超时必须是 Go `defaultTimeOut` 的 5s（纳秒表示）。
    #[test]
    fn dial_timeout_matches_go_default_and_reaches_the_wire() {
        assert_eq!(TARGET_DIAL_TIMEOUT_NS, 5_000_000_000);
        assert_eq!(TARGET_DIAL_TIMEOUT_NS, nps_proto::DEFAULT_LINK_TIMEOUT_NS);

        let mut link = nps_proto::Link::tcp("127.0.0.1:22", "127.0.0.1:5555");
        link.option.timeout = TARGET_DIAL_TIMEOUT_NS;
        let value = serde_json::to_value(&link).unwrap();
        // 老 npc 用 net.DialTimeout(..., lk.Option.Timeout) 消费该字段
        assert_eq!(value["Option"]["Timeout"], 5_000_000_000i64);
    }

    /// 读缓冲与 Go `common.PoolSizeCopy` 一致（32 KiB），只影响 read 粒度。
    #[test]
    fn copy_buf_matches_go_pool_size_copy() {
        assert_eq!(COPY_BUF, 32 * 1024);
    }

    /// `STOP_TIMEOUT` 必须是有限上界（用于 stop 等待 accept 任务）；
    /// 真正的"超时就强制 abort"行为由集成测试
    /// `disable_with_live_connections_returns_quickly` 覆盖。
    #[test]
    fn stop_timeout_is_a_finite_bound() {
        assert!(!STOP_TIMEOUT.is_zero());
        assert!(STOP_TIMEOUT <= Duration::from_secs(30));
    }
}
