//! UDP 隧道转发：外部 UDP 数据报 -> mux 子流 -> 老 npc 拨号内网 UDP 目标。
//!
//! 对齐 Go `server/proxy/udp.go` 的数据面语义：
//! ```text
//! 外部 UDP socket --recv_from--> nps-server 监听端口
//!   ├─ 按「来源地址 addr.String()」1:1 映射一条 mux 子流（等价 addrMap）
//!   ├─ 命中：直接把原始 UDP 载荷写进子流（无任何封装头）
//!   ├─ 未命中：bridge.get_tunnel(client_id) -> open_stream()
//!   │          首帧 int32 LE 长度 + Link JSON（ConnType="udp"）
//!   │          写首包 -> 独立回写任务 socket.send_to(chunk, addr)
//!   └─ 子流空闲 10 分钟（可配置）回收映射与计数
//! 老 npc 收到 ConnType="udp" 会 net.DialTimeout("udp", lk.Host, ...)，
//! 并把子流字节直接当 UDP 载荷发给目标（双向对拷）。
//! ```
//!
//! ## 并发模型（UDP 数据报绝不能阻塞整个端口）
//! - 主 [`UdpTunnel::recv_loop`] 只做无阻塞操作：`recv_from`、查映射、`try_send`、
//!   CAS 预留名额。建流（`open_stream` 可能要等对端确认，最长 120s）放在独立任务，
//!   绝不出现在 recv 路径上。
//! - 每个来源地址一个有界 `mpsc` 队列（默认 [`DEFAULT_PER_FLOW_QUEUE`]）：慢子流只让
//!   自己的队列溢出丢包，不拖住 recv 循环，也不影响其他来源。
//! - 每流两个独立任务（up：队列->mux，down：mux->socket）；任一方向结束即 abort
//!   另一方向，两个半边在函数返回时 Drop，从而向 npc 发 `ConnClose`。
//! - 映射表用 tokio `Mutex` 正常 `.await` 加锁，**没有** `try_lock` 后跳过清理的模式；
//!   条目以 `Arc<FlowEntry>` + `Arc::ptr_eq` 做代际校验，避免超时回收误删「同地址
//!   刚重建」的新流。
//! - 名额用 CAS 预留（[`FlowReservation`]）+ RAII 归还：建流失败、任务被 abort、
//!   空闲回收等任何退出路径都把计数还回 0，不会泄漏也不会下溢。
//!
//! ## 与现有架构的关系
//! 本模块是**独立可装配**的 UDP 数据面：复用 `Bridge::get_tunnel` / `open_stream`
//! 与 `Link` 序列化（帧格式与 TCP 侧 `tunnel.rs` 完全一致），但**不依赖** `Tunnel`
//! 结构（其字段是 `pub(crate)` 且正由其它代理改动）。计数风格对齐 `ActiveGuard`：
//! RAII 保证活跃流数最终归零。快照复用 [`TunnelSnapshot`] 契约，父代理可原样接进
//! `Server::snapshot`。
//!
//! ## 大包会被分片（与原版一致）
//! mux 单帧上限 4085 字节，原版 Go 服务端下行还用 1672 字节（`PoolSizeUdp`）缓冲读取，
//! 因此 **一条超过 4085 字节的 UDP 数据报会被拆成多个数据报**送达/回传。本实现同样
//! 以 [`UDP_WRITE_CHUNK`]（1672，对齐 Go）分块写回。验证时对小包校验「单数据报
//! 逐字节一致」，大包校验「拼接后逐字节一致」。

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use nps_legacy::Bridge;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, info, warn};

use crate::config::UdpTunnelConfig;
use crate::snapshot::TunnelSnapshot;

/// 子流空闲回收默认值。对齐 Go `SetReadDeadline(time.Now().Add(time.Minute * 10))`。
///
/// 实际值由 [`UdpTunnelConfig::idle_timeout_secs`] 决定，这里只是默认常量。
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// 单隧道默认最大并发子流数，对齐 mux 的 `MAX_STREAMS = 512`。
pub const DEFAULT_MAX_FLOWS: usize = 512;
/// 每流默认有界队列深度（数据报个数）。慢子流超过即丢包并记日志。
pub const DEFAULT_PER_FLOW_QUEUE: usize = 256;
/// 每流排队字节上限（默认 256 KiB）。数据报个数上限之外再加一道字节水位，
/// 防止「256 × 64 KiB ≈ 16 MiB / 流」的内存放大；总上限 ≈ 512 × 256 KiB。
pub const DEFAULT_PER_FLOW_BYTES: usize = 256 * 1024;
/// 单次 `recv_from` 缓冲。对齐 Go `common.PoolSize`（64 KiB），可容纳 65507 字节
/// 的最大 UDP 载荷。
pub const UDP_RECV_BUF: usize = 64 * 1024;
/// 下行写回的单块上限。对齐 Go `common.PoolSizeUdp`（1472 + 200 = 1672）：
/// 原版就是按这个缓冲 `Read` 后 `WriteTo`，所以一条大包在线上也是这个粒度的分片。
pub const UDP_WRITE_CHUNK: usize = 1472 + 200;
/// 空闲检查间隔（1s）：回收精度足够，开销可忽略。
const IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(1);
/// 下发给 npc 的拨号超时（Go `conn.defaultTimeOut = 5s`）。
const TARGET_DIAL_TIMEOUT_NS: i64 = nps_proto::DEFAULT_LINK_TIMEOUT_NS;
/// 关闭时等待后台任务退出的上限。
const STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// 每个来源地址对应的子流发送句柄。
struct FlowEntry {
    /// 有界队列：recv 循环只 `try_send`，慢流只丢自己的包
    send: mpsc::Sender<Vec<u8>>,
    /// 最近一次活动（上行命中 / 下行响应）的毫秒时间戳
    last_active: Arc<AtomicU64>,
    /// 已入队但未被子流消费的字节数（近似值：并发下允许短暂超采，仅用于限流）
    queued_bytes: Arc<AtomicU64>,
    /// 每流排队字节上限
    max_queued_bytes: usize,
}

/// 并发名额的 RAII 守卫。
///
/// 名额在「检查上限 → spawn 建流任务」之间就用 CAS 预留，避免多个建流任务并发
/// 通过上限检查导致超限；任务结束（成功/失败/被 abort）时饱和归还，计数不泄漏。
struct FlowReservation {
    counter: Arc<AtomicU64>,
}

impl FlowReservation {
    fn try_acquire(counter: &Arc<AtomicU64>, max: usize) -> Option<Self> {
        counter
            .try_update(Ordering::AcqRel, Ordering::Relaxed, |v| {
                if v < max as u64 {
                    Some(v + 1)
                } else {
                    None
                }
            })
            .ok()
            .map(|_| Self {
                counter: counter.clone(),
            })
    }
}

impl Drop for FlowReservation {
    fn drop(&mut self) {
        // 饱和自减：即使外部误清零也只会停在 0，不会回绕成 u64::MAX
        let _ = self
            .counter
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }
}

/// 转发任务的取消守卫。
///
/// 裸 `JoinHandle` 被 Drop 后任务是**分离**而不是取消，读写泵会变孤儿继续持有
/// mux 半边；这里显式 abort，保证停用/关闭后没有残留任务。
struct Pump(JoinHandle<()>);

impl Pump {
    fn new(task: JoinHandle<()>) -> Self {
        Self(task)
    }
}

impl Drop for Pump {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// 运行中的 UDP 监听任务。
struct UdpRun {
    cancel: watch::Sender<bool>,
    task: JoinHandle<()>,
    bound_addr: SocketAddr,
}

/// 一条 UDP 隧道的运行态。
pub struct UdpTunnel {
    /// 复用 `config.rs` 的配置类型（父代理已追加 `udp_tunnels` / `idle_timeout_secs`
    /// / `max_sessions`，本模块不再自定义重复类型）
    pub cfg: UdpTunnelConfig,
    idle_timeout: Duration,
    max_flows: usize,
    per_flow_queue: usize,
    /// 每流排队字节上限（见 [`DEFAULT_PER_FLOW_BYTES`]）
    per_flow_bytes: usize,
    /// 当前活跃子流数（含正在建流的名额），只由 [`FlowReservation`] 增减
    active_flows: Arc<AtomicU64>,
    /// 外部 UDP -> mux 累计字节（Go `Flow.Add(len, 0)`）
    bytes_to_client: Arc<AtomicU64>,
    /// mux -> 外部 UDP 累计字节（Go `Flow.Add(0, n)`）
    bytes_from_client: Arc<AtomicU64>,
    last_error: Mutex<Option<String>>,
    /// `Some` 即「已启用」，内含实际绑定地址
    runtime: Mutex<Option<UdpRun>>,
}

impl UdpTunnel {
    /// 用配置里的 `idle_timeout_secs` / `max_sessions` 构建。
    pub fn new(cfg: UdpTunnelConfig) -> Self {
        let idle = Duration::from_secs(cfg.idle_timeout_secs.max(1));
        let max = cfg.max_sessions.max(1);
        Self::with_limits(cfg, idle, max, DEFAULT_PER_FLOW_QUEUE)
    }

    /// 自定义上限与超时，供测试 / 特殊部署使用。
    pub fn with_limits(
        cfg: UdpTunnelConfig,
        idle_timeout: Duration,
        max_flows: usize,
        per_flow_queue: usize,
    ) -> Self {
        Self {
            cfg,
            idle_timeout: idle_timeout.max(Duration::from_millis(1)),
            max_flows: max_flows.max(1),
            per_flow_queue: per_flow_queue.max(1),
            per_flow_bytes: DEFAULT_PER_FLOW_BYTES,
            active_flows: Arc::new(AtomicU64::new(0)),
            bytes_to_client: Arc::new(AtomicU64::new(0)),
            bytes_from_client: Arc::new(AtomicU64::new(0)),
            last_error: Mutex::new(None),
            runtime: Mutex::new(None),
        }
    }

    pub fn id(&self) -> u32 {
        self.cfg.id
    }

    /// 当前活跃子流数（快照与测试用）。
    pub fn active_flows(&self) -> u64 {
        self.active_flows.load(Ordering::Relaxed)
    }

    /// `(上行字节, 下行字节)`。
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

    /// 快照，复用现有 [`TunnelSnapshot`] 契约（字段一致，父代理可直接接进 Web 层）。
    pub async fn snapshot(&self) -> TunnelSnapshot {
        let runtime = self.runtime.lock().await;
        let (enabled, bound_addr) = match runtime.as_ref() {
            Some(run) => (true, Some(run.bound_addr.to_string())),
            None => (false, None),
        };
        TunnelSnapshot {
            id: self.cfg.id,
            name: self.cfg.name.clone(),
            client_id: self.cfg.client_id,
            listen_addr: self.cfg.listen_addr.clone(),
            target_addr: self.cfg.target_addr.clone(),
            enabled,
            active_connections: self.active_flows(),
            bytes_to_client: self.bytes_to_client.load(Ordering::Relaxed),
            bytes_from_client: self.bytes_from_client.load(Ordering::Relaxed),
            last_error: self.last_error.lock().await.clone(),
            bound_addr,
        }
    }

    /// 当前是否有正在运行的监听任务。
    pub async fn is_listening(&self) -> bool {
        let runtime = self.runtime.lock().await;
        runtime
            .as_ref()
            .is_some_and(|run| !run.task.is_finished())
    }

    /// 绑定 UDP 端口，支持 `:0` 由系统分配。
    pub async fn bind(&self) -> Result<UdpSocket> {
        UdpSocket::bind(&self.cfg.listen_addr).await.with_context(|| {
            format!(
                "UDP 隧道 {} ({}) 无法监听 {}",
                self.cfg.id, self.cfg.name, self.cfg.listen_addr
            )
        })
    }

    /// 绑定并启动转发循环，返回实际绑定地址。
    pub async fn start(self: &Arc<Self>, bridge: Bridge) -> Result<SocketAddr> {
        let socket = self.bind().await?;
        self.start_with_socket(bridge, socket).await
    }

    /// 用已绑定的 socket 启动（测试 / 父代理原子启动阶段使用）。
    ///
    /// 先起任务再登记 runtime：登记完成即代表「已启用」，不会出现
    /// 「显示已启用但没有监听器」的中间态。
    pub async fn start_with_socket(
        self: &Arc<Self>,
        bridge: Bridge,
        socket: UdpSocket,
    ) -> Result<SocketAddr> {
        let bound_addr = socket.local_addr().context("读取 UDP 实际绑定地址失败")?;
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let this = self.clone();
        let task = tokio::spawn(async move {
            this.recv_loop(bridge, socket, cancel_rx).await;
        });
        let stale = self.runtime.lock().await.replace(UdpRun {
            cancel: cancel_tx,
            task,
            bound_addr,
        });
        if let Some(previous) = stale {
            warn!("UDP 隧道 {} 发现残留监听任务，取消旧实例", self.cfg.id);
            let _ = previous.cancel.send(true);
            previous.task.abort();
        }
        info!(
            "UDP 隧道 {} ({}) 监听 {} -> {}",
            self.cfg.id, self.cfg.name, bound_addr, self.cfg.target_addr
        );
        Ok(bound_addr)
    }

    /// 主接收循环：只做无阻塞操作，永不因慢子流停滞。
    async fn recv_loop(
        self: Arc<Self>,
        bridge: Bridge,
        socket: UdpSocket,
        mut cancel: watch::Receiver<bool>,
    ) {
        let socket = Arc::new(socket);
        let flows: Arc<Mutex<HashMap<SocketAddr, Arc<FlowEntry>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let pending: Arc<Mutex<HashSet<SocketAddr>>> = Arc::new(Mutex::new(HashSet::new()));
        let mut tasks: JoinSet<()> = JoinSet::new();
        let mut buf = vec![0u8; UDP_RECV_BUF];

        loop {
            let (n, addr) = tokio::select! {
                _ = cancel.changed() => break,
                r = socket.recv_from(&mut buf) => match r {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("UDP 隧道 {} recv_from 失败: {e}", self.cfg.id);
                        self.set_error(format!("recv_from 失败: {e}")).await;
                        continue;
                    }
                },
            };
            let data = buf[..n].to_vec();

            // ① 命中映射：刷新活跃时间，非阻塞入队
            let existing = flows.lock().await.get(&addr).cloned();
            if let Some(entry) = existing {
                touch(&entry.last_active);
                enqueue(&entry, data, self.cfg.id, addr);
                continue;
            }

            // ② 该地址正在建流：UDP 允许丢包，直接丢弃以避免重复建流
            {
                if !pending.lock().await.insert(addr) {
                    continue;
                }
            }

            // ③ CAS 预留名额（含建流中的流），超限丢弃并记日志
            let Some(reservation) =
                FlowReservation::try_acquire(&self.active_flows, self.max_flows)
            else {
                warn!(
                    "UDP 隧道 {} 并发流已达上限 {}，丢弃来自 {addr} 的数据报",
                    self.cfg.id, self.max_flows
                );
                pending.lock().await.remove(&addr);
                continue;
            };

            // ④ 建流放到独立任务：绝不阻塞 recv 循环
            let this = self.clone();
            let tunnel_id = self.cfg.id;
            let b = bridge.clone();
            let f = flows.clone();
            let p = pending.clone();
            let s = socket.clone();
            let c = cancel.clone();
            tasks.spawn(async move {
                let result = this
                    .establish_and_run(b, addr, data, f, s, c, reservation)
                    .await;
                // 无论成功失败都清掉「建流中」标记（正常 .await，不用 try_lock）
                p.lock().await.remove(&addr);
                if let Err(e) = result {
                    debug!("UDP 隧道 {tunnel_id} 来源 {addr} 建流结束: {e:#}");
                }
            });

            // 顺手回收已结束的建流任务，避免 JoinSet 无限增长
            while let Some(joined) = tasks.try_join_next() {
                if let Err(e) = joined {
                    warn!("UDP 隧道 {} 建流任务异常: {e}", self.cfg.id);
                }
            }
        }

        // 退出：取消所有建流任务并清空映射
        // （计数由各任务的 Reservation Drop 归零，不在此强行清零）
        tasks.shutdown().await;
        flows.lock().await.clear();
        pending.lock().await.clear();
        debug!("UDP 隧道 {} recv 循环退出", self.cfg.id);
    }

    /// 为某个来源地址建流并运行双向转发，直到超时 / 子流关闭 / 取消。
    #[allow(clippy::too_many_arguments)]
    async fn establish_and_run(
        self: Arc<Self>,
        bridge: Bridge,
        addr: SocketAddr,
        first: Vec<u8>,
        flows: Arc<Mutex<HashMap<SocketAddr, Arc<FlowEntry>>>>,
        socket: Arc<UdpSocket>,
        cancel: watch::Receiver<bool>,
        _reservation: FlowReservation,
    ) -> Result<()> {
        if *cancel.borrow() {
            return Ok(());
        }

        // 客户端离线：不建流，记录原因（不 panic、不泄漏名额）
        let mux = match bridge.get_tunnel(self.cfg.client_id).await {
            Some(m) => m,
            None => {
                let msg = format!("客户端 {} 离线，无法建立 UDP 隧道流", self.cfg.client_id);
                self.set_error(&msg).await;
                debug!("UDP 隧道 {} {msg}", self.cfg.id);
                return Ok(());
            }
        };

        let stream = match mux.open_stream().await {
            Ok(s) => s,
            Err(e) => {
                self.set_error(format!("mux 建流失败: {e}")).await;
                warn!("UDP 隧道 {} mux 建流失败: {e}", self.cfg.id);
                return Ok(());
            }
        };

        // 首帧：int32 LE 长度 + Link JSON（对齐 Go `SendInfo(link, "")`，无 flag）
        let mut link = nps_proto::Link::new(
            nps_proto::CONN_UDP,
            self.cfg.target_addr.clone(),
            false,
            false,
            addr.to_string(),
            false,
        );
        link.option.timeout = TARGET_DIAL_TIMEOUT_NS;
        let link_json = match serde_json::to_vec(&link) {
            Ok(v) => v,
            Err(e) => {
                self.set_error(format!("Link 序列化失败: {e}")).await;
                warn!("UDP 隧道 {} Link 序列化失败: {e}", self.cfg.id);
                return Ok(());
            }
        };
        let mut frame = Vec::with_capacity(4 + link_json.len());
        frame.extend_from_slice(&(link_json.len() as i32).to_le_bytes());
        frame.extend_from_slice(&link_json);

        let (mut send, mut recv) = stream.into_split();
        if let Err(e) = send.send_data(&frame).await {
            self.set_error(format!("发送 Link 失败: {e}")).await;
            warn!("UDP 隧道 {} 发送 Link 失败: {e}", self.cfg.id);
            return Ok(());
        }

        let (tx, mut rx) = mpsc::channel(self.per_flow_queue);
        let last_active = Arc::new(AtomicU64::new(now_millis()));
        let entry = Arc::new(FlowEntry {
            send: tx.clone(),
            last_active: last_active.clone(),
            queued_bytes: Arc::new(AtomicU64::new(first.len() as u64)),
            max_queued_bytes: self.per_flow_bytes,
        });
        flows.lock().await.insert(addr, entry.clone());
        self.clear_error().await;
        debug!(
            "UDP 隧道 {}: {addr} -> {} 已建立",
            self.cfg.id, self.cfg.target_addr
        );

        // 首包入队（队列刚建，必有容量）
        let _ = tx.try_send(first);

        // 上行：队列 -> mux。慢子流在这里 await，不阻塞 recv 循环。
        let up_last = last_active.clone();
        let up_bytes = entry.queued_bytes.clone();
        let up_tunnel = self.clone();
        let up_addr = addr;
        let mut up = Pump::new(tokio::spawn(async move {
            while let Some(data) = rx.recv().await {
                touch(&up_last);
                // 无论成功与否都释放排队字节额度（数据已出队）
                let _ = up_bytes.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(data.len() as u64))
                });
                if send.send_data(&data).await.is_err() {
                    break;
                }
                // 只统计真正写入 mux 的字节（对齐 Go `Flow.Add(len, 0)` 在 Write 之后）
                up_tunnel
                    .bytes_to_client
                    .fetch_add(data.len() as u64, Ordering::Relaxed);
                let _ = up_addr;
            }
            // 不做半关闭：老协议没有独立半关闭帧，发 ConnClose 会截断下行响应
        }));

        // 下行：mux -> UDP socket（独立任务；按 Go `PoolSizeUdp` 分块写回）
        let this = self.clone();
        let down_last = last_active.clone();
        let down_socket = socket.clone();
        let mut down_cancel = cancel.clone();
        let mut down = Pump::new(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(IDLE_CHECK_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    data = recv.recv_data() => match data {
                        Some(data) => {
                            this.bytes_from_client
                                .fetch_add(data.len() as u64, Ordering::Relaxed);
                            for chunk in data.chunks(UDP_WRITE_CHUNK) {
                                if down_socket.send_to(chunk, addr).await.is_err() {
                                    return;
                                }
                            }
                            touch(&down_last);
                        }
                        // 子流被关闭（对端 ConnClose / mux 会话断开）
                        None => return,
                    },
                    _ = ticker.tick() => {
                        let now = now_millis();
                        let last = down_last.load(Ordering::Relaxed);
                        let idle = Duration::from_millis(now.saturating_sub(last));
                        if idle >= this.idle_timeout {
                            debug!(
                                "UDP 隧道 {} 来源 {addr} 空闲 {} 秒，回收子流",
                                this.cfg.id, idle.as_secs()
                            );
                            return;
                        }
                    }
                    _ = down_cancel.changed() => return,
                }
            }
        }));

        // 任一方向结束即终止另一方向，并等两个半边真正落地：
        // 这样 `MuxSendHalf` / `MuxRecvHalf` 都在本函数返回前 Drop，
        // `StreamState::drop` 才有机会向 npc 发 ConnClose 释放目标 UDP 连接。
        let up_first = tokio::select! {
            _ = &mut up.0 => true,
            _ = &mut down.0 => false,
        };
        if up_first {
            down.0.abort();
            let _ = (&mut down.0).await;
        } else {
            up.0.abort();
            let _ = (&mut up.0).await;
        }

        // 从映射表移除；仅当仍是本流（`Arc::ptr_eq`），避免误删同地址刚重建的新流
        {
            let mut map = flows.lock().await;
            if map.get(&addr).is_some_and(|h| Arc::ptr_eq(h, &entry)) {
                map.remove(&addr);
            }
        }
        debug!("UDP 隧道 {}: {addr} 流结束", self.cfg.id);
        Ok(())
    }

    /// 停止监听：发取消信号，终止 recv、所有建流与转发任务，回收映射与计数。
    ///
    /// 先摘除 runtime（快照立即看到未启用），再等任务退出；超时强制 abort。
    /// 活跃计数由各任务的 `FlowReservation` Drop 归零，不在此强行清零。
    pub async fn disable(&self) {
        let run = self.runtime.lock().await.take();
        if let Some(run) = run {
            let _ = run.cancel.send(true);
            let mut task = run.task;
            match tokio::time::timeout(STOP_TIMEOUT, &mut task).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!("UDP 隧道 {} recv 任务异常: {e}", self.cfg.id),
                Err(_) => {
                    warn!("UDP 隧道 {} recv 任务停止超时，强制终止", self.cfg.id);
                    task.abort();
                    let _ = task.await;
                }
            }
        }
        // 有界等待计数自然归零，让「关闭返回时活跃流数为 0」成为可依赖语义
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            let active = self.active_flows();
            if active == 0 {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                warn!(
                    "UDP 隧道 {} 关闭后仍有 {active} 条流未退出（计数保持真实值，不强行清零）",
                    self.cfg.id
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// 优雅关闭（别名，供父代理在 shutdown 流程中直接调用）。
    pub async fn shutdown(&self) {
        self.disable().await;
    }
}

/// 把数据报放进该来源地址的队列，同时受「数据报个数」与「排队字节」双重水位约束。
///
/// 超限时丢弃本数据报（UDP 允许丢包）并记日志，**绝不阻塞** recv 循环。
fn enqueue(entry: &FlowEntry, data: Vec<u8>, tunnel_id: u32, addr: SocketAddr) {
    let len = data.len() as u64;
    // 先占额度：并发下允许短暂超采，只用于防内存放大，不需要精确
    let over = entry
        .queued_bytes
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            if v + len > entry.max_queued_bytes as u64 {
                None
            } else {
                Some(v + len)
            }
        })
        .is_err();
    if over {
        debug!("UDP 隧道 {tunnel_id} 来源 {addr} 排队字节超限，丢弃 {len} 字节");
        return;
    }
    if entry.send.try_send(data).is_err() {
        // 队列满：撤销刚占用的额度
        let _ = entry
            .queued_bytes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(len))
            });
        debug!("UDP 隧道 {tunnel_id} 来自 {addr} 的流队列已满，丢弃 {len} 字节");
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn touch(v: &AtomicU64) {
    v.store(now_millis(), Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DEFAULT_UDP_IDLE_SECS, DEFAULT_UDP_MAX_SESSIONS};

    fn cfg() -> UdpTunnelConfig {
        UdpTunnelConfig {
            id: 1,
            name: "u".into(),
            client_id: 1,
            listen_addr: "127.0.0.1:0".into(),
            target_addr: "127.0.0.1:9".into(),
            enabled: true,
            idle_timeout_secs: DEFAULT_UDP_IDLE_SECS,
            max_sessions: DEFAULT_UDP_MAX_SESSIONS,
        }
    }

    #[test]
    fn constants_match_go_semantics() {
        assert_eq!(DEFAULT_IDLE_TIMEOUT, Duration::from_secs(600));
        assert_eq!(DEFAULT_MAX_FLOWS, 512);
        assert_eq!(UDP_RECV_BUF, 64 * 1024);
        // Go `common.PoolSizeUdp = 1472 + 200`
        assert_eq!(UDP_WRITE_CHUNK, 1672);
        assert_eq!(TARGET_DIAL_TIMEOUT_NS, nps_proto::DEFAULT_LINK_TIMEOUT_NS);
        assert_eq!(TARGET_DIAL_TIMEOUT_NS, 5_000_000_000);
    }

    /// 默认值必须与 config.rs 的默认值一致（否则两边漂移）
    #[test]
    fn defaults_agree_with_config() {
        let t = UdpTunnel::new(cfg());
        assert_eq!(t.idle_timeout, Duration::from_secs(DEFAULT_UDP_IDLE_SECS));
        assert_eq!(t.max_flows, DEFAULT_UDP_MAX_SESSIONS);
        assert_eq!(DEFAULT_MAX_FLOWS, DEFAULT_UDP_MAX_SESSIONS);
        assert_eq!(DEFAULT_IDLE_TIMEOUT.as_secs(), DEFAULT_UDP_IDLE_SECS);
        assert_eq!(t.per_flow_queue, DEFAULT_PER_FLOW_QUEUE);
    }

    #[test]
    fn reservation_acquires_up_to_max_and_saturates() {
        let counter = Arc::new(AtomicU64::new(0));
        let r1 = FlowReservation::try_acquire(&counter, 2).unwrap();
        let r2 = FlowReservation::try_acquire(&counter, 2).unwrap();
        assert!(FlowReservation::try_acquire(&counter, 2).is_none());
        assert_eq!(counter.load(Ordering::Relaxed), 2);
        drop(r1);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        drop(r2);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    /// 即便外部误清零，归还也只能停在 0（不回绕成 u64::MAX）。
    #[test]
    fn reservation_saturates_at_zero() {
        let counter = Arc::new(AtomicU64::new(0));
        let r = FlowReservation::try_acquire(&counter, 4).unwrap();
        counter.store(0, Ordering::Relaxed);
        drop(r);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    /// Link 必须是 `ConnType="udp"`，且字段名与 Go 一致（老 npc 靠它选 udp 拨号）。
    #[test]
    fn udp_link_wire_shape_matches_go() {
        let mut link = nps_proto::Link::new(
            nps_proto::CONN_UDP,
            "127.0.0.1:7",
            false,
            false,
            "127.0.0.1:5555",
            false,
        );
        link.option.timeout = TARGET_DIAL_TIMEOUT_NS;
        let v = serde_json::to_value(&link).unwrap();
        assert_eq!(v["ConnType"], "udp");
        assert_eq!(v["Host"], "127.0.0.1:7");
        assert_eq!(v["RemoteAddr"], "127.0.0.1:5555");
        assert_eq!(v["Option"]["Timeout"], 5_000_000_000i64);
        assert!(v.as_object().unwrap().contains_key("LocalProxy"));
    }
}
