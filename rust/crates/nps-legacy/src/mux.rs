//! nps-mux 多路复用协议（Rust 兼容层实现）
//!
//! 对齐 `ehang.io/nps-mux v0.0.0-20210407130203-4afa0c10c992`
//! （源码 `C:\Users\kybll\AppData\Local\Temp\nps-mux-src`，已核对 go.mod 锁定 commit）。
//!
//! ## 帧格式（Little Endian，见 netpackager.go）
//! ```text
//! 帧头：flag(u8) + id(i32 LE)
//!   muxPingFlag(0)/muxPingReturn(8)/muxNewMsg(3)/muxNewMsgPart(4)
//!       → + len(u16 LE) + content（len <= 4085）
//!   muxMsgSendOk(5)
//!       → + window(u64 LE)
//!   其它（1/2/6/7）仅 5 字节帧头
//! ```
//!
//! ## 窗口（见 conn.go `window.pack`）
//! `wait(1bit)<<63 | maxSize(31bit)<<32 | read(31bit)`；
//! 初始窗口 4085*30 = 122550；发送方按 `sent` 与对端 ack 的 `read` 差值滑动。
//! `read` 是**自上次确认以来应用已消费的字节增量**。
//!
//! ## 相对原型的修复
//! - 真实收发窗口 + SendOk 消费确认（不再忽略 SendOk）；
//! - 每条子流有界字节预算的接收队列，reader 只做入队不做阻塞等待，
//!   慢子流不会堵死整个会话的读循环；
//! - 对端越过接收预算 → 关闭该子流（限制恶意对端），而不是让 reader 排队等待；
//! - NewConnOk/NewConnFail 区分、建流超时、掉线/关闭唤醒 pending、路由清理、ping 响应；
//! - 会话关闭/Drop 回收资源；`into_split` 拆分本身不关闭子流。
//!
//! ## 半关闭说明
//! Go 协议没有独立的 half-close 帧（`muxConnClose` 即整条子流结束）。
//! 因此 `MuxSendHalf::close` 只在本端停止发送（不发帧、不影响接收方向），
//! 与 Go `copyConns` 中“上行 EOF 后仍继续接收下行”的行为一致；
//! `MuxStream::close` 才是整条子流关闭（向对端发 `muxConnClose`）。

use std::collections::{HashMap, VecDeque};
use std::io::{Error as IoError, ErrorKind as IoKind};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard, Weak};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tracing::{debug, trace, warn};

/// flag 常量（对齐 Go `mux.go`）
pub const MUX_PING_FLAG: u8 = 0;
pub const MUX_NEW_CONN_OK: u8 = 1;
pub const MUX_NEW_CONN_FAIL: u8 = 2;
pub const MUX_NEW_MSG: u8 = 3;
pub const MUX_NEW_MSG_PART: u8 = 4;
pub const MUX_MSG_SEND_OK: u8 = 5;
pub const MUX_NEW_CONN: u8 = 6;
pub const MUX_CONN_CLOSE: u8 = 7;
pub const MUX_PING_RETURN: u8 = 8;

/// ping 的特殊 id（Go: `muxPing int32 = -1`）
pub const MUX_PING_ID: i32 = -1;

/// 单帧内容上限（Go: `maximumSegmentSize = poolSizeWindow = 4085`）
pub const MAXIMUM_SEGMENT_SIZE: usize = 4096 - 2 - 4 - 4 - 1; // = 4085

/// 初始窗口（Go: `maximumSegmentSize*30`）
pub const INITIAL_WINDOW: u32 = MAXIMUM_SEGMENT_SIZE as u32 * 30; // = 122550

/// Go `maximumWindowSize = 1 << 27`，用于钳制对端宣称的窗口
pub const MAX_WINDOW_SIZE: u32 = 1 << 27;

/// 单会话最大子流数（防资源耗尽；个人/小团队场景足够）
pub const MAX_STREAMS: usize = 512;

const WINDOW_SHIFT: u32 = 32;
const WINDOW_MASK: u32 = 0x7FFF_FFFF;

/// 每流接收字节预算：初始窗口 + 若干在途帧余量
/// （Go 的 receiveWindow 在窗口满后仍可能推入已收到的帧，留出少量余量；
/// 超出即视为对端违约/超窗，关闭该子流）
const RECV_BYTE_CAP: u32 = INITIAL_WINDOW + 8 * MAXIMUM_SEGMENT_SIZE as u32;
/// 每流接收队列帧数上限；达到后先尝试并入队尾，仍不行则判超限
const RECV_FRAME_CAP: usize = 4096;
/// 会话数据帧写队列上限（约 4MB）
const WRITE_QUEUE_FRAMES: usize = 1024;
/// 会话控制帧写队列上限（sendOk / close / ping 回包等，每帧 <= 21B）
const CTRL_QUEUE_FRAMES: usize = 8192;
/// 对端新建子流队列上限
const NEW_STREAM_QUEUE: usize = 64;
/// 与 Go `Mux.NewConn` 一致：等待 NewConnOk 2 分钟
const OPEN_STREAM_TIMEOUT: Duration = Duration::from_secs(120);
/// ping 间隔（Go: 5s）
const PING_INTERVAL: Duration = Duration::from_secs(5);
/// 连续未收到 ping 回包的容忍次数（Go: 60）
const PING_THRESHOLD: u64 = 60;

/// 一条 mux 帧（编码/解码的中间表示；公开以便独立字节样例测试）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxFrame {
    pub flag: u8,
    pub id: i32,
    /// muxNewMsg/muxNewMsgPart/muxPingFlag/muxPingReturn 携带的内容
    pub content: Option<Vec<u8>>,
    /// muxMsgSendOk 携带的窗口字
    pub window: Option<u64>,
}

/// 会话路由表：子流 id → 弱引用。
///
/// 用 `std::sync::Mutex`（而不是 `tokio::Mutex`）是刻意的：
/// 临界区全部是 O(1) 的 HashMap 操作、不含任何 `await`，因此不会阻塞
/// runtime；而同步锁的**清理路径永远能拿到锁**，从根上消灭了
/// “`try_lock` 抢不到就跳过清理 → 残留永久留在表里”的一整类泄漏：
/// - 残留的弱引用会计入 `MAX_STREAMS`，累计 512 个之后**永久拒绝建流**；
/// - 残留的 id 会让对端用同一 id 重建子流时永远收到 `NewConnFail`。
type RouteMap = StdMutex<HashMap<i32, Weak<StreamState>>>;

/// 等待对端 `NewConnOk/Fail` 的建流请求表（同样只需短临界区）
type PendingMap = StdMutex<HashMap<i32, oneshot::Sender<PendingResult>>>;

/// 取路由表锁。临界区内不会 panic；这里仍然对毒化做兜底，
/// 绝不能让 `Drop` 路径因为 `PoisonError` 二次 panic。
fn lock_route(m: &RouteMap) -> MutexGuard<'_, HashMap<i32, Weak<StreamState>>> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn lock_pending(m: &PendingMap) -> MutexGuard<'_, HashMap<i32, oneshot::Sender<PendingResult>>> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// 剪掉指向已释放子流的弱引用，返回清理后**仍存活**的路由数。
///
/// `Weak::strong_count()` 不会触碰 Arc 内部对象，因此在子流正在 Drop 时
/// 读取也安全（此时强引用计数已经是 0）。
fn prune_dead_routes(map: &mut HashMap<i32, Weak<StreamState>>) -> usize {
    map.retain(|_, w| w.strong_count() > 0);
    map.len()
}

/// 某个 id 是否被**存活**的子流占用（死弱引用不算）
fn route_is_live(map: &HashMap<i32, Weak<StreamState>>, id: i32) -> bool {
    map.get(&id).map(|w| w.strong_count() > 0).unwrap_or(false)
}

impl MuxFrame {
    /// 编码为字节流（对齐 Go `muxPackager.Pack`）
    ///
    /// 内容帧的长度一律**先钳制**到 `MAXIMUM_SEGMENT_SIZE` 再写入，
    /// 保证“长度字段”与“实际写入字节数”永远一致。否则 `len as u16`
    /// 在内容 > 64KiB 时会截断，令对端读到错误长度的帧、整条会话失步。
    /// 正常路径（`send_data_on` 按 4085 分片、ping 30 字节）不会触发钳制。
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(13);
        buf.push(self.flag);
        buf.extend_from_slice(&self.id.to_le_bytes());
        match self.flag {
            MUX_NEW_MSG | MUX_NEW_MSG_PART | MUX_PING_FLAG | MUX_PING_RETURN => {
                let content = self.content.as_deref().unwrap_or(&[]);
                let content = &content[..content.len().min(MAXIMUM_SEGMENT_SIZE)];
                buf.extend_from_slice(&(content.len() as u16).to_le_bytes());
                buf.extend_from_slice(content);
            }
            MUX_MSG_SEND_OK => {
                buf.extend_from_slice(&self.window.unwrap_or(0).to_le_bytes());
            }
            _ => {}
        }
        buf
    }

    /// 从 reader 解码一帧。
    ///
    /// - 帧边界处干净 EOF → `Ok(None)`
    /// - 半帧 EOF、内容长度 > 4085、未知 flag → `Err`
    ///
    /// ## 半包/粘包
    /// 每次调用只消费**恰好一帧**：帧头 5 字节用 `read_exact` 读满（底层
    /// `read` 只返回一部分字节时自动续读），内容再按校验通过的长度读满；
    /// 一次 `read` 里有多个帧也不会被吞掉——多余的字节留在内核缓冲，
    /// 由下一次 `decode` 读取。首字节单独读是为了区分“帧边界干净 EOF”与
    /// “半帧 EOF”，这两种情况对会话的处理不同（前者正常退出，后者报错）。
    pub async fn decode<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Option<MuxFrame>> {
        // 先读 1 字节，以区分“干净 EOF”与“半帧 EOF”
        let mut first = [0u8; 1];
        loop {
            match r.read(&mut first).await {
                Ok(0) => return Ok(None),
                Ok(_) => break,
                // 信号中断不是协议错误，重试而不是整条会话报错
                Err(e) if e.kind() == IoKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        let mut head = [0u8; 5];
        head[0] = first[0];
        r.read_exact(&mut head[1..]).await?;
        let flag = head[0];
        let id = i32::from_le_bytes([head[1], head[2], head[3], head[4]]);

        let mut frame = MuxFrame {
            flag,
            id,
            content: None,
            window: None,
        };
        match flag {
            MUX_NEW_MSG | MUX_NEW_MSG_PART | MUX_PING_FLAG | MUX_PING_RETURN => {
                let mut lenb = [0u8; 2];
                r.read_exact(&mut lenb).await?;
                let len = u16::from_le_bytes(lenb) as usize;
                // 先校验再分配：上限 4085 远小于任何能造成内存压力的量级
                if len > MAXIMUM_SEGMENT_SIZE {
                    return Err(IoError::new(
                        IoKind::InvalidData,
                        format!("mux: content length {len} exceeds {MAXIMUM_SEGMENT_SIZE}"),
                    ));
                }
                let mut content = vec![0u8; len];
                r.read_exact(&mut content).await?;
                frame.content = Some(content);
            }
            MUX_MSG_SEND_OK => {
                let mut w = [0u8; 8];
                r.read_exact(&mut w).await?;
                frame.window = Some(u64::from_le_bytes(w));
            }
            MUX_NEW_CONN_OK | MUX_NEW_CONN_FAIL | MUX_NEW_CONN | MUX_CONN_CLOSE => {}
            _ => {
                return Err(IoError::new(
                    IoKind::InvalidData,
                    format!("mux: unknown flag {flag}"),
                ));
            }
        }
        Ok(Some(frame))
    }

    /// 构造 sendOk 帧（对齐 Go `window.pack`）
    pub fn send_ok(id: i32, max_size: u32, read: u32, wait: bool) -> Self {
        Self {
            flag: MUX_MSG_SEND_OK,
            id,
            content: None,
            window: Some(pack_window(max_size, read, wait)),
        }
    }

    /// 解析 sendOk 帧的窗口状态（对齐 Go `window.unpack`）
    pub fn unpack_window(v: u64) -> (u32, u32, bool) {
        unpack_window(v)
    }
}

fn pack_window(max_size: u32, read: u32, wait: bool) -> u64 {
    let wait_bit = if wait { 1u64 << 63 } else { 0 };
    wait_bit | (u64::from(max_size & WINDOW_MASK) << WINDOW_SHIFT) | u64::from(read & WINDOW_MASK)
}

fn unpack_window(v: u64) -> (u32, u32, bool) {
    let max_size = ((v >> WINDOW_SHIFT) & u64::from(WINDOW_MASK)) as u32;
    let read = (v & u64::from(WINDOW_MASK)) as u32;
    let wait = (v >> 63) & 1 == 1;
    (max_size, read, wait)
}

/// 生成 Go `time.Time.MarshalText()` 兼容的 UTC 时间串
/// （RFC3339Nano：`2020-09-13T12:26:40.000000000Z`）。
///
/// 必须用这个格式：Go 对端 `pingCh` 处理时会 `now.UnmarshalText(data)`，
/// 解析失败会把零值时间代入延迟计算，从而污染其自适应接收窗口。
fn rfc3339_from_unix(secs: i64, nanos: u32) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{nanos:09}Z")
}

/// Howard Hinnant 的 civil_from_days：Unix 纪元天数 → (年, 月, 日)
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn rfc3339_now() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    rfc3339_from_unix(d.as_secs() as i64, d.subsec_nanos())
}

fn broken_pipe(msg: &'static str) -> IoError {
    IoError::new(IoKind::BrokenPipe, msg)
}

/// 发送侧窗口状态
#[derive(Debug)]
struct SendState {
    /// 对端允许的最大在途字节数
    max_size: u32,
    /// 已交给写循环、尚未被对端 `read` 确认的字节数
    sent: u32,
}

/// 接收侧窗口 + 有界接收队列
#[derive(Debug)]
struct RecvState {
    max_size: u32,
    /// 已入队、应用尚未读取的字节数
    queued: u32,
    /// 自上次 sendOk 以来应用已读取的字节数
    read_since_ack: u32,
    /// 是否已进入“窗口满、等应用消费”的状态
    wait: bool,
    /// 已入队的数据（每块 <= MAXIMUM_SEGMENT_SIZE）
    chunks: VecDeque<Vec<u8>>,
}

/// 一条子流的共享状态；最后一个持有者 Drop 时向对端发 ConnClose。
struct StreamState {
    id: i32,
    /// 数据帧写队列（有界，施加字节级背压）
    write_tx: mpsc::Sender<Vec<u8>>,
    /// 控制帧写队列（sendOk/close 等，reader 用 try_send，绝不阻塞读循环）
    ctrl_tx: mpsc::Sender<Vec<u8>>,
    /// 会话路由表（id -> 弱引用）
    streams: Arc<RouteMap>,
    send: Mutex<SendState>,
    /// 发送窗口可用量（watch 保存最新值，天然无丢唤醒）
    avail_tx: watch::Sender<u32>,
    /// 是否已停止发送（半关闭）
    send_closed: AtomicBool,
    recv: Mutex<RecvState>,
    /// 接收队列版本号（入队/关闭时递增，用于唤醒 recv_data）
    recv_gen: watch::Sender<u64>,
    /// 本流关闭信号（此后不再有新数据，发送也失败）
    closed_tx: watch::Sender<bool>,
    /// 本地关闭：立即丢弃已排队数据；对端关闭时保留，先让应用读完残留数据
    discard_recv: AtomicBool,
    /// 会话关闭信号（克隆自会话）
    session_closed: watch::Receiver<bool>,
}

impl StreamState {
    fn new(
        id: i32,
        write_tx: mpsc::Sender<Vec<u8>>,
        ctrl_tx: mpsc::Sender<Vec<u8>>,
        streams: Arc<RouteMap>,
        session_closed: watch::Receiver<bool>,
    ) -> Self {
        let (avail_tx, _) = watch::channel(INITIAL_WINDOW);
        let (recv_gen, _) = watch::channel(0u64);
        let (closed_tx, _) = watch::channel(false);
        Self {
            id,
            write_tx,
            ctrl_tx,
            streams,
            send: Mutex::new(SendState {
                max_size: INITIAL_WINDOW,
                sent: 0,
            }),
            avail_tx,
            send_closed: AtomicBool::new(false),
            recv: Mutex::new(RecvState {
                max_size: INITIAL_WINDOW,
                queued: 0,
                read_since_ack: 0,
                wait: false,
                chunks: VecDeque::new(),
            }),
            recv_gen,
            closed_tx,
            discard_recv: AtomicBool::new(false),
            session_closed,
        }
    }

    fn is_closed(&self) -> bool {
        *self.closed_tx.borrow() || *self.session_closed.borrow()
    }
}

impl Drop for StreamState {
    fn drop(&mut self) {
        if !*self.closed_tx.borrow() {
            self.closed_tx.send_replace(true);
            self.avail_tx.send_replace(0);
            self.discard_recv.store(true, Ordering::Release);
            self.bump_recv_gen();
            let frame = MuxFrame {
                flag: MUX_CONN_CLOSE,
                id: self.id,
                content: None,
                window: None,
            };
            // 与 Go 一致：ConnClose 排在已入队数据之后（同一条 FIFO），
            // 避免关闭帧超车把尾部数据截断；队列满时才退回控制队列
            let bytes = frame.encode();
            if self.write_tx.try_send(bytes.clone()).is_err() {
                let _ = self.ctrl_tx.try_send(bytes);
            }
        }
        // 清理会话路由里指向本流（此时强引用计数已为 0，必然无法 upgrade）的项。
        // 同步锁保证这一步**一定会执行**：早期用 `try_lock` 时，只要当时有别的
        // 任务持有路由表（建流/查表），清理就被静默跳过，留下一条永久残留 ——
        // 残留累计到 MAX_STREAMS 后整个会话再也建不了流。
        let mut map = lock_route(&self.streams);
        if !route_is_live(&map, self.id) {
            map.remove(&self.id);
        }
    }
}

impl StreamState {
    fn bump_recv_gen(&self) {
        let next = self.recv_gen.borrow().wrapping_add(1);
        self.recv_gen.send_replace(next);
    }
}

/// 关闭一条子流：置关闭信号（唤醒所有等待者）、可选地通知对端、清理会话路由。
fn close_stream_sync(state: &Arc<StreamState>, notify_peer: bool) {
    if !*state.closed_tx.borrow() {
        state.closed_tx.send_replace(true);
        state.avail_tx.send_replace(0);
        state.discard_recv.store(true, Ordering::Release);
        state.bump_recv_gen();
        if notify_peer {
            let frame = MuxFrame {
                flag: MUX_CONN_CLOSE,
                id: state.id,
                content: None,
                window: None,
            };
            // 与 Go 一致：关闭帧排在已入队数据之后，避免截断尾部数据
            let bytes = frame.encode();
            if state.write_tx.try_send(bytes.clone()).is_err() {
                let _ = state.ctrl_tx.try_send(bytes);
            }
        }
    }
    remove_own_route(state);
}

/// 只有当路由表该项确实指向 `state` 时才删除（避免误删对端同 id 的新子流）。
fn remove_own_route(state: &Arc<StreamState>) {
    let mut map = lock_route(&state.streams);
    let is_self = map
        .get(&state.id)
        .and_then(|w| w.upgrade())
        .map(|s| Arc::ptr_eq(&s, state))
        .unwrap_or(false);
    if is_self {
        map.remove(&state.id);
    }
}



/// 对端发起关闭（收到 `muxConnClose`）。
///
/// 对齐 Go `readSession`: `closingFlag = true; receiveWindow.Stop()`——
/// 发送方向不可再用，但接收方向**先排空已入队数据**再返回 EOF，
/// 避免把对端最后几帧丢掉。
fn peer_close_stream(state: &Arc<StreamState>) {
    if !*state.closed_tx.borrow() {
        state.closed_tx.send_replace(true);
        state.avail_tx.send_replace(0);
        state.bump_recv_gen();
        // 注意：不设置 discard_recv，让 recv_data 先读完残留数据
    }
    remove_own_route(state);
}

/// 发送数据：受对端窗口约束，按 4085 分片。
async fn send_data_on(state: &Arc<StreamState>, data: &[u8]) -> std::io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    if state.send_closed.load(Ordering::Acquire) {
        return Err(broken_pipe("mux send side closed"));
    }
    let mut closed_rx = state.closed_tx.subscribe();
    let mut session_rx = state.session_closed.clone();
    let mut avail_rx = state.avail_tx.subscribe();
    let mut off = 0usize;

    while off < data.len() {
        // 等窗口：以 `send` 锁内的状态为准，watch 仅用于唤醒（不会丢唤醒）
        loop {
            if *closed_rx.borrow_and_update() || *session_rx.borrow_and_update() {
                return Err(broken_pipe("mux stream closed"));
            }
            if state.send_closed.load(Ordering::Acquire) {
                return Err(broken_pipe("mux send side closed"));
            }
            {
                let s = state.send.lock().await;
                if s.max_size > s.sent {
                    break;
                }
            }
            tokio::select! {
                _ = avail_rx.changed() => {}
                result = closed_rx.changed() => {
                    if result.is_err() {
                        return Err(broken_pipe("mux stream closed"));
                    }
                }
                result = session_rx.changed() => {
                    if result.is_err() {
                        return Err(broken_pipe("mux stream closed"));
                    }
                }
            }
        }

        let (chunk_len, part) = {
            let mut s = state.send.lock().await;
            let room = s.max_size.saturating_sub(s.sent) as usize;
            if room == 0 {
                state.avail_tx.send_replace(0);
                continue;
            }
            let want = (data.len() - off).min(MAXIMUM_SEGMENT_SIZE);
            let n = want.min(room);
            // 与 Go `sendWindow.sent` 一致：计入已交给写循环的字节
            s.sent = s.sent.wrapping_add(n as u32);
            let avail = s.max_size.saturating_sub(s.sent);
            state.avail_tx.send_replace(avail);
            (n, off + n < data.len())
        };

        let frame = MuxFrame {
            flag: if part { MUX_NEW_MSG_PART } else { MUX_NEW_MSG },
            id: state.id,
            content: Some(data[off..off + chunk_len].to_vec()),
            window: None,
        };
        // 入队也可能阻塞（写队列 1024 帧满 = 底层写不动）。必须与关闭信号
        // 竞争，否则会话/子流关闭后被卡在这里的 `send_data` 永远醒不过来。
        let queued = tokio::select! {
            r = state.write_tx.send(frame.encode()) => r,
            _ = wait_closed(&mut closed_rx, &mut session_rx) => {
                return Err(broken_pipe("mux stream closed"));
            }
        };
        queued.map_err(|_| broken_pipe("mux session closed"))?;
        off += chunk_len;
    }
    Ok(())
}

/// 等待“子流关闭 / 会话关闭”任一发生；已经关闭则立即返回。
async fn wait_closed(
    closed_rx: &mut watch::Receiver<bool>,
    session_rx: &mut watch::Receiver<bool>,
) {
    if *closed_rx.borrow_and_update() || *session_rx.borrow_and_update() {
        return;
    }
    tokio::select! {
        _ = closed_rx.changed() => {}
        _ = session_rx.changed() => {}
    }
}

/// 接收数据；`None` 表示子流关闭（对端关闭、本地关闭或会话关闭）。
async fn recv_data_on(state: &Arc<StreamState>) -> Option<Vec<u8>> {
    let mut closed_rx = state.closed_tx.subscribe();
    let mut session_rx = state.session_closed.clone();
    let mut gen_rx = state.recv_gen.subscribe();
    loop {
        // 本地关闭/会话关闭：立即结束；对端关闭：先把已入队数据读完再结束
        if state.discard_recv.load(Ordering::Acquire) || *session_rx.borrow_and_update() {
            // 本端主动关闭后残留数据不再交付，顺手释放缓冲：
            // 否则一条已关闭的子流还能继续占住最多 RECV_BYTE_CAP 字节。
            let mut r = state.recv.lock().await;
            r.chunks.clear();
            r.queued = 0;
            return None;
        }
        {
            let mut r = state.recv.lock().await;
            if let Some(chunk) = r.chunks.pop_front() {
                let len = chunk.len() as u32;
                r.queued = r.queued.saturating_sub(len);
                r.read_since_ack = r.read_since_ack.wrapping_add(len);
                let should_ack = (r.wait && r.queued < r.max_size)
                    || r.read_since_ack >= r.max_size / 2
                    || r.queued == 0;
                if should_ack {
                    let frame = MuxFrame::send_ok(state.id, r.max_size, r.read_since_ack, false);
                    // 写队列满时跳过，read_since_ack 保留到下次确认
                    if state.ctrl_tx.try_send(frame.encode()).is_ok() {
                        r.read_since_ack = 0;
                        r.wait = false;
                    }
                }
                drop(r);
                return Some(chunk);
            }
            if *closed_rx.borrow_and_update() && r.chunks.is_empty() {
                return None;
            }
        }
        tokio::select! {
            _ = gen_rx.changed() => {}
            _ = closed_rx.changed() => {}
            _ = session_rx.changed() => {}
        }
    }
}

/// 处理对端 SendOk：扣减已发未确认字节、更新窗口、唤醒发送者。
async fn handle_send_ok(state: &Arc<StreamState>, window: u64) {
    let (max_size, read, _wait) = unpack_window(window);
    // 只做上界钳制；下界保留对端真实值（Go 的发送窗口可以小于一个分片），
    // 否则会越过对端声明窗口。0 表示对端暂停接收，需等新的 sendOk。
    let max_size = max_size.min(MAX_WINDOW_SIZE);
    let mut s = state.send.lock().await;
    if read > s.sent {
        // Go 原版同样忽略该确认（read > send）
        warn!("mux: illegal sendOk read={read} > sent={}", s.sent);
        return;
    }
    s.sent -= read;
    s.max_size = max_size;
    let avail = s.max_size.saturating_sub(s.sent);
    state.avail_tx.send_replace(avail);
}

/// 处理到达的数据帧。`Err(())` 表示对端越过接收预算，调用方应关闭该子流。
///
/// 全程不等待：只做入队与窗口记账，避免慢子流堵住会话读循环。
async fn handle_data(state: &Arc<StreamState>, mut content: Vec<u8>) -> Result<(), ()> {
    let len = content.len() as u32; // decode 已保证 <= 4085
    if len == 0 {
        // Go 的 packager 不会产生零长度数据帧；收到则忽略（避免空块堆积）
        return Ok(());
    }
    let mut r = state.recv.lock().await;
    if r.queued.saturating_add(len) > RECV_BYTE_CAP {
        return Err(());
    }
    if r.chunks.len() >= RECV_FRAME_CAP {
        // 大量小帧时先并入队尾，避免帧数放大；不行则视为超限
        let merged = match r.chunks.back_mut() {
            Some(last) if last.len() + content.len() <= MAXIMUM_SEGMENT_SIZE => {
                last.extend_from_slice(&content);
                true
            }
            _ => false,
        };
        if !merged {
            return Err(());
        }
    } else {
        content.shrink_to_fit();
        r.chunks.push_back(content);
    }
    r.queued += len;
    if r.queued >= r.max_size {
        // 窗口满：置 wait，不发送确认（对齐 Go receiveWindow.Write）
        r.wait = true;
    } else {
        let frame = MuxFrame::send_ok(state.id, r.max_size, r.read_since_ack, false);
        if state.ctrl_tx.try_send(frame.encode()).is_ok() {
            r.read_since_ack = 0;
            r.wait = false;
        }
    }
    drop(r);
    state.bump_recv_gen();
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingResult {
    Ok,
    Fail,
}

struct SessionShared {
    closed: AtomicBool,
    next_id: AtomicI32,
    /// `Arc` 包裹，使同一张路由表可交给每条 `StreamState`
    streams: Arc<RouteMap>,
    /// 等待 NewConnOk/Fail 的建流请求
    pending: PendingMap,
    /// 数据帧写队列（有界）
    write_tx: mpsc::Sender<Vec<u8>>,
    /// 控制帧写队列（有界；reader 只 try_send）
    ctrl_tx: mpsc::Sender<Vec<u8>>,
    /// 对端新建的子流
    new_stream_tx: mpsc::Sender<MuxStream>,
    new_stream_rx: Mutex<mpsc::Receiver<MuxStream>>,
    /// 会话关闭信号（`send_replace` 保证值一定写入）
    closed_tx: watch::Sender<bool>,
    /// 连续未收到 ping 回包的次数
    ping_missed: AtomicU64,
}

fn close_session(shared: &Arc<SessionShared>) {
    if shared.closed.swap(true, Ordering::AcqRel) {
        return;
    }
    shared.closed_tx.send_replace(true);

    // 先把两张表在锁内搬空，再逐个收尾。
    // 收尾过程会重新获取同一把路由表锁（`close_stream_sync` / 子流 Drop），
    // 持锁调用会自锁；同时这里**不再用 `try_lock`**——抢不到锁就跳过收尾会让
    // 等待中的 `open_stream` 白等到 120s 超时。
    let pending: Vec<oneshot::Sender<PendingResult>> =
        lock_pending(&shared.pending).drain().map(|(_, tx)| tx).collect();
    for tx in pending {
        let _ = tx.send(PendingResult::Fail);
    }

    let routes: Vec<Arc<StreamState>> = lock_route(&shared.streams)
        .drain()
        .filter_map(|(_, weak)| weak.upgrade())
        .collect();
    for state in routes {
        close_stream_sync(&state, false);
    }
    debug!("mux session closed");
}

/// 分配一个新的子流 id（仅保证与**存活**子流不冲突；真正落表在 `open_stream`）。
async fn alloc_id(shared: &Arc<SessionShared>) -> Result<i32, MuxError> {
    loop {
        if shared.closed.load(Ordering::Acquire) {
            return Err(MuxError::Closed);
        }
        let cur = shared.next_id.load(Ordering::Relaxed);
        if i32::MAX - cur < 10_000 {
            shared.next_id.store(0, Ordering::Relaxed);
        }
        let id = shared.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        if id <= 0 {
            continue;
        }
        // 只认“存活占用”：指向已释放子流的死弱引用不该长期占住 id
        if route_is_live(&lock_route(&shared.streams), id) {
            continue;
        }
        if lock_pending(&shared.pending).contains_key(&id) {
            continue;
        }
        return Ok(id);
    }
}

fn lookup_stream(shared: &Arc<SessionShared>, id: i32) -> Option<Arc<StreamState>> {
    lock_route(&shared.streams).get(&id).and_then(|w| w.upgrade())
}

/// 收到未知/已关闭子流的帧时，顺手清掉指向已释放子流的残留路由。
fn close_stale_route(shared: &Arc<SessionShared>, id: i32) {
    let mut streams = lock_route(&shared.streams);
    if !route_is_live(&streams, id) {
        streams.remove(&id);
    }
}

/// 对端主动建流（`MUX_NEW_CONN`）。
///
/// 对抗性输入下的三条硬约束：
/// 1. 先 `try_reserve` 一个控制帧许可（**非阻塞**）。取不到（写队列满）就
///    直接放弃本次请求：既不静默丢 OK 让对端空等 120 秒，也不在自己的
///    路由表里留下一条没人回应的孤儿子流。
/// 2. id 必须是正数，且不能被存活子流占用；判定容量前先剪掉死弱引用，
///    否则历史残留会把会话永久顶在 `MAX_STREAMS` 上。
/// 3. 交给 accept 队列失败（应用不接收）时回滚路由并回 `NewConnFail`。
fn accept_peer_stream(id: i32, shared: &Arc<SessionShared>) -> Result<(), MuxError> {
    let Ok(permit) = shared.ctrl_tx.try_reserve() else {
        warn!("mux: ctrl queue full, drop peer new conn id={id}");
        return Ok(());
    };

    let (stream, weak) = {
        let mut streams = lock_route(&shared.streams);
        let live = prune_dead_routes(&mut streams);
        if id <= 0 || live >= MAX_STREAMS || route_is_live(&streams, id) {
            let fail = MuxFrame {
                flag: MUX_NEW_CONN_FAIL,
                id,
                content: None,
                window: None,
            };
            permit.send(fail.encode());
            debug!("mux: peer new conn id={id} rejected");
            return Ok(());
        }
        let state = Arc::new(StreamState::new(
            id,
            shared.write_tx.clone(),
            shared.ctrl_tx.clone(),
            shared.streams.clone(),
            shared.closed_tx.subscribe(),
        ));
        let weak = Arc::downgrade(&state);
        streams.insert(id, weak.clone());
        (MuxStream { id, state }, weak)
    };

    match shared.new_stream_tx.try_send(stream) {
        Ok(()) => {
            let ok = MuxFrame {
                flag: MUX_NEW_CONN_OK,
                id,
                content: None,
                window: None,
            };
            permit.send(ok.encode());
            debug!("mux: peer new conn id={id} -> ok");
        }
        Err(_) => {
            // 应用没有调用 accept_stream（或积压已满）：撤销登记，明确拒绝。
            // 只删**自己这条**路由：此时子流可能已经 Drop 并清掉了它，
            // 期间同 id 的新建流也可能已经登记，不能盲删 id。
            {
                let mut streams = lock_route(&shared.streams);
                let still_mine = streams
                    .get(&id)
                    .map(|cur| cur.ptr_eq(&weak))
                    .unwrap_or(false);
                if still_mine {
                    streams.remove(&id);
                }
            }
            let fail = MuxFrame {
                flag: MUX_NEW_CONN_FAIL,
                id,
                content: None,
                window: None,
            };
            permit.send(fail.encode());
            debug!("mux: accept queue full, reject peer new conn id={id}");
        }
    }
    Ok(())
}

async fn handle_frame(frame: MuxFrame, shared: &Arc<SessionShared>) -> Result<(), MuxError> {
    match frame.flag {
        MUX_NEW_CONN => accept_peer_stream(frame.id, shared)?,
        MUX_NEW_CONN_OK | MUX_NEW_CONN_FAIL => {
            let sender = lock_pending(&shared.pending).remove(&frame.id);
            if let Some(tx) = sender {
                let result = if frame.flag == MUX_NEW_CONN_OK {
                    PendingResult::Ok
                } else {
                    PendingResult::Fail
                };
                let _ = tx.send(result);
            }
        }
        MUX_PING_FLAG => {
            // 绝不能把空内容原样回显：Go 的 `basePackager.Set` 对零长度内容
            // 返回错误，`sendInfo` 随即 `Close()` 整条 mux —— 也就是说
            // “回一个空 ping”等于把对端会话毒死。内容为空时用自己的时间戳。
            let content = match frame.content {
                Some(c) if !c.is_empty() => c,
                _ => rfc3339_now().into_bytes(),
            };
            let out = MuxFrame {
                flag: MUX_PING_RETURN,
                id: MUX_PING_ID,
                content: Some(content),
                window: None,
            };
            // ping 回包不阻塞 reader
            let _ = shared.ctrl_tx.try_send(out.encode());
        }
        MUX_PING_RETURN => {
            shared.ping_missed.store(0, Ordering::Relaxed);
        }
        MUX_NEW_MSG | MUX_NEW_MSG_PART => match lookup_stream(shared, frame.id) {
            Some(state) if !state.is_closed() => {
                if handle_data(&state, frame.content.unwrap_or_default())
                    .await
                    .is_err()
                {
                    warn!("mux: stream {} exceeded receive budget, closing", frame.id);
                    close_stream_sync(&state, true);
                }
            }
            _ => {
                trace!("mux: drop data for unregistered stream {}", frame.id);
                close_stale_route(shared, frame.id);
            }
        },
        MUX_MSG_SEND_OK => {
            if let Some(state) = lookup_stream(shared, frame.id) {
                if let Some(window) = frame.window {
                    handle_send_ok(&state, window).await;
                }
            }
        }
        MUX_CONN_CLOSE => {
            // 对端关闭：置关闭信号、清路由，不回发 ConnClose；先让应用读净残留数据
            if let Some(state) = lookup_stream(shared, frame.id) {
                peer_close_stream(&state);
            }
            close_stale_route(shared, frame.id);
        }
        other => {
            return Err(MuxError::Protocol(format!("unknown mux flag {other}")));
        }
    }
    Ok(())
}

/// mux 会话：封装一条底层连接，向对端提供多路复用通道。
///
/// 可被 `Arc` 持有，所有方法均为 `&self`。
pub struct MuxSession {
    inner: Arc<SessionShared>,
}

impl MuxSession {
    /// 在一条已建立（且不会被其它数据污染）的连接上创建会话。
    pub fn new<S>(conn: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (read_half, write_half) = tokio::io::split(conn);
        let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(WRITE_QUEUE_FRAMES);
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Vec<u8>>(CTRL_QUEUE_FRAMES);
        let (new_stream_tx, new_stream_rx) = mpsc::channel::<MuxStream>(NEW_STREAM_QUEUE);
        let (closed_tx, _) = watch::channel(false);
        let closed_keepalive = closed_tx.subscribe();

        let shared = Arc::new(SessionShared {
            closed: AtomicBool::new(false),
            next_id: AtomicI32::new(0),
            streams: Arc::new(StdMutex::new(HashMap::new())),
            pending: StdMutex::new(HashMap::new()),
            write_tx: write_tx.clone(),
            ctrl_tx: ctrl_tx.clone(),
            new_stream_tx,
            new_stream_rx: Mutex::new(new_stream_rx),
            closed_tx: closed_tx.clone(),
            ping_missed: AtomicU64::new(0),
        });

        // ---- 写循环 ----
        {
            let shared = Arc::clone(&shared);
            let mut closed_rx = closed_keepalive.clone();
            tokio::spawn(async move {
                let mut wh = write_half;
                loop {
                    if *closed_rx.borrow_and_update() {
                        break;
                    }
                    let bytes = tokio::select! {
                        biased;
                        ctrl = ctrl_rx.recv() => {
                            match ctrl {
                                Some(bytes) => bytes,
                                None => break,
                            }
                        }
                        bytes = write_rx.recv() => {
                            match bytes {
                                Some(bytes) => bytes,
                                None => break,
                            }
                        }
                        result = closed_rx.changed() => {
                            if result.is_err() || *closed_rx.borrow() {
                                break;
                            }
                            continue;
                        }
                    };
                    // 写本身也必须可被关闭打断。
                    // 对端不读 socket 时 `write_all` 会一直挂着（TCP 反压），
                    // 若这里不可取消，`close()` 就没有任何效果：写循环永不退出，
                    // `write_rx`/`ctrl_rx` 永不关闭，于是所有 `send_data` /
                    // `open_stream` 永久阻塞 —— 整个会话“卡死”而不是断开。
                    // 取消一次未写完的帧没有副作用：连接随后就被 shutdown。
                    tokio::select! {
                        r = wh.write_all(&bytes) => {
                            if r.is_err() {
                                break;
                            }
                        }
                        _ = closed_rx.changed() => {
                            if *closed_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
                let _ = wh.shutdown().await;
                close_session(&shared);
                debug!("mux write loop exit");
            });
        }

        // ---- 读循环 ----
        {
            let shared = Arc::clone(&shared);
            let mut closed_rx = closed_keepalive.clone();
            tokio::spawn(async move {
                let mut rh = read_half;
                loop {
                    if *closed_rx.borrow_and_update() {
                        break;
                    }
                    tokio::select! {
                        decoded = MuxFrame::decode(&mut rh) => {
                            match decoded {
                                Ok(Some(frame)) => {
                                    if let Err(e) = handle_frame(frame, &shared).await {
                                        warn!("mux: {e}");
                                        break;
                                    }
                                }
                                Ok(None) => break,
                                Err(e) => {
                                    warn!("mux: read error: {e}");
                                    break;
                                }
                            }
                        }
                        result = closed_rx.changed() => {
                            if result.is_err() || *closed_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
                close_session(&shared);
                debug!("mux read loop exit");
            });
        }

        // ---- ping ----
        {
            let shared = Arc::clone(&shared);
            // ping 走控制队列，避免被大数据流排队拖慢
            let ping_tx = shared.ctrl_tx.clone();
            let mut closed_rx = closed_keepalive.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(PING_INTERVAL);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {}
                        _ = closed_rx.changed() => {
                            if *closed_rx.borrow() {
                                break;
                            }
                            continue;
                        }
                    }
                    if *closed_rx.borrow() {
                        break;
                    }
                    if shared.ping_missed.fetch_add(1, Ordering::Relaxed) >= PING_THRESHOLD {
                        warn!("mux: ping timeout, closing session");
                        close_session(&shared);
                        break;
                    }
                    // 控制队列已满（对端不读 socket、写循环卡在反压里）时**绝不能 await**：
                    // 一旦在 `send` 上挂起，下面的超时检查就永远轮不到执行，
                    // 死会话永远不被回收（连接 + 子流全部泄漏，探活形同虚设）。
                    // 丢弃这一次 ping，让 missed 计数继续累积，到阈值正常断开。
                    if ping_tx.capacity() == 0 {
                        debug!("mux: ctrl queue full, skip ping");
                        continue;
                    }
                    // 必须与 Go 一致使用 RFC3339Nano 文本：对端会 UnmarshalText，
                    // 失败会污染其延迟/窗口计算。内容也绝不能为空
                    // （Go 的 packager 对零长度内容报错并关闭 mux）。
                    let frame = MuxFrame {
                        flag: MUX_PING_FLAG,
                        id: MUX_PING_ID,
                        content: Some(rfc3339_now().into_bytes()),
                        window: None,
                    };
                    let _ = ping_tx.try_send(frame.encode());
                }
            });
        }

        Self { inner: shared }
    }

    /// 主动开一条子流，等待对端 NewConnOk（拒绝/超时返回 Err）。
    pub async fn open_stream(&self) -> Result<MuxStream, MuxError> {
        let shared = &self.inner;
        if shared.closed.load(Ordering::Acquire) {
            return Err(MuxError::Closed);
        }

        // 分配 id + 登记路由 + 登记 pending 必须在同一个**同步**临界区里完成：
        // 两步之间若被其它任务插入（多线程 runtime），对端可能用同一个 id
        // 建流，双方会互相覆盖路由表。
        let (id, state, ok_rx) = loop {
            let id = alloc_id(shared).await?;
            // 先只做校验，再创建 StreamState：避免在 id 冲突时白造一个对象、
            // 其 Drop 还会向对端发一条莫名其妙的 ConnClose。
            let mut streams = lock_route(&shared.streams);
            // 容量只按**存活**子流计：先剪掉死弱引用，避免历史残留把会话顶死
            if prune_dead_routes(&mut streams) >= MAX_STREAMS {
                return Err(MuxError::Protocol("too many streams".into()));
            }
            if route_is_live(&streams, id) {
                drop(streams); // 该 id 被对端并发占走，换一个
                continue;
            }
            let state = Arc::new(StreamState::new(
                id,
                shared.write_tx.clone(),
                shared.ctrl_tx.clone(),
                shared.streams.clone(),
                shared.closed_tx.subscribe(),
            ));
            let (ok_tx, ok_rx) = oneshot::channel();
            streams.insert(id, Arc::downgrade(&state));
            // 锁序固定 route -> pending，其它路径要么只拿一把、要么同序，不会死锁
            lock_pending(&shared.pending).insert(id, ok_tx);
            drop(streams);
            break (id, state, ok_rx);
        };

        let req = MuxFrame {
            flag: MUX_NEW_CONN,
            id,
            content: None,
            window: None,
        };
        // 建流请求走控制队列：不会排在大流量数据帧之后。
        // 与关闭信号竞争，避免写队列满时 close() 后仍永久挂起。
        let mut closed_rx = shared.closed_tx.subscribe();
        let sent = tokio::select! {
            r = shared.ctrl_tx.send(req.encode()) => r,
            _ = closed_rx.changed() => {
                cleanup_pending(shared, id, &state).await;
                return Err(MuxError::Closed);
            }
        };
        if sent.is_err() {
            cleanup_pending(shared, id, &state).await;
            return Err(MuxError::Closed);
        }

        let result = tokio::select! {
            result = ok_rx => result,
            _ = tokio::time::sleep(OPEN_STREAM_TIMEOUT) => {
                cleanup_pending(shared, id, &state).await;
                return Err(MuxError::ConnRefused(id));
            }
            _ = closed_rx.changed() => {
                cleanup_pending(shared, id, &state).await;
                return Err(MuxError::Closed);
            }
        };

        // 会话关闭与建流结果可能同时就绪；此时统一报告 Closed 以区分“对端拒绝”
        if shared.closed.load(Ordering::Acquire) {
            cleanup_pending(shared, id, &state).await;
            return Err(MuxError::Closed);
        }
        match result {
            Ok(PendingResult::Ok) => Ok(MuxStream { id, state }),
            Ok(PendingResult::Fail) | Err(_) => {
                cleanup_pending(shared, id, &state).await;
                Err(MuxError::ConnRefused(id))
            }
        }
    }

    /// 接受对端主动创建的子流。
    pub async fn accept_stream(&self) -> Result<MuxStream, MuxError> {
        let shared = &self.inner;
        let mut closed_rx = shared.closed_tx.subscribe();
        let mut rx = shared.new_stream_rx.lock().await;
        loop {
            if *closed_rx.borrow_and_update() || shared.closed.load(Ordering::Acquire) {
                return Err(MuxError::Closed);
            }
            tokio::select! {
                maybe = rx.recv() => {
                    return maybe.ok_or(MuxError::Closed);
                }
                result = closed_rx.changed() => {
                    if result.is_err() || *closed_rx.borrow() {
                        return Err(MuxError::Closed);
                    }
                }
            }
        }
    }

    /// 关闭会话：唤醒所有 pending / 子流，停止读写循环，回收路由。
    pub fn close(&self) {
        close_session(&self.inner);
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    /// 等待会话关闭（已关闭则立即返回）。
    pub async fn wait_closed(&self) {
        let mut rx = self.inner.closed_tx.subscribe();
        if *rx.borrow_and_update() {
            return;
        }
        let _ = rx.changed().await;
    }
}

impl Drop for MuxSession {
    fn drop(&mut self) {
        close_session(&self.inner);
    }
}

async fn cleanup_pending(shared: &Arc<SessionShared>, id: i32, state: &Arc<StreamState>) {
    lock_pending(&shared.pending).remove(&id);
    lock_route(&shared.streams).remove(&id);
    // 超时/拒绝：通知对端释放可能已建立的同一 id 子流（未知 id 的 ConnClose 对端会忽略）
    close_stream_sync(state, true);
}

/// 一条 mux 子流（一端视角等同 net.Conn）
pub struct MuxStream {
    pub id: i32,
    state: Arc<StreamState>,
}

impl MuxStream {
    pub fn id(&self) -> i32 {
        self.id
    }

    /// 发送一段数据到对端子流（按 4085 分片并受发送窗口约束）
    pub async fn send_data(&mut self, data: &[u8]) -> std::io::Result<()> {
        send_data_on(&self.state, data).await
    }

    /// 接收一段数据；`None` 表示子流已关闭
    pub async fn recv_data(&mut self) -> Option<Vec<u8>> {
        recv_data_on(&self.state).await
    }

    /// 关闭整条子流（通知对端，双向结束）
    pub fn close(&mut self) {
        close_stream_sync(&self.state, true);
    }

    /// 拆成可分别移入不同 task 的发送/接收半边。
    ///
    /// 拆分本身不关闭子流；两个半边都 Drop 之后（`StreamState` 最后一个
    /// 引用消失）才向对端发 ConnClose，因此一半先结束不会截断另一半。
    pub fn into_split(self) -> (MuxSendHalf, MuxRecvHalf) {
        let id = self.id;
        let send = MuxSendHalf {
            id,
            state: self.state.clone(),
        };
        let recv = MuxRecvHalf {
            id,
            state: self.state,
        };
        (send, recv)
    }
}

/// 子流发送半边（由 `MuxStream::into_split` 产生）
pub struct MuxSendHalf {
    pub id: i32,
    state: Arc<StreamState>,
}

impl MuxSendHalf {
    pub fn id(&self) -> i32 {
        self.id
    }

    pub async fn send_data(&mut self, data: &[u8]) -> std::io::Result<()> {
        send_data_on(&self.state, data).await
    }

    /// 半关闭：只停止本端发送，不影响接收方向、也不向对端发帧。
    ///
    /// Go 协议没有独立的 half-close 帧；若在此发 `muxConnClose`，
    /// 对端会把整条子流关掉，从而截断响应方向（Go `copyConns` 语义是
    /// 上行 EOF 后继续等下行结束）。
    pub fn close(&mut self) {
        self.state.send_closed.store(true, Ordering::Release);
        // 唤醒可能阻塞在等窗口上的发送者
        self.state.avail_tx.send_replace(0);
    }
}

// 注意：MuxSendHalf 不实现 Drop 关闭逻辑——发送半边结束不应关闭子流，
// 接收方向可能仍在工作进行。整条子流由 `StreamState::drop` 收尾。

/// 子流接收半边（由 `MuxStream::into_split` 产生）
pub struct MuxRecvHalf {
    pub id: i32,
    state: Arc<StreamState>,
}

impl MuxRecvHalf {
    pub fn id(&self) -> i32 {
        self.id
    }

    pub async fn recv_data(&mut self) -> Option<Vec<u8>> {
        recv_data_on(&self.state).await
    }
}

/// mux 层错误
#[derive(Debug, thiserror::Error)]
pub enum MuxError {
    #[error("mux 会话已关闭")]
    Closed,
    #[error("mux 建流被对端拒绝或超时: id={0}")]
    ConnRefused(i32),
    #[error("mux 协议错误: {0}")]
    Protocol(String),
}

#[cfg(test)]
mod tests;
