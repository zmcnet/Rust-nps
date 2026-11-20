//! 客户端会话管理：main/chan 双连接、mux 子流接入、断线重连与优雅退出。
//!
//! 连接流程（与真实 Go npc 对齐）：
//! 1. （可选）先走 `conf`/`rgst` 拿到服务端下发的 vkey，见 [`crate::registration`]
//! 2. TCP 连接桥端口，完成 `main` 握手（注册 signal 连接）
//! 3. 再建一条 TCP 连接，完成 `chan` 握手，在其上创建 mux 会话
//! 4. 服务端通过 mux `NewConn` 拨入子流，本端 accept 后按 Link 拨号目标并双向转发
//! 5. main/chan 任一断开 → 关闭 mux、中止全部子流，整体重连（指数退避 + 抖动）

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nps_legacy::mux::MuxSession;
use tokio::net::TcpStream;
use tokio::sync::{watch, Semaphore};
use tokio::task::{JoinError, JoinSet};
use tracing::{debug, info, trace, warn};

use crate::cli::{RunConfig, Target};
use crate::handshake::{client_handshake, HandshakeError, FLAG_CHAN, FLAG_MAIN};
use crate::registration;
use crate::tunnel;

/// 并发子流上限；超过时直接拒绝（丢弃子流即向服务端回 NewConnFail/Close），不会 panic。
pub const MAX_CONCURRENT_STREAMS: usize = 256;

/// 建立到桥端口的 TCP 连接超时。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// main 连接健康帧长度上限（Go `health.go` 用 64 KiB 缓冲）。
const MAX_HEALTH_FRAME_LEN: usize = 64 * 1024;
/// 重连退避下限。
const RECONNECT_MIN: Duration = Duration::from_secs(1);
/// 重连退避上限。
const RECONNECT_MAX: Duration = Duration::from_secs(30);
/// 会话持续在线超过该时长后，下一次断线重新从 1s 开始退避。
const BACKOFF_RESET_AFTER: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("无法连接服务端 {server}：{error}")]
    Unreachable { server: String, error: String },
    #[error("服务端拒绝了认证密钥，请检查 -vkey")]
    VkeyRejected,
    #[error("握手或协议帧非法：{0}")]
    Protocol(String),
    #[error("配置文件错误：{0}")]
    Config(#[from] crate::config::ConfigError),
    #[error("注册/配置上传失败：{0}")]
    Registration(#[from] crate::registration::RegistrationError),
}

impl ClientError {
    pub fn exit_code(&self) -> u8 {
        match self {
            ClientError::Unreachable { .. } => crate::cli::EXIT_UNREACHABLE,
            ClientError::VkeyRejected => crate::cli::EXIT_VKEY_REJECTED,
            ClientError::Protocol(_) => crate::cli::EXIT_PROTOCOL,
            ClientError::Config(error) => error.exit_code(),
            ClientError::Registration(error) => error.exit_code(),
        }
    }
}

enum FatalKind {
    VkeyRejected,
    Protocol(String),
}

struct SessionEnd {
    /// 是否已经完成 main + chan 注册（否则视为首次连接失败）。
    established: bool,
    online: Duration,
    reason: String,
    fatal: Option<FatalKind>,
}

/// 客户端入口：解析启动目标，必要时先完成注册/配置上传，再进入 main+chan 主循环。
pub async fn run(config: RunConfig, shutdown: watch::Receiver<bool>) -> Result<(), ClientError> {
    match config.target {
        Target::Direct {
            server,
            vkey: Some(vkey),
        } => run_loop(server, vkey, true, shutdown).await,
        Target::Direct { server, vkey: None } => {
            // 模式 4：无 vkey，由服务端下发密钥。
            // 注册被拒绝时立即失败（专门退出码），不做无限重试。
            info!(server = %server, "未提供 -vkey，进入注册流程");
            let vkey = registration::negotiate_vkey(&server)
                .await
                .map_err(ClientError::Registration)?;
            run_loop(server, vkey, true, shutdown).await
        }
        Target::ConfigFile { path } => run_config_file(path, shutdown).await,
        Target::Instance { name } => run_instance(name, shutdown).await,
    }
}

/// 实例模式：从 `<data_root>/instances/<name>/config.json` 读取并连接。
///
/// 这是 `install` 注册的自启项实际走的路径（`rnpc run --name <name>`）。
/// 与配置文件模式的区别：
/// - 配置是 rnpc 自己的 `config.json`（含 server/port/vkey），不是原版 npc.conf
/// - 启动时写运行时记录，正常退出时清除（供 `rnpc stop` / `rnpc list` 使用）
async fn run_instance(
    name: String,
    shutdown: watch::Receiver<bool>,
) -> Result<(), ClientError> {
    use crate::instance::{InstancePaths, read_config};

    crate::instance::validate_instance_name(&name).map_err(|e| {
        ClientError::Config(crate::config::ConfigError::Invalid {
            field: "instance".to_owned(),
            reason: e.to_string(),
        })
    })?;
    let root = crate::instance::data_root();
    let paths = InstancePaths::new(&root, &name);
    if !paths.is_installed() {
        return Err(ClientError::Config(crate::config::ConfigError::Invalid {
            field: "instance".to_owned(),
            reason: format!("实例 {name} 未安装；请先运行 rnpc install --name {name}"),
        }));
    }
    let cfg = read_config(&paths.config_path()).map_err(|e| {
        ClientError::Config(crate::config::ConfigError::Read {
            path: paths.config_path().display().to_string(),
            error: e.to_string(),
        })
    })?;
    let server = cfg.server_addr();
    let vkey = if cfg.vkey.is_empty() {
        info!(instance = %name, server = %server, "实例未设置 vkey，进入注册流程");
        let key = registration::negotiate_vkey(&server)
            .await
            .map_err(ClientError::Registration)?;
        // 把服务端下发的 vkey 落盘，避免每次重启都重新注册
        if let Ok(mut updated) = read_config(&paths.config_path()) {
            updated.vkey = key.clone();
            if let Err(e) = crate::instance::write_config(&paths.config_path(), &updated) {
                warn!(instance = %name, error = %e, "回写下发的 vkey 失败（不影响本次运行）");
            }
        }
        key
    } else {
        cfg.vkey.clone()
    };

    info!(instance = %name, server = %server, "实例启动");

    // 写运行时记录（供 stop/list 使用）。失败不阻断启动。
    if let Err(e) = crate::instance::record_runtime(&paths.runtime_path(), &name) {
        warn!(instance = %name, error = %e, "写运行时记录失败（rnpc stop 可能不可用）");
    }

    let result = run_loop(server, vkey, true, shutdown).await;

    // 无论成功失败都清除运行时记录
    if let Err(e) = crate::instance::clear_runtime(&paths.runtime_path()) {
        warn!(instance = %name, error = %e, "清除运行时记录失败");
    }
    result
}

/// 模式 3：读取配置文件 → `conf` 上传 → main+chan 主循环。
async fn run_config_file(
    path: std::path::PathBuf,
    shutdown: watch::Receiver<bool>,
) -> Result<(), ClientError> {
    let text = crate::config::read_text(&path).map_err(ClientError::Config)?;
    let (config, warnings) =
        crate::config::parse_str_with_warnings(&text).map_err(ClientError::Config)?;
    for warning in warnings {
        warn!("{warning}");
    }
    info!(
        server = %config.common.server,
        tasks = config.tasks.len(),
        hosts = config.hosts.len(),
        "配置文件已加载"
    );

    let server = config.common.server.clone();
    let reconnect = config.common.auto_reconnection;
    let vkey = registration::configure(&server, &config)
        .await
        .map_err(ClientError::Registration)?;
    info!(
        server = %server,
        detail = %registration::describe_tasks(&config),
        "配置上传完成，进入 main+chan 运行"
    );
    run_loop(server, vkey, reconnect, shutdown).await
}

/// main+chan 主循环：首次连接失败直接报错退出；已上线后的断线按退避无限重连。
async fn run_loop(
    server: String,
    vkey: String,
    reconnect: bool,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ClientError> {
    let mut attempt: u32 = 0;
    // 只有「从未成功上线」时的连接失败才作为不可达退出；
    // 成功上线后的断线重连必须按退避持续重试。
    let mut ever_established = false;

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }

        let end = run_session(&server, &vkey, &mut shutdown).await;

        if let Some(fatal) = end.fatal {
            return Err(match fatal {
                FatalKind::VkeyRejected => ClientError::VkeyRejected,
                FatalKind::Protocol(message) => ClientError::Protocol(message),
            });
        }

        if *shutdown.borrow() {
            info!("收到退出信号，客户端已停止");
            return Ok(());
        }

        if end.established {
            ever_established = true;
        } else if !ever_established {
            return Err(ClientError::Unreachable {
                server,
                error: end.reason,
            });
        }

        // 配置文件里 auto_reconnection=false：本次会话结束后不再重连，正常退出。
        if !reconnect && end.established {
            info!(reason = %end.reason, "auto_reconnection=false，客户端停止");
            return Ok(());
        }

        if end.established && end.online >= BACKOFF_RESET_AFTER {
            attempt = 0;
        }
        let delay = backoff_delay(attempt);
        attempt = attempt.saturating_add(1);

        warn!(
            reason = %end.reason,
            online_ms = end.online.as_millis() as u64,
            retry_in_ms = delay.as_millis() as u64,
            "连接已断开，准备重连"
        );

        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);
        tokio::select! {
            _ = &mut sleep => {}
            _ = wait_for_shutdown(&mut shutdown) => {
                info!("收到退出信号，停止重连");
                return Ok(());
            }
        }
    }
}

async fn run_session(server: &str, vkey: &str, shutdown: &mut watch::Receiver<bool>) -> SessionEnd {
    let started = Instant::now();

    // ---- 1. main 连接 ----
    let mut main = match dial(server).await {
        Ok(stream) => stream,
        Err(error) => {
            return SessionEnd {
                established: false,
                online: Duration::ZERO,
                reason: format!("main 连接失败: {error}"),
                fatal: None,
            }
        }
    };
    if let Err(error) = client_handshake(&mut main, vkey, FLAG_MAIN).await {
        return handshake_failure("main", error);
    }

    // ---- 2. chan 连接 ----
    let mut chan = match dial(server).await {
        Ok(stream) => stream,
        Err(error) => {
            return SessionEnd {
                established: false,
                online: Duration::ZERO,
                reason: format!("chan 连接失败: {error}"),
                fatal: None,
            }
        }
    };
    if let Err(error) = client_handshake(&mut chan, vkey, FLAG_CHAN).await {
        return handshake_failure("chan", error);
    }

    // ---- 3. mux 会话 + 子流接受 ----
    let mux = Arc::new(MuxSession::new(chan));
    info!(server = %server, "已连接服务端，等待隧道子流");
    trace!(
        max_streams = MAX_CONCURRENT_STREAMS,
        "客户端并发子流上限"
    );

    let mut health = tokio::spawn(read_health_loop(main));
    let mut accept = tokio::spawn(accept_loop(
        mux.clone(),
        Arc::new(Semaphore::new(MAX_CONCURRENT_STREAMS)),
        shutdown.clone(),
    ));

    // `select!` 的胜出分支可能已经把对应 JoinHandle 轮询到完成；
    // 之后再 await 同一个 JoinHandle 会 panic（"polled after completion"），
    // 因此这里用标志记录「accept 任务是否已结束」再决定是否等待。
    let mut accept_done = false;
    let reason = tokio::select! {
        _ = wait_for_shutdown(shutdown) => "收到退出信号".to_owned(),
        result = &mut health => format!("main 连接断开: {}", describe_health_end(result)),
        result = &mut accept => {
            accept_done = true;
            match result {
                Ok(reason) => reason,
                Err(error) => format!("mux 接受任务异常: {error}"),
            }
        }
    };

    // 先关 mux，让子流读端立即返回，避免 shutdown 时泵悬挂。
    mux.close();
    health.abort();
    if !accept_done {
        let _ =
            tokio::time::timeout(Duration::from_secs(3), async { let _ = accept.await; }).await;
    }

    debug!(reason = %reason, "客户端会话结束");
    SessionEnd {
        established: true,
        online: started.elapsed(),
        reason,
        fatal: None,
    }
}

async fn dial(server: &str) -> std::io::Result<TcpStream> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(server))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("连接超时（{}s）", CONNECT_TIMEOUT.as_secs()),
            )
        })??;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

fn handshake_failure(stage: &str, error: HandshakeError) -> SessionEnd {
    let fatal = match &error {
        HandshakeError::VkeyRejected => Some(FatalKind::VkeyRejected),
        HandshakeError::VersionMismatch(_) | HandshakeError::BadStatus(_) => {
            Some(FatalKind::Protocol(format!("{stage} 握手失败: {error}")))
        }
        HandshakeError::Io(_) | HandshakeError::Timeout(_) | HandshakeError::Closed => None,
    };
    SessionEnd {
        established: false,
        online: Duration::ZERO,
        reason: format!("{stage} 握手失败: {error}"),
        fatal,
    }
}

/// 持续读取 main 连接上服务端下发的健康帧并丢弃。
///
/// 帧格式：`int32 LE 长度 + UTF-8 "<target>*#*<0|1>"`，长度必须满足 `0 < len <= 64 KiB`。
async fn read_health_loop(mut stream: TcpStream) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt;

    let mut len_buffer = [0u8; 4];
    loop {
        stream.read_exact(&mut len_buffer).await?;
        let len = i32::from_le_bytes(len_buffer);
        if len <= 0 || len as usize > MAX_HEALTH_FRAME_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("健康帧长度非法: {len}"),
            ));
        }
        let mut payload = vec![0u8; len as usize];
        stream.read_exact(&mut payload).await?;
        match std::str::from_utf8(&payload) {
            Ok(text) => trace!(frame = %text, "收到 main 健康帧，已忽略"),
            Err(_) => trace!(len = len as usize, "收到非 UTF-8 健康帧，已忽略"),
        }
    }
}

fn describe_health_end(result: Result<std::io::Result<()>, JoinError>) -> String {
    match result {
        Ok(Ok(())) => "对端关闭".to_owned(),
        Ok(Err(error)) => error.to_string(),
        Err(error) => format!("读取任务异常: {error}"),
    }
}

/// 接受服务端拨入的 mux 子流；退出时中止所有转发任务。
async fn accept_loop(
    mux: Arc<MuxSession>,
    limiter: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
) -> String {
    let mut tasks: JoinSet<()> = JoinSet::new();

    let reason = loop {
        tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => break "收到退出信号".to_owned(),
            completed = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = completed {
                    warn!(%error, "子流转发任务异常结束");
                }
            }
            accepted = mux.accept_stream() => {
                match accepted {
                    Ok(stream) => {
                        match limiter.clone().try_acquire_owned() {
                            Ok(permit) => {
                                tasks.spawn(async move {
                                    let _permit = permit;
                                    if let Err(error) = tunnel::handle_stream(stream).await {
                                        debug!(%error, "子流已关闭");
                                    }
                                });
                            }
                            Err(_) => {
                                warn!(
                                    limit = MAX_CONCURRENT_STREAMS,
                                    "并发子流数已达上限，拒绝新子流"
                                );
                                // drop 触发 muxConnClose，服务端可立即释放对应连接。
                                drop(stream);
                            }
                        }
                    }
                    Err(error) => break format!("mux 会话结束: {error}"),
                }
            }
        }
    };

    mux.close();
    // 给泵一个短暂的收尾窗口；超时后硬中止，保证 Ctrl+C 后进程能退出。
    let deadline = tokio::time::sleep(Duration::from_secs(3));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => {
                tasks.shutdown().await;
                break;
            }
            completed = tasks.join_next() => match completed {
                None => break,
                Some(Err(error)) => warn!(%error, "子流转发任务异常结束"),
                Some(Ok(())) => {}
            },
        }
    }
    reason
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow_and_update() {
            return;
        }
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

/// 指数退避：1s 起，x2 增长，30s 封顶，并带最多 +20% 抖动（封顶后不再增加）。
pub fn backoff_delay(attempt: u32) -> Duration {
    backoff_delay_with_entropy(attempt, jitter_entropy())
}

fn backoff_delay_with_entropy(attempt: u32, entropy: u64) -> Duration {
    let shift = attempt.min(5);
    let base_ms = (RECONNECT_MIN.as_millis() as u64) << shift;
    let base_ms = base_ms.min(RECONNECT_MAX.as_millis() as u64);
    let jitter_ms = (base_ms / 5).min(entropy % (RECONNECT_MAX.as_millis() as u64 / 5 + 1));
    Duration::from_millis(base_ms.saturating_add(jitter_ms).min(RECONNECT_MAX.as_millis() as u64))
}

fn jitter_entropy() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_starts_at_one_second_and_is_capped() {
        for attempt in 0..64 {
            let delay = backoff_delay_with_entropy(attempt, 0);
            assert!(
                delay >= RECONNECT_MIN && delay <= RECONNECT_MAX,
                "attempt={attempt} delay={delay:?}"
            );
        }
        assert_eq!(backoff_delay_with_entropy(0, 0), RECONNECT_MIN);
        assert_eq!(backoff_delay_with_entropy(1, 0), Duration::from_secs(2));
        assert_eq!(backoff_delay_with_entropy(2, 0), Duration::from_secs(4));
        assert_eq!(backoff_delay_with_entropy(3, 0), Duration::from_secs(8));
        assert_eq!(backoff_delay_with_entropy(4, 0), Duration::from_secs(16));
        assert_eq!(backoff_delay_with_entropy(5, 0), RECONNECT_MAX);
        assert_eq!(backoff_delay_with_entropy(u32::MAX, 0), RECONNECT_MAX);
    }

    #[test]
    fn backoff_jitter_is_bounded() {
        assert_eq!(
            backoff_delay_with_entropy(0, u64::MAX),
            Duration::from_millis(1200)
        );
        assert_eq!(backoff_delay_with_entropy(5, u64::MAX), RECONNECT_MAX);
    }

    #[test]
    fn unreachable_error_never_contains_vkey() {
        let config = RunConfig {
            target: Target::Direct {
                server: "127.0.0.1:1".into(),
                vkey: Some("top-secret".into()),
            },
            conn_type: crate::cli::ConnType::Tcp,
            log_level: "info".into(),
        };
        let error = ClientError::Unreachable {
            server: "127.0.0.1:1".into(),
            error: "connection refused".into(),
        };
        assert!(!error.to_string().contains("top-secret"));
        assert!(!format!("{config:?}").contains("top-secret"));
    }

    #[test]
    fn client_error_exit_codes() {
        assert_eq!(
            ClientError::VkeyRejected.exit_code(),
            crate::cli::EXIT_VKEY_REJECTED
        );
        assert_eq!(
            ClientError::Protocol("x".into()).exit_code(),
            crate::cli::EXIT_PROTOCOL
        );
        assert_eq!(
            ClientError::Registration(crate::registration::RegistrationError::RegisterDenied(
                "x".into()
            ))
            .exit_code(),
            crate::cli::EXIT_REGISTER_DENIED
        );
        assert_eq!(
            ClientError::Config(crate::config::ConfigError::Read {
                path: "x".into(),
                error: "y".into()
            })
            .exit_code(),
            crate::cli::EXIT_CONFIG_FILE
        );
    }
}