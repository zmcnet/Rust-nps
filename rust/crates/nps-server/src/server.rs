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

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
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

        let static_tunnels: Vec<Arc<Tunnel>> = config
            .tunnels
            .iter()
            .cloned()
            .map(Tunnel::new)
            .map(Arc::new)
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

        // ---- 3. 配置文件模式（默认关闭）----
        let shutdown = Arc::new(AtomicBool::new(false));
        let conf = if config.conf_register {
            let listen_host = config
                .conf_listen_host
                .trim()
                .parse()
                .context("conf_listen_host 非法")?;
            let registry = Arc::new(ConfRegistry::new(
                tunnels.clone(),
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

        let clients = config
            .clients
            .iter()
            .map(|c| (c.id, c.name.clone()))
            .collect();
        // config 在此释放：明文 vkey 不进入任何长期存活的服务器状态
        drop(config);

        info!("Rust-nps 服务端启动完成，桥监听 {}", bridge_addr);

        Ok(Self {
            inner: Arc::new(ServerInner {
                bridge,
                bridge_addr,
                clients,
                tunnels,
                conf,
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

    pub fn is_shutdown(&self) -> bool {
        self.inner.shutdown.load(Ordering::Acquire)
    }
}
