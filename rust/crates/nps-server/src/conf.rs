//! 配置文件模式（老 npc `-config`）隧道注册。
//!
//! 对齐 Go `bridge/bridge.go:getConfig`，只实现 **TCP 隧道**子集：
//!
//! ```text
//! 服务端 -> 客户端   1B      isPub（bool，本实现恒为 0/false）
//! 循环（客户端 -> 服务端）：
//!   4B flag + int32 LE len + JSON   flag = "task" | "host" | "conf"
//!   4B flag + 32B md5(vkey)         flag = "stus"
//! 服务端 -> 客户端   1B      task/host/conf 的应答（true/false）
//! 服务端 -> 客户端   int32 LE len + "remark*#*remark*#*"   stus 的应答
//! ```
//!
//! 为什么 `isPub` 恒为 false：本实现**不动态创建客户端**、不生成新 vkey。
//! 客户端必须使用服务端 `clients` 中已配置的 vkey 完成握手；`isPub=false`
//! 时原版 npc 会跳过 `NEW_CONF`，直接上报 host/task，并用同一 vkey 建立
//! `main`/`chan` 连接。这既避免伪造密钥，也让注册隧道天然归属到该 client id。
//! 若对端仍发 `NEW_CONF`（`isPub=true` 的客户端），返回 false 并关闭连接。
//!
//! ## 安全约定
//! - 会话内的 JSON **绝不整体写日志**：`file.Client` / `file.Tunnel` 的 JSON
//!   里带 `VerifyKey`（vkey 明文），`stus` 的 32 字节是 md5(vkey)。日志只写
//!   remark / 端口 / 目标地址这类可公开字段。
//! - 快照与错误信息不含 vkey / md5(vkey)。
//! - 注册隧道只存内存：`rnps` 重启后失效（无持久化数据库）。
//! - 注册隧道与配置隧道共用 [`Tunnel`]，连接计数（`ActiveGuard`）、字节统计、
//!   启停、关闭全部走同一套逻辑，不存在绕过统计的第二套实现。
//!
//! ## 限制
//! - 每个任务段只支持**单个端口**与**单个目标**；多端口/多目标返回 false。
//! - 只支持 `mode=tcp`（大小写敏感，与 Go 一致）；udp/http/https/socks5/file/
//!   secret/p2p 一律返回 false。
//! - 监听 IP 由服务端配置 `conf_listen_host` 决定，忽略客户端上报的
//!   `ServerIp`（避免客户端指定绑定网卡）。
//! - 特权端口（<1024）直接拒绝；端口被占用时返回 false（原因写进日志与
//!   `last_error`）。

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nps_legacy::bridge::{ConfSession, ConfSessionHandler};
use nps_legacy::Bridge;
use nps_proto::CONN_DATA_SEQ;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{watch, Mutex};
use tracing::{debug, info, warn};

use crate::config::{validate_host_port, TcpTunnelConfig, CONF_MIN_LISTEN_PORT};
use crate::tunnel::Tunnel;

/// 单个 `conf` 帧（JSON）的长度上限，对齐 Go `common.BufPoolMax`（64 KiB）。
const MAX_CONF_FRAME: usize = 64 * 1024;
/// 单次读取的空闲上限：原版 npc 注册完就关闭 conf 连接，超过该时间没有任何
/// 帧说明对端异常，直接关闭以回收任务/内存（不无限挂起）。
const CONF_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// 单个任务最多接受的端口数（多端口本阶段不支持，仅用于拒绝前的粗校验）
const MAX_TASK_PORTS: usize = 16;
/// 注册隧道名（remark）的最大长度，避免异常客户端把日志/UI 撑爆
const MAX_NAME_LEN: usize = 128;

/// 配置文件模式注册表：与 [`crate::server::Server`] 共享隧道表。
pub(crate) struct ConfRegistry {
    inner: Arc<Inner>,
}

struct Inner {
    /// 与 Server 共享的隧道表（配置隧道在前、注册隧道追加）
    tunnels: Arc<Mutex<Vec<Arc<Tunnel>>>>,
    /// 与 Server 共享的 UDP 隧道表（conf 注册的 UDP 任务追加到这里）
    udp_tunnels: Arc<Mutex<Vec<Arc<crate::udp::UdpTunnel>>>>,
    /// md5(vkey) -> client id，仅用于 `stus` 帧校验归属（不写日志、不进快照）
    verify: Arc<std::collections::HashMap<String, i32>>,
    /// 注册隧道的监听 IP（客户端只上报端口）
    listen_host: IpAddr,
    /// 隧道总数上限（含配置内的静态隧道）
    max_tunnels: usize,
    /// 注册隧道的 id 分配器（从静态隧道最大 id + 1 起）
    next_id: AtomicU32,
    /// 服务端关闭标志
    shutdown: Arc<AtomicBool>,
    /// 串行化注册，保证「检查上限/端口 -> 绑定 -> 入表」不互相踩踏
    register_op: Mutex<()>,
    /// 当前活跃的 conf 会话数（shutdown 时等待其退出）
    active_sessions: AtomicUsize,
}

impl ConfRegistry {
    pub(crate) fn new(
        tunnels: Arc<Mutex<Vec<Arc<Tunnel>>>>,
        udp_tunnels: Arc<Mutex<Vec<Arc<crate::udp::UdpTunnel>>>>,
        verify: Arc<std::collections::HashMap<String, i32>>,
        listen_host: IpAddr,
        max_tunnels: usize,
        first_dynamic_id: u32,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                tunnels,
                udp_tunnels,
                verify,
                listen_host,
                max_tunnels,
                next_id: AtomicU32::new(first_dynamic_id),
                shutdown,
                register_op: Mutex::new(()),
                active_sessions: AtomicUsize::new(0),
            }),
        }
    }

    /// 当前活跃的 conf 会话数
    pub(crate) fn active_sessions(&self) -> usize {
        self.inner.active_sessions.load(Ordering::Acquire)
    }

    /// 取得注册串行锁。
    ///
    /// 关闭流程必须拿它：否则「注册已通过上限/端口检查 → 关闭流程取完隧道列表
    /// → 注册才 push」会让一条新隧道在 shutdown 之后仍然监听。持有该锁期间
    /// 关闭标志先置位，注册路径会看到标志并放弃，两者不会交错。
    pub(crate) async fn lock_register(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.inner.register_op.lock().await
    }

    /// 处理一个 `conf` 会话（握手与 vkey 鉴权已在桥内完成）。
    async fn serve(&self, session: ConfSession) {
        let ConfSession {
            client_id,
            client_version,
            peer,
            mut stream,
            bridge,
            mut closing,
        } = session;

        if *closing.borrow() || self.inner.shutdown.load(Ordering::Acquire) {
            return;
        }
        self.inner.active_sessions.fetch_add(1, Ordering::AcqRel);
        debug!("配置文件模式会话开始 (clientId {client_id}, client {client_version}, from {peer})");

        // ① isPub = false（1 字节 bool）。见模块注释：不动态创建客户端。
        if stream.write_all(&[0u8]).await.is_err() {
            self.inner.active_sessions.fetch_sub(1, Ordering::AcqRel);
            return;
        }

        loop {
            let flag = tokio::select! {
                _ = closing.changed() => break,
                r = tokio::time::timeout(CONF_IDLE_TIMEOUT, nps_legacy::read_flag(&mut stream)) => {
                    match r {
                        Ok(Ok(flag)) => flag,
                        // 客户端注册完成后会主动关闭连接（Go: c.Close()）
                        Ok(Err(_)) => break,
                        Err(_) => {
                            debug!("配置文件模式会话空闲超时 (clientId {client_id})");
                            break;
                        }
                    }
                }
            };

            match &flag {
                b"task" => {
                    let Some(body) = read_frame(&mut stream, &mut closing).await else {
                        break;
                    };
                    let outcome = match serde_json::from_slice::<TaskInfo>(&body) {
                        Ok(info) => self.register_task(&bridge, client_id, &info).await,
                        // 不打印 body：里面可能带 VerifyKey
                        Err(_) => Err("task 帧 JSON 无法解析".to_owned()),
                    };
                    match &outcome {
                        Ok(registered) => {
                            let action = if registered.created {
                                "注册"
                            } else {
                                "幂等复用"
                            };
                            info!(
                                "配置文件模式{action}隧道成功 (clientId {client_id}, tunnel {}, {})",
                                registered.id, registered.describe
                            );
                        }
                        Err(reason) => {
                            warn!("配置文件模式注册隧道失败 (clientId {client_id}): {reason}");
                        }
                    }
                    if write_bool(&mut stream, outcome.is_ok()).await.is_err() || outcome.is_err() {
                        // 对齐 Go `WriteAddFail`：失败后关闭连接
                        break;
                    }
                }
                b"host" => {
                    // 域名代理本阶段未实现：吃掉帧保持协议同步，然后如实返回失败。
                    let _ = read_frame(&mut stream, &mut closing).await;
                    warn!(
                        "配置文件模式的域名代理（host）尚未实现，返回失败 (clientId {client_id})"
                    );
                    let _ = write_bool(&mut stream, false).await;
                    break;
                }
                b"conf" => {
                    // NEW_CONF 只在 isPub=true 时由客户端发送；本实现不创建客户端。
                    let _ = read_frame(&mut stream, &mut closing).await;
                    warn!(
                        "配置文件模式不支持动态创建客户端（isPub=false），返回失败 (clientId {client_id})"
                    );
                    let _ = write_bool(&mut stream, false).await;
                    break;
                }
                b"stus" => {
                    // 32 字节 md5(vkey)，无长度前缀。**不得**写日志/回显。
                    let mut digest = [0u8; 32];
                    let read = tokio::select! {
                        _ = closing.changed() => break,
                        r = tokio::time::timeout(
                            CONF_IDLE_TIMEOUT,
                            stream.read_exact(&mut digest),
                        ) => match r {
                            Ok(r) => r,
                            Err(_) => break,
                        },
                    };
                    if read.is_err() {
                        break;
                    }
                    match self.status_payload(&digest, client_id).await {
                        Some(payload) => {
                            if nps_legacy::write_len_content(&mut stream, &payload)
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        None => {
                            warn!(
                                "配置文件模式状态查询失败：vkey 归属与当前连接不一致 (clientId {client_id})"
                            );
                            break;
                        }
                    }
                }
                other => {
                    // 未知 flag：无法保证后续帧边界，直接关闭（只打印 hex，避免日志注入）
                    warn!(
                        "配置文件模式收到未知 flag {:02x?}，关闭连接 (clientId {client_id})",
                        other
                    );
                    break;
                }
            }
        }

        let _ = stream.shutdown().await;
        self.inner.active_sessions.fetch_sub(1, Ordering::AcqRel);
        debug!("配置文件模式会话结束 (clientId {client_id})");
    }

    /// 处理一条 `task` 帧。
    ///
    /// 返回 `Ok(Registered)` 表示该端口已可用（新建或幂等复用）；
    /// 返回 `Err(reason)` 时调用方回 false 并关闭连接（对齐 Go）。
    async fn register_task(
        &self,
        bridge: &Bridge,
        client_id: i32,
        info: &TaskInfo,
    ) -> Result<Registered, String> {
        match info.mode.as_str() {
            "" | "tcp" => self.register_tcp_task(bridge, client_id, info).await,
            "udp" => self.register_udp_task(bridge, client_id, info).await,
            other => Err(format!(
                "暂不支持 mode={other:?}（当前支持 tcp / udp）"
            )),
        }
    }

    /// 注册一条 UDP 隧道。
    ///
    /// 对齐 Go `bridge.go` 的 `NEW_TASK` 处理：原版对每个端口调 `s.OpenTask <- tl`，
    /// 即**真的创建监听器**（`NewMode` 按 `mode` 选 `UdpModeServer`），
    /// 所以这里也必须真正建 UDP 监听，而不是只回 true。
    async fn register_udp_task(
        &self,
        bridge: &Bridge,
        client_id: i32,
        info: &TaskInfo,
    ) -> Result<Registered, String> {
        let ports = parse_ports(&info.ports, info.port);
        if ports.is_empty() {
            return Err("server_port 缺失或非法".to_owned());
        }
        if ports.len() > 1 {
            return Err(format!(
                "多端口任务未支持（收到 {} 个端口，请拆成多个配置段）",
                ports.len()
            ));
        }
        let port = ports[0];
        if port < CONF_MIN_LISTEN_PORT {
            return Err(format!(
                "端口 {port} 是特权端口（<{CONF_MIN_LISTEN_PORT}），拒绝监听"
            ));
        }
        let target = resolve_target(info)?;
        let name = display_name(&info.remark, port);
        if name.is_empty() {
            return Err("隧道名（remark）清洗后为空".to_owned());
        }
        let listen = SocketAddr::new(self.inner.listen_host, port);

        let _serial = self.inner.register_op.lock().await;
        if self.inner.shutdown.load(Ordering::Acquire) {
            return Err("服务端正在关闭".to_owned());
        }

        let existing_udp = self.inner.udp_tunnels.lock().await.clone();
        let existing_tcp = self.inner.tunnels.lock().await.clone();

        // ① 幂等：同 client + 同 remark + 同端口 + 同目标 -> 复用
        if let Some(prev) = existing_udp
            .iter()
            .find(|t| same_udp_identity(t, client_id, &name, port, &target))
        {
            let id = t_id(prev);
            if prev.is_listening().await {
                return Ok(Registered {
                    id,
                    created: false,
                    describe: format!("{listen}/udp -> {target}（已在运行）"),
                });
            }
            // 存在但未监听：重新启动
            prev.start(bridge.clone())
                .await
                .map_err(|e| format!("重新启动 UDP 隧道 {id} 失败: {e:#}"))?;
            info!("配置文件模式重新启动已存在的 UDP 隧道 {id} ({name}) 监听 {listen}");
            return Ok(Registered {
                id,
                created: false,
                describe: format!("{listen}/udp -> {target}（重新启动）"),
            });
        }

        // ② 端口冲突：TCP 与 UDP 共享同一 IP:port 是允许的（协议不同），
        //    但同一协议内不允许重复。
        for t in &existing_udp {
            if parse_listen_addr(&t.cfg.listen_addr) == Some(listen) && t.is_listening().await {
                return Err(format!(
                    "UDP 端口 {listen} 已被隧道 {} ({}) 占用",
                    t_id(t),
                    t.cfg.name
                ));
            }
        }
        let _ = &existing_tcp; // TCP 同端口不冲突，仅保留以表明这是有意为之

        // ③ 总数上限
        if existing_udp.len() + existing_tcp.len() >= self.inner.max_tunnels {
            return Err(format!(
                "隧道总数已达上限 {}（conf_max_tunnels）",
                self.inner.max_tunnels
            ));
        }

        // ④ 分配 id、建 UdpTunnel、绑定并启动
        let id = self
            .inner
            .next_id
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .map_err(|_| "隧道 id 已耗尽".to_owned())?;
        let tunnel = Arc::new(crate::udp::UdpTunnel::new(
            crate::config::UdpTunnelConfig {
                id,
                name: name.clone(),
                client_id,
                listen_addr: listen.to_string(),
                target_addr: target.clone(),
                enabled: true,
                idle_timeout_secs: crate::config::DEFAULT_UDP_IDLE_SECS,
                max_sessions: crate::config::DEFAULT_UDP_MAX_SESSIONS,
            },
        ));
        let bound = tunnel
            .start(bridge.clone())
            .await
            .map_err(|e| format!("UDP 监听 {listen} 失败: {e:#}"))?;
        self.inner.udp_tunnels.lock().await.push(tunnel);
        Ok(Registered {
            id,
            created: true,
            describe: format!("{bound}/udp -> {target}"),
        })
    }

    async fn register_tcp_task(
        &self,
        bridge: &Bridge,
        client_id: i32,
        info: &TaskInfo,
    ) -> Result<Registered, String> {
        let ports = parse_ports(&info.ports, info.port);
        if ports.is_empty() {
            return Err("server_port 缺失或非法".to_owned());
        }
        if ports.len() > 1 {
            return Err(format!(
                "多端口任务未支持（收到 {} 个端口，请拆成多个配置段）",
                ports.len()
            ));
        }
        let port = ports[0];
        if port < CONF_MIN_LISTEN_PORT {
            return Err(format!(
                "端口 {port} 是特权端口（<{CONF_MIN_LISTEN_PORT}），拒绝监听"
            ));
        }

        let target = resolve_target(info)?;
        let name = display_name(&info.remark, port);
        if name.is_empty() {
            return Err("隧道名（remark）清洗后为空".to_owned());
        }
        let listen = SocketAddr::new(self.inner.listen_host, port);

        // 串行化注册：上限检查 + 端口检查 + 绑定 + 入表 必须原子
        let _serial = self.inner.register_op.lock().await;
        if self.inner.shutdown.load(Ordering::Acquire) {
            return Err("服务端正在关闭".to_owned());
        }

        let existing = self.inner.tunnels.lock().await.clone();

        // ① 幂等：同 client + 同 remark + 同端口 + 同目标 -> 不重复建监听
        if let Some(prev) = existing
            .iter()
            .find(|t| same_identity(t, client_id, &name, port, &target))
        {
            let id = prev.id();
            if prev.is_listening().await {
                return Ok(Registered {
                    id,
                    created: false,
                    describe: format!("{listen} -> {target}（已在运行）"),
                });
            }
            // 存在但被停用（例如管理端手工停用）：重新启用而不是新建
            let _guard = prev.lock_op().await;
            prev.enable(bridge.clone())
                .await
                .map_err(|e| format!("重新启用隧道 {id} 失败: {e:#}"))?;
            drop(_guard);
            info!("配置文件模式重新启用已存在的隧道 {id} ({name}) 监听 {listen}");
            return Ok(Registered {
                id,
                created: false,
                describe: format!("{listen} -> {target}（重新启用）"),
            });
        }

        // ② 端口冲突：本进程内已有隧道在监听同一 IP:port
        for t in &existing {
            if parse_listen_addr(&t.cfg.listen_addr) == Some(listen) && t.is_listening().await {
                return Err(format!(
                    "端口 {listen} 已被隧道 {} ({}) 占用",
                    t.id(),
                    t.cfg.name
                ));
            }
        }

        // ③ 总数上限（含配置内的静态隧道）
        if existing.len() >= self.inner.max_tunnels {
            return Err(format!(
                "隧道总数已达上限 {}（conf_max_tunnels）",
                self.inner.max_tunnels
            ));
        }

        // ④ 分配 id、建 Tunnel、绑定并启动监听（绑定失败 = 端口被外部占用）
        let id = self
            .inner
            .next_id
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .map_err(|_| "隧道 id 已耗尽".to_owned())?;
        let tunnel = Arc::new(Tunnel::new(TcpTunnelConfig {
            id,
            name: name.clone(),
            client_id,
            listen_addr: listen.to_string(),
            target_addr: target.clone(),
            enabled: true,
        }));
        {
            let _guard = tunnel.lock_op().await;
            tunnel
                .enable(bridge.clone())
                .await
                .map_err(|e| format!("监听 {listen} 失败: {e:#}"))?;
        }
        self.inner.tunnels.lock().await.push(tunnel);
        Ok(Registered {
            id,
            created: true,
            describe: format!("{listen} -> {target}"),
        })
    }

    /// 构造 `stus` 的应答载荷：该客户端当前正在监听的隧道 remark 列表，
    /// 每个 remark 后跟 `*#*`（与 Go 版拼接方式一致）。
    ///
    /// `digest` 必须是当前连接所用 vkey 的 md5，否则返回 `None`（防止越权查询）。
    async fn status_payload(&self, digest: &[u8; 32], client_id: i32) -> Option<Vec<u8>> {
        let text = std::str::from_utf8(digest).ok()?;
        if self.inner.verify.get(text).copied() != Some(client_id) {
            return None;
        }
        let list = self.inner.tunnels.lock().await.clone();
        let mut out = String::new();
        for t in list {
            if t.cfg.client_id != client_id {
                continue;
            }
            if t.is_listening().await {
                out.push_str(&t.cfg.name);
                out.push_str(CONN_DATA_SEQ);
            }
        }
        Some(out.into_bytes())
    }
}

impl ConfSessionHandler for ConfRegistry {
    fn handle(&self, session: ConfSession) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(self.serve(session))
    }
}

/// 一次成功注册的结果
struct Registered {
    id: u32,
    created: bool,
    /// 仅用于日志的可读描述（listen -> target）
    describe: String,
}

/// `task` 帧里用到的字段（Go `file.Tunnel`，无 json tag，字段名即 JSON key）
#[derive(Debug, Default, Deserialize)]
struct TaskInfo {
    /// `server_port`，如 `"6000"`；保留字符串形态以兼容范围/列表语法
    #[serde(default, rename = "Ports")]
    ports: String,
    /// 兜底字段（部分客户端只填 Port）
    #[serde(default, rename = "Port")]
    port: i64,
    #[serde(default, rename = "Mode")]
    mode: String,
    #[serde(default, rename = "Remark")]
    remark: String,
    /// `target_ip`（可选，配合 target 里的裸端口）
    #[serde(default, rename = "TargetAddr")]
    target_addr: String,
    #[serde(default, rename = "Target")]
    target: Option<TargetInfo>,
}

#[derive(Debug, Default, Deserialize)]
struct TargetInfo {
    /// `target_addr` / `target_port`（config 解析后逗号会变成换行）
    #[serde(default, rename = "TargetStr")]
    target_str: String,
}

/// 读一个 `flag` 之后的帧体：int32 LE 长度 + 内容。
///
/// 长度必须落在 `1..=64 KiB`（对齐 Go `ReadLen`：`cLen <= 0 || cLen > len(buf)`
/// 视为错误），超限直接返回 `None` 让调用方关闭连接，绝不按声明长度预分配。
async fn read_frame(
    stream: &mut TcpStream,
    closing: &mut watch::Receiver<bool>,
) -> Option<Vec<u8>> {
    let len = tokio::select! {
        _ = closing.changed() => return None,
        r = tokio::time::timeout(CONF_IDLE_TIMEOUT, nps_legacy::read_len_i32(stream)) => {
            match r {
                Ok(r) => r.ok()?,
                Err(_) => return None,
            }
        }
    };
    if len <= 0 || len as usize > MAX_CONF_FRAME {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    tokio::select! {
        _ = closing.changed() => None,
        r = tokio::time::timeout(CONF_IDLE_TIMEOUT, stream.read_exact(&mut buf)) => {
            match r {
                Ok(r) => r.ok().map(|_| buf),
                Err(_) => None,
            }
        }
    }
}

/// 写 1 字节 bool 应答（Go `binary.Write(c, LittleEndian, bool)` = 1 字节 0/1）
async fn write_bool<W: AsyncWrite + Unpin>(stream: &mut W, ok: bool) -> std::io::Result<()> {
    stream.write_all(&[u8::from(ok)]).await?;
    stream.flush().await
}

/// 解析 `server_port` 语法（对齐 Go `common.GetPorts`：逗号分隔 + `a-b` 范围）。
///
/// `spec` 为空时回退到 `single`（`Port` 字段）。范围长度设上限，避免异常输入
/// （如 `1-65000`）产生大量待注册端口。
fn parse_ports(spec: &str, single: i64) -> Vec<u16> {
    let mut out: Vec<u16> = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let (Ok(start), Ok(end)) = (a.trim().parse::<u32>(), b.trim().parse::<u32>()) else {
                continue;
            };
            if start == 0 || end < start || end > 65535 || end - start >= MAX_TASK_PORTS as u32 {
                continue;
            }
            for p in start..=end {
                if out.len() >= MAX_TASK_PORTS {
                    break;
                }
                out.push(p as u16);
            }
        } else if let Ok(p) = part.parse::<u16>() {
            if p != 0 && out.len() < MAX_TASK_PORTS {
                out.push(p);
            }
        }
    }
    if out.is_empty() && (1..=65535).contains(&single) {
        out.push(single as u16);
    }
    out
}

/// 解析目标地址：`Target.TargetStr`（host:port）优先；只有裸端口时用
/// `TargetAddr`（target_ip）补齐。多目标/缺端口一律拒绝。
fn resolve_target(info: &TaskInfo) -> Result<String, String> {
    let raw = info
        .target
        .as_ref()
        .map(|t| t.target_str.as_str())
        .unwrap_or("");
    let entries: Vec<&str> = raw
        .split(|c| c == ',' || c == '\n')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if entries.len() > 1 {
        return Err("多目标（逗号/换行分隔）未支持".to_owned());
    }
    let ip = info.target_addr.trim();
    let target = match entries.first() {
        Some(entry) if entry.contains(':') => (*entry).to_owned(),
        Some(entry) if !ip.is_empty() => format!("{ip}:{entry}"),
        Some(_) => return Err("目标地址缺少主机部分（请写 host:port 或配置 target_ip）".into()),
        None if !ip.is_empty() => return Err("目标地址缺少端口".into()),
        None => return Err("缺少目标地址（target_addr）".into()),
    };
    validate_host_port(&target).map_err(|e| format!("目标地址非法: {e:#}"))?;
    Ok(target)
}

/// 隧道名：remark 去掉控制字符并限长；空 remark 用 `conf-<port>`。
fn display_name(remark: &str, port: u16) -> String {
    let cleaned: String = remark
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME_LEN)
        .collect();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        format!("conf-{port}")
    } else {
        cleaned.to_owned()
    }
}

/// 是否是同一客户端重复注册的同一条隧道（remark + 端口 + 目标）
fn same_identity(t: &Tunnel, client_id: i32, name: &str, port: u16, target: &str) -> bool {
    t.cfg.client_id == client_id
        && t.cfg.name == name
        && t.cfg.target_addr == target
        && parse_listen_addr(&t.cfg.listen_addr).map(|a| a.port()) == Some(port)
}

/// UDP 隧道的身份比较（与 TCP 版同语义，但作用在 `UdpTunnel` 上）
fn same_udp_identity(
    t: &crate::udp::UdpTunnel,
    client_id: i32,
    name: &str,
    port: u16,
    target: &str,
) -> bool {
    t.cfg.client_id == client_id
        && t.cfg.name == name
        && t.cfg.target_addr == target
        && parse_listen_addr(&t.cfg.listen_addr).map(|a| a.port()) == Some(port)
}

/// 取 UDP 隧道 id（`UdpTunnel::id()` 已有，这里只是让调用处更简洁）
fn t_id(t: &crate::udp::UdpTunnel) -> u32 {
    t.id()
}

fn parse_listen_addr(addr: &str) -> Option<SocketAddr> {
    addr.parse::<SocketAddr>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ports_accepts_go_syntax() {
        assert_eq!(parse_ports("6000", 0), vec![6000]);
        assert_eq!(parse_ports("6000,6001", 0), vec![6000, 6001]);
        assert_eq!(parse_ports("6000-6002", 0), vec![6000, 6001, 6002]);
        assert_eq!(parse_ports("", 6005), vec![6005]);
        assert!(parse_ports("", 0).is_empty());
        assert!(parse_ports("abc", 0).is_empty());
        // 0 端口 / 越界 / 过宽范围都被拒
        assert!(parse_ports("0", 0).is_empty());
        assert!(parse_ports("70000", 0).is_empty());
        assert!(parse_ports("1-65000", 0).len() <= MAX_TASK_PORTS);
    }

    #[test]
    fn resolve_target_prefers_host_port_and_requires_valid_form() {
        let mut info = TaskInfo {
            target: Some(TargetInfo {
                target_str: "127.0.0.1:22".into(),
            }),
            ..Default::default()
        };
        assert_eq!(resolve_target(&info).unwrap(), "127.0.0.1:22");

        // 裸端口 + target_ip
        info.target_addr = "10.0.0.5".into();
        info.target.as_mut().unwrap().target_str = "22".into();
        assert_eq!(resolve_target(&info).unwrap(), "10.0.0.5:22");

        // 缺端口 / 缺目标 / 多目标
        info.target_addr.clear();
        assert!(resolve_target(&info).is_err());
        info.target.as_mut().unwrap().target_str = "a:1,b:2".into();
        assert!(resolve_target(&info).is_err());
        info.target = None;
        assert!(resolve_target(&info).is_err());
    }

    #[test]
    fn display_name_strips_control_chars_and_bounds_length() {
        assert_eq!(display_name("ssh", 6000), "ssh");
        assert_eq!(display_name("  ", 6000), "conf-6000");
        assert_eq!(display_name("a\r\nb", 6000), "ab");
        let long = "x".repeat(500);
        assert_eq!(display_name(&long, 6000).len(), MAX_NAME_LEN);
    }

    /// 独立字节样例：Go `binary.Write(c, LittleEndian, false)` 是单个 0x00，
    /// `true` 是单个 0x01；客户端 `GetAddStatus` 只读 1 字节。
    #[tokio::test]
    async fn bool_reply_is_one_byte_little_endian() {
        let (mut a, mut b) = tokio::io::duplex(16);
        write_bool(&mut a, true).await.unwrap();
        write_bool(&mut a, false).await.unwrap();
        let mut buf = [0u8; 2];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [1, 0]);
    }
}
