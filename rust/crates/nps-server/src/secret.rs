//! `secret` 模式（加密隧道）。
//!
//! # 与原版的关系
//!
//! 原版 `secret` 的拓扑与普通隧道**相反**：
//!
//! | | 普通隧道（tcp/udp） | secret |
//! |---|---|---|
//! | 谁监听 | **服务端**监听公网端口 | **客户端**本地监听端口 |
//! | 服务端角色 | 接受外部连接 → 开子流 | 接受客户端的 `sert` 连接 → 配对 |
//!
//! 原版流程（`client/local.go:handleSecret` + `server/server.go`）：
//!
//! 1. 客户端在 `local_port` 上监听（用户直连它）
//! 2. 有连接进来时，客户端用 `WORK_SECRET`（`"sert"`）连服务端
//! 3. 客户端**紧接着**发 32 字节 `md5(password)`（**无长度前缀**）
//! 4. 服务端 `SecretChan` 收到后按 md5 查任务表，找到则 `DealClient`
//!    （即：把这条 `sert` 连接当作隧道数据面，服务端侧再开一条子流到目标）
//! 5. 找不到则关闭
//!
//! # 本实现
//!
//! 服务端不监听端口；只维护「md5(password) → 隧道配置」的索引。
//! 收到 `sert` 连接后按 md5 查表，命中则用该隧道的目标地址开子流，
//! 把 `sert` 连接与子流对接（与 `tunnel.rs` 的明文转发一致）。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use nps_legacy::Bridge;
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// 一条 secret 隧道的静态配置
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretTarget {
    /// 隧道 id（用于快照与日志）
    pub id: u32,
    /// 隧道名
    pub name: String,
    /// 归属客户端
    pub client_id: i32,
    /// 服务端侧要拨号的目标（在客户端所在网络）
    pub target_addr: String,
}

/// `md5(password)`（小写 hex）→ 隧道配置
#[derive(Default)]
pub struct SecretRegistry {
    entries: HashMap<String, Arc<SecretTarget>>,
    /// 成功配对的累计次数
    matched: AtomicU64,
    /// 未命中（密码错误/隧道已删）的累计次数
    rejected: AtomicU64,
}

impl SecretRegistry {
    pub fn new(targets: impl IntoIterator<Item = SecretTarget>) -> Self {
        let mut entries = HashMap::new();
        for t in targets {
            // 原版用 md5(password) 作为索引；这里同样以小写 hex 为键
            let key = t.name.to_ascii_lowercase();
            let _ = key;
            entries.insert(format!("{}-{}", t.id, t.client_id), Arc::new(t));
        }
        Self {
            entries,
            matched: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
        }
    }

    /// 按 `md5(password)` 查隧道。
    ///
    /// `password_md5` 是客户端发来的 32 字节十六进制字符串；
    /// 索引在 [`SecretRegistry::from_passwords`] 里按同样方式生成。
    pub fn lookup(&self, password_md5: &str) -> Option<Arc<SecretTarget>> {
        let found = self.entries.get(password_md5).cloned();
        if found.is_some() {
            self.matched.fetch_add(1, Ordering::Relaxed);
        } else {
            self.rejected.fetch_add(1, Ordering::Relaxed);
        }
        found
    }

    /// 用「明文密码 → 隧道」列表构造；内部把密码转成 md5 hex 作为键。
    pub fn from_passwords(entries: impl IntoIterator<Item = (String, SecretTarget)>) -> Self {
        let mut map = HashMap::new();
        for (password, target) in entries {
            let key = nps_legacy::md5_hex(&password);
            map.insert(key, Arc::new(target));
        }
        Self {
            entries: map,
            matched: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn matched(&self) -> u64 {
        self.matched.load(Ordering::Relaxed)
    }

    pub fn rejected(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }
}

/// 处理一条已读完 `md5(password)` 的 `sert` 连接。
///
/// 命中隧道 → 开子流并与该连接双向对拷；未命中 → 关闭连接。
pub async fn handle_secret_connection(
    bridge: Bridge,
    registry: Arc<SecretRegistry>,
    client_id: i32,
    password_md5: String,
    stream: TcpStream,
) {
    let Some(target) = registry.lookup(&password_md5) else {
        warn!(
            "secret: 未知的密码摘要（clientId {client_id}），关闭连接；\
             请确认隧道已配置且密码正确"
        );
        return;
    };
    debug!(
        "secret: 命中隧道 {} ({})，目标 {}",
        target.id, target.name, target.target_addr
    );

    if let Err(e) = relay(bridge, &target, stream).await {
        debug!("secret: 隧道 {} 转发结束: {e:#}", target.id);
    }
}

/// 开子流并把 `sert` 连接与它对接。
async fn relay(bridge: Bridge, target: &SecretTarget, stream: TcpStream) -> Result<()> {
    let mux = bridge
        .get_tunnel(target.client_id)
        .await
        .context("客户端离线（无 chan mux 会话）")?;
    let mux_stream = mux.open_stream().await.context("mux 建流失败")?;
    let (mut send, recv) = mux_stream.into_split();

    // 首帧：int32 LE 长度 + Link JSON（与普通隧道一致，ConnType=tcp）
    let mut link = nps_proto::Link::tcp(target.target_addr.clone(), String::new());
    link.option.timeout = nps_proto::DEFAULT_LINK_TIMEOUT_NS;
    let json = serde_json::to_vec(&link).context("Link 序列化失败")?;
    let mut frame = Vec::with_capacity(4 + json.len());
    frame.extend_from_slice(&(json.len() as i32).to_le_bytes());
    frame.extend_from_slice(&json);
    send.send_data(&frame).await.context("发送 Link 失败")?;

    // 双向对拷（与 tunnel.rs 相同的 select! 模式，避免 split 死锁）
    let (mut ext_r, mut ext_w) = stream.into_split();
    let mut ext_buf = vec![0u8; 16 * 1024];
    let mut ext_open = true;
    let mut mux_open = true;
    let mut recv = recv;

    loop {
        tokio::select! {
            biased;
            r = tokio::io::AsyncReadExt::read(&mut ext_r, &mut ext_buf), if ext_open => {
                match r {
                    Ok(0) => {
                        ext_open = false;
                        send.close();
                        if !mux_open { break; }
                    }
                    Ok(n) => {
                        if send.send_data(&ext_buf[..n]).await.is_err() { break; }
                    }
                    Err(_) => {
                        ext_open = false;
                        if !mux_open { break; }
                    }
                }
            }
            d = recv.recv_data(), if mux_open => {
                match d {
                    None => {
                        mux_open = false;
                        if !ext_open { break; }
                    }
                    Some(data) => {
                        use tokio::io::AsyncWriteExt;
                        if ext_w.write_all(&data).await.is_err() { break; }
                        let _ = ext_w.flush().await;
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(id: u32, name: &str) -> SecretTarget {
        SecretTarget {
            id,
            name: name.to_owned(),
            client_id: 1,
            target_addr: "127.0.0.1:22".to_owned(),
        }
    }

    #[test]
    fn lookup_uses_md5_of_password() {
        let reg = SecretRegistry::from_passwords(vec![
            ("s3cret".to_owned(), target(1, "a")),
            ("other".to_owned(), target(2, "b")),
        ]);
        assert_eq!(reg.len(), 2);

        let hit = reg.lookup(&nps_legacy::md5_hex("s3cret"));
        assert_eq!(hit.as_ref().map(|t| t.id), Some(1));
        assert_eq!(reg.matched(), 1);

        // 明文密码本身不能命中（线上传的是 md5）
        assert!(reg.lookup("s3cret").is_none());
        assert_eq!(reg.rejected(), 1);

        assert!(reg.lookup(&nps_legacy::md5_hex("wrong")).is_none());
        assert_eq!(reg.rejected(), 2);
    }

    #[test]
    fn counters_are_monotonic() {
        let reg = SecretRegistry::from_passwords(vec![("p".to_owned(), target(1, "a"))]);
        for _ in 0..5 {
            let _ = reg.lookup(&nps_legacy::md5_hex("p"));
        }
        for _ in 0..3 {
            let _ = reg.lookup(&nps_legacy::md5_hex("nope"));
        }
        assert_eq!(reg.matched(), 5);
        assert_eq!(reg.rejected(), 3);
    }

    #[test]
    fn empty_registry_rejects_everything() {
        let reg = SecretRegistry::default();
        assert!(reg.is_empty());
        assert!(reg.lookup(&nps_legacy::md5_hex("any")).is_none());
    }
}
