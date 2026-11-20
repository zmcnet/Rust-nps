//! 累计流量持久化。
//!
//! 原版 nps 用 `flow_store_interval`（分钟）定时把流量落盘到 JSON 数据库。
//! 我们的架构是「JSON 配置 + 内存态」，因此单独维护一个 `flow.json`：
//!
//! - 启动时读回，恢复到各隧道计数器；
//! - 运行期定时写盘（默认 5 分钟，可配 0 关闭）；
//! - 优雅关闭时再写一次。
//!
//! 文件很小（每隧道两个 u64），写入用「临时文件 + 原子改名」，
//! 避免断电/崩溃留下半截 JSON。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// 默认落盘间隔（分钟）。对齐原版语义：0 表示不落盘。
pub const DEFAULT_FLOW_STORE_INTERVAL_MIN: u64 = 5;

/// 单条隧道的累计流量
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowRecord {
    /// 服务端 -> 客户端方向累计字节
    #[serde(default)]
    pub bytes_to_client: u64,
    /// 客户端 -> 服务端方向累计字节
    #[serde(default)]
    pub bytes_from_client: u64,
}

/// 落盘文件的内容。用 `BTreeMap` 保证输出稳定（便于 diff 与人工查看）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowSnapshot {
    /// 版本号，便于将来迁移
    #[serde(default = "default_version")]
    pub version: u32,
    /// 隧道 id -> 累计流量
    #[serde(default)]
    pub tunnels: BTreeMap<u32, FlowRecord>,
}

fn default_version() -> u32 {
    1
}

/// 流量持久化器
#[derive(Debug, Clone)]
pub struct FlowStore {
    path: PathBuf,
}

impl FlowStore {
    /// 指定落盘路径（通常是 `<data_dir>/flow.json`）
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 读回已保存的流量。
    ///
    /// 文件不存在视为「首次启动」，返回空快照而不是错误；
    /// 文件损坏则记录警告并返回空快照——**不阻塞启动**，
    /// 因为流量统计的准确性低于服务可用性。
    pub fn load(&self) -> FlowSnapshot {
        let raw = match std::fs::read(&self.path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!("流量文件不存在，按首次启动处理: {}", self.path.display());
                return FlowSnapshot::default();
            }
            Err(e) => {
                warn!("读取流量文件失败（按空处理）: {} ({e})", self.path.display());
                return FlowSnapshot::default();
            }
        };
        match serde_json::from_slice::<FlowSnapshot>(&raw) {
            Ok(snap) => {
                debug!(
                    "已读回 {} 条隧道的累计流量: {}",
                    snap.tunnels.len(),
                    self.path.display()
                );
                snap
            }
            Err(e) => {
                warn!(
                    "流量文件格式无效（按空处理，不会覆盖原文件直到下次写入）: {} ({e})",
                    self.path.display()
                );
                FlowSnapshot::default()
            }
        }
    }

    /// 原子写入：先写临时文件，再改名。
    pub fn save(&self, snapshot: &FlowSnapshot) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("无法创建流量文件目录 {}", parent.display()))?;
            }
        }
        let json = serde_json::to_vec_pretty(snapshot).context("序列化流量快照失败")?;

        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, &json)
            .with_context(|| format!("写入临时流量文件失败: {}", tmp.display()))?;
        // Windows 上 rename 到已存在文件会失败，先删
        if self.path.exists() {
            let _ = std::fs::remove_file(&self.path);
        }
        std::fs::rename(&tmp, &self.path).with_context(|| {
            format!(
                "替换流量文件失败: {} -> {}",
                tmp.display(),
                self.path.display()
            )
        })?;
        debug!("流量已落盘: {}", self.path.display());
        Ok(())
    }
}

/// 定时落盘循环。
///
/// `collect` 每次调用返回当前全量快照；`interval_min == 0` 时立即返回
/// （表示不启用持久化）。收到 cancel 后**再写一次**才退出，
/// 保证关闭前的最后一段流量不丢。
pub async fn run_flow_store_loop<F>(
    store: FlowStore,
    interval_min: u64,
    mut cancel: tokio::sync::watch::Receiver<bool>,
    collect: F,
) where
    F: Fn() -> FlowSnapshot + Send + Sync + 'static,
{
    if interval_min == 0 {
        debug!("流量持久化已关闭（flow_store_interval=0）");
        return;
    }
    let interval = Duration::from_secs(interval_min.saturating_mul(60));
    info!(
        "流量持久化已启用：每 {} 分钟写入 {}",
        interval_min,
        store.path().display()
    );

    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // 第一次 tick 会立即触发，跳过它（刚启动时没必要立刻写）
    ticker.tick().await;

    loop {
        tokio::select! {
            _ = cancel.changed() => break,
            _ = ticker.tick() => {
                if let Err(e) = store.save(&collect()) {
                    warn!("定时落盘失败: {e:#}");
                }
            }
        }
    }

    // 关闭前最后写一次
    if let Err(e) = store.save(&collect()) {
        warn!("关闭前落盘失败: {e:#}");
    } else {
        info!("流量已在关闭前保存到 {}", store.path().display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nps-flow-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn missing_file_loads_as_empty() {
        let dir = tmpdir();
        let store = FlowStore::new(dir.join("flow.json"));
        let snap = store.load();
        assert!(snap.tunnels.is_empty());
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = tmpdir();
        let store = FlowStore::new(dir.join("flow.json"));
        let mut snap = FlowSnapshot::default();
        snap.tunnels.insert(
            1,
            FlowRecord {
                bytes_to_client: 1234,
                bytes_from_client: 5678,
            },
        );
        snap.tunnels.insert(
            7,
            FlowRecord {
                bytes_to_client: u64::MAX,
                bytes_from_client: 0,
            },
        );
        store.save(&snap).unwrap();

        let loaded = store.load();
        assert_eq!(loaded, snap);
        // 确认真的写了文件
        assert!(store.path().exists());
        // 临时文件不应残留
        assert!(!store.path().with_extension("json.tmp").exists());
    }

    #[test]
    fn corrupted_file_loads_as_empty_without_panic() {
        let dir = tmpdir();
        let path = dir.join("flow.json");
        std::fs::write(&path, b"{ this is not json").unwrap();
        let store = FlowStore::new(&path);
        let snap = store.load();
        assert!(snap.tunnels.is_empty());
        // 原文件不被 load 破坏
        assert!(path.exists());
    }

    #[test]
    fn save_is_atomic_and_creates_parent_dirs() {
        let dir = tmpdir();
        let store = FlowStore::new(dir.join("nested/deep/flow.json"));
        let mut snap = FlowSnapshot::default();
        snap.tunnels.insert(1, FlowRecord::default());
        store.save(&snap).unwrap();
        assert!(store.path().exists());
        assert_eq!(store.load(), snap);
    }

    #[tokio::test]
    async fn loop_writes_on_shutdown() {
        let dir = tmpdir();
        let store = FlowStore::new(dir.join("flow.json"));
        let (tx, rx) = tokio::sync::watch::channel(false);

        let handle = tokio::spawn(run_flow_store_loop(
            store.clone(),
            5,
            rx,
            || {
                let mut s = FlowSnapshot::default();
                s.tunnels.insert(
                    42,
                    FlowRecord {
                        bytes_to_client: 999,
                        bytes_from_client: 111,
                    },
                );
                s
            },
        ));

        // 立刻取消：循环应跳过首次 tick 并在退出时写一次
        tokio::time::sleep(Duration::from_millis(50)).await;
        tx.send(true).unwrap();
        handle.await.unwrap();

        let loaded = store.load();
        assert_eq!(
            loaded.tunnels.get(&42),
            Some(&FlowRecord {
                bytes_to_client: 999,
                bytes_from_client: 111
            }),
            "关闭前必须落盘一次"
        );
    }

    #[tokio::test]
    async fn zero_interval_disables_persistence() {
        let dir = tmpdir();
        let store = FlowStore::new(dir.join("flow.json"));
        let (_tx, rx) = tokio::sync::watch::channel(false);
        run_flow_store_loop(store.clone(), 0, rx, FlowSnapshot::default).await;
        assert!(!store.path().exists(), "interval=0 时不应写任何文件");
    }
}
