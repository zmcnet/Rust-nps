//! 管理 API 对 `nps-server` 的最小依赖面。
//!
//! 生产路径直接使用 [`nps_server::Server`]；测试路径使用同形状的内存实现，
//! 这样路由层可以在不依赖 `nps-server` 构造方式的前提下被完整测试。

use std::future::Future;

use nps_server::{Server, ServerSnapshot};

/// 管理界面需要后端提供的能力。
pub trait AdminBackend: Clone + Send + Sync + 'static {
    /// 获取当前只读快照。
    fn snapshot(&self) -> impl Future<Output = ServerSnapshot> + Send;

    /// 运行时启停指定隧道。`id` 不存在时应返回错误（路由层会先行检查）。
    fn set_tunnel_enabled(
        &self,
        id: u32,
        enabled: bool,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
}

impl AdminBackend for Server {
    async fn snapshot(&self) -> ServerSnapshot {
        Server::snapshot(self).await
    }

    async fn set_tunnel_enabled(&self, id: u32, enabled: bool) -> anyhow::Result<()> {
        Server::set_tunnel_enabled(self, id, enabled).await
    }
}
