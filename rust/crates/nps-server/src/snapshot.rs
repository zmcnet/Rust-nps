//! 运行状态快照（Web 代理固定对接契约）
//!
//! 字段名一旦发布不可改动；需要更多信息时只允许**追加**字段。
//! `snapshot` 中绝不包含 vkey / 密文 / token。

use serde::{Deserialize, Serialize};

/// 服务端整体快照
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSnapshot {
    /// 桥实际绑定地址（`:0` 时返回系统分配后的端口）
    pub bridge_addr: String,
    pub clients: Vec<ClientSnapshot>,
    pub tunnels: Vec<TunnelSnapshot>,
}

/// 单客户端状态
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSnapshot {
    pub id: i32,
    pub name: String,
    /// signal + tunnel 均在线才为 true
    pub online: bool,
    /// 客户端上报的版本，未连接时为空串
    pub version: String,
}

/// 单隧道状态
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelSnapshot {
    pub id: u32,
    pub name: String,
    pub client_id: i32,
    pub listen_addr: String,
    pub target_addr: String,
    pub enabled: bool,
    /// 当前正在转发的外部连接数
    pub active_connections: u64,
    /// 外部 -> 服务端 -> 客户端方向累计字节
    pub bytes_to_client: u64,
    /// 客户端 -> 服务端 -> 外部方向累计字节
    pub bytes_from_client: u64,
    /// 最近一次错误（成功建立转发后清空）
    pub last_error: Option<String>,
    /// 附加字段：监听器实际绑定地址（含 `:0` 分配结果），未启用时为空
    #[serde(default)]
    pub bound_addr: Option<String>,
}
