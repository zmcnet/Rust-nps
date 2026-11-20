//! Rust-nps 服务端：配置、运行状态与 **TCP 隧道**服务。
//!
//! 定位：个人 / 小团队自部署，轻内嵌 UI，过渡期兼容老 npc。
//! 本 crate 只是库（二进制入口由上层组装，产物名 `rnps`），提供：
//! - [`ServerConfig`]：JSON 配置（不含 admin token；所有 vkey 必须显式配置）
//! - [`Server`]：启动 / 快照 / 单隧道启停 / 关闭
//! - 外部 TCP → 老 npc 反向拨号的转发链路
//! - 可选的**配置文件模式注册**：老 npc 用 `-config=npc.conf` 上报隧道，
//!   服务端自动建监听（[`ServerConfig::conf_register`]，默认关闭）
//!
//! # 能力边界
//! 这是 **TCP 兼容 P0**，不是全功能 NPS：
//! - 仅 `tcp` 隧道；UDP / HTTP(S) / SOCKS5 / P2P / 文件服务 / 配置下发均未实现
//! - 桥的 `main`（健康上报）与 `chan`（mux 数据面）两种连接被处理
//! - `conf` 连接在 `conf_register=true` 时处理 `task` / `stus`，
//!   `host`（域名代理）如实返回失败；`rgst` / `sert` / `p2pm` / `file` 未实现
//! - 注册隧道只存内存：重启即失效，不做持久化
//!
//! # 停用与关闭的连接语义
//! - `set_tunnel_enabled(id, false)`：关闭监听器（端口立即释放），并断开该隧道
//!   当前正在转发的连接。
//! - `shutdown()`：停所有隧道（含 conf 注册的）与桥，断开全部连接，
//!   等待后台任务退出；幂等。

pub mod config;
mod conf;
mod server;
pub mod snapshot;
mod tunnel;

pub use config::{ClientConfig, ServerConfig, TcpTunnelConfig};
pub use server::Server;
pub use snapshot::{ClientSnapshot, ServerSnapshot, TunnelSnapshot};
