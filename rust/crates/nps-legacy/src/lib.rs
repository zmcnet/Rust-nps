//! nps-legacy：老 nps 协议的兼容层（Rust 实现）
//!
//! 目标：让老 npc 客户端（Go 版）能连上 Rust 重写的服务端，
//! 作为"新内核 + 老客户端"渐进迁移期的兼容桥。
//!
//! 职责：
//! - 帧编解码（与 `lib/conn/conn.go` 对齐）
//! - nps-mux 多路复用（与 `ehang-io/nps-mux` 对齐）
//! - 握手流程（桥协议，与 `bridge/bridge.go` 对齐）
//! - 老 npc 连接接入后，转换到新内核的统一链路模型
//!
//! 迁移期结束后，此 crate 整体删除，仅保留 nps-proto 作为协议常量参考。

pub mod bridge;
pub mod codec;
pub mod handshake;
pub mod mux;

/// 桥端口 vkey 防爆破（按来源 IP 记账）——`bridge` 的内部组件，不对外导出。
mod ip_guard;

pub use bridge::{Bridge, ClientState};
pub use codec::*;
pub use handshake::{md5_hex, server_handshake, HandshakeError, HandshakeResult};
pub use mux::{MuxError, MuxFrame, MuxSession, MuxStream};