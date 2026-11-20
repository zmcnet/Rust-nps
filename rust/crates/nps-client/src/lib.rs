//! nps-client（Rust-nps 客户端 `rnpc`）：过渡期保留原版 Go 服务端
//!
//! 本 crate 实现老 nps 协议的**客户端侧**，提供三种可用启动模式：
//! 1. 命令行直连：`rnpc -server host:port -vkey <key>`
//! 2. 主机 + 端口分离：`rnpc -s host -p 8024`（vkey 可省略，改走服务端注册）
//! 3. 配置文件：`rnpc -config npc.json`（对齐原版 npc.conf 字段）
//!
//! 协议要点：
//! - 握手（TST / 版本 / md5(vkey) / 连接类型），见 [`handshake`]
//! - `main` 连接：注册后持续读取并忽略服务端健康帧
//! - `chan` 连接：在其上建立 `nps_legacy::mux::MuxSession`，接受服务端拨入的子流
//! - 子流首帧 Link JSON → 按 `Link.Host` 拨号目标 → 双向对拷
//!
//! 本阶段明确不实现：UDP、SOCKS5、HTTP 域名代理、KCP、P2P、加密、压缩。
//! 迁移期结束后，本 crate 与 `nps-legacy` 一并删除。

pub mod cli;
pub mod client;
pub mod config;
pub mod handshake;
pub mod registration;
pub mod tunnel;

pub use cli::{
    parse_args, CliError, Command, ConnType, RunConfig, Target, EXIT_CONFIG, EXIT_CONFIG_FILE,
    EXIT_OK, EXIT_PROTOCOL, EXIT_REGISTER_DENIED, EXIT_UNREACHABLE, EXIT_UNSUPPORTED,
    EXIT_VKEY_REJECTED,
};
