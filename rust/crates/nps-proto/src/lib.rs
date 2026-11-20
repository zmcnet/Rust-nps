//! nps-proto：老 nps 协议的常量与数据结构定义 crate
//!
//! 本 crate 是**协议真相的唯一来源**，不含任何 I/O 逻辑。
//! 常量来源：`resources/nps/lib/common/const.go`
//! 结构来源：`resources/nps/lib/conn/link.go`
//!
//! 后续若协议演进（如引入 protobuf），旧常量保留于此供兼容层参考，
//! 新结构另立 crate，避免破坏已运行的老 npc。

pub mod consts;
pub mod error;
pub mod link;

pub use consts::*;
pub use error::{Error, Result};
pub use link::{Link, Options};