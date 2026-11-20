//! nps-proto 错误类型

use thiserror::Error;

/// 协议层错误
#[derive(Debug, Error)]
pub enum Error {
    /// IO 错误（底层 socket 读写失败）
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON 解析错误
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// 数据长度越界
    #[error("length out of bound: got {got}, max {max}")]
    LengthOutOfBound { got: usize, max: usize },

    /// 内容长度非法（<=0 或超限）
    #[error("invalid content length: {0}")]
    InvalidLength(usize),

    /// 对端关闭
    #[error("connection closed")]
    Closed,

    /// mux 子流 id 冲突/不存在
    #[error("mux stream not found: id={0}")]
    MuxStreamNotFound(i32),

    /// 其他协议错误
    #[error("protocol error: {0}")]
    Protocol(String),
}

pub type Result<T> = std::result::Result<T, Error>;