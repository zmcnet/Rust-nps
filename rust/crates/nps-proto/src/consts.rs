//! nps-proto: 老 npc 通信协议的常量与数据结构定义
//!
//! 数据来源：`D:\Developing\NPS\resources\nps`
//! - `lib/common/const.go` — 协议常量
//! - `lib/conn/link.go` — Link 结构（JSON 序列化）
//!
//! 本 crate 不含 I/O，仅定义协议常量与 serde 结构，供
//! 服务端兼容层（nps-legacy）与未来客户端共用。

/// 字段分隔符（配置文件模式、健康检查等场景使用）
pub const CONN_DATA_SEQ: &str = "*#*";

/// 握手成功/失败标志
pub const VERIFY_EER: &str = "vkey";
pub const VERIFY_SUCCESS: &str = "sucs";

/// 握手探测字节（3 字节）
pub const CONN_TEST: &str = "TST";

/// 连接类型 flag（握手后首个 4 字节）
pub const WORK_MAIN: &str = "main"; // 信号连接
pub const WORK_CHAN: &str = "chan"; // 数据隧道
pub const WORK_CONFIG: &str = "conf"; // 配置文件模式
pub const WORK_REGISTER: &str = "rgst"; // IP 注册
pub const WORK_SECRET: &str = "sert"; // secret 模式
pub const WORK_FILE: &str = "file"; // 文件服务
pub const WORK_P2P: &str = "p2pm"; // p2p 打洞
pub const WORK_P2P_VISITOR: &str = "p2pv";
pub const WORK_P2P_PROVIDER: &str = "p2pp";
pub const WORK_P2P_CONNECT: &str = "p2pc";
pub const WORK_P2P_SUCCESS: &str = "p2ps";
pub const WORK_P2P_END: &str = "p2pe";
pub const WORK_P2P_LAST: &str = "p2pl";

/// 控制 flag
pub const WORK_STATUS: &str = "stus";
pub const RES_MSG: &str = "msg0";
pub const RES_CLOSE: &str = "clse";
pub const NEW_UDP_CONN: &str = "udpc";
pub const NEW_TASK: &str = "task";
pub const NEW_CONF: &str = "conf";
pub const NEW_HOST: &str = "host";

/// 链路类型
pub const CONN_TCP: &str = "tcp";
pub const CONN_UDP: &str = "udp";

/// 免登录返回头（服务端 HTTP 代理对未授权请求的响应）
pub const UNAUTHORIZED_BYTES: &[u8] = b"HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain; charset=utf-8\r\nWWW-Authenticate: Basic realm=\"easyProxy\"\r\n\r\n401 Unauthorized";
pub const CONNECTION_FAIL_BYTES: &[u8] = b"HTTP/1.1 404 Not Found\r\n\r\n";

/// 核心版本号（握手互验用的版本）
///
/// 来源：`lib/version/version.go` 的 `GetVersion()`，**不是** `VERSION`。
/// 老 npc 客户端发送 `version.GetVersion()`，服务端在
/// `bridge.cliProcess` 中与其比对；双方都必须是 `"0.26.0"`。
pub const CORE_VERSION: &str = "0.26.0";

/// 完整版本号（仅用于日志/展示，不参与握手校验）
///
/// 来源：`lib/version/version.go` 的 `VERSION` 常量。
pub const FULL_VERSION: &str = "0.26.10";

/// 握手时读写的"长度前缀"内容上限，与 `conn.GetShortLenContent` 的 32KB 上限一致
/// （`lib/conn/conn.go`: `if l < 0 || l > 32<<10`）
pub const MAX_SHORT_LEN: usize = 32 * 1024;

/// `conn.Link.Options.Timeout` 的默认值（Go: `defaultTimeOut = time.Second * 5`）
///
/// Go 侧 `time.Duration` 以纳秒表示，JSON 序列化后是同一个整数，
/// 因此这里必须是 `5_000_000_000`。
pub const DEFAULT_LINK_TIMEOUT_NS: i64 = 5_000_000_000;
