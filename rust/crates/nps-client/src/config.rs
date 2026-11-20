//! JSON 配置文件：字段名对齐原版 `npc.conf`（`resources/nps/lib/config/config.go`）。
//!
//! 原版 npc 用 INI（`[common]` + 若干 `[隧道名]` 段）。这里用 JSON 表达同一组字段，
//! 让用户能把 `npc.conf` 的键名直接照抄过来：
//!
//! ```json
//! {
//!   "common": {
//!     "server_addr": "127.0.0.1:8024",
//!     "server_port": 8024,
//!     "vkey": "<密钥>",
//!     "conn_type": "tcp",
//!     "auto_reconnection": true,
//!     "remark": "my-npc",
//!     "max_conn": 1000,
//!     "rate_limit": 1000,
//!     "flow_limit": 1000,
//!     "basic_username": "u",
//!     "basic_password": "p",
//!     "disconnect_timeout": 60
//!   },
//!   "hosts": [
//!     { "remark": "web", "host": "c.o.com", "target_addr": "127.0.0.1:8083" }
//!   ],
//!   "tasks": [
//!     { "remark": "tcp", "mode": "tcp",
//!       "server_port": "10000", "target_addr": "127.0.0.1:8080" }
//!   ]
//! }
//! ```
//!
//! - `server_addr` 可只给主机，此时端口取 `server_port`（缺省 8024），
//!   与命令行 `-server host -p port` 的语义一致。
//! - `tasks` / `hosts` 既可以是数组，也可以是 `{"隧道名": {...}}` 对象
//!   （对象形式的键等价于原版 INI 的段名，即 `remark`）。
//! - 本阶段只有 `mode=tcp` 的隧道会被上传；其它类型会明确告警并跳过。
//! - 读取上限 1 MiB；JSON 语法错误带行号/列号。

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::cli::{normalize_server, ConnType};

/// 配置文件大小上限（1 MiB）。
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("配置文件 {path} 读取失败：{error}")]
    Read { path: String, error: String },
    #[error("配置文件 {path} 超过 1 MiB 上限（已读到 {bytes} 字节）")]
    TooLarge { path: String, bytes: u64 },
    #[error("配置文件 {path} 不是合法 UTF-8")]
    NotUtf8 { path: String },
    #[error("JSON 语法错误（第 {line} 行第 {column} 列）：{message}")]
    Syntax {
        line: usize,
        column: usize,
        message: String,
    },
    #[error("配置项 {field} 非法：{reason}")]
    Invalid { field: String, reason: String },
}

impl ConfigError {
    pub fn exit_code(&self) -> u8 {
        crate::cli::EXIT_CONFIG_FILE
    }
}

/// 解析后的配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileConfig {
    pub common: CommonConfig,
    pub tasks: Vec<TaskConfig>,
    pub hosts: Vec<HostConfig>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct CommonConfig {
    /// 归一化后的 `host:port`。
    pub server: String,
    /// 明文密钥。**不得写入任何日志**。
    pub vkey: String,
    pub conn_type: ConnType,
    pub auto_reconnection: bool,
    pub disconnect_timeout: Option<u64>,
    pub remark: String,
    pub max_conn: i32,
    pub rate_limit: i32,
    pub flow_limit: i64,
    pub basic_username: String,
    pub basic_password: String,
}

impl std::fmt::Debug for CommonConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommonConfig")
            .field("server", &self.server)
            .field("vkey", &"<redacted>")
            .field("conn_type", &self.conn_type)
            .field("auto_reconnection", &self.auto_reconnection)
            .field("disconnect_timeout", &self.disconnect_timeout)
            .field("remark", &self.remark)
            .field("max_conn", &self.max_conn)
            .field("rate_limit", &self.rate_limit)
            .field("flow_limit", &self.flow_limit)
            .field("basic_username", &self.basic_username)
            .field("basic_password", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskConfig {
    pub remark: String,
    pub mode: String,
    /// 原版 `server_port`，保留字符串形式以支持 `"10000,10001"` / `"10000-10010"`。
    pub server_port: String,
    pub server_ip: String,
    pub target_addr: Option<String>,
    pub target_port: Option<i32>,
    pub target_ip: String,
    pub password: String,
    pub local_path: String,
    pub strip_pre: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostConfig {
    pub remark: String,
    pub host: String,
    pub target_addr: String,
    pub scheme: String,
    pub location: String,
    pub host_change: String,
}

// ---------------------------------------------------------------------------
// 原始反序列化结构（字段名 = npc.conf 键名）
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
struct RawConfig {
    #[serde(default)]
    common: RawCommon,
    #[serde(default)]
    tasks: TasksSpec,
    #[serde(default)]
    hosts: HostsSpec,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize, Default)]
struct RawCommon {
    server_addr: Option<String>,
    server_port: Option<u16>,
    vkey: Option<String>,
    conn_type: Option<String>,
    auto_reconnection: Option<bool>,
    disconnect_timeout: Option<u64>,
    remark: Option<String>,
    max_conn: Option<i32>,
    rate_limit: Option<i32>,
    flow_limit: Option<i64>,
    basic_username: Option<String>,
    basic_password: Option<String>,
    compress: Option<bool>,
    crypt: Option<bool>,
    proxy_url: Option<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum TasksSpec {
    List(Vec<RawTask>),
    Map(BTreeMap<String, RawTask>),
}

impl Default for TasksSpec {
    fn default() -> Self {
        TasksSpec::List(Vec::new())
    }
}

impl TasksSpec {
    fn into_vec(self) -> Vec<(Option<String>, RawTask)> {
        match self {
            TasksSpec::List(list) => list.into_iter().map(|item| (None, item)).collect(),
            TasksSpec::Map(map) => map
                .into_iter()
                .map(|(key, item)| (Some(key), item))
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct RawTask {
    remark: Option<String>,
    mode: Option<String>,
    server_port: Option<PortSpec>,
    server_ip: Option<String>,
    target_addr: Option<String>,
    target_port: Option<i32>,
    target_ip: Option<String>,
    password: Option<String>,
    local_path: Option<String>,
    strip_pre: Option<String>,
    multi_account: Option<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PortSpec {
    Number(i64),
    Text(String),
}

impl PortSpec {
    fn into_string(self) -> String {
        match self {
            PortSpec::Number(number) => number.to_string(),
            PortSpec::Text(text) => text,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum HostsSpec {
    List(Vec<RawHost>),
    Map(BTreeMap<String, RawHost>),
}

impl Default for HostsSpec {
    fn default() -> Self {
        HostsSpec::List(Vec::new())
    }
}

impl HostsSpec {
    fn into_vec(self) -> Vec<(Option<String>, RawHost)> {
        match self {
            HostsSpec::List(list) => list.into_iter().map(|item| (None, item)).collect(),
            HostsSpec::Map(map) => map
                .into_iter()
                .map(|(key, item)| (Some(key), item))
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct RawHost {
    remark: Option<String>,
    host: Option<String>,
    target_addr: Option<String>,
    scheme: Option<String>,
    location: Option<String>,
    host_change: Option<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

// ---------------------------------------------------------------------------
// 加载与校验
// ---------------------------------------------------------------------------

/// 从磁盘加载并校验配置文件。
pub fn load(path: impl AsRef<Path>) -> Result<FileConfig, ConfigError> {
    let text = read_text(path.as_ref())?;
    let (config, _) = parse_str_with_warnings(&text)?;
    Ok(config)
}

/// 读取配置文件文本（带 1 MiB 上限与 UTF-8 校验）。
pub fn read_text(path: &Path) -> Result<String, ConfigError> {
    let display = path.display().to_string();
    let file = std::fs::File::open(path).map_err(|error| ConfigError::Read {
        path: display.clone(),
        error: error.to_string(),
    })?;

    // 先按上限 +1 读取，确保超限能被发现且不会把大文件读进内存。
    let mut buffer = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut buffer)
        .map_err(|error| ConfigError::Read {
            path: display.clone(),
            error: error.to_string(),
        })?;
    if buffer.len() as u64 > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge {
            path: display,
            bytes: buffer.len() as u64,
        });
    }
    String::from_utf8(buffer).map_err(|_| ConfigError::NotUtf8 { path: display })
}

/// 从字符串解析（便于单测）。返回值里携带非致命的告警信息。
pub fn parse_str(text: &str) -> Result<FileConfig, ConfigError> {
    let config = parse_str_with_warnings(text)?;
    Ok(config.0)
}

/// 同 [`parse_str`]，额外返回可读的告警（未知字段、暂不支持的开关等）。
pub fn parse_str_with_warnings(
    text: &str,
) -> Result<(FileConfig, Vec<String>), ConfigError> {
    let raw: RawConfig = serde_json::from_str(text).map_err(|error| ConfigError::Syntax {
        line: error.line(),
        column: error.column(),
        message: strip_position(&error.to_string()),
    })?;

    let mut warnings = Vec::new();
    if !raw.extra.is_empty() {
        warnings.push(format!(
            "配置文件顶层存在未识别的键，已忽略：{}",
            keys(&raw.extra)
        ));
    }
    if !raw.common.extra.is_empty() {
        warnings.push(format!(
            "[common] 中存在未识别的键，已忽略：{}",
            keys(&raw.common.extra)
        ));
    }
    if raw.common.compress == Some(true) {
        warnings.push("common.compress=true 暂不支持，已按未压缩上报".to_owned());
    }
    if raw.common.crypt == Some(true) {
        warnings.push("common.crypt=true 暂不支持，已按不加密上报".to_owned());
    }
    if raw
        .common
        .proxy_url
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        warnings.push("common.proxy_url 暂不支持（不支持经由代理连接服务端），已忽略".to_owned());
    }

    let server_addr = raw
        .common
        .server_addr
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ConfigError::Invalid {
            field: "common.server_addr".to_owned(),
            reason: "必填，形如 10.0.0.1 或 10.0.0.1:8024".to_owned(),
        })?;
    let (_, server) = normalize_server(server_addr, raw.common.server_port).map_err(|error| {
        ConfigError::Invalid {
            field: "common.server_addr".to_owned(),
            reason: error.to_string(),
        }
    })?;

    let vkey = raw
        .common
        .vkey
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ConfigError::Invalid {
            field: "common.vkey".to_owned(),
            reason: "必填；值可以是普通客户端密钥，也可以是服务端 public_vkey".to_owned(),
        })?;
    if vkey.len() > 1024 || vkey.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(ConfigError::Invalid {
            field: "common.vkey".to_owned(),
            reason: "不能包含控制字符，长度不超过 1024".to_owned(),
        });
    }

    let conn_type = match raw.common.conn_type.as_deref() {
        None | Some("") | Some("tcp") | Some("TCP") => ConnType::Tcp,
        Some(other) => {
            return Err(ConfigError::Invalid {
                field: "common.conn_type".to_owned(),
                reason: format!("暂不支持 {other}，本阶段只支持 tcp"),
            })
        }
    };

    let mut tasks = Vec::new();
    for (key, task) in raw.tasks.into_vec() {
        let remark = task
            .remark
            .clone()
            .or(key)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| format!("task{}", tasks.len() + 1));
        if !task.extra.is_empty() {
            warnings.push(format!(
                "隧道 {remark} 存在未识别的键，已忽略：{}",
                keys(&task.extra)
            ));
        }
        if task.multi_account.is_some() {
            warnings.push(format!(
                "隧道 {remark} 的 multi_account 暂不支持，已忽略"
            ));
        }
        let server_port = task
            .server_port
            .map(PortSpec::into_string)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| ConfigError::Invalid {
                field: format!("tasks.{remark}.server_port"),
                reason: "必填，例 10000 / \"10000,10001\" / \"10000-10010\"".to_owned(),
            })?;

        tasks.push(TaskConfig {
            remark,
            mode: task.mode.unwrap_or_else(|| "tcp".to_owned()).trim().to_owned(),
            server_port,
            server_ip: task.server_ip.unwrap_or_default(),
            target_addr: task.target_addr.filter(|v| !v.trim().is_empty()),
            target_port: task.target_port,
            target_ip: task.target_ip.unwrap_or_default(),
            password: task.password.unwrap_or_default(),
            local_path: task.local_path.unwrap_or_default(),
            strip_pre: task.strip_pre.unwrap_or_default(),
        });
    }

    let mut hosts = Vec::new();
    for (key, host) in raw.hosts.into_vec() {
        let remark = host
            .remark
            .clone()
            .or(key)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| format!("host{}", hosts.len() + 1));
        if !host.extra.is_empty() {
            warnings.push(format!(
                "域名 {remark} 存在未识别的键，已忽略：{}",
                keys(&host.extra)
            ));
        }
        hosts.push(HostConfig {
            remark,
            host: host.host.unwrap_or_default(),
            target_addr: host.target_addr.unwrap_or_default(),
            scheme: host.scheme.unwrap_or_else(|| "all".to_owned()),
            location: host.location.unwrap_or_else(|| "/".to_owned()),
            host_change: host.host_change.unwrap_or_default(),
        });
    }

    Ok((
        FileConfig {
            common: CommonConfig {
                server,
                vkey: vkey.to_owned(),
                conn_type,
                auto_reconnection: raw.common.auto_reconnection.unwrap_or(true),
                disconnect_timeout: raw.common.disconnect_timeout,
                remark: raw
                    .common
                    .remark
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| "rust-npsc".to_owned()),
                max_conn: raw.common.max_conn.unwrap_or(0),
                rate_limit: raw.common.rate_limit.unwrap_or(0),
                flow_limit: raw.common.flow_limit.unwrap_or(0),
                basic_username: raw.common.basic_username.unwrap_or_default(),
                basic_password: raw.common.basic_password.unwrap_or_default(),
            },
            tasks,
            hosts,
        },
        warnings,
    ))
}

fn strip_position(message: &str) -> String {
    // serde_json 的错误串形如 "expected value at line 3 column 5"，
    // 行列已经单独提取，这里去掉尾部位置描述避免重复。
    match message.find(" at line ") {
        Some(index) => message[..index].to_owned(),
        None => message.to_owned(),
    }
}

fn keys(map: &BTreeMap<String, Value>) -> String {
    map.keys().cloned().collect::<Vec<_>>().join(", ")
}

// ---------------------------------------------------------------------------
// 拼装发往服务端的 JSON（键名 = Go 导出字段名，见 lib/file/obj.go）
// ---------------------------------------------------------------------------

impl FileConfig {
    /// 可上传的 tcp 隧道。
    pub fn tcp_tasks(&self) -> Vec<&TaskConfig> {
        self.tasks
            .iter()
            .filter(|task| task.mode.eq_ignore_ascii_case("tcp"))
            .collect()
    }

    /// 明确跳过的隧道（非 tcp）。
    pub fn skipped_tasks(&self) -> Vec<&TaskConfig> {
        self.tasks
            .iter()
            .filter(|task| !task.mode.eq_ignore_ascii_case("tcp"))
            .collect()
    }

    /// `NEW_CONF` 的载荷：`file.Client` 的 JSON（Go 字段名）。
    pub fn client_json(&self) -> Value {
        json!({
            "Cnf": {
                "U": self.common.basic_username,
                "P": self.common.basic_password,
                // 压缩/加密本阶段未实现，绝不能上报 true，否则服务端会按压缩流解析。
                "Compress": false,
                "Crypt": false,
            },
            "Id": 0,
            // 留空：服务端会生成 16 字节密钥并通过 conf 连接回传。
            "VerifyKey": "",
            "Addr": "",
            "Remark": self.common.remark,
            "Status": true,
            "IsConnect": false,
            "RateLimit": self.common.rate_limit,
            "Flow": { "ExportFlow": 0, "InletFlow": 0, "FlowLimit": self.common.flow_limit },
            "NoStore": true,
            "NoDisplay": false,
            "MaxConn": self.common.max_conn,
            "NowConn": 0,
            "WebUserName": "",
            "WebPassword": "",
            "ConfigConnAllow": false,
            "MaxTunnelNum": 0,
            "Version": nps_proto::FULL_VERSION,
        })
    }

    /// `NEW_TASK` 的载荷：`file.Tunnel` 的 JSON（Go 字段名）。
    ///
    /// 注意服务端会读 `t.Target.TargetStr`，`Target` **不能**省略。
    pub fn task_json(task: &TaskConfig) -> Value {
        let target_str = match (&task.target_addr, task.target_port) {
            (Some(addr), _) => addr.clone(),
            (None, Some(port)) => port.to_string(),
            (None, None) => String::new(),
        };
        json!({
            "Id": 0,
            "Port": 0,
            "ServerIp": task.server_ip,
            "Mode": task.mode,
            "Status": true,
            "RunStatus": true,
            "Client": Value::Null,
            "Ports": task.server_port,
            "Flow": Value::Null,
            "Password": task.password,
            "Remark": task.remark,
            // 多端口才会用到；单端口时服务端忽略。
            "TargetAddr": task.target_ip,
            "NoStore": true,
            "LocalPath": task.local_path,
            "StripPre": task.strip_pre,
            "Target": {
                "TargetStr": target_str,
                "TargetArr": Value::Null,
                "LocalProxy": false,
            },
            "MultiAccount": Value::Null,
        })
    }

    /// `NEW_HOST` 的载荷：`file.Host` 的 JSON（Go 字段名）。
    pub fn host_json(host: &HostConfig) -> Value {
        json!({
            "Id": 0,
            "Host": host.host,
            "Scheme": host.scheme,
            "Location": host.location,
            "HostChange": host.host_change,
            "Remark": host.remark,
            "Target": {
                "TargetStr": host.target_addr,
                "TargetArr": Value::Null,
                "LocalProxy": false,
            },
            "NoStore": true,
            "Flow": Value::Null,
            "Client": Value::Null,
            "MultiAccount": Value::Null,
        })
    }
}

/// 解析原版 `server_port` 语法（对齐 Go `common.GetPorts`）。
pub fn parse_ports(spec: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for piece in spec.split(',') {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        match piece.split_once('-') {
            Some((start, end)) => {
                let (Ok(start), Ok(end)) = (start.trim().parse::<u16>(), end.trim().parse::<u16>())
                else {
                    continue;
                };
                if start == 0 || end == 0 || start > end {
                    continue;
                }
                ports.extend(start..=end);
            }
            None => match piece.parse::<u16>() {
                Ok(0) | Err(_) => {}
                Ok(port) => ports.push(port),
            },
        }
    }
    ports
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
    {
      "common": {
        "server_addr": "10.0.0.1",
        "server_port": 8024,
        "vkey": "secret",
        "conn_type": "tcp",
        "auto_reconnection": false,
        "remark": "box",
        "max_conn": 10
      },
      "tasks": [
        { "remark": "tcp1", "mode": "tcp", "server_port": "10000",
          "target_addr": "127.0.0.1:8080" }
      ]
    }
    "#;

    #[test]
    fn parses_sample_and_normalizes_server() {
        let config = parse_str(SAMPLE).unwrap();
        assert_eq!(config.common.server, "10.0.0.1:8024");
        assert_eq!(config.common.vkey, "secret");
        assert!(!config.common.auto_reconnection);
        assert_eq!(config.common.remark, "box");
        assert_eq!(config.tasks.len(), 1);
        assert_eq!(config.tasks[0].remark, "tcp1");
        assert_eq!(config.tcp_tasks().len(), 1);
    }

    #[test]
    fn server_port_in_addr_wins_and_p_is_not_needed() {
        let config = parse_str(
            r#"{"common":{"server_addr":"[::1]:9000","vkey":"k"},"tasks":[]}"#,
        )
        .unwrap();
        assert_eq!(config.common.server, "[::1]:9000");
    }

    #[test]
    fn default_port_is_8024() {
        let config =
            parse_str(r#"{"common":{"server_addr":"2001:db8::1","vkey":"k"}}"#).unwrap();
        assert_eq!(config.common.server, "[2001:db8::1]:8024");
    }

    #[test]
    fn tasks_may_be_an_object_keyed_by_remark() {
        let config = parse_str(
            r#"{
                "common": {"server_addr": "127.0.0.1:8024", "vkey": "k"},
                "tasks": {
                    "ssh": {"mode": "tcp", "server_port": 10001,
                            "target_addr": "127.0.0.1:22"},
                    "web": {"mode": "tcp", "server_port": "10002",
                            "target_addr": "127.0.0.1:80"}
                }
            }"#,
        )
        .unwrap();
        assert_eq!(config.tasks.len(), 2);
        let remarks: Vec<_> = config.tasks.iter().map(|t| t.remark.as_str()).collect();
        assert_eq!(remarks, vec!["ssh", "web"]);
        assert_eq!(config.tasks[0].server_port, "10001");
    }

    #[test]
    fn non_tcp_tasks_are_reported_as_skipped() {
        let config = parse_str(
            r#"{
                "common": {"server_addr": "127.0.0.1:8024", "vkey": "k"},
                "tasks": [
                    {"remark": "a", "mode": "tcp", "server_port": "1", "target_addr": "127.0.0.1:1"},
                    {"remark": "b", "mode": "udp", "server_port": "2", "target_addr": "8.8.8.8:53"},
                    {"remark": "c", "mode": "socks5", "server_port": "3"},
                    {"remark": "d", "mode": "file", "server_port": "4"},
                    {"remark": "e", "mode": "httpProxy", "server_port": "5"}
                ]
            }"#,
        )
        .unwrap();
        assert_eq!(config.tcp_tasks().len(), 1);
        let skipped: Vec<_> = config
            .skipped_tasks()
            .iter()
            .map(|t| t.mode.as_str())
            .collect();
        assert_eq!(skipped, vec!["udp", "socks5", "file", "httpProxy"]);
    }

    #[test]
    fn syntax_error_reports_line_and_column() {
        let error = parse_str("{\n  \"common\": ,\n}").unwrap_err();
        match error {
            ConfigError::Syntax { line, column, .. } => {
                assert_eq!(line, 2, "行号应为 2");
                assert!(column >= 1);
            }
            other => panic!("期望 Syntax，实际 {other:?}"),
        }
        assert_eq!(error.exit_code(), crate::cli::EXIT_CONFIG_FILE);
    }

    #[test]
    fn missing_common_is_an_invalid_field_error() {
        let error = parse_str(r#"{"tasks": []}"#).unwrap_err();
        match error {
            ConfigError::Invalid { field, .. } => assert_eq!(field, "common.server_addr"),
            other => panic!("期望 Invalid，实际 {other:?}"),
        }
    }

    #[test]
    fn missing_vkey_is_an_invalid_field_error() {
        let error =
            parse_str(r#"{"common":{"server_addr":"127.0.0.1:8024"}}"#).unwrap_err();
        match error {
            ConfigError::Invalid { field, .. } => assert_eq!(field, "common.vkey"),
            other => panic!("期望 Invalid，实际 {other:?}"),
        }
    }

    #[test]
    fn unsupported_conn_type_is_rejected() {
        let error = parse_str(
            r#"{"common":{"server_addr":"127.0.0.1:8024","vkey":"k","conn_type":"kcp"}}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("kcp"));
    }

    #[test]
    fn task_without_server_port_is_rejected() {
        let error = parse_str(
            r#"{"common":{"server_addr":"127.0.0.1:8024","vkey":"k"},
                "tasks":[{"remark":"x","mode":"tcp","target_addr":"127.0.0.1:1"}]}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("server_port"));
    }

    #[test]
    fn file_larger_than_one_mib_is_rejected() {
        let dir = std::env::temp_dir().join(format!(
            "npsc-cfg-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("big.json");
        // 1 MiB + 1 字节的填充（内容本身不是合法 JSON，但大小检查先触发）
        let mut payload = vec![b' '; MAX_CONFIG_BYTES as usize + 1];
        payload[0] = b'{';
        payload[1] = b'}';
        std::fs::write(&path, &payload).unwrap();
        let error = load(&path).unwrap_err();
        assert!(matches!(error, ConfigError::TooLarge { .. }), "got {error:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_is_a_read_error() {
        let error = load("definitely-not-here/npc.json").unwrap_err();
        assert!(matches!(error, ConfigError::Read { .. }));
    }

    #[test]
    fn upload_json_uses_go_field_names() {
        let config = parse_str(SAMPLE).unwrap();
        let client = config.client_json();
        assert_eq!(client["Remark"], "box");
        assert_eq!(client["VerifyKey"], "");
        assert_eq!(client["Status"], true);
        assert_eq!(client["Cnf"]["Compress"], false);
        assert_eq!(client["Cnf"]["Crypt"], false);

        let task = FileConfig::task_json(&config.tasks[0]);
        assert_eq!(task["Mode"], "tcp");
        assert_eq!(task["Ports"], "10000");
        assert_eq!(task["Remark"], "tcp1");
        assert_eq!(task["Target"]["TargetStr"], "127.0.0.1:8080");
        // Target 必须存在，服务端会直接解引用
        assert!(task["Target"].is_object());
    }

    #[test]
    fn task_json_falls_back_to_target_port() {
        let task = TaskConfig {
            remark: "x".into(),
            mode: "tcp".into(),
            server_port: "10000".into(),
            server_ip: String::new(),
            target_addr: None,
            target_port: Some(22),
            target_ip: String::new(),
            password: String::new(),
            local_path: String::new(),
            strip_pre: String::new(),
        };
        let json = FileConfig::task_json(&task);
        assert_eq!(json["Target"]["TargetStr"], "22");
    }

    #[test]
    fn parse_ports_matches_go_get_ports() {
        assert_eq!(parse_ports("10000"), vec![10000]);
        assert_eq!(parse_ports("10000,10001"), vec![10000, 10001]);
        assert_eq!(parse_ports("10000-10003"), vec![10000, 10001, 10002, 10003]);
        assert_eq!(parse_ports("10000,10002-10003"), vec![10000, 10002, 10003]);
        assert!(parse_ports("").is_empty());
        assert!(parse_ports("0").is_empty());
        assert!(parse_ports("abc").is_empty());
        assert!(parse_ports("70000").is_empty());
        assert!(parse_ports("10003-10000").is_empty());
    }

    #[test]
    fn warnings_are_collected_not_fatal() {
        let (_, warnings) = parse_str_with_warnings(
            r#"{"common":{"server_addr":"127.0.0.1:8024","vkey":"k","compress":true},
                "unknown_top": 1}"#,
        )
        .unwrap();
        assert!(warnings.iter().any(|w| w.contains("compress")));
        assert!(warnings.iter().any(|w| w.contains("unknown_top")));
    }

    #[test]
    fn vkey_never_leaks_through_debug() {
        let config = parse_str(SAMPLE).unwrap();
        // ConfigFile 结构自身带明文 vkey，但打印配置时只应打印 server。
        let text = format!("{:?}", config.common.server);
        assert!(!text.contains("secret"));
    }
}
