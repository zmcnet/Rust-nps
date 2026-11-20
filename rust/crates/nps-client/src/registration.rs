//! 注册与配置上传流程。
//!
//! ## `conf` 流程（模式 3，对齐 Go `bridge.go:getConfig` / `client.go:StartFromFile`）
//! 1. 完成握手，flag 为 `conf`
//! 2. 读 1 字节 bool `isPub`（Go `binary.Write(c, binary.LittleEndian, isPub)`）
//! 3. 若 `isPub=true`：
//!    - `SendInfo(客户端信息, NEW_CONF)` → 读 1 字节 bool
//!    - 读 **16 字节**明文 vkey（无长度前缀），作为后续 main/chan 的密钥
//! 4. 逐条 `SendInfo(NEW_HOST / NEW_TASK, json)` → 每条读 1 字节 bool
//! 5. 关闭 conf 连接，用（可能被替换的）vkey 进入正常 main + chan 运行
//!
//! `SendInfo` = `flag(4B) + int32 LE len + JSON`，与 Go `conn.SendInfo` 完全一致。
//!
//! ## `rgst` 流程（模式 4 的第一选择）
//! 握手（空 vkey）后声明 `rgst`，写 int32 LE 小时数，再读 16 字节服务端分配的 vkey。
//!
//! **与原版 Go 的差异（读源码确认，不是猜测）**：`resources/nps` 的服务端
//! `bridge.register()` 只把「IP → 到期时间」写进内存表，**从不回写任何字节**；
//! 而且 `rgst` 同样要先通过 `GetIdByVerifyKey` 校验，空 vkey 必然被拒。
//! 也就是说原版 Go 服务端**没有**「rgst 分配 vkey」这条路径。
//! 真正由服务端分配 16 字节 vkey 的是 `conf + isPub=true`（公开 vkey 模式）。
//!
//! 因此模式 4 的做法是：先按规格尝试 `rgst`；若服务端拒绝/不回应，
//! 自动改用公开 vkey 的 `conf` 注册（`register_public`）拿到服务端分配的 vkey，
//! 再进入 main + chan，由服务端下发隧道。两条路都失败时给出明确原因并退出码 7。

use std::io;
use std::time::Duration;

use nps_legacy::codec::write_flag_content;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::config::{FileConfig, HostConfig, TaskConfig};
use crate::handshake::{client_handshake, FLAG_CONF, FLAG_RGST};

/// 连接桥端口的超时。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// 等待服务端响应（注册结果 / isPub 字节）的超时。
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);
/// 服务端分配的 vkey 长度（Go `crypt.GetRandomString(16)`）。
pub const ASSIGNED_VKEY_LEN: usize = 16;
/// IP 注册默认有效期（小时，对齐 Go `npc -time` 默认值 2）。
pub const DEFAULT_REGISTER_HOURS: i32 = 2;

#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    #[error("无法连接服务端 {server}：{error}")]
    Unreachable { server: String, error: String },
    #[error("握手或协议帧非法：{0}")]
    Protocol(String),
    #[error("服务端拒绝了认证密钥")]
    VkeyRejected,
    #[error("服务端拒绝注册：{0}")]
    RegisterDenied(String),
    #[error("隧道 {remark} 注册失败（服务端返回失败状态）")]
    TaskRejected { remark: String },
    #[error("域名 {remark} 注册失败（服务端返回失败状态）")]
    HostRejected { remark: String },
    #[error("服务端下发的 vkey 非法（长度或内容异常）")]
    InvalidAssignedVkey,
}

impl RegistrationError {
    pub fn exit_code(&self) -> u8 {
        match self {
            RegistrationError::Unreachable { .. } => crate::cli::EXIT_UNREACHABLE,
            RegistrationError::VkeyRejected => crate::cli::EXIT_VKEY_REJECTED,
            RegistrationError::RegisterDenied(_) | RegistrationError::InvalidAssignedVkey => {
                crate::cli::EXIT_REGISTER_DENIED
            }
            RegistrationError::TaskRejected { .. }
            | RegistrationError::HostRejected { .. }
            | RegistrationError::Protocol(_) => crate::cli::EXIT_PROTOCOL,
        }
    }

    /// 是否属于「服务端不接受这个注册方式」——模式 4 据此决定是否换方案。
    fn is_denial(&self) -> bool {
        !matches!(self, RegistrationError::Unreachable { .. })
    }
}

/// 连接到桥端口（带超时，设置 nodelay）。
pub async fn dial_bridge(server: &str) -> io::Result<TcpStream> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(server))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("连接超时（{}s）", CONNECT_TIMEOUT.as_secs()),
            )
        })??;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// 带超时读 1 字节 bool（Go `binary.Read(..., &bool)`）。
///
/// 服务端不接受时会直接关闭连接，因此必须限时，不能无限阻塞。
async fn read_bool<S: AsyncRead + Unpin>(stream: &mut S) -> Result<bool, RegistrationError> {
    let mut byte = [0u8; 1];
    match tokio::time::timeout(REPLY_TIMEOUT, stream.read_exact(&mut byte)).await {
        Ok(Ok(_)) => Ok(byte[0] != 0),
        Ok(Err(error)) => Err(RegistrationError::RegisterDenied(format!(
            "服务端未返回状态（连接已关闭或读取失败：{error}）"
        ))),
        Err(_) => Err(RegistrationError::RegisterDenied(format!(
            "等待服务端状态超时（{}s）",
            REPLY_TIMEOUT.as_secs()
        ))),
    }
}

/// 读定长字节（带超时）。
async fn read_exact_timed<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut [u8],
) -> Result<(), RegistrationError> {
    match tokio::time::timeout(REPLY_TIMEOUT, stream.read_exact(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(RegistrationError::RegisterDenied(format!(
            "服务端未下发密钥（连接已关闭或读取失败：{error}）"
        ))),
        Err(_) => Err(RegistrationError::RegisterDenied(format!(
            "等待服务端下发密钥超时（{}s）",
            REPLY_TIMEOUT.as_secs()
        ))),
    }
}

/// 发送 `SendInfo(json, flag)`：`flag(4B) + int32 LE len + JSON`。
pub async fn send_info<S: AsyncWrite + Unpin>(
    stream: &mut S,
    flag: &[u8; 4],
    payload: &serde_json::Value,
) -> Result<(), RegistrationError> {
    let body = serde_json::to_vec(payload)
        .map_err(|error| RegistrationError::Protocol(format!("配置 JSON 序列化失败: {error}")))?;
    if body.len() > nps_proto::MAX_SHORT_LEN {
        return Err(RegistrationError::Protocol(format!(
            "配置 JSON 超过协议上限 {} 字节",
            nps_proto::MAX_SHORT_LEN
        )));
    }
    write_flag_content(stream, flag, &body)
        .await
        .map_err(|error| RegistrationError::Protocol(format!("上传配置帧失败: {error}")))?;
    stream
        .flush()
        .await
        .map_err(|error| RegistrationError::Protocol(format!("刷新配置帧失败: {error}")))?;
    Ok(())
}

/// 校验服务端下发的 vkey。
fn validate_assigned(bytes: &[u8; ASSIGNED_VKEY_LEN]) -> Result<String, RegistrationError> {
    let text = String::from_utf8(bytes.to_vec()).map_err(|_| RegistrationError::InvalidAssignedVkey)?;
    if text.len() != ASSIGNED_VKEY_LEN
        || text.is_empty()
        || text.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(RegistrationError::InvalidAssignedVkey);
    }
    Ok(text)
}

/// 把配置上传到服务端，返回最终生效的 vkey。
///
/// `stream` 必须是已经完成 `conf` 握手的连接。
pub async fn upload_config<S>(
    stream: &mut S,
    config: &FileConfig,
) -> Result<String, RegistrationError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // ① 读 isPub（1 字节 bool）
    let is_pub = read_bool(stream).await?;
    debug!(is_pub, "conf 连接已建立");

    let mut effective_vkey = config.common.vkey.clone();

    // ② isPub=true：上传客户端信息，服务端分配新的 16 字节 vkey
    if is_pub {
        send_info(stream, &flag(nps_proto::NEW_CONF), &config.client_json()).await?;
        if !read_bool(stream).await? {
            return Err(RegistrationError::RegisterDenied(
                "服务端拒绝客户端信息（NEW_CONF）；public vkey 可能已被占用".to_owned(),
            ));
        }
        let mut assigned = [0u8; ASSIGNED_VKEY_LEN];
        read_exact_timed(stream, &mut assigned).await?;
        effective_vkey = validate_assigned(&assigned)?;
        info!("服务端已分配新的客户端密钥（内容已隐藏）");
    }

    // ③ 上传域名
    for host in &config.hosts {
        send_info(stream, &flag(nps_proto::NEW_HOST), &FileConfig::host_json(host)).await?;
        if !read_bool(stream).await? {
            return Err(RegistrationError::HostRejected {
                remark: host.remark.clone(),
            });
        }
    }

    // ④ 上传隧道：只支持 tcp；其它 mode 明确告警并跳过（不伪造成功）
    for task in config.skipped_tasks() {
        warn!(
            remark = %task.remark,
            mode = %task.mode,
            "隧道模式暂不支持，已跳过（未向服务端注册）"
        );
    }
    for task in config.tcp_tasks() {
        send_info(stream, &flag(nps_proto::NEW_TASK), &FileConfig::task_json(task)).await?;
        if !read_bool(stream).await? {
            return Err(RegistrationError::TaskRejected {
                remark: task.remark.clone(),
            });
        }
        info!(remark = %task.remark, "tcp 隧道已在服务端注册");
    }

    Ok(effective_vkey)
}

/// 配置文件模式的完整 conf 流程：建连 → 握手 → 上传 → 断开，返回生效 vkey。
pub async fn configure(server: &str, config: &FileConfig) -> Result<String, RegistrationError> {
    let mut stream = dial_bridge(server).await.map_err(|error| {
        RegistrationError::Unreachable {
            server: server.to_owned(),
            error: error.to_string(),
        }
    })?;
    client_handshake(&mut stream, &config.common.vkey, FLAG_CONF)
        .await
        .map_err(map_handshake)?;
    let vkey = upload_config(&mut stream, config).await?;
    // Go 侧上传完成后 c.Close()；这里正常关闭 conf 连接。
    let _ = stream.shutdown().await;
    Ok(vkey)
}

/// `rgst` 注册：握手后写 int32 LE 小时数，读 16 字节服务端分配的 vkey。
///
/// 注意：原版 Go 服务端不会在 `rgst` 上回写 vkey（见模块文档），
/// 因此对真实 nps 这条路径会以 [`RegistrationError::RegisterDenied`] 结束。
pub async fn register(server: &str, hours: i32) -> Result<String, RegistrationError> {
    let mut stream = dial_bridge(server).await.map_err(|error| {
        RegistrationError::Unreachable {
            server: server.to_owned(),
            error: error.to_string(),
        }
    })?;
    client_handshake(&mut stream, "", FLAG_RGST)
        .await
        .map_err(map_handshake)?;

    stream
        .write_all(&hours.to_le_bytes())
        .await
        .map_err(|error| RegistrationError::RegisterDenied(format!("发送注册请求失败: {error}")))?;
    stream
        .flush()
        .await
        .map_err(|error| RegistrationError::RegisterDenied(format!("刷新注册请求失败: {error}")))?;

    let mut assigned = [0u8; ASSIGNED_VKEY_LEN];
    read_exact_timed(&mut stream, &mut assigned).await?;
    let vkey = validate_assigned(&assigned)?;
    info!("rgst 注册成功，服务端已分配客户端密钥（内容已隐藏）");
    Ok(vkey)
}

/// 公开 vkey 注册：`conf` 握手 + isPub=true + 只上传客户端信息（不建隧道）。
///
/// 这是原版 nps 真正「由服务端分配 vkey」的机制。分配到的客户端为公共客户端，
/// 隧道由服务端（管理端）配置后下发，客户端只需接受 mux 子流并拨号 `Link.Host`。
pub async fn register_public(
    server: &str,
    public_vkey: &str,
    remark: &str,
) -> Result<String, RegistrationError> {
    let mut stream = dial_bridge(server).await.map_err(|error| {
        RegistrationError::Unreachable {
            server: server.to_owned(),
            error: error.to_string(),
        }
    })?;
    client_handshake(&mut stream, public_vkey, FLAG_CONF)
        .await
        .map_err(map_handshake)?;

    let is_pub = read_bool(&mut stream).await?;
    if !is_pub {
        return Err(RegistrationError::RegisterDenied(
            "该密钥不是服务端的 public_vkey，服务端不会分配新密钥".to_owned(),
        ));
    }

    let client = serde_json::json!({
        "Cnf": { "U": "", "P": "", "Compress": false, "Crypt": false },
        "Id": 0,
        "VerifyKey": "",
        "Addr": "",
        "Remark": remark,
        "Status": true,
        "IsConnect": false,
        "RateLimit": 0,
        "Flow": { "ExportFlow": 0, "InletFlow": 0, "FlowLimit": 0 },
        "NoStore": true,
        "NoDisplay": false,
        "MaxConn": 0,
        "NowConn": 0,
        "WebUserName": "",
        "WebPassword": "",
        "ConfigConnAllow": false,
        "MaxTunnelNum": 0,
        "Version": nps_proto::FULL_VERSION,
    });
    send_info(&mut stream, &flag(nps_proto::NEW_CONF), &client).await?;
    if !read_bool(&mut stream).await? {
        return Err(RegistrationError::RegisterDenied(
            "服务端拒绝公共客户端注册（NEW_CONF）".to_owned(),
        ));
    }
    let mut assigned = [0u8; ASSIGNED_VKEY_LEN];
    read_exact_timed(&mut stream, &mut assigned).await?;
    let vkey = validate_assigned(&assigned)?;
    let _ = stream.shutdown().await;
    info!("公共 vkey 注册成功，服务端已分配客户端密钥（内容已隐藏）");
    Ok(vkey)
}

/// 模式 4：无 vkey 的极简启动，拿到服务端分配的 vkey。
///
/// 顺序：
/// 1. `rgst`（规格要求的第一选择）
/// 2. 若服务端拒绝，改用 `public_vkey`（环境变量 `NPS_PUBLIC_VKEY`，
///    缺省取原版示例配置里的 `123`）走 `conf` 公开注册
///
/// 两条路都失败时把**两个**原因都带上，便于定位；不重试。
pub async fn negotiate_vkey(server: &str) -> Result<String, RegistrationError> {
    let rgst_result = register(server, DEFAULT_REGISTER_HOURS).await;
    match rgst_result {
        Ok(vkey) => return Ok(vkey),
        Err(error) if !error.is_denial() => return Err(error),
        Err(error) => {
            info!(reason = %error, "rgst 注册未被服务端接受，改用 public_vkey 注册");
            let public_vkey = public_vkey_from_env();
            match register_public(server, &public_vkey, "rust-npsc").await {
                Ok(vkey) => Ok(vkey),
                Err(second) if !second.is_denial() => Err(second),
                Err(second) => Err(RegistrationError::RegisterDenied(format!(
                    "rgst 注册被拒绝（{error}）；public_vkey 注册也失败（{second}）。\
                     请用 -vkey 显式指定密钥，或在服务端开启 public_vkey"
                ))),
            }
        }
    }
}

/// 公开 vkey 来源：`NPS_PUBLIC_VKEY` 环境变量，缺省 `123`（原版示例值）。
fn public_vkey_from_env() -> String {
    std::env::var("NPS_PUBLIC_VKEY")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "123".to_owned())
}

fn flag(value: &str) -> [u8; 4] {
    // 协议常量均为 4 字节 ASCII，长度不符属于编程错误。
    let bytes = value.as_bytes();
    debug_assert_eq!(bytes.len(), 4, "协议 flag 必须是 4 字节: {value}");
    let mut out = [0u8; 4];
    out[..bytes.len().min(4)].copy_from_slice(&bytes[..bytes.len().min(4)]);
    out
}

fn map_handshake(error: crate::handshake::HandshakeError) -> RegistrationError {
    use crate::handshake::HandshakeError;
    match error {
        HandshakeError::VkeyRejected => RegistrationError::VkeyRejected,
        HandshakeError::VersionMismatch(_) | HandshakeError::BadStatus(_) => {
            RegistrationError::Protocol(error.to_string())
        }
        HandshakeError::Io(_) | HandshakeError::Timeout(_) | HandshakeError::Closed => {
            RegistrationError::Protocol(error.to_string())
        }
    }
}

/// 供模式 3/4 复用的「上传内容摘要」，只用于日志，绝不含密钥。
pub fn describe_tasks(config: &FileConfig) -> String {
    let tcp = config.tcp_tasks().len();
    let skipped = config.skipped_tasks().len();
    format!(
        "tcp={tcp} 条已注册, 跳过={skipped} 条, 域名={} 条",
        config.hosts.len()
    )
}

/// 占位以保持 `HostConfig` / `TaskConfig` 的类型在公开 API 中可见。
#[allow(dead_code)]
fn _types(_: &HostConfig, _: &TaskConfig) {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// 走完握手：TST + len(core) + len(full) → md5(core) → md5(vkey) → sucs → flag。
    async fn server_handshake(stream: &mut tokio::io::DuplexStream, expected_flag: &[u8; 4]) {
        let mut tst = [0u8; 3];
        stream.read_exact(&mut tst).await.unwrap();
        assert_eq!(&tst, b"TST");
        for _ in 0..2 {
            let mut len = [0u8; 4];
            stream.read_exact(&mut len).await.unwrap();
            let mut buf = vec![0u8; i32::from_le_bytes(len) as usize];
            stream.read_exact(&mut buf).await.unwrap();
        }
        stream
            .write_all(nps_legacy::md5_hex(nps_proto::CORE_VERSION).as_bytes())
            .await
            .unwrap();
        let mut digest = [0u8; 32];
        stream.read_exact(&mut digest).await.unwrap();
        stream.write_all(nps_proto::VERIFY_SUCCESS.as_bytes()).await.unwrap();
        let mut flag = [0u8; 4];
        stream.read_exact(&mut flag).await.unwrap();
        assert_eq!(&flag, expected_flag);
    }

    /// 读一条 SendInfo 帧，返回 (flag, JSON)。
    async fn read_info_frame<S: AsyncRead + Unpin>(stream: &mut S) -> (String, serde_json::Value) {
        let mut flag = [0u8; 4];
        stream.read_exact(&mut flag).await.unwrap();
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).await.unwrap();
        let mut body = vec![0u8; i32::from_le_bytes(len) as usize];
        stream.read_exact(&mut body).await.unwrap();
        (
            String::from_utf8(flag.to_vec()).unwrap(),
            serde_json::from_slice(&body).unwrap(),
        )
    }

    fn sample_config() -> FileConfig {
        crate::config::parse_str(
            r#"{
                "common": {"server_addr": "127.0.0.1:8024", "vkey": "secret"},
                "tasks": [
                    {"remark": "a", "mode": "tcp", "server_port": "10000",
                     "target_addr": "127.0.0.1:8080"},
                    {"remark": "b", "mode": "udp", "server_port": "10001",
                     "target_addr": "8.8.8.8:53"}
                ],
                "hosts": []
            }"#,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn upload_config_uploads_only_tcp_and_keeps_vkey() {
        let (mut client, mut server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            server.write_all(&[0]).await.unwrap(); // isPub=false
            let mut flags = Vec::new();
            loop {
                let mut f = [0u8; 4];
                if server.read_exact(&mut f).await.is_err() {
                    break;
                }
                let mut len = [0u8; 4];
                server.read_exact(&mut len).await.unwrap();
                let mut body = vec![0u8; i32::from_le_bytes(len) as usize];
                server.read_exact(&mut body).await.unwrap();
                let _: serde_json::Value = serde_json::from_slice(&body).unwrap();
                server.write_all(&[1]).await.unwrap();
                flags.push(String::from_utf8(f.to_vec()).unwrap());
            }
            flags
        });

        let config = sample_config();
        let vkey = upload_config(&mut client, &config).await.unwrap();
        assert_eq!(vkey, "secret");
        drop(client); // 让服务端读到 EOF 结束循环
        let flags = server_task.await.unwrap();
        assert_eq!(flags, vec![nps_proto::NEW_TASK.to_owned()]);
    }

    #[tokio::test]
    async fn upload_config_with_is_pub_reads_16_byte_vkey() {
        let (mut client, mut server) = duplex(64 * 1024);
        let assigned = *b"abcdefghijklmnop";
        let server_task = tokio::spawn(async move {
            server.write_all(&[1]).await.unwrap(); // isPub=true
            let (flag, _) = read_info_frame(&mut server).await;
            assert_eq!(flag, nps_proto::NEW_CONF);
            server.write_all(&[1]).await.unwrap();
            server.write_all(&assigned).await.unwrap();
            let (flag, _) = read_info_frame(&mut server).await;
            assert_eq!(flag, nps_proto::NEW_TASK);
            server.write_all(&[1]).await.unwrap();
        });

        let config = sample_config();
        let vkey = upload_config(&mut client, &config).await.unwrap();
        assert_eq!(vkey, "abcdefghijklmnop");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn upload_config_rejects_task_and_stops() {
        let (mut client, mut server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            server.write_all(&[0]).await.unwrap();
            let (flag, _) = read_info_frame(&mut server).await;
            assert_eq!(flag, nps_proto::NEW_TASK);
            server.write_all(&[0]).await.unwrap();
        });

        let config = sample_config();
        let error = upload_config(&mut client, &config).await.unwrap_err();
        assert!(
            matches!(error, RegistrationError::TaskRejected { .. }),
            "got {error:?}"
        );
        assert!(error.to_string().contains('a'));
        assert_eq!(error.exit_code(), crate::cli::EXIT_PROTOCOL);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn upload_config_rejects_blank_assigned_vkey() {
        let (mut client, mut server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            server.write_all(&[1]).await.unwrap();
            let _ = read_info_frame(&mut server).await;
            server.write_all(&[1]).await.unwrap();
            server.write_all(&[0u8; ASSIGNED_VKEY_LEN]).await.unwrap();
        });

        let config = sample_config();
        let error = upload_config(&mut client, &config).await.unwrap_err();
        assert!(
            matches!(error, RegistrationError::InvalidAssignedVkey),
            "got {error:?}"
        );
        assert_eq!(error.exit_code(), crate::cli::EXIT_REGISTER_DENIED);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn send_info_frame_matches_go_sendinfo() {
        let (mut client, mut server) = duplex(4096);
        let payload = serde_json::json!({"Remark": "a"});
        send_info(&mut client, b"task", &payload).await.unwrap();

        let (flag, value) = read_info_frame(&mut server).await;
        assert_eq!(flag, "task");
        assert_eq!(value, payload);
    }

    #[tokio::test]
    async fn rgst_returns_assigned_vkey_when_server_replies() {
        let (mut client, mut server) = duplex(64 * 1024);
        let assigned = *b"0123456789abcdef";
        let server_task = tokio::spawn(async move {
            server_handshake(&mut server, FLAG_RGST).await;
            let mut hours = [0u8; 4];
            server.read_exact(&mut hours).await.unwrap();
            assert_eq!(i32::from_le_bytes(hours), DEFAULT_REGISTER_HOURS);
            server.write_all(&assigned).await.unwrap();
            // 保持连接不立即关闭
            let _ = tokio::time::sleep(Duration::from_millis(20)).await;
        });

        // 绕过 dial_bridge，直接在内存流上复现 register 的帧序
        client_handshake(&mut client, "", FLAG_RGST).await.unwrap();
        client
            .write_all(&DEFAULT_REGISTER_HOURS.to_le_bytes())
            .await
            .unwrap();
        let mut buf = [0u8; ASSIGNED_VKEY_LEN];
        read_exact_timed(&mut client, &mut buf).await.unwrap();
        assert_eq!(validate_assigned(&buf).unwrap(), "0123456789abcdef");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn rgst_denied_is_reported_not_retried() {
        let (mut client, mut server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            // 服务端拒绝：握手阶段就回 vkey 并关闭
            let mut tst = [0u8; 3];
            server.read_exact(&mut tst).await.unwrap();
            for _ in 0..2 {
                let mut len = [0u8; 4];
                server.read_exact(&mut len).await.unwrap();
                let mut buf = vec![0u8; i32::from_le_bytes(len) as usize];
                server.read_exact(&mut buf).await.unwrap();
            }
            server
                .write_all(nps_legacy::md5_hex(nps_proto::CORE_VERSION).as_bytes())
                .await
                .unwrap();
            let mut digest = [0u8; 32];
            server.read_exact(&mut digest).await.unwrap();
            server.write_all(nps_proto::VERIFY_EER.as_bytes()).await.unwrap();
        });

        let error = client_handshake(&mut client, "", FLAG_RGST)
            .await
            .map_err(map_handshake)
            .unwrap_err();
        assert!(matches!(error, RegistrationError::VkeyRejected));
        assert_eq!(error.exit_code(), crate::cli::EXIT_VKEY_REJECTED);
        server_task.await.unwrap();
    }

    #[test]
    fn exit_codes_are_dedicated() {
        assert_eq!(
            RegistrationError::RegisterDenied("x".into()).exit_code(),
            crate::cli::EXIT_REGISTER_DENIED
        );
        assert_eq!(
            RegistrationError::InvalidAssignedVkey.exit_code(),
            crate::cli::EXIT_REGISTER_DENIED
        );
        assert_eq!(
            RegistrationError::VkeyRejected.exit_code(),
            crate::cli::EXIT_VKEY_REJECTED
        );
        assert_eq!(
            RegistrationError::Protocol("x".into()).exit_code(),
            crate::cli::EXIT_PROTOCOL
        );
    }

    #[test]
    fn denial_classification() {
        assert!(RegistrationError::RegisterDenied("x".into()).is_denial());
        assert!(!RegistrationError::Unreachable {
            server: "x".into(),
            error: "y".into()
        }
        .is_denial());
    }

    #[test]
    fn no_secret_in_error_text() {
        let error = RegistrationError::TaskRejected {
            remark: "tcp-1".into(),
        };
        assert!(!error.to_string().contains("secret"));
    }

    #[test]
    fn describe_tasks_counts_without_secrets() {
        let config = sample_config();
        let text = describe_tasks(&config);
        assert!(text.contains("tcp=1"));
        assert!(text.contains("跳过=1"));
        assert!(!text.contains("secret"));
    }

    #[test]
    fn flag_helper_rejects_non_ascii_padding() {
        assert_eq!(&flag(nps_proto::NEW_TASK), b"task");
        assert_eq!(&flag(nps_proto::NEW_CONF), b"conf");
    }
}
