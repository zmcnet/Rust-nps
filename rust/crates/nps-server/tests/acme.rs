//! ACME 模块集成测试。
//!
//! 两类测试：
//! 1. **永远可跑（离线）**：预检失败不产生 CA 请求、配置/启动流程零网络请求、
//!    续期关闭后立即返回、http-01 / tls-alpn-01 应答服务器行为、域名校验等。
//! 2. **Pebble 端到端（可选）**：本机存在 Pebble 可执行文件时，启动一个**独立实例**
//!    （随机端口 + 临时 CA），走完 账户注册 → 下单 → 挑战 → 验证 → 签发 → 落盘，
//!    并用 rustls 以 Pebble 的根证书校验签发的证书链。
//!
//! Pebble 可执行文件通过环境变量 `NPS_PEBBLE_BIN` 指定，或在 `PATH` 中能找到
//! `pebble.exe` / `pebble` 时自动启用。找不到时会打印 `SKIP`，不伪装通过。

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use nps_server::acme::{
    certificate_not_after, format_system_time, run_renewal_loop, AcmeClient, AcmeConfig, AcmeEvent,
    AcmeEvents, AcmeProvider, AcmeService, AcmeStage, CertificateRequest, ChallengeKind, DnsProvider,
    DnsRecord, Http01Responder, RenewalPolicy, RenewalTarget, TlsAlpnResponder,
};

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

/// 进程内唯一的临时目录（测试结束删除）
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "nps-acme-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    l.local_addr().expect("local addr").port()
}

fn pebble_bin() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("NPS_PEBBLE_BIN") {
        let p = PathBuf::from(explicit);
        if p.is_file() {
            return Some(p);
        }
        eprintln!("NPS_PEBBLE_BIN 指向的文件不存在：{}", p.display());
        return None;
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for name in ["pebble.exe", "pebble"] {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// 测试域名：只解析到 127.0.0.1 的公共域名。
const TEST_DOMAIN: &str = "lvh.me";

async fn resolves_to_loopback(domain: &str) -> bool {
    match tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((domain, 0))).await {
        Ok(Ok(addrs)) => addrs.map(|a| a.ip()).any(|ip| ip == IpAddr::from([127, 0, 0, 1])),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Pebble 实例
// ---------------------------------------------------------------------------

struct Pebble {
    child: Child,
    _dir: TempDir,
    acme_port: u16,
    mgmt_port: u16,
    http_port: u16,
    tls_port: u16,
    /// 给 Pebble 的 HTTPS 监听签证书的测试 CA（PEM）
    ca_pem: String,
}

impl Pebble {
    /// 启动一个独立 Pebble 实例；返回 `None` 表示环境不具备条件。
    ///
    /// 设置 `NPS_REQUIRE_PEBBLE=1` 后，环境不满足条件会**直接失败**，
    /// 用来在 CI / 交付验证里强制跑真实 ACME 流程，避免"静默跳过"被当成通过。
    async fn start(tag: &str) -> Option<Self> {
        let required = std::env::var("NPS_REQUIRE_PEBBLE").is_ok_and(|v| v != "0");
        let missing = |why: String| {
            if required {
                panic!("NPS_REQUIRE_PEBBLE=1 但环境不满足：{why}");
            }
            eprintln!("SKIP: {why}");
            None
        };
        let bin = match pebble_bin() {
            Some(bin) => bin,
            None => {
                return missing(
                    "未找到 pebble 可执行文件（设置 NPS_PEBBLE_BIN，或把 pebble 放进 PATH）"
                        .to_string(),
                )
            }
        };
        if !resolves_to_loopback(TEST_DOMAIN).await {
            return missing(format!(
                "{TEST_DOMAIN} 未解析到 127.0.0.1，无法做 Pebble 端到端验证"
            ));
        }

        let dir = TempDir::new(tag);
        let (ca_pem, cert_path, key_path) = write_pebble_tls_pki(&dir);
        let acme_port = free_port();
        let mgmt_port = free_port();
        let http_port = free_port();
        let tls_port = free_port();

        let config = format!(
            r#"{{
  "pebble": {{
    "listenAddress": "127.0.0.1:{acme_port}",
    "managementListenAddress": "127.0.0.1:{mgmt_port}",
    "certificate": "{}",
    "privateKey": "{}",
    "httpPort": {http_port},
    "tlsPort": {tls_port},
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false,
    "keyAlgorithm": "ecdsa",
    "retryAfter": {{ "authz": 1, "order": 1 }}
  }}
}}"#,
            cert_path.display().to_string().replace('\\', "/"),
            key_path.display().to_string().replace('\\', "/"),
        );
        let config_path = dir.join("pebble-config.json");
        std::fs::write(&config_path, config).expect("write pebble config");

        let child = Command::new(&bin)
            .arg("-config")
            .arg(&config_path)
            .env("PEBBLE_VA_NOSLEEP", "1")
            .env("PEBBLE_WFE_NONCEREJECT", "0")
            .env("PEBBLE_AUTHZREUSE", "0")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("无法启动 {}：{e}", bin.display()));

        let pebble = Self {
            child,
            _dir: dir,
            acme_port,
            mgmt_port,
            http_port,
            tls_port,
            ca_pem,
        };

        if !wait_port(pebble.acme_port, Duration::from_secs(20)).await {
            let mut me = pebble;
            let _ = me.child.kill();
            if required {
                panic!("NPS_REQUIRE_PEBBLE=1 但 Pebble 没有在 20s 内监听 {}", me.acme_port);
            }
            eprintln!("SKIP: Pebble 没有在 20s 内监听 {}", me.acme_port);
            return None;
        }
        Some(pebble)
    }

    fn directory_url(&self) -> String {
        format!("https://localhost:{}/dir", self.acme_port)
    }

    /// 从 management API 取 Pebble 运行期生成的根证书
    async fn root_pem(&self) -> String {
        let url = format!("https://localhost:{}/roots/0", self.mgmt_port);
        fetch_pem_with_ca(&url, self.ca_pem.as_bytes())
            .await
            .expect("获取 Pebble 根证书失败")
    }
}

impl Drop for Pebble {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn wait_port(port: u16, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// 生成"测试 CA + localhost 叶证书"，供 Pebble 自己的 HTTPS 端点使用。
fn write_pebble_tls_pki(dir: &TempDir) -> (String, PathBuf, PathBuf) {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "nps-acme test CA");
    let ca_key = KeyPair::generate().expect("ca key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

    let mut leaf_params = CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("leaf cert");

    let cert_path = dir.join("pebble-cert.pem");
    let key_path = dir.join("pebble-key.pem");
    std::fs::write(&cert_path, leaf_cert.pem()).expect("write leaf cert");
    std::fs::write(&key_path, leaf_key.serialize_pem()).expect("write leaf key");
    (ca_cert.pem(), cert_path, key_path)
}

/// 用给定 CA 校验 HTTPS 并取回 PEM（仅测试用；正式代码里没有这种"信任任意 CA"的入口）。
async fn fetch_pem_with_ca(url: &str, ca_pem: &[u8]) -> Result<String, String> {
    use bytes::Bytes;
    use http::Request;
    use instant_acme::{BodyWrapper, BytesResponse, HttpClient};
    use rustls::pki_types::CertificateDer;
    use rustls::RootCertStore;
    use std::sync::Arc;

    struct Http {
        inner: hyper_util::client::legacy::Client<
            hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
            BodyWrapper<Bytes>,
        >,
    }

    impl HttpClient for Http {
        fn request(
            &self,
            req: Request<BodyWrapper<Bytes>>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<BytesResponse, instant_acme::Error>>
                    + Send,
            >,
        > {
            let fut = self.inner.request(req);
            Box::pin(async move {
                fut.await
                    .map(BytesResponse::from)
                    .map_err(|e| instant_acme::Error::Other(Box::new(e)))
            })
        }
    }

    let mut roots = RootCertStore::empty();
    let mut cursor = std::io::Cursor::new(ca_pem.to_vec());
    for cert in rustls_pemfile::certs(&mut cursor) {
        let cert: CertificateDer<'static> = cert.map_err(|e| e.to_string())?;
        roots.add(cert).map_err(|e| e.to_string())?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only()
        .enable_http1()
        .build();
    let client = Http {
        inner: hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(connector),
    };

    let req = Request::builder()
        .method(http::Method::GET)
        .uri(url)
        .body(BodyWrapper::from(Vec::new()))
        .map_err(|e| e.to_string())?;
    let mut rsp = client.request(req).await.map_err(|e| e.to_string())?;
    let status = rsp.parts.status;
    let body = rsp.body.into_bytes().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }
    Ok(String::from_utf8_lossy(&body).to_string())
}

fn acme_config(data_dir: &Path) -> AcmeConfig {
    let mut cfg = AcmeConfig::new(data_dir);
    cfg.preflight_timeout = Duration::from_secs(5);
    cfg.challenge_timeout = Duration::from_secs(60);
    cfg
}

// ---------------------------------------------------------------------------
// 1. 绝不自动申请 / 零网络请求
// ---------------------------------------------------------------------------

#[tokio::test]
async fn constructing_service_and_planning_requests_sends_nothing() {
    let dir = TempDir::new("zero");
    let mut cfg = acme_config(&dir.path);
    // 指向一个必然连不上的地址：任何真实请求都会立刻失败
    cfg.provider = AcmeProvider::Custom("https://127.0.0.1:1/dir".to_string());
    cfg.public_ip = Some(IpAddr::from([127, 0, 0, 1]));

    let service = AcmeService::new(cfg).expect("service");
    let audit = service.audit();
    assert_eq!(audit.count(), 0, "构造服务不应发出任何网络请求");

    // 站点配置里写了 tls_mode=acme —— 依然什么都不做
    let mut site = nps_server::HttpSiteConfig {
        id: 1,
        name: "site".into(),
        client_id: 1,
        domain: "example.com".into(),
        target_addr: "127.0.0.1:8080".into(),
        routes: Vec::new(),
        websocket: true,
        enabled: true,
        tls_mode: nps_server::TlsMode::Acme,
        force_https: true,
    };
    let pending = service.pending_requests(std::slice::from_ref(&site));
    assert_eq!(pending.len(), 1, "应该翻译出一条待办");
    assert_eq!(pending[0].domains(), &["example.com".to_string()]);
    assert_eq!(audit.count(), 0, "读配置不得产生 ACME 请求");

    // 同一域名出现两次（大小写/尾点不同）只生成一条待办
    let mut dup = site.clone();
    dup.id = 2;
    dup.domain = "Example.COM.".into();
    let pending = service.pending_requests(&[site.clone(), dup]);
    assert_eq!(pending.len(), 1, "重复域名应去重");
    assert_eq!(audit.count(), 0);

    // 站点改成 off 后没有待办
    site.tls_mode = nps_server::TlsMode::Off;
    assert!(service.pending_requests(&[site]).is_empty());
    assert_eq!(audit.count(), 0);

    // 账户目录已创建（本地准备），但没有网络请求
    assert!(dir.path.join("acme").is_dir());
    assert!(audit.urls().is_empty());
}

#[tokio::test]
async fn disabled_renewal_loop_never_contacts_ca() {
    let dir = TempDir::new("renew-off");
    let mut cfg = acme_config(&dir.path);
    cfg.provider = AcmeProvider::Custom("https://127.0.0.1:1/dir".to_string());
    cfg.renewal = RenewalPolicy::disabled();
    let client = std::sync::Arc::new(AcmeClient::new(cfg).expect("client"));
    let audit = client.audit();

    let target = RenewalTarget {
        request: CertificateRequest::renewal(vec!["example.com".into()], ChallengeKind::Http01)
            .expect("request"),
        not_after: SystemTime::now() - Duration::from_secs(86_400), // 已过期
        failures: 0,
    };
    // 用超时兜底：关闭自动续期时必须立刻返回，而不是挂住
    let res = tokio::time::timeout(
        Duration::from_secs(2),
        run_renewal_loop(client, vec![target], RenewalPolicy::disabled(), AcmeEvents::noop()),
    )
    .await
    .expect("disabled loop must return immediately");
    assert!(res.is_ok());
    assert_eq!(audit.count(), 0, "关闭自动续期后不得联系 CA");
}

#[tokio::test]
async fn preflight_failure_consumes_no_ca_quota() {
    let dir = TempDir::new("preflight");
    let mut cfg = acme_config(&dir.path);
    cfg.provider = AcmeProvider::Custom("https://127.0.0.1:1/dir".to_string());
    cfg.public_ip = Some(IpAddr::from([203, 0, 113, 7]));
    let client = AcmeClient::new(cfg).expect("client");
    let audit = client.audit();
    let (events, recorded) = AcmeEvents::recording();

    let req = CertificateRequest::user(vec!["no-such-host-nps.invalid".into()]).expect("request");
    let err = client
        .request_certificate(&req, &events)
        .await
        .expect_err("预检必须失败");
    assert_eq!(err.stage, AcmeStage::Preflight);
    assert_eq!(audit.count(), 0, "预检失败不得发出任何 ACME 请求");
    assert!(audit.urls().is_empty());

    let events = recorded.lock().unwrap().clone();
    assert!(events.contains(&AcmeEvent::PreflightStarted));
    assert!(matches!(events.last(), Some(AcmeEvent::Failed { stage, .. }) if stage == "preflight"));
    assert!(!events.iter().any(|e| matches!(e, AcmeEvent::AccountReady)));
    assert!(err.reason().contains("解析"), "原因要可操作：{}", err.reason());
}

#[tokio::test]
async fn ip_mismatch_reports_both_addresses() {
    let dir = TempDir::new("ip-mismatch");
    let mut cfg = acme_config(&dir.path);
    cfg.provider = AcmeProvider::Custom("https://127.0.0.1:1/dir".to_string());
    cfg.public_ip = Some(IpAddr::from([203, 0, 113, 7]));
    let client = AcmeClient::new(cfg).expect("client");
    let audit = client.audit();

    let req = CertificateRequest::user(vec![TEST_DOMAIN.into()]).expect("request");
    let err = client
        .request_certificate(&req, &AcmeEvents::noop())
        .await
        .expect_err("IP 不匹配必须失败");
    assert_eq!(err.stage, AcmeStage::Preflight);
    assert!(err.reason().contains("203.0.113.7"));
    assert!(err.reason().contains("127.0.0.1"));
    assert_eq!(audit.count(), 0);
}

// ---------------------------------------------------------------------------
// 2. 挑战应答服务器
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http01_responder_serves_token_only() {
    use nps_server::acme::ChallengeStore;

    let store = ChallengeStore::new();
    store.insert("tok-1", "tok-1.thumb");
    let responder = Http01Responder::bind(store.clone(), "127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind");
    let addr = responder.local_addr();

    // 命中的路径
    let body = http_get(addr, "/.well-known/acme-challenge/tok-1").await;
    assert!(body.starts_with("HTTP/1.1 200"), "{body}");
    assert!(body.ends_with("tok-1.thumb"), "{body}");

    // 未命中的 token
    let body = http_get(addr, "/.well-known/acme-challenge/other").await;
    assert!(body.starts_with("HTTP/1.1 404"), "{body}");

    // 其它路径
    let body = http_get(addr, "/admin").await;
    assert!(body.starts_with("HTTP/1.1 404"), "{body}");
    responder.shutdown();
}

async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read");
    String::from_utf8_lossy(&buf).to_string()
}

#[tokio::test]
async fn tls_alpn_responder_speaks_acme_tls_1() {
    let responder = TlsAlpnResponder::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind");
    let digest = [7u8; 32];
    responder.publish("alpn.example.com", &digest).expect("publish");

    // 用一个"接受任意证书"的 rustls 客户端做真实握手，检查 ALPN 与证书内容
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAny))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(cfg));

    let tcp = tokio::net::TcpStream::connect(responder.local_addr())
        .await
        .expect("connect");
    let name = rustls::pki_types::ServerName::try_from("alpn.example.com").unwrap();
    let stream = connector.connect(name, tcp).await.expect("handshake");
    let (_, conn) = stream.get_ref();
    assert_eq!(
        conn.alpn_protocol(),
        Some(&b"acme-tls/1"[..]),
        "ALPN 必须协商成 acme-tls/1"
    );
    let certs = conn.peer_certificates().expect("peer cert");
    assert_eq!(certs.len(), 1);
    // 证书里必须有 critical 的 pe-acmeIdentifier 扩展 (1.3.6.1.5.5.7.1.31) 且内容为 digest
    let der = certs[0].as_ref();
    let needle: [u8; 8] = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07];
    let oid_pos = der
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("acmeIdentifier OID 必须存在");
    let tail = &der[oid_pos + needle.len()..];
    assert_eq!(tail[0], 0x01, "OID 最后一段应为 0x1f (31)");
    assert_eq!(tail[1], 0x1f);
    // OID 剩余内容 [0x01, 0x1f]，随后是 BOOLEAN(critical)=TRUE，再是 OCTET STRING(32)+digest
    assert_eq!(tail[2], 0x01, "critical 字段应为 BOOLEAN");
    assert_eq!(tail[3], 0x01, "BOOLEAN 长度应为 1");
    assert!(
        tail[4] == 0x01 || tail[4] == 0xff,
        "acmeIdentifier 必须是 critical 扩展（实际 {:#x}）",
        tail[4]
    );
    // extnValue 是外层 OCTET STRING（长度 34 = 内层 2 字节头 + 32 字节摘要）
    assert_eq!(tail[5], 0x04, "extnValue 应为 OCTET STRING");
    assert_eq!(tail[6], 0x22, "extnValue 长度应为 34");
    assert_eq!(tail[7], 0x04, "内层应为 OCTET STRING");
    assert_eq!(tail[8], 0x20, "摘要长度应为 32 字节");
    assert_eq!(&tail[9..41], &digest);
    responder.shutdown();
}

/// 测试用：接受任意证书
#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

#[tokio::test]
async fn dns01_without_provider_is_explicitly_unsupported() {
    // 阿里云只提供占位实现：必须如实返回 Unsupported
    use nps_server::acme::AliyunDns;
    let provider = AliyunDns;
    let record = DnsRecord {
        fqdn: "_acme-challenge.example.com".into(),
        value: "x".into(),
    };
    let err = provider
        .present(&record)
        .await
        .expect_err("阿里云必须返回未实现");
    assert!(err.reason().contains("尚未实现"));

    // 未配置 provider 时，AcmeClient::new 在预检阶段就拒绝
    let dir = TempDir::new("dns-none");
    let mut cfg = acme_config(&dir.path);
    cfg.challenge = ChallengeKind::Dns01;
    cfg.provider = AcmeProvider::Custom("https://127.0.0.1:1/dir".to_string());
    let err = AcmeClient::new(cfg).expect_err("dns-01 无 provider 必须拒绝");
    assert_eq!(err.stage, AcmeStage::Preflight);
}

// ---------------------------------------------------------------------------
// 3. Pebble 端到端
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http01_end_to_end_with_pebble() {
    let Some(pebble) = Pebble::start("http01").await else {
        return;
    };
    let root_pem = pebble.root_pem().await;
    let dir = TempDir::new("http01-data");
    let root_path = dir.join("pebble-root.pem");
    std::fs::write(&root_path, &root_pem).expect("write root");
    // Pebble 的 HTTPS 端点用测试 CA 签的证书，签发的证书链才用 Pebble 运行期根
    let ca_path = dir.join("pebble-tls-ca.pem");
    std::fs::write(&ca_path, pebble.ca_pem.as_bytes()).expect("write ca");

    let mut cfg = acme_config(&dir.join("data"));
    cfg.provider = AcmeProvider::Custom(pebble.directory_url());
    cfg.challenge = ChallengeKind::Http01;
    cfg.http_bind = format!("127.0.0.1:{}", pebble.http_port).parse().unwrap();
    cfg.public_http_port = pebble.http_port;
    cfg.public_ip = Some(IpAddr::from([127, 0, 0, 1]));
    cfg.contact_email = Some("acme-test@example.com".to_string());
    cfg.extra_trust_roots = vec![ca_path.clone(), root_path.clone()];
    cfg.use_public_roots = false;

    let cfg_for_restart = cfg.clone();
    let client = AcmeClient::new(cfg).expect("client");
    let audit = client.audit();
    let (events, recorded) = AcmeEvents::recording();

    let req = CertificateRequest::user(vec![TEST_DOMAIN.into()]).expect("request");
    let cert = client
        .request_certificate(&req, &events)
        .await
        .expect("Pebble 应当签发证书");

    // ---- 事件序列 ----
    let events = recorded.lock().unwrap().clone();
    let names: Vec<&str> = events
        .iter()
        .map(|e| match e {
            AcmeEvent::PreflightStarted => "preflight",
            AcmeEvent::DnsResolved { .. } => "dns",
            AcmeEvent::PortReachable { .. } => "port",
            AcmeEvent::AccountReady => "account",
            AcmeEvent::OrderCreated { .. } => "order",
            AcmeEvent::ChallengeReady { .. } => "challenge",
            AcmeEvent::Validating => "validating",
            AcmeEvent::ChallengeValidated => "validated",
            AcmeEvent::CertificateIssued { .. } => "issued",
            AcmeEvent::Deployed => "deployed",
            AcmeEvent::Failed { .. } => "failed",
        })
        .collect();
    println!("事件序列: {names:?}");
    assert_eq!(names.first(), Some(&"preflight"));
    assert!(names.contains(&"account"));
    assert!(names.contains(&"order"));
    assert!(names.contains(&"challenge"));
    assert!(names.contains(&"validated"));
    assert!(names.contains(&"issued"));
    assert_eq!(names.last(), Some(&"deployed"));
    assert!(!names.contains(&"failed"));

    // ---- 证书内容 ----
    println!("签发域名: {:?}", cert.domains);
    println!("到期时间: {}", cert.not_after_rfc3339());
    println!("证书路径: {}", cert.cert_path.display());
    println!("证书链长度: {} 字节", cert.certificate_pem.len());
    assert_eq!(cert.challenge, ChallengeKind::Http01);
    assert!(cert.certificate_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(cert.private_key_pem.contains("BEGIN PRIVATE KEY"));
    assert!(cert.not_after > SystemTime::now() + Duration::from_secs(60 * 86_400));
    assert!(cert.days_remaining(SystemTime::now()) > 60);
    assert_eq!(
        certificate_not_after(&cert.certificate_pem).unwrap(),
        cert.not_after
    );
    // SAN 必须包含申请域名
    let der = {
        let block = x509_parser::pem::parse_x509_pem(cert.certificate_pem.as_bytes())
            .expect("pem")
            .1;
        block.contents
    };
    let (_, parsed) = x509_parser::parse_x509_certificate(&der).expect("x509");
    let san = parsed
        .subject_alternative_name()
        .expect("san ext")
        .expect("san value");
    let names: Vec<String> = san
        .value
        .general_names
        .iter()
        .filter_map(|n| match n {
            x509_parser::extensions::GeneralName::DNSName(d) => Some(d.to_string()),
            _ => None,
        })
        .collect();
    println!("证书 SAN: {names:?}");
    assert!(names.iter().any(|n| n == TEST_DOMAIN));

    // ---- 用 rustls 以 Pebble 根 CA 校验链（真实 TLS 握手）----
    nps_server::acme::verify_chain_via_tls(
        &cert.certificate_pem,
        &cert.private_key_pem,
        root_pem.as_bytes(),
        TEST_DOMAIN,
    )
    .await
    .expect("证书链必须能通过 Pebble 根 CA 校验");

    // ---- 落盘 ----
    assert!(cert.cert_path.exists());
    assert!(cert.key_path.exists());
    assert!(cert
        .cert_path
        .parent()
        .expect("dir")
        .join("meta.json")
        .exists());
    assert!(dir.join("data/acme/account.key").exists());
    assert!(dir.join("data/acme/account.json").exists());
    assert!(audit.count() > 0);
    println!("ACME 网络请求数: {}（账户注册 + 订单 + 挑战 + 签发）", audit.count());

    // ---- 与 tls::CertificateStore 的落盘契约 ----
    // 证书根目录交给 CertificateStore 应能直接加载（含来源标注为 acme）
    let store_root = dir.join("data/acme/certs");
    let tls_store = nps_server::tls::CertificateStore::open(&store_root).expect("CertificateStore::open");
    let info = tls_store.get(TEST_DOMAIN).expect("TLS 层必须能加载 ACME 产物");
    assert_eq!(info.source, nps_server::tls::CertSource::Acme);
    assert!(!info.expired);
    assert!(info.days_remaining > 60);
    assert!(info.san.iter().any(|d| d == TEST_DOMAIN));
    println!(
        "TLS 层加载到 ACME 证书：source={} issuer={} 剩余 {} 天 指纹 {}",
        info.source, info.issuer, info.days_remaining, info.fingerprint_sha256
    );

    // ---- 账户复用 ----
    let credentials_before =
        std::fs::read_to_string(dir.join("data/acme/account.json")).expect("read creds");
    let accounts_before = audit.count();
    let req2 = CertificateRequest::user(vec![TEST_DOMAIN.into()]).expect("request2");
    let cert2 = client
        .request_certificate(&req2, &AcmeEvents::noop())
        .await
        .expect("第二次申请应当复用账户");
    let credentials_after =
        std::fs::read_to_string(dir.join("data/acme/account.json")).expect("read creds");
    assert_eq!(credentials_before, credentials_after, "账户凭据不应重新生成");
    assert!(audit.count() > accounts_before);
    println!(
        "第二次申请（复用账户）到期：{}，请求数 {} → {}",
        cert2.not_after_rfc3339(),
        accounts_before,
        audit.count()
    );

    // ---- 模拟重启：删掉 account.json，只留 account.key，必须复用同一账户 ----
    let account_id_before: serde_json::Value =
        serde_json::from_str(&credentials_before).expect("account.json");
    std::fs::remove_file(dir.join("data/acme/account.json")).expect("remove credentials");
    let restarted = AcmeClient::new(cfg_for_restart).expect("restarted client");
    let req3 = CertificateRequest::user(vec![TEST_DOMAIN.into()]).expect("request3");
    restarted
        .request_certificate(&req3, &AcmeEvents::noop())
        .await
        .expect("仅凭 account.key 应当能找回账户");
    let credentials_recreated: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("data/acme/account.json")).expect("read creds"),
    )
    .expect("account.json");
    println!(
        "账户 ID：{}（删除凭据后仍是同一个）",
        account_id_before["id"]
    );
    assert_eq!(
        account_id_before["id"], credentials_recreated["id"],
        "同一把 account.key 必须映射到同一个 ACME 账户"
    );

}

#[tokio::test]
async fn tls_alpn_end_to_end_with_pebble() {
    let Some(pebble) = Pebble::start("alpn").await else {
        return;
    };
    let root_pem = pebble.root_pem().await;
    let dir = TempDir::new("alpn-data");
    let root_path = dir.join("pebble-root.pem");
    std::fs::write(&root_path, &root_pem).expect("write root");
    let ca_path = dir.join("pebble-tls-ca.pem");
    std::fs::write(&ca_path, pebble.ca_pem.as_bytes()).expect("write ca");

    let mut cfg = acme_config(&dir.join("data"));
    cfg.provider = AcmeProvider::Custom(pebble.directory_url());
    cfg.challenge = ChallengeKind::TlsAlpn01;
    cfg.tls_alpn_bind = format!("127.0.0.1:{}", pebble.tls_port).parse().unwrap();
    cfg.public_tls_port = pebble.tls_port;
    cfg.public_ip = Some(IpAddr::from([127, 0, 0, 1]));
    cfg.extra_trust_roots = vec![ca_path, root_path];
    cfg.use_public_roots = false;

    let client = AcmeClient::new(cfg).expect("client");
    let audit = client.audit();
    let req = CertificateRequest::user_with(vec![TEST_DOMAIN.into()], ChallengeKind::TlsAlpn01)
        .expect("request");
    let cert = client
        .request_certificate(&req, &AcmeEvents::noop())
        .await
        .expect("tls-alpn-01 应当签发成功");

    println!(
        "tls-alpn-01 签发成功：{}，到期 {}，请求数 {}",
        cert.domains.join(","),
        cert.not_after_rfc3339(),
        audit.count()
    );
    nps_server::acme::verify_chain_via_tls(
        &cert.certificate_pem,
        &cert.private_key_pem,
        root_pem.as_bytes(),
        TEST_DOMAIN,
    )
    .await
    .expect("证书链必须通过 Pebble 根 CA 校验");
}

#[tokio::test]
async fn renewal_loop_renews_due_certificate_against_pebble() {
    let Some(pebble) = Pebble::start("renew").await else {
        return;
    };
    let root_pem = pebble.root_pem().await;
    let dir = TempDir::new("renew-data");
    let root_path = dir.join("pebble-root.pem");
    std::fs::write(&root_path, &root_pem).expect("write root");
    let ca_path = dir.join("pebble-tls-ca.pem");
    std::fs::write(&ca_path, pebble.ca_pem.as_bytes()).expect("write ca");

    let mut cfg = acme_config(&dir.join("data"));
    cfg.provider = AcmeProvider::Custom(pebble.directory_url());
    cfg.challenge = ChallengeKind::Http01;
    cfg.http_bind = format!("127.0.0.1:{}", pebble.http_port).parse().unwrap();
    cfg.public_http_port = pebble.http_port;
    cfg.public_ip = Some(IpAddr::from([127, 0, 0, 1]));
    cfg.extra_trust_roots = vec![ca_path, root_path];
    cfg.use_public_roots = false;
    cfg.renewal = RenewalPolicy {
        enabled: true,
        renew_before: Duration::from_secs(30 * 86_400),
        ..RenewalPolicy::default()
    };

    let policy = cfg.renewal.clone();
    let client = std::sync::Arc::new(AcmeClient::new(cfg).expect("client"));
    let audit = client.audit();

    // 第一次：确保证书目录里有东西
    let req = CertificateRequest::user(vec![TEST_DOMAIN.into()]).expect("request");
    let first = client
        .request_certificate(&req, &AcmeEvents::noop())
        .await
        .expect("首次申请");
    let baseline = audit.count();

    // 构造一个"已到期"的续期目标，循环应立刻续期一次
    let target = RenewalTarget {
        request: CertificateRequest::renewal(vec![TEST_DOMAIN.into()], ChallengeKind::Http01)
            .expect("renewal request"),
        not_after: SystemTime::now() - Duration::from_secs(3600),
        failures: 0,
    };
    let (events, recorded) = AcmeEvents::recording();
    let handle = tokio::spawn(run_renewal_loop(
        std::sync::Arc::clone(&client),
        vec![target],
        policy,
        events,
    ));

    // 等续期真正发出请求
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while audit.count() <= baseline && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(audit.count() > baseline, "续期循环必须发起新订单");

    // 等续期完成（证书文件被重写）
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while !recorded
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, AcmeEvent::Deployed))
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    handle.abort();

    let events = recorded.lock().unwrap().clone();
    println!("续期事件数: {}", events.len());
    assert!(
        events.iter().any(|e| matches!(e, AcmeEvent::Deployed)),
        "续期应当完成并落盘"
    );
    let renewed = nps_server::acme::certificate_not_after(&first.certificate_pem).unwrap();
    assert!(renewed > SystemTime::now());
}

#[tokio::test]
async fn pebble_rejects_wrong_challenge_and_reports_actionable_failure() {
    let Some(pebble) = Pebble::start("fail").await else {
        return;
    };
    let root_pem = pebble.root_pem().await;
    let dir = TempDir::new("fail-data");
    let root_path = dir.join("pebble-root.pem");
    std::fs::write(&root_path, &root_pem).expect("write root");
    let ca_path = dir.join("pebble-tls-ca.pem");
    std::fs::write(&ca_path, pebble.ca_pem.as_bytes()).expect("write ca");

    let mut cfg = acme_config(&dir.join("data"));
    cfg.provider = AcmeProvider::Custom(pebble.directory_url());
    cfg.challenge = ChallengeKind::Http01;
    // 故意指向一个没有 http-01 应答的端口：Pebble 验证会失败
    cfg.http_bind = "127.0.0.1:0".parse().unwrap();
    // 一个必然没有人监听的端口
    cfg.public_http_port = free_port();
    cfg.preflight_port_check = false; // 跳过本机探测，确保失败发生在 CA 验证阶段
    cfg.public_ip = Some(IpAddr::from([127, 0, 0, 1]));
    cfg.challenge_timeout = Duration::from_secs(20);
    cfg.extra_trust_roots = vec![ca_path, root_path];
    cfg.use_public_roots = false;

    let client = AcmeClient::new(cfg).expect("client");
    let (events, recorded) = AcmeEvents::recording();
    let req = CertificateRequest::user(vec![TEST_DOMAIN.into()]).expect("request");
    let err = client
        .request_certificate(&req, &events)
        .await
        .expect_err("挑战应当失败");
    assert_eq!(err.stage, AcmeStage::Challenge);
    println!("预期失败原因: {}", err.reason());
    let events = recorded.lock().unwrap().clone();
    assert!(matches!(events.last(), Some(AcmeEvent::Failed { stage, .. }) if stage == "challenge"));
}

// ---------------------------------------------------------------------------
// 4. 工具函数
// ---------------------------------------------------------------------------

#[test]
fn system_time_formatting_is_utc() {
    assert_eq!(
        format_system_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
        "2023-11-14T22:13:20Z"
    );
}

#[test]
fn provider_defaults_and_validation() {
    let dir = TempDir::new("provider");
    let cfg = AcmeConfig::new(&dir.path);
    assert_eq!(
        cfg.provider.directory_url(),
        "https://acme-v02.api.letsencrypt.org/directory"
    );
    assert_eq!(
        AcmeProvider::LetsEncryptStaging.directory_url(),
        "https://acme-staging-v02.api.letsencrypt.org/directory"
    );
    assert_eq!(
        AcmeProvider::ZeroSsl.directory_url(),
        "https://acme.zerossl.com/v2/DV90"
    );

    let mut bad = cfg.clone();
    bad.provider = AcmeProvider::Custom("http://insecure.example/dir".into());
    let err = AcmeClient::new(bad).expect_err("明文 URL 必须被拒绝");
    assert!(err.reason().contains("https"));
}

#[test]
fn wildcard_needs_dns01() {
    let err = CertificateRequest::user(vec!["*.example.com".into()]).expect_err("必须拒绝");
    assert!(err.reason().contains("dns-01"));
    assert!(CertificateRequest::user_with(vec!["*.example.com".into()], ChallengeKind::Dns01).is_ok());
}
