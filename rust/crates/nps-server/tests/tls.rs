//! HTTPS 监听 / SNI 证书路由 / 热加载 / 私钥保护的集成测试。
//!
//! 这里**真起 TCP 监听 + 真做 TLS 握手**（tokio-rustls 客户端），不 mock。
//! 测试用自签证书或临时 CA 签发，客户端用「记录型 verifier」：
//! 它接受任何证书但把叶子证书抄下来，便于断言服务器实际返回了哪张证书。

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nps_server::tls::{
    generate_self_signed, CertSource, CertificateStore, SniResolver, TlsListener, TlsListenerConfig,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::TlsConnector;

// ---------------------------------------------------------------------------
// 客户端：记录服务器出示的叶子证书
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct CapturingVerifier {
    leaf: Arc<Mutex<Option<Vec<u8>>>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // 测试里不信任库：只记录，不校验
        *self.leaf.lock().unwrap() = Some(end_entity.as_ref().to_vec());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

struct Client {
    connector: TlsConnector,
    leaf: Arc<Mutex<Option<Vec<u8>>>>,
}

impl Client {
    fn new() -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let leaf = Arc::new(Mutex::new(None));
        let verifier = Arc::new(CapturingVerifier {
            leaf: leaf.clone(),
            provider: provider.clone(),
        });
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        // 与服务端一致地宣告 http/1.1，用来验证 ALPN 协商
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            connector: TlsConnector::from(Arc::new(config)),
            leaf,
        }
    }

    /// 发起握手；成功返回流 + 服务器出示的叶子证书 DER。
    async fn connect(
        &self,
        addr: SocketAddr,
        sni: &str,
    ) -> Result<(ClientTlsStream<TcpStream>, Vec<u8>), String> {
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("TCP 连接失败: {e}"))?;
        let name = ServerName::try_from(sni.to_string()).map_err(|e| format!("SNI 不合法: {e}"))?;
        let stream = self
            .connector
            .connect(name, tcp)
            .await
            .map_err(|e| format!("TLS 握手失败: {e}"))?;
        let leaf = self
            .leaf
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| "服务器没有出示证书".to_string())?;
        Ok((stream, leaf))
    }
}

// ---------------------------------------------------------------------------
// 测试服务器：真 NPS TLS 监听 + 每连接回一条标记
// ---------------------------------------------------------------------------

struct TestServer {
    addr: SocketAddr,
    listener: Arc<TlsListener>,
    task: tokio::task::JoinHandle<()>,
}

impl TestServer {
    async fn start(store: &CertificateStore) -> Self {
        let listener = TlsListener::with_config(
            store.resolver(),
            TlsListenerConfig {
                handshake_timeout: Duration::from_secs(5),
                alpn_protocols: vec![b"http/1.1".to_vec()],
            },
        )
        .unwrap();
        let tcp = listener.bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let task = spawn_accept_loop(listener.clone(), tcp);
        Self {
            addr,
            listener,
            task,
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn spawn_accept_loop(listener: Arc<TlsListener>, tcp: TcpListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match listener.accept(&tcp).await {
                Ok(mut session) => {
                    // 保持连接一小会儿，让客户端完成读取后再关
                    tokio::spawn(async move {
                        let _ = session.stream.write_all(b"nps-tls-ok\n").await;
                        let mut buf = [0u8; 64];
                        let _ = tokio::time::timeout(
                            Duration::from_secs(3),
                            session.stream.read(&mut buf),
                        )
                        .await;
                    });
                }
                Err(_) => {
                    // 被拒绝的握手（未匹配 SNI 等）不影响循环
                    tokio::task::yield_now().await;
                }
            }
        }
    })
}

// ---------------------------------------------------------------------------
// 自签 / CA 证书工具
// ---------------------------------------------------------------------------

fn temp_dir(tag: &str) -> std::path::PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("nps-tls-{tag}-{}-{nanos}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn dn(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn
}

/// 自签证书（可指定有效期），返回 (cert_pem, key_pem, 证书 DER)
fn make_leaf(
    domain: &str,
    not_before: Option<time::OffsetDateTime>,
    not_after: Option<time::OffsetDateTime>,
) -> (String, String, Vec<u8>) {
    let mut params = CertificateParams::new(vec![domain.to_string()]).unwrap();
    params.distinguished_name = dn(domain);
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    if let Some(t) = not_before {
        params.not_before = t;
    }
    if let Some(t) = not_after {
        params.not_after = t;
    }
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert.pem(), key.serialize_pem(), cert.der().to_vec())
}

/// 临时 CA + 由它签发的叶子证书；返回 (叶子 PEM, 叶子私钥 PEM, CA PEM, CA 私钥对象)
fn make_ca_and_leaf(domain: &str) -> (String, String, String, KeyPair) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.distinguished_name = dn("NPS Test Root CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let mut leaf_params = CertificateParams::new(vec![domain.to_string()]).unwrap();
    leaf_params.distinguished_name = dn(domain);
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = KeyPair::generate().unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

    (
        leaf_cert.pem(),
        leaf_key.serialize_pem(),
        ca_cert.pem(),
        ca_key,
    )
}

fn common_name(der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok().map(str::to_owned));
    name
}

fn san_list(der: &[u8]) -> Vec<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).unwrap();
    let mut out = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            if let x509_parser::extensions::GeneralName::DNSName(n) = name {
                out.push((*n).to_string());
            }
        }
    }
    out
}

fn open_store(tag: &str) -> (std::path::PathBuf, Arc<CertificateStore>) {
    let dir = temp_dir(tag);
    let store = CertificateStore::open(&dir).unwrap();
    (dir, store)
}

/// 建一个只含 `domain` 一张自签证书的 store
fn store_with(tag: &str, domains: &[&str]) -> (std::path::PathBuf, Arc<CertificateStore>) {
    let (dir, store) = open_store(tag);
    for domain in domains {
        store.put_self_signed(domain).unwrap();
    }
    (dir, store)
}

// ---------------------------------------------------------------------------
// 1. SNI 路由
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sni_matching_domain_serves_its_certificate() {
    let (_dir, store) = store_with("match", &["a.example.com", "b.example.com"]);
    let server = TestServer::start(&store).await;
    let client = Client::new();

    let (mut stream, leaf) = client
        .connect(server.addr, "a.example.com")
        .await
        .expect("匹配域名应握手成功");
    // 服务器返回的证书必须是 a.example.com 那张
    assert_eq!(common_name(&leaf).as_deref(), Some("a.example.com"));
    assert!(san_list(&leaf).iter().any(|s| s == "a.example.com"));

    // 上层数据能正常收发（说明返回的确实是解密流）
    let mut buf = [0u8; 32];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .expect("读取超时")
        .expect("读取失败");
    assert_eq!(&buf[..n], b"nps-tls-ok\n");

    assert_eq!(server.listener.accepted_handshakes(), 1);
}

#[tokio::test]
async fn sni_unmatched_domain_is_rejected_without_default_certificate() {
    let (_dir, store) = store_with("reject", &["a.example.com"]);
    let server = TestServer::start(&store).await;
    let client = Client::new();

    // 先确认监听器本身是健康的
    client
        .connect(server.addr, "a.example.com")
        .await
        .expect("已部署域名应握手成功");

    let err = client
        .connect(server.addr, "unknown.example.org")
        .await
        .expect_err("未部署域名必须握手失败");
    println!("[未匹配域名拒绝握手] 客户端收到: {err}");

    // 客户端没有拿到任何证书 —— 服务器没有退回默认证书
    assert!(
        err.contains("TLS 握手失败"),
        "失败原因应该发生在握手阶段: {err}"
    );
    assert!(
        err.contains("AccessDenied")
            || err.contains("alert")
            || err.contains("received fatal")
            || err.contains("peer sent"),
        "应当在握手中收到服务器的 fatal alert: {err}"
    );
    assert_eq!(server.listener.rejected_handshakes(), 1);
    assert_eq!(server.listener.accepted_handshakes(), 1);
}

#[tokio::test]
async fn sni_wildcard_matches_exactly_one_label() {
    let (_dir, store) = store_with("wildcard", &["*.example.com"]);
    let server = TestServer::start(&store).await;
    let client = Client::new();

    // a.example.com → 命中 *.example.com
    let (_stream, leaf) = client
        .connect(server.addr, "a.example.com")
        .await
        .expect("*.example.com 应匹配 a.example.com");
    assert!(san_list(&leaf).iter().any(|s| s == "*.example.com"));

    // example.com → 不匹配（通配不能覆盖裸域）
    let err = client
        .connect(server.addr, "example.com")
        .await
        .expect_err("*.example.com 不应匹配 example.com");
    println!("[通配不匹配裸域] 客户端收到: {err}");

    // a.b.example.com → 不匹配（通配只能替换一个标签）
    let err = client
        .connect(server.addr, "a.b.example.com")
        .await
        .expect_err("*.example.com 不应匹配 a.b.example.com");
    println!("[通配不匹配多级子域] 客户端收到: {err}");
}

#[tokio::test]
async fn sni_exact_match_wins_over_wildcard() {
    let (_dir, store) = store_with("exact-first", &["*.example.com", "a.example.com"]);
    let server = TestServer::start(&store).await;
    let client = Client::new();

    let (_stream, leaf) = client
        .connect(server.addr, "a.example.com")
        .await
        .expect("应握手成功");
    // 精确证书的 CN 是 a.example.com；通配证书的 SAN 是 *.example.com
    assert_eq!(common_name(&leaf).as_deref(), Some("a.example.com"));
}

// ---------------------------------------------------------------------------
// 2. 热加载
// ---------------------------------------------------------------------------

#[tokio::test]
async fn hot_reload_swaps_certificate_without_restarting_listener() {
    let (_dir, store) = open_store("reload");
    let (cert1, key1) = generate_self_signed("a.example.com").unwrap();
    store
        .put("a.example.com", &cert1, &key1, CertSource::Upload)
        .unwrap();

    let server = TestServer::start(&store).await;
    let client = Client::new();

    let (_s1, first) = client
        .connect(server.addr, "a.example.com")
        .await
        .expect("第一次握手");
    let first_fingerprint = store.get("a.example.com").unwrap().fingerprint_sha256;

    // 换一张证书（同一域名、不同密钥/序列号）
    let (cert2, key2) = generate_self_signed("a.example.com").unwrap();
    let info2 = store
        .put("a.example.com", &cert2, &key2, CertSource::Upload)
        .unwrap();
    assert_ne!(info2.fingerprint_sha256, first_fingerprint);

    // **同一个监听器、同一个 TcpListener**，再握一次
    let (_s2, second) = client
        .connect(server.addr, "a.example.com")
        .await
        .expect("热替换后握手应成功");
    assert_ne!(first, second, "第二次握手拿到的证书必须变了");
    assert_eq!(
        common_name(&second).as_deref(),
        Some("a.example.com"),
        "新证书内容应正确"
    );
    assert_eq!(
        store.get("a.example.com").unwrap().fingerprint_sha256,
        info2.fingerprint_sha256
    );
    // listener 一直没重建（握手计数是异步递增的，稍等一下再断言）
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while server.listener.accepted_handshakes() < 2 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        server.listener.accepted_handshakes(),
        2,
        "两次握手都发生在同一个 listener 上（没有重建）"
    );
}

#[tokio::test]
async fn hot_reload_removal_makes_that_domain_unroutable() {
    let (_dir, store) = store_with("remove", &["a.example.com"]);
    let server = TestServer::start(&store).await;
    let client = Client::new();

    client
        .connect(server.addr, "a.example.com")
        .await
        .expect("删除前应握手成功");

    assert!(store.remove("a.example.com").unwrap());
    let err = client
        .connect(server.addr, "a.example.com")
        .await
        .expect_err("删除后该域名必须握手失败");
    println!("[删除证书后拒绝握手] 客户端收到: {err}");
}

// ---------------------------------------------------------------------------
// 3. 证书校验
// ---------------------------------------------------------------------------

#[test]
fn mismatched_key_is_rejected() {
    let (_dir, store) = open_store("mismatch");
    let (cert_a, _key_a, _der) = make_leaf("a.example.com", None, None);
    let (cert_b, key_b, _der_b) = make_leaf("b.example.com", None, None);

    let err = store
        .put("a.example.com", &cert_a, &key_b, CertSource::Upload)
        .expect_err("证书与私钥不匹配时必须报错");
    let msg = format!("{err:#}");
    println!("[证书与私钥不匹配] {msg}");
    assert!(
        msg.contains("证书与私钥不匹配"),
        "错误信息应明确指出不匹配: {msg}"
    );
    // 失败不应留下半成品
    assert!(store.get("a.example.com").is_none());
    assert!(!store.domain_dir("a.example.com").join("cert.pem").exists());
    let _ = (cert_b, key_b);
}

#[test]
fn expired_certificate_loads_but_is_marked() {
    let (_dir, store) = open_store("expired");
    let not_before = time::OffsetDateTime::now_utc() - time::Duration::days(400);
    let not_after = time::OffsetDateTime::now_utc() - time::Duration::days(30);
    let (cert, key, _der) = make_leaf("old.example.com", Some(not_before), Some(not_after));

    let info = store
        .put("old.example.com", &cert, &key, CertSource::Upload)
        .expect("过期证书仍应能加载");
    assert!(info.expired, "过期证书必须被标记");
    assert!(info.days_remaining < 0, "剩余天数应为负数");
    assert!(info.is_expired());
    println!(
        "[过期证书] not_after={} days_remaining={} expired={}",
        info.not_after, info.days_remaining, info.expired
    );
    // 过期证书确实在证书表里（不会被静默丢弃）
    assert!(store.contains("old.example.com"));
}

#[test]
fn incomplete_chain_is_rejected() {
    let (_dir, store) = open_store("chain-missing");
    // 叶子由 CA 签发，但只上传叶子 -> 缺中间证书
    let (leaf_pem, leaf_key, _ca_pem, _ca_key) = make_ca_and_leaf("a.example.com");
    let err = store
        .put("a.example.com", &leaf_pem, &leaf_key, CertSource::Upload)
        .expect_err("缺少中间证书时必须报错");
    let msg = format!("{err:#}");
    println!("[证书链不完整] {msg}");
    assert!(
        msg.contains("证书链不完整"),
        "错误信息应指出链不完整: {msg}"
    );
}

#[test]
fn complete_chain_is_accepted_and_ordered() {
    let (_dir, store) = open_store("chain-ok");
    let (leaf_pem, leaf_key, ca_pem, _ca_key) = make_ca_and_leaf("a.example.com");

    // 顺序正确：leaf + CA
    let full_chain = format!("{leaf_pem}{ca_pem}");
    let info = store
        .put("a.example.com", &full_chain, &leaf_key, CertSource::Upload)
        .expect("完整链应能加载");
    assert_eq!(info.issuer, "CN=NPS Test Root CA");
    assert!(info.san.iter().any(|s| s == "a.example.com"));

    // 顺序错误：CA + leaf -> 拒绝
    let reversed = format!("{ca_pem}{leaf_pem}");
    let err = store
        .put("a.example.com", &reversed, &leaf_key, CertSource::Upload)
        .expect_err("链顺序错误时必须报错");
    println!("[链顺序错误] {:#}", err);
}

#[test]
fn unknown_or_malformed_pem_is_rejected() {
    let (_dir, store) = open_store("badpem");
    let (cert, key, _der) = make_leaf("a.example.com", None, None);

    let err = store
        .put("a.example.com", "not a pem", &key, CertSource::Upload)
        .expect_err("非法证书 PEM 必须报错");
    assert!(
        !format!("{err:#}").contains("PRIVATE KEY"),
        "错误里不能出现私钥"
    );

    let err = store
        .put("a.example.com", &cert, "not a pem", CertSource::Upload)
        .expect_err("非法私钥 PEM 必须报错");
    assert!(!format!("{err:#}").contains("PRIVATE KEY"));
}

// ---------------------------------------------------------------------------
// 4. 私钥保护
// ---------------------------------------------------------------------------

#[test]
fn private_key_never_appears_in_cert_info_or_debug() {
    let (_dir, store) = open_store("secret");
    let (cert_pem, key_pem, _der) = make_leaf("a.example.com", None, None);
    store
        .put("a.example.com", &cert_pem, &key_pem, CertSource::Upload)
        .unwrap();

    // 取私钥 PEM 里一段足够独特的 base64（去掉头尾与换行）
    let key_body: String = key_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let needle = {
        let start = key_body.len() / 2;
        let end = (start + 32).min(key_body.len());
        key_body[start..end].to_string()
    };
    assert!(!needle.is_empty(), "测试前提：私钥必须有内容");

    let info = store.get("a.example.com").unwrap();
    let debug = format!("{:?}", info);
    let json = serde_json::to_string(&info).unwrap();
    let store_debug = format!("{:?}", store);
    let resolver_debug = format!("{:?}", store.resolver());

    for (label, text) in [
        ("CertInfo Debug", debug.as_str()),
        ("CertInfo JSON", json.as_str()),
        ("CertificateStore Debug", store_debug.as_str()),
        ("SniResolver Debug", resolver_debug.as_str()),
    ] {
        assert!(
            !text.contains("PRIVATE KEY"),
            "{label} 不能出现 PRIVATE KEY 标记: {text}"
        );
        assert!(!text.contains(&needle), "{label} 不能出现私钥片段: {text}");
    }

    // meta.json 同理
    let meta =
        std::fs::read_to_string(store.domain_dir("a.example.com").join("meta.json")).unwrap();
    assert!(!meta.contains("PRIVATE KEY"));
    assert!(!meta.contains(&needle));
    // 但证书指纹必须要有，且与私钥无关
    assert!(meta.contains(&info.fingerprint_sha256));

    // CertInfo 里根本不包含任何密钥字段
    assert!(!json.contains("key_pem"));
    assert!(!json.contains("private_key"));
}

#[cfg(unix)]
#[test]
fn key_file_permissions_are_restricted_on_unix() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, store) = open_store("perm");
    store.put_self_signed("a.example.com").unwrap();
    let key_meta = std::fs::metadata(store.domain_dir("a.example.com").join("key.pem")).unwrap();
    assert_eq!(
        key_meta.permissions().mode() & 0o777,
        0o600,
        "key.pem 必须是 0600"
    );
}

#[test]
fn meta_json_records_source_and_certificate_metadata() {
    let (_dir, store) = open_store("meta");
    let info = store.put_self_signed("a.example.com").unwrap();
    assert_eq!(info.source, CertSource::SelfSigned);

    let meta: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(store.domain_dir("a.example.com").join("meta.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(meta["source"], "self-signed");
    assert_eq!(meta["issuer"], "CN=a.example.com");
    assert!(meta["not_after"].as_str().unwrap().ends_with('Z'));
    assert_eq!(meta["fingerprint_sha256"], info.fingerprint_sha256);

    // 记录错误不会破坏证书，也不会丢掉别的模块写的附加字段（如 ACME）
    let meta_path = store.domain_dir("a.example.com").join("meta.json");
    let mut value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();
    value["challenge"] = serde_json::Value::String("http-01".to_owned());
    value["directory_url"] = serde_json::Value::String("https://acme.test/dir".to_owned());
    std::fs::write(&meta_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

    store
        .record_error("a.example.com", "ACME 续期失败：DNS 超时")
        .unwrap();
    let meta: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();
    assert_eq!(meta["last_error"], "ACME 续期失败：DNS 超时");
    assert_eq!(meta["challenge"], "http-01", "附加字段必须保留");
    assert_eq!(meta["directory_url"], "https://acme.test/dir");
    assert_eq!(meta["source"], "self-signed");
    let got = store.get("a.example.com").unwrap();
    assert_eq!(got.last_error.as_deref(), Some("ACME 续期失败：DNS 超时"));

    store.clear_error("a.example.com").unwrap();
    let meta: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();
    assert!(meta.get("last_error").is_none());
    assert_eq!(meta["challenge"], "http-01");
}

// ---------------------------------------------------------------------------
// 5. 存储的持久化 / 重载 / 域名安全
// ---------------------------------------------------------------------------

#[test]
fn store_persists_and_reloads_from_disk() {
    let dir = temp_dir("persist");
    let (cert_pem, key_pem, _der) = make_leaf("a.example.com", None, None);
    {
        let store = CertificateStore::open(&dir).unwrap();
        store
            .put("a.example.com", &cert_pem, &key_pem, CertSource::Upload)
            .unwrap();
        let wild = store.put_self_signed("*.example.com").unwrap();
        assert_eq!(wild.domain, "*.example.com");
    }

    // 重新打开：证书应自动加载，通配目录名在磁盘上是安全的
    let store = CertificateStore::open(&dir).unwrap();
    let list = store.list();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].domain, "*.example.com");
    assert_eq!(list[1].domain, "a.example.com");
    assert_eq!(list[1].source, CertSource::Upload);
    assert!(dir.join("_wildcard_.example.com").is_dir());
    assert!(!dir.join("*.example.com").exists());

    // 通配证书也能被重新加载后路由
    assert!(store
        .resolver()
        .domains()
        .contains(&"*.example.com".to_string()));
}

#[test]
fn path_traversal_domain_is_rejected() {
    let (_dir, store) = open_store("traversal");
    for bad in ["../evil", "a/b", "a\\b", "..", "*", "*.com"] {
        assert!(
            store.put_self_signed(bad).is_err(),
            "危险域名 {bad:?} 必须被拒绝"
        );
        assert!(
            store.remove(bad).is_err(),
            "危险域名 {bad:?} 的删除必须被拒绝"
        );
    }
}

#[test]
fn list_returns_certificates_sorted_and_without_keys() {
    let (_dir, store) = store_with("list", &["b.example.com", "a.example.com"]);
    let list = store.list();
    assert_eq!(
        list.iter().map(|i| i.domain.as_str()).collect::<Vec<_>>(),
        vec!["a.example.com", "b.example.com"]
    );
    for info in list {
        assert!(info.days_remaining > 300, "自签证书有效期一年");
        assert!(!info.expired);
        assert!(info.fingerprint_sha256.contains(':'));
        assert_eq!(info.fingerprint_sha256.split(':').count(), 32);
    }
}

// ---------------------------------------------------------------------------
// 6. 监听器细节
// ---------------------------------------------------------------------------

#[tokio::test]
async fn alpn_declares_http11() {
    let (_dir, store) = store_with("alpn", &["a.example.com"]);
    let server = TestServer::start(&store).await;
    let client = Client::new();

    let (stream, _leaf) = client
        .connect(server.addr, "a.example.com")
        .await
        .expect("握手成功");
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(&b"http/1.1"[..]),
        "应协商到 http/1.1"
    );
}

#[tokio::test]
async fn resolver_is_empty_and_rejects_everything_when_no_certs() {
    let dir = temp_dir("empty");
    let store = CertificateStore::open(&dir).unwrap();
    let resolver: Arc<SniResolver> = store.resolver();
    assert!(resolver.is_empty());
    assert!(resolver.domains().is_empty());

    let listener = TlsListener::new(store.resolver()).unwrap();
    let tcp = listener.bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let task = spawn_accept_loop(listener.clone(), tcp);

    let client = Client::new();
    let err = client
        .connect(addr, "a.example.com")
        .await
        .expect_err("没有证书时必须拒绝握手");
    println!("[空证书表拒绝握手] 客户端收到: {err}");
    assert_eq!(listener.accepted_handshakes(), 0);
    task.abort();
}

// ---------------------------------------------------------------------------
// 7. 独立客户端（OpenSSL）验证：默认忽略，手动 `cargo test -- --ignored` 运行
// ---------------------------------------------------------------------------

/// 用系统 openssl 做一次「非 rustls」的独立验证：
/// 匹配域名能拿到证书、未声明域名被拒绝。
///
/// 标记 `#[ignore]` 是因为它依赖机器上装了 openssl；常规测试不受影响。
#[tokio::test]
#[ignore = "依赖系统 openssl 可执行文件，手动运行：cargo test -p nps-server --test tls -- --ignored"]
async fn openssl_client_sees_routing_and_rejection() {
    let (_dir, store) = store_with("openssl", &["a.example.com"]);
    let server = TestServer::start(&store).await;
    let connect = server.addr.to_string();

    async fn run_s_client(connect: &str, sni: &str) -> (bool, String) {
        let output = tokio::time::timeout(
            Duration::from_secs(16),
            tokio::process::Command::new("openssl")
                .args([
                    "s_client",
                    "-connect",
                    connect,
                    "-servername",
                    sni,
                    "-showcerts",
                ])
                .stdin(std::process::Stdio::null())
                .output(),
        )
        .await
        .expect("openssl 超时")
        .expect("需要系统 openssl");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        (output.status.success(), text)
    }

    let (ok, text) = run_s_client(&connect, "a.example.com").await;
    println!("[openssl 匹配域名] success={ok}");
    assert!(ok, "openssl 应能完成握手:\n{text}");
    assert!(text.contains("BEGIN CERTIFICATE"));
    assert!(
        text.contains("CN = a.example.com") || text.contains("CN=a.example.com"),
        "openssl 看到的证书应是 a.example.com:\n{text}"
    );

    let (ok, text) = run_s_client(&connect, "unknown.example.org").await;
    println!("[openssl 未声明域名] success={ok}");
    assert!(!ok, "未声明域名应当握手失败:\n{text}");
    assert!(
        text.contains("AccessDenied") || text.to_ascii_lowercase().contains("alert"),
        "应看到服务器发回的 alert:\n{text}"
    );
}
