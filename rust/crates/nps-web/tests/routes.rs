//! 路由层测试：令牌校验、鉴权、只读状态、隧道启停与跨站防护。
//!
//! 使用内存后端实现 [`AdminBackend`]，不启动真实网络，也不依赖 `nps-server` 的运行方式。

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use nps_server::{ClientSnapshot, ServerSnapshot, TunnelSnapshot};
use nps_web::{
    AcmeIssueResult, AcmeSummary, CertView, ListenerView, SiteInput, SiteView,
};
use nps_web::{router_with_backend, AdminBackend};
use serde_json::Value;
use tower::ServiceExt;

const TOKEN: &str = "test-admin-token-0123456789abcdef";

#[derive(Clone)]
struct MockBackend {
    inner: Arc<Mutex<MockState>>,
    fail_with: Option<String>,
}

struct MockState {
    tunnels: Vec<TunnelRow>,
    sites: Vec<SiteView>,
    certs: Vec<CertView>,
}

struct TunnelRow {
    id: u32,
    name: String,
    client_id: i32,
    listen_addr: String,
    target_addr: String,
    enabled: bool,
    active_connections: u64,
    bytes_to_client: u64,
    bytes_from_client: u64,
    last_error: Option<String>,
}

impl MockBackend {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockState {
                tunnels: vec![
                    TunnelRow {
                        id: 7,
                        name: "ssh".to_string(),
                        client_id: 1,
                        listen_addr: "0.0.0.0:6001".to_string(),
                        target_addr: "127.0.0.1:22".to_string(),
                        enabled: true,
                        active_connections: 2,
                        bytes_to_client: 4096,
                        bytes_from_client: 1024,
                        last_error: None,
                    },
                    TunnelRow {
                        id: 9,
                        name: "web".to_string(),
                        client_id: 2,
                        listen_addr: "0.0.0.0:6002".to_string(),
                        target_addr: "192.168.1.10:80".to_string(),
                        enabled: false,
                        active_connections: 0,
                        bytes_to_client: 0,
                        bytes_from_client: 0,
                        last_error: Some("client offline".to_string()),
                    },
                ],
                sites: Vec::new(),
                certs: Vec::new(),
            })),
            fail_with: None,
        }
    }

    fn failing(message: &str) -> Self {
        let mut backend = Self::new();
        backend.fail_with = Some(message.to_string());
        backend
    }

    fn enabled_of(&self, id: u32) -> bool {
        self.inner
            .lock()
            .expect("mock state poisoned")
            .tunnels
            .iter()
            .find(|tunnel| tunnel.id == id)
            .expect("tunnel present")
            .enabled
    }
}

impl AdminBackend for MockBackend {
    async fn snapshot(&self) -> ServerSnapshot {
        let state = self.inner.lock().expect("mock state poisoned");
        ServerSnapshot {
            bridge_addr: "0.0.0.0:8024".to_string(),
            clients: vec![
                ClientSnapshot {
                    id: 1,
                    name: "home-nas".to_string(),
                    online: true,
                    version: "0.26.0".to_string(),
                },
                ClientSnapshot {
                    id: 2,
                    name: "office".to_string(),
                    online: false,
                    version: "0.26.0".to_string(),
                },
            ],
            tunnels: state
                .tunnels
                .iter()
                .map(|tunnel| TunnelSnapshot {
                    id: tunnel.id,
                    name: tunnel.name.clone(),
                    client_id: tunnel.client_id,
                    listen_addr: tunnel.listen_addr.clone(),
                    target_addr: tunnel.target_addr.clone(),
                    enabled: tunnel.enabled,
                    active_connections: tunnel.active_connections,
                    bytes_to_client: tunnel.bytes_to_client,
                    bytes_from_client: tunnel.bytes_from_client,
                    last_error: tunnel.last_error.clone(),
                    bound_addr: None,
                })
                .collect(),
        }
    }

    async fn set_tunnel_enabled(&self, id: u32, enabled: bool) -> anyhow::Result<()> {
        if let Some(message) = &self.fail_with {
            anyhow::bail!("{message}");
        }
        let mut state = self.inner.lock().expect("mock state poisoned");
        let tunnel = state
            .tunnels
            .iter_mut()
            .find(|tunnel| tunnel.id == id)
            .expect("路由层应先检查隧道是否存在");
        tunnel.enabled = enabled;
        Ok(())
    }

    // ---- 站点 ----

    async fn list_sites(&self) -> Vec<SiteView> {
        self.inner
            .lock()
            .expect("mock state poisoned")
            .sites
            .clone()
    }

    async fn upsert_site(&self, site: SiteInput) -> anyhow::Result<SiteView> {
        if site.domain.trim().is_empty() {
            anyhow::bail!("域名不能为空");
        }
        let view = SiteView {
            domain: site.domain.trim().to_owned(),
            client_id: site.client_id,
            target: site.target.clone(),
            routes: site.routes.clone(),
            websocket: site.websocket,
        };
        let mut state = self.inner.lock().expect("mock state poisoned");
        state.sites.retain(|s| s.domain != view.domain);
        state.sites.push(view.clone());
        Ok(view)
    }

    async fn remove_site(&self, domain: String) -> anyhow::Result<bool> {
        let mut state = self.inner.lock().expect("mock state poisoned");
        let before = state.sites.len();
        state.sites.retain(|s| s.domain != domain);
        Ok(state.sites.len() != before)
    }

    // ---- 证书 ----

    async fn list_certificates(&self) -> Vec<CertView> {
        self.inner
            .lock()
            .expect("mock state poisoned")
            .certs
            .clone()
    }

    async fn upload_certificate(
        &self,
        domain: String,
        cert_pem: String,
        key_pem: String,
    ) -> anyhow::Result<CertView> {
        if cert_pem.trim().is_empty() || key_pem.trim().is_empty() {
            anyhow::bail!("证书与私钥都不能为空");
        }
        if !cert_pem.contains("BEGIN CERTIFICATE") {
            anyhow::bail!("不是合法的 PEM 证书");
        }
        let view = fake_cert(&domain, "upload");
        let mut state = self.inner.lock().expect("mock state poisoned");
        state.certs.retain(|c| c.domain != domain);
        state.certs.push(view.clone());
        Ok(view)
    }

    async fn generate_self_signed(&self, domain: String) -> anyhow::Result<CertView> {
        let view = fake_cert(&domain, "self-signed");
        let mut state = self.inner.lock().expect("mock state poisoned");
        state.certs.retain(|c| c.domain != domain);
        state.certs.push(view.clone());
        Ok(view)
    }

    async fn remove_certificate(&self, domain: String) -> anyhow::Result<bool> {
        let mut state = self.inner.lock().expect("mock state poisoned");
        let before = state.certs.len();
        state.certs.retain(|c| c.domain != domain);
        Ok(state.certs.len() != before)
    }

    async fn reload_certificates(&self) -> anyhow::Result<usize> {
        Ok(self.inner.lock().expect("mock state poisoned").certs.len())
    }

    fn acme_summary(&self) -> AcmeSummary {
        AcmeSummary {
            available: true,
            provider: "letsencrypt".to_owned(),
            challenge: "http-01".to_owned(),
            auto_renew: true,
            contact_email_set: true,
        }
    }

    fn listener_stats(&self) -> ListenerView {
        ListenerView {
            udp_tunnels: 1,
            udp_active_flows: 3,
            http_configured: true,
            http_active_connections: 2,
            http_served_requests: 42,
            socks5_listeners: 1,
            socks5_active_connections: 1,
        }
    }

    async fn request_acme_certificate(
        &self,
        domain: String,
    ) -> anyhow::Result<AcmeIssueResult> {
        let view = fake_cert(&domain, "acme");
        let mut state = self.inner.lock().expect("mock state poisoned");
        state.certs.retain(|c| c.domain != domain);
        state.certs.push(view);
        Ok(AcmeIssueResult {
            domain,
            issued: true,
            not_after: "2030-01-01T00:00:00Z".to_owned(),
            reason: None,
        })
    }
}

fn fake_cert(domain: &str, source: &str) -> CertView {
    CertView {
        domain: domain.to_owned(),
        source: source.to_owned(),
        issuer: "CN=Test CA".to_owned(),
        not_before: "2026-01-01T00:00:00Z".to_owned(),
        not_after: "2030-01-01T00:00:00Z".to_owned(),
        days_remaining: 365,
        san: vec![domain.to_owned()],
        fingerprint_sha256: "AA:BB:CC".to_owned(),
        expired: false,
        last_error: None,
    }
}

fn app(backend: MockBackend) -> Router {
    router_with_backend(backend, TOKEN.to_string()).expect("测试令牌应通过校验")
}

fn authed(request: Request<Body>) -> Request<Body> {
    let (mut parts, body) = request.into_parts();
    parts.headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {TOKEN}").parse().unwrap(),
    );
    Request::from_parts(parts, body)
}

fn get(path: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .unwrap()
}

fn post_json(path: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

async fn body_json(response: axum::response::Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("json body")
    };
    (status, value)
}

// ---------------------------------------------------------------------------
// 令牌校验
// ---------------------------------------------------------------------------

#[test]
fn rejects_empty_token() {
    assert!(router_with_backend(MockBackend::new(), String::new()).is_err());
}

#[test]
fn rejects_short_token() {
    // 23 字节，不足最小长度。
    let token = "0123456789abcdefghijklm".to_string();
    assert_eq!(token.len(), 23);
    assert!(router_with_backend(MockBackend::new(), token).is_err());
}

#[test]
fn trims_surrounding_whitespace_from_token() {
    let token = format!("  {}\n", "a".repeat(24));
    assert!(router_with_backend(MockBackend::new(), token).is_ok());
}

#[test]
fn accepts_minimum_length_token() {
    let token = "a".repeat(24);
    assert!(router_with_backend(MockBackend::new(), token).is_ok());
}

// ---------------------------------------------------------------------------
// 鉴权
// ---------------------------------------------------------------------------

#[tokio::test]
async fn status_without_token_is_unauthorized() {
    let response = app(MockBackend::new())
        .oneshot(get("/api/status"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer realm=\"nps-admin\"")
    );
    let (_, body) = body_json(response).await;
    assert!(body.get("error").is_some());
    assert!(body.get("bridge_addr").is_none());
}

#[tokio::test]
async fn status_with_wrong_token_is_unauthorized() {
    let mut request = get("/api/status");
    request.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {}", "z".repeat(TOKEN.len()))
            .parse()
            .unwrap(),
    );
    let response = app(MockBackend::new()).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn status_with_non_bearer_scheme_is_unauthorized() {
    let mut request = get("/api/status");
    request
        .headers_mut()
        .insert(header::AUTHORIZATION, TOKEN.parse().unwrap());
    let response = app(MockBackend::new()).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_in_query_string_is_not_accepted() {
    let response = app(MockBackend::new())
        .oneshot(get(&format!("/api/status?token={TOKEN}")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// 只读状态
// ---------------------------------------------------------------------------

#[tokio::test]
async fn status_returns_snapshot_fields() {
    let response = app(MockBackend::new())
        .oneshot(authed(get("/api/status")))
        .await
        .unwrap();
    let (status, body) = body_json(response).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["bridge_addr"], "0.0.0.0:8024");
    assert_eq!(body["clients"][0]["name"], "home-nas");
    assert_eq!(body["clients"][1]["online"], false);
    assert_eq!(body["tunnels"][0]["id"], 7);
    assert_eq!(body["tunnels"][0]["active_connections"], 2);
    assert_eq!(body["tunnels"][1]["last_error"], "client offline");
}

#[tokio::test]
async fn status_is_not_cached() {
    let response = app(MockBackend::new())
        .oneshot(authed(get("/api/status")))
        .await
        .unwrap();
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
}

#[tokio::test]
async fn unknown_api_route_requires_auth_then_404() {
    let response = app(MockBackend::new())
        .oneshot(get("/api/nope"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app(MockBackend::new())
        .oneshot(authed(get("/api/nope")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mutation_with_oversized_body_is_rejected() {
    // 上限已放宽到 256 KiB（证书上传需要带完整证书链），
    // 用 512 KiB 的请求体验证限制仍然生效。
    let huge = format!(
        r#"{{"enabled":true,"padding":"{}"}}"#,
        "x".repeat(512 * 1024)
    );
    let response = app(MockBackend::new())
        .oneshot(authed(post_json("/api/tunnels/9/state", &huge)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn unauthorized_response_does_not_echo_credentials() {
    let mut request = get("/api/status");
    request.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {}", "s".repeat(TOKEN.len()))
            .parse()
            .unwrap(),
    );
    let response = app(MockBackend::new()).oneshot(request).await.unwrap();
    let (_, body) = body_json(response).await;
    let text = body.to_string();
    assert!(!text.contains(&"s".repeat(TOKEN.len())));
    assert!(!text.contains("Bearer"));
}

// ---------------------------------------------------------------------------
// 隧道启停
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mutation_requires_token() {
    let response = app(MockBackend::new())
        .oneshot(post_json("/api/tunnels/9/state", r#"{"enabled":true}"#))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mutation_enables_tunnel() {
    let backend = MockBackend::new();
    assert!(!backend.enabled_of(9));

    let response = app(backend.clone())
        .oneshot(authed(post_json(
            "/api/tunnels/9/state",
            r#"{"enabled":true}"#,
        )))
        .await
        .unwrap();
    let (status, body) = body_json(response).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);
    assert_eq!(body["id"], 9);
    assert_eq!(body["enabled"], true);
    assert!(backend.enabled_of(9));
}

#[tokio::test]
async fn mutation_disables_tunnel() {
    let backend = MockBackend::new();
    assert!(backend.enabled_of(7));

    let response = app(backend.clone())
        .oneshot(authed(post_json(
            "/api/tunnels/7/state",
            r#"{"enabled":false}"#,
        )))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(!backend.enabled_of(7));
}

#[tokio::test]
async fn mutation_on_unknown_tunnel_is_404() {
    let backend = MockBackend::new();
    let response = app(backend)
        .oneshot(authed(post_json(
            "/api/tunnels/404/state",
            r#"{"enabled":true}"#,
        )))
        .await
        .unwrap();
    let (status, body) = body_json(response).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body["error"].as_str().unwrap().contains("隧道"));
}

#[tokio::test]
async fn mutation_with_non_numeric_id_is_400() {
    let response = app(MockBackend::new())
        .oneshot(authed(post_json(
            "/api/tunnels/abc/state",
            r#"{"enabled":true}"#,
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn mutation_with_bad_json_is_400() {
    let response = app(MockBackend::new())
        .oneshot(authed(post_json("/api/tunnels/9/state", "{enabled:")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = app(MockBackend::new())
        .oneshot(authed(post_json("/api/tunnels/9/state", "")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = app(MockBackend::new())
        .oneshot(authed(post_json(
            "/api/tunnels/9/state",
            r#"{"enabled":"yes"}"#,
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn mutation_without_json_content_type_is_415() {
    let request = Request::builder()
        .method("POST")
        .uri("/api/tunnels/9/state")
        .body(Body::from(r#"{"enabled":true}"#))
        .unwrap();
    let response = app(MockBackend::new())
        .oneshot(authed(request))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn mutation_reports_port_conflict_as_409_without_details() {
    let backend =
        MockBackend::failing("bind 0.0.0.0:6002: address already in use (os error 10048)");
    let response = app(backend)
        .oneshot(authed(post_json(
            "/api/tunnels/9/state",
            r#"{"enabled":true}"#,
        )))
        .await
        .unwrap();
    let (status, body) = body_json(response).await;
    let message = body["error"].as_str().unwrap();

    assert_eq!(status, StatusCode::CONFLICT);
    assert!(!message.contains("os error"));
    assert!(!message.contains("0.0.0.0:6002"));
}

#[tokio::test]
async fn mutation_reports_other_failures_as_500_without_details() {
    let backend = MockBackend::failing("internal pointer 0xdeadbeef exploded");
    let response = app(backend)
        .oneshot(authed(post_json(
            "/api/tunnels/9/state",
            r#"{"enabled":true}"#,
        )))
        .await
        .unwrap();
    let (status, body) = body_json(response).await;
    let message = body["error"].as_str().unwrap();

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!message.contains("0xdeadbeef"));
}

// ---------------------------------------------------------------------------
// 跨站请求
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cross_origin_mutation_is_rejected() {
    let mut request = post_json("/api/tunnels/9/state", r#"{"enabled":true}"#);
    request
        .headers_mut()
        .insert(header::ORIGIN, "https://evil.example".parse().unwrap());
    request
        .headers_mut()
        .insert(header::HOST, "nps.example:8080".parse().unwrap());
    let response = app(MockBackend::new())
        .oneshot(authed(request))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn same_origin_mutation_is_allowed() {
    let mut request = post_json("/api/tunnels/9/state", r#"{"enabled":false}"#);
    request
        .headers_mut()
        .insert(header::ORIGIN, "http://nps.example:8080".parse().unwrap());
    request
        .headers_mut()
        .insert(header::HOST, "nps.example:8080".parse().unwrap());
    let response = app(MockBackend::new())
        .oneshot(authed(request))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn response_never_advertises_cors() {
    let response = app(MockBackend::new())
        .oneshot(authed(get("/api/status")))
        .await
        .unwrap();
    assert!(response
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_none());
}

// ---------------------------------------------------------------------------
// 静态资源与安全头
// ---------------------------------------------------------------------------

#[tokio::test]
async fn index_is_served_anonymously_with_security_headers() {
    let response = app(MockBackend::new()).oneshot(get("/")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let headers = response.headers();
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(
        headers
            .get(header::X_FRAME_OPTIONS)
            .and_then(|v| v.to_str().ok()),
        Some("DENY")
    );
    assert_eq!(
        headers
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert!(headers
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|value| value.contains("default-src 'self'")));

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("NPS · Rust"));
    assert!(html.contains("NPS_ADMIN_TOKEN"));
    assert!(!html.contains("http://"));
    assert!(!html.contains("https://"));
}

#[tokio::test]
async fn javascript_asset_never_uses_inner_html_with_data() {
    let response = app(MockBackend::new())
        .oneshot(get("/assets/app.js"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let script = String::from_utf8(body.to_vec()).unwrap();
    // 仅允许静态骨架使用 createElement；不出现 innerHTML / insertAdjacentHTML。
    assert!(!script.contains("innerHTML"));
    assert!(!script.contains("insertAdjacentHTML"));
    assert!(!script.contains("document.write"));
}

#[tokio::test]
async fn unknown_static_path_returns_html_404() {
    let response = app(MockBackend::new())
        .oneshot(get("/missing.html"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/html; charset=utf-8")
    );
}

// ---------------------------------------------------------------------------
// 站点 API
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sites_list_requires_auth() {
    let response = app(MockBackend::new())
        .oneshot(get("/api/sites"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sites_list_is_empty_initially() {
    let response = app(MockBackend::new())
        .oneshot(authed(get("/api/sites")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json.as_array().map(|a| a.len()), Some(0));
}

#[tokio::test]
async fn site_can_be_created_listed_and_deleted() {
    let backend = MockBackend::new();

    let payload = serde_json::json!({
        "domain": "app.example.com",
        "client_id": 1,
        "target": "127.0.0.1:3000",
        "routes": [],
        "websocket": true
    });
    let response = app(backend.clone())
        .oneshot(authed(post_json("/api/sites", &payload.to_string())))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let view: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(view["domain"], "app.example.com");
    assert_eq!(view["websocket"], true);

    // 列表里能看到
    let response = app(backend.clone())
        .oneshot(authed(get("/api/sites")))
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let list: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(list.as_array().map(|a| a.len()), Some(1));

    // 删除
    let response = app(backend.clone())
        .oneshot(authed(axum::http::Request::builder()
            .method("DELETE")
            .uri("/api/sites/app.example.com")
            .body(Body::empty())
            .unwrap()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app(backend)
        .oneshot(authed(get("/api/sites")))
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let list: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(list.as_array().map(|a| a.len()), Some(0));
}

#[tokio::test]
async fn site_with_empty_domain_is_rejected() {
    let payload = serde_json::json!({
        "domain": "   ",
        "client_id": 1,
        "target": "127.0.0.1:3000"
    });
    let response = app(MockBackend::new())
        .oneshot(authed(post_json("/api/sites", &payload.to_string())))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deleting_missing_site_is_404() {
    let response = app(MockBackend::new())
        .oneshot(authed(axum::http::Request::builder()
            .method("DELETE")
            .uri("/api/sites/nope.example.com")
            .body(Body::empty())
            .unwrap()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// 证书 API
// ---------------------------------------------------------------------------

#[tokio::test]
async fn certs_list_requires_auth() {
    let response = app(MockBackend::new())
        .oneshot(get("/api/certs"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cert_upload_rejects_empty_key() {
    let payload = serde_json::json!({
        "domain": "a.example.com",
        "cert_pem": "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----",
        "key_pem": "   "
    });
    let response = app(MockBackend::new())
        .oneshot(authed(post_json("/api/certs/upload", &payload.to_string())))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn cert_upload_never_echoes_private_key() {
    let key = "-----BEGIN PRIVATE KEY-----\nSUPERSECRETKEYMATERIAL\n-----END PRIVATE KEY-----";
    let payload = serde_json::json!({
        "domain": "a.example.com",
        "cert_pem": "-----BEGIN CERTIFICATE-----\nCERTDATA\n-----END CERTIFICATE-----",
        "key_pem": key
    });
    let response = app(MockBackend::new())
        .oneshot(authed(post_json("/api/certs/upload", &payload.to_string())))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body);
    assert!(
        !text.contains("SUPERSECRETKEYMATERIAL"),
        "响应体泄漏了私钥: {text}"
    );
    assert!(!text.contains("PRIVATE KEY"), "响应体出现了私钥标记");
}

#[tokio::test]
async fn self_signed_cert_can_be_generated_and_removed() {
    let backend = MockBackend::new();
    let payload = serde_json::json!({ "domain": "test.local" });

    let response = app(backend.clone())
        .oneshot(authed(post_json(
            "/api/certs/self-signed",
            &payload.to_string(),
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let view: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(view["source"], "self-signed");

    let response = app(backend.clone())
        .oneshot(authed(axum::http::Request::builder()
            .method("DELETE")
            .uri("/api/certs/test.local")
            .body(Body::empty())
            .unwrap()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn acme_summary_is_exposed() {
    let response = app(MockBackend::new())
        .oneshot(authed(get("/api/acme")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["available"], true);
    assert_eq!(json["provider"], "letsencrypt");
    assert_eq!(json["challenge"], "http-01");
}

#[tokio::test]
async fn listener_stats_are_exposed() {
    let response = app(MockBackend::new())
        .oneshot(authed(get("/api/listeners")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["udp_tunnels"], 1);
    assert_eq!(json["http_served_requests"], 42);
    assert_eq!(json["socks5_listeners"], 1);
}
