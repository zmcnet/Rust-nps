//! 多用户登录与权限隔离的端到端测试（走真实 HTTP 路由）。

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use nps_server::{ClientSnapshot, ServerSnapshot, TunnelSnapshot};
use nps_web::{AccountStore, AdminBackend};
use serde_json::Value;
use tower::ServiceExt;

const ADMIN_TOKEN: &str = "test-admin-token-at-least-24-bytes";

#[derive(Clone)]
struct MockBackend {
    _inner: Arc<Mutex<()>>,
}

impl MockBackend {
    fn new() -> Self {
        Self {
            _inner: Arc::new(Mutex::new(())),
        }
    }
}

impl AdminBackend for MockBackend {
    async fn snapshot(&self) -> ServerSnapshot {
        let tunnel = |id: u32, client_id: i32, name: &str| TunnelSnapshot {
            id,
            name: name.to_owned(),
            client_id,
            listen_addr: format!("127.0.0.1:{}", 6000 + id),
            target_addr: "127.0.0.1:22".to_owned(),
            enabled: true,
            active_connections: 0,
            bytes_to_client: 0,
            bytes_from_client: 0,
            last_error: None,
            bound_addr: None,
            targets: Vec::new(),
        };
        ServerSnapshot {
            bridge_addr: "127.0.0.1:8024".to_owned(),
            clients: vec![
                ClientSnapshot {
                    id: 1,
                    name: "alice-nas".to_owned(),
                    online: true,
                    version: "0.26.0".to_owned(),
                },
                ClientSnapshot {
                    id: 2,
                    name: "bob-office".to_owned(),
                    online: true,
                    version: "0.26.0".to_owned(),
                },
            ],
            tunnels: vec![tunnel(10, 1, "alice-ssh"), tunnel(20, 2, "bob-web")],
        }
    }

    async fn set_tunnel_enabled(&self, _id: u32, _enabled: bool) -> anyhow::Result<()> {
        Ok(())
    }
    async fn list_certificates(&self) -> Vec<nps_web::CertView> {
        Vec::new()
    }
    async fn upload_certificate(
        &self,
        _d: String,
        _c: String,
        _k: String,
    ) -> anyhow::Result<nps_web::CertView> {
        anyhow::bail!("not used")
    }
    async fn generate_self_signed(&self, _d: String) -> anyhow::Result<nps_web::CertView> {
        anyhow::bail!("not used")
    }
    async fn remove_certificate(&self, _d: String) -> anyhow::Result<bool> {
        Ok(false)
    }
    async fn reload_certificates(&self) -> anyhow::Result<usize> {
        Ok(0)
    }
    fn acme_summary(&self) -> nps_web::AcmeSummary {
        nps_web::AcmeSummary {
            available: false,
            provider: String::new(),
            challenge: String::new(),
            auto_renew: false,
            contact_email_set: false,
        }
    }
    fn listener_stats(&self) -> nps_web::ListenerView {
        nps_web::ListenerView::default()
    }
    async fn list_sites(&self) -> Vec<nps_web::SiteView> {
        Vec::new()
    }
    async fn upsert_site(&self, _s: nps_web::SiteInput) -> anyhow::Result<nps_web::SiteView> {
        anyhow::bail!("not used")
    }
    async fn remove_site(&self, _d: String) -> anyhow::Result<bool> {
        Ok(false)
    }
    async fn request_acme_certificate(
        &self,
        _d: String,
    ) -> anyhow::Result<nps_web::AcmeIssueResult> {
        anyhow::bail!("not used")
    }
}

fn app_with_accounts() -> Router {
    let accounts = AccountStore::build(
        Some(("root".to_owned(), "rootpw".to_owned())),
        &[
            (1, "alice".to_owned(), "alicepw".to_owned(), "vk1".to_owned()),
            (2, "bob".to_owned(), "bobpw".to_owned(), "vk2".to_owned()),
        ],
    );
    nps_web::router_with_accounts_and_backend(MockBackend::new(), ADMIN_TOKEN.to_owned(), accounts)
        .expect("router")
}

fn post_json(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn with_bearer(mut req: Request<Body>, token: &str) -> Request<Body> {
    req.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    req
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

async fn login(app: &Router, user: &str, pass: &str) -> String {
    let body = format!("{{\"username\":\"{user}\",\"password\":\"{pass}\"}}");
    let response = app
        .clone()
        .oneshot(post_json("/api/auth/login", &body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "登录应成功: {user}");
    body_json(response).await["token"]
        .as_str()
        .expect("应返回会话令牌")
        .to_owned()
}

#[tokio::test]
async fn admin_token_still_works_unchanged() {
    let response = app_with_accounts()
        .oneshot(with_bearer(get("/api/status"), ADMIN_TOKEN))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["clients"].as_array().map(|a| a.len()), Some(2));
    assert_eq!(json["tunnels"].as_array().map(|a| a.len()), Some(2));
}

#[tokio::test]
async fn login_returns_session_token_and_grants_access() {
    let app = app_with_accounts();

    let response = app
        .clone()
        .oneshot(post_json(
            "/api/auth/login",
            "{\"username\":\"root\",\"password\":\"rootpw\"}",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let token = json["token"].as_str().expect("应返回会话令牌").to_owned();
    assert_eq!(token.len(), 64, "32 字节 hex 应为 64 字符");
    assert_eq!(json["is_admin"], true);

    let response = app
        .oneshot(with_bearer(get("/api/status"), &token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn wrong_password_is_401_and_does_not_echo_password() {
    let response = app_with_accounts()
        .oneshot(post_json(
            "/api/auth/login",
            "{\"username\":\"root\",\"password\":\"wrong-secret-value\"}",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        !text.contains("wrong-secret-value"),
        "响应不应回显密码: {text}"
    );
    assert!(!text.contains("不存在"), "不应区分用户是否存在: {text}");
}

#[tokio::test]
async fn client_sees_only_own_resources() {
    let app = app_with_accounts();
    let token = login(&app, "alice", "alicepw").await;

    let response = app
        .oneshot(with_bearer(get("/api/status"), &token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;

    let clients = json["clients"].as_array().expect("clients 数组");
    assert_eq!(clients.len(), 1, "客户端账号只应看到自己: {json}");
    assert_eq!(clients[0]["id"], 1);

    let tunnels = json["tunnels"].as_array().expect("tunnels 数组");
    assert_eq!(tunnels.len(), 1, "只应看到自己的隧道: {json}");
    assert_eq!(tunnels[0]["client_id"], 1);
}

#[tokio::test]
async fn whoami_reports_principal() {
    let app = app_with_accounts();
    let token = login(&app, "bob", "bobpw").await;

    let response = app
        .oneshot(with_bearer(get("/api/whoami"), &token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["is_admin"], false);
    assert_eq!(json["visible_clients"], serde_json::json!([2]));
}

#[tokio::test]
async fn logout_revokes_session() {
    let app = app_with_accounts();
    let token = login(&app, "root", "rootpw").await;

    let ok = app
        .clone()
        .oneshot(with_bearer(get("/api/status"), &token))
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);

    let out = app
        .clone()
        .oneshot(with_bearer(post_json("/api/auth/logout", "{}"), &token))
        .await
        .unwrap();
    assert_eq!(out.status(), StatusCode::OK);

    let denied = app
        .oneshot(with_bearer(get("/api/status"), &token))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_disabled_when_no_accounts() {
    // 空账号表：等价于只有 admin token 的部署
    let app = nps_web::router_with_accounts_and_backend(
        MockBackend::new(),
        ADMIN_TOKEN.to_owned(),
        AccountStore::empty(),
    )
    .expect("router");
    let response = app
        .oneshot(post_json(
            "/api/auth/login",
            "{\"username\":\"x\",\"password\":\"y\"}",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unknown_token_is_rejected() {
    let response = app_with_accounts()
        .oneshot(with_bearer(
            get("/api/status"),
            "not-a-real-token-but-long-enough-xx",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_throttle_locks_after_repeated_failures() {
    let app = app_with_accounts();
    for _ in 0..10 {
        let response = app
            .clone()
            .oneshot(post_json(
                "/api/auth/login",
                "{\"username\":\"root\",\"password\":\"bad\"}",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = app
        .oneshot(post_json(
            "/api/auth/login",
            "{\"username\":\"root\",\"password\":\"rootpw\"}",
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "达到失败上限后即使密码正确也应被限流"
    );
}

// ---------------------------------------------------------------------------
// 权限隔离：客户端账号必须被管理员端点拒绝
// ---------------------------------------------------------------------------

fn with_auth(mut request: Request<Body>, token: &str) -> Request<Body> {
    request
        .headers_mut()
        .insert(header::AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
    request
}

#[tokio::test]
async fn client_account_is_forbidden_on_admin_endpoints() {
    let app = app_with_accounts();
    let client_token = login(&app, "alice", "alicepw").await;

    // 这些端点只有管理员能碰；客户端账号必须 403，而不是 200
    let cases: Vec<(&str, &str, &str)> = vec![
        ("POST", "/api/tunnels/1/state", r#"{"enabled":false}"#),
        ("GET", "/api/sites", ""),
        ("POST", "/api/sites", r#"{"domain":"x.test","target":"127.0.0.1:22"}"#),
        ("DELETE", "/api/sites/x.test", ""),
        ("GET", "/api/certs", ""),
        ("POST", "/api/certs/reload", "{}"),
        ("DELETE", "/api/certs/x.test", ""),
        ("GET", "/api/acme", ""),
    ];

    for (method, uri, body) in cases {
        let mut builder = Request::builder().method(method).uri(uri);
        if !body.is_empty() {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        let request = builder.body(Body::from(body.to_owned())).unwrap();
        let request = with_auth(request, &client_token);
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{method} {uri} 应拒绝客户端账号"
        );
    }
}

#[tokio::test]
async fn admin_account_is_allowed_on_admin_endpoints() {
    let app = app_with_accounts();
    let admin_token = login(&app, "root", "rootpw").await;

    for uri in ["/api/sites", "/api/certs", "/api/acme"] {
        let request = with_auth(get(uri), &admin_token);
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "GET {uri} 应允许管理员"
        );
    }
}

#[tokio::test]
async fn super_admin_token_still_reaches_admin_endpoints() {
    // 已有部署靠 NPS_ADMIN_TOKEN，加了权限校验后必须仍然可用
    let app = app_with_accounts();
    for uri in ["/api/sites", "/api/certs", "/api/acme", "/api/status"] {
        let request = with_auth(get(uri), ADMIN_TOKEN);
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "GET {uri} 应允许超级管理员令牌"
        );
    }
}

#[tokio::test]
async fn unauthenticated_admin_endpoints_are_401() {
    let app = app_with_accounts();
    for uri in ["/api/sites", "/api/certs", "/api/acme"] {
        let response = app.clone().oneshot(get(uri)).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "GET {uri} 未认证应 401"
        );
    }
}

#[tokio::test]
async fn client_can_still_read_own_status() {
    // 权限收紧不能误伤客户端本来就能用的端点
    let app = app_with_accounts();
    let client_token = login(&app, "alice", "alicepw").await;
    let response = app
        .clone()
        .oneshot(with_auth(get("/api/status"), &client_token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "/api/status 应允许客户端账号");

    let body = body_json(response).await;
    let clients = body["clients"].as_array().expect("clients 数组");
    assert_eq!(clients.len(), 1, "客户端只应看到自己");
    assert_eq!(clients[0]["id"], 1);
}
