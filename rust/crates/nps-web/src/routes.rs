//! HTTP 路由、鉴权与静态资源服务。

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, Path, Request as AxumRequest, State};
use axum::http::header::{self, HeaderMap, HeaderName, HeaderValue};
use axum::http::{Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::assets;
use crate::backend::AdminBackend;

/// 管理令牌的最小长度（字节）。与需求一致：24 字节即可。
const MIN_TOKEN_LEN: usize = 24;

/// `/api` 请求体上限，状态变更请求只有一个布尔值。
///  请求体上限。证书上传可能带上完整证书链，放宽到 256 KiB。
const API_BODY_LIMIT: usize = 256 * 1024;

const HTML_CACHE: &str = "no-store";
const ASSET_CACHE: &str = "no-cache";
const API_CACHE: &str = "no-store";

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; \
img-src 'self' data:; font-src 'self'; connect-src 'self'; \
base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'";

const NOT_FOUND_HTML: &str = "<!doctype html><html lang=\"zh-CN\"><head>\
<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>页面不存在 · NPS</title></head><body>\
<h1>404</h1><p>页面不存在。</p><p><a href=\"/\">返回管理台</a></p></body></html>";

/// 构建管理界面的路由器。
///
/// `admin_token` 由调用方从环境变量 `NPS_ADMIN_TOKEN` 读取后传入；
/// 空令牌或短于 24 字节时返回错误。函数本身不会打印令牌内容。
pub fn router(server: nps_server::Server, admin_token: String) -> anyhow::Result<Router> {
    router_with_backend(server, admin_token)
}

/// 与 [`router`] 相同，但接受任意 [`AdminBackend`] 实现（供测试与嵌入式复用）。
pub fn router_with_backend<B: AdminBackend>(
    backend: B,
    admin_token: String,
) -> anyhow::Result<Router> {
    let token = Arc::<str>::from(validate_token(admin_token)?);
    let state = WebState {
        backend,
        token,
        // 账号表默认空：只有 NPS_ADMIN_TOKEN 可用（现有部署行为不变）。
        // 需要用户名密码登录时由 `router_with_accounts` 注入。
        accounts: Arc::new(crate::auth::AccountStore::empty()),
        sessions: Arc::new(crate::auth::SessionStore::with_default_ttl()),
        throttle: Arc::new(crate::auth::LoginThrottle::with_defaults()),
    };

    let api = Router::new()
        .route("/status", get(get_status::<B>))
        .route("/listeners", get(get_listeners::<B>))
        .route("/tunnels/{id}/state", post(set_tunnel_state::<B>))
        .route("/sites", get(list_sites::<B>).post(upsert_site::<B>))
        .route("/sites/{domain}", axum::routing::delete(remove_site::<B>))
        .route("/certs", get(list_certs::<B>))
        .route("/certs/upload", post(upload_cert::<B>))
        .route("/certs/self-signed", post(self_signed_cert::<B>))
        .route("/certs/reload", post(reload_certs::<B>))
        .route("/certs/acme-request", post(acme_request::<B>))
        .route("/certs/{domain}", axum::routing::delete(remove_cert::<B>))
        .route("/acme", get(get_acme::<B>))
        .fallback(api_not_found)
        .layer(DefaultBodyLimit::max(API_BODY_LIMIT))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_admin::<B>,
        ))
        .with_state(state);

    let app = Router::new()
        .route("/", get(index))
        .route("/index.html", get(index))
        .route("/assets/app.css", get(app_css))
        .route("/assets/app.js", get(app_js))
        .route("/favicon.svg", get(favicon))
        .fallback(static_not_found)
        .nest("/api", api)
        .layer(middleware::from_fn(security_headers));

    Ok(app)
}

/// 与 [`router`] 相同，但启用用户名密码登录。
///
/// `accounts` 为空时等价于 [`router`]（只允许 `NPS_ADMIN_TOKEN`）。
pub fn router_with_accounts(
    server: nps_server::Server,
    admin_token: String,
    accounts: crate::auth::AccountStore,
) -> anyhow::Result<Router> {
    router_with_accounts_and_backend(server, admin_token, accounts)
}

/// 与 [`router_with_accounts`] 相同，但接受任意 [`AdminBackend`]（供测试）。
pub fn router_with_accounts_and_backend<B: AdminBackend>(
    backend: B,
    admin_token: String,
    accounts: crate::auth::AccountStore,
) -> anyhow::Result<Router> {
    let token = Arc::<str>::from(validate_token(admin_token)?);
    let state = WebState {
        backend,
        token,
        accounts: Arc::new(accounts),
        sessions: Arc::new(crate::auth::SessionStore::with_default_ttl()),
        throttle: Arc::new(crate::auth::LoginThrottle::with_defaults()),
    };

    let api = Router::new()
        .route("/status", get(get_status::<B>))
        .route("/listeners", get(get_listeners::<B>))
        .route("/whoami", get(whoami::<B>))
        .route(
            "/tunnels/{id}/state",
            post(set_tunnel_state::<B>),
        )
        .route(
            "/sites",
            get(list_sites::<B>).post(upsert_site::<B>),
        )
        .route(
            "/sites/{domain}",
            axum::routing::delete(remove_site::<B>),
        )
        .route("/certs", get(list_certs::<B>))
        .route("/certs/upload", post(upload_cert::<B>))
        .route(
            "/certs/self-signed",
            post(self_signed_cert::<B>),
        )
        .route("/certs/reload", post(reload_certs::<B>))
        .route(
            "/certs/acme-request",
            post(acme_request::<B>),
        )
        .route(
            "/certs/{domain}",
            axum::routing::delete(remove_cert::<B>),
        )
        .route("/acme", get(get_acme::<B>))
        .fallback(api_not_found)
        .layer(DefaultBodyLimit::max(API_BODY_LIMIT))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_admin::<B>,
        ))
        .with_state(state.clone());

    // 登录端点**不**走 require_admin（否则无法登录）
    let login = Router::new()
        .route("/login", post(login_handler::<B>))
        .route("/logout", post(logout_handler::<B>))
        .fallback(api_not_found)
        .layer(DefaultBodyLimit::max(API_BODY_LIMIT))
        .with_state(state);

    let app = Router::new()
        .route("/", get(index))
        .route("/index.html", get(index))
        .route("/assets/app.css", get(app_css))
        .route("/assets/app.js", get(app_js))
        .route("/favicon.svg", get(favicon))
        .fallback(static_not_found)
        .nest("/api/auth", login)
        .nest("/api", api)
        .layer(middleware::from_fn(security_headers));

    Ok(app)
}

fn validate_token(raw: String) -> anyhow::Result<String> {
    let token = raw.trim();
    if token.len() < MIN_TOKEN_LEN {
        anyhow::bail!(
            "NPS_ADMIN_TOKEN 无效：至少需要 {MIN_TOKEN_LEN} 字节（当前 {} 字节）",
            token.len()
        );
    }
    Ok(token.to_owned())
}

#[derive(Clone)]
struct WebState<B> {
    backend: B,
    /// 超级管理员令牌（`NPS_ADMIN_TOKEN`）。刻意不实现 `Debug`，避免误打印。
    token: Arc<str>,
    /// 账号表（用户名密码登录）。为空表示只允许 token。
    accounts: Arc<crate::auth::AccountStore>,
    /// 会话表
    sessions: Arc<crate::auth::SessionStore>,
    /// 登录失败限流
    throttle: Arc<crate::auth::LoginThrottle>,
}

// ---------------------------------------------------------------------------
// 中间件
// ---------------------------------------------------------------------------

/// 所有 `/api` 请求的统一入口：跨站变更拦截 -> Bearer 鉴权 -> no-store。
async fn require_admin<B: AdminBackend>(
    State(state): State<WebState<B>>,
    request: AxumRequest,
    next: Next,
) -> Response {
    if is_mutating(request.method()) && !mutation_origin_allowed(request.headers()) {
        let mut response = error_response(StatusCode::FORBIDDEN, "拒绝跨站请求");
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static(API_CACHE));
        return response;
    }

    // 鉴权：先比超级管理员 token，再查会话令牌
    // 鉴权通过即可；具体主体在各 handler 里按需重新解析（避免跨层传递）
    match resolve_principal(request.headers(), &state) {
        Some(_) => {}
        None => {
            let mut response =
                error_response(StatusCode::UNAUTHORIZED, "未授权：缺少或无效的凭证");
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"nps-admin\""),
            );
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static(API_CACHE));
            return response;
        }
    }

    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(API_CACHE));
    response
}

async fn security_headers(request: AxumRequest, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    const SECURITY: &[(&str, &str)] = &[
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        ("content-security-policy", CSP),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        ),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
    ];
    for (name, value) in SECURITY {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    response
}

/// 解析请求主体：`NPS_ADMIN_TOKEN` 优先，其次会话令牌。
/// 管理员专用端点守卫。
///
/// 只有已认证**且** `is_admin()` 的主体能通过；客户端账号返回 403。
///
/// 前端会隐藏管理功能入口，但那只是 UI 约束——绕过前端直接发请求必须在这里被拦住。
fn require_admin_principal<B>(
    headers: &HeaderMap,
    state: &WebState<B>,
) -> Option<Response> {
    match resolve_principal(headers, state) {
        Some(principal) if principal.is_admin() => None,
        Some(principal) => {
            let mut response = error_response(
                StatusCode::FORBIDDEN,
                &format!("需要管理员权限（当前身份：{}）", principal.display()),
            );
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static(API_CACHE));
            Some(response)
        }
        None => Some(error_response(
            StatusCode::UNAUTHORIZED,
            "未授权：缺少或无效的凭证",
        )),
    }
}

fn resolve_principal<B>(
    headers: &HeaderMap,
    state: &WebState<B>,
) -> Option<crate::auth::Principal> {
    let value = headers.get(header::AUTHORIZATION)?;
    let value = value.to_str().ok()?;
    let provided = bearer_credentials(value)?;

    // 1) 超级管理员 token（常量时间比较）
    if constant_time_eq(provided.as_bytes(), state.token.as_bytes()) {
        return Some(crate::auth::Principal::Admin);
    }
    // 2) 会话令牌
    state.sessions.verify(provided)
}

fn bearer_credentials(value: &str) -> Option<&str> {
    let (scheme, rest) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let credentials = rest.trim();
    if credentials.is_empty() {
        None
    } else {
        Some(credentials)
    }
}

/// 长度比较会提前返回；内容比较按整串异或累加，避免逐字节短路。
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn is_mutating(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// 带 Origin 的变更请求必须与 Host 同源；无法解析的 Origin（含 `null`）一律拒绝。
/// 未携带 Origin 的请求放行，其凭据仍是 Bearer 令牌（本服务从不使用 Cookie）。
fn mutation_origin_allowed(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN) else {
        return true;
    };
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    let Some((scheme, rest)) = origin.split_once("://") else {
        return false;
    };
    let default_port = if scheme.eq_ignore_ascii_case("http") {
        80
    } else if scheme.eq_ignore_ascii_case("https") {
        443
    } else {
        return false;
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let Some((origin_host, origin_port)) = split_authority(&rest[..end]) else {
        return false;
    };

    // HTTP/2 直连时可能没有 Host 头；此时不凭 Origin 拒绝，令牌校验仍然生效。
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return true;
    };
    let Some((host_name, host_port)) = split_authority(host) else {
        return false;
    };

    origin_host.eq_ignore_ascii_case(&host_name)
        && origin_port.unwrap_or(default_port) == host_port.unwrap_or(default_port)
}

fn split_authority(authority: &str) -> Option<(String, Option<u16>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = if tail.is_empty() {
            None
        } else {
            Some(tail.strip_prefix(':')?.parse().ok()?)
        };
        return Some((format!("[{host}]"), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            Some((host.to_ascii_lowercase(), Some(port.parse().ok()?)))
        }
        _ => Some((authority.to_ascii_lowercase(), None)),
    }
}

// ---------------------------------------------------------------------------
// API 处理
// ---------------------------------------------------------------------------

/// `GET /api/status`：按当前主体过滤。
///
/// 客户端账号只能看到自己的 client 与隧道；管理员看全部。
async fn get_status<B: AdminBackend>(
    State(state): State<WebState<B>>,
    headers: HeaderMap,
) -> Response {
    let principal = resolve_principal(&headers, &state);
    let mut snapshot = state.backend.snapshot().await;
    if let Some(p) = principal.as_ref() {
        if let Some(visible) = p.visible_clients() {
            snapshot.clients.retain(|c| visible.contains(&c.id));
            snapshot.tunnels.retain(|t| visible.contains(&t.client_id));
        }
    }
    Json(snapshot).into_response()
}

#[derive(Deserialize)]
struct StatePayload {
    enabled: bool,
}

/// `POST /api/tunnels/{id}/state`，请求体 `{"enabled":true|false}`。
///
/// 状态码约定：401 未授权、400 JSON 无效、404 隧道不存在、
/// 409 监听端口被占用、415 非 JSON、500 其他启停失败。
/// 返回给客户端的信息不包含内部错误链或堆栈。
async fn set_tunnel_state<B: AdminBackend>(
    State(state): State<WebState<B>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    if let Some(response) = require_admin_principal(&headers, &state) {
        return response;
    }
    if !is_json_content_type(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "请求必须使用 application/json",
        );
    }
    let body = match body {
        Ok(body) => body,
        Err(rejection) => {
            return error_response(rejection.status(), "请求体读取失败");
        }
    };
    if body.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "请求体不能为空");
    }
    let payload: StatePayload = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "请求 JSON 无效，应为 {\"enabled\":true|false}",
            );
        }
    };

    let Ok(tunnel_id) = id.parse::<u32>() else {
        return error_response(StatusCode::BAD_REQUEST, "隧道 ID 无效");
    };

    let snapshot = state.backend.snapshot().await;
    if !snapshot.tunnels.iter().any(|tunnel| tunnel.id == tunnel_id) {
        return error_response(StatusCode::NOT_FOUND, "未找到该隧道");
    }

    match state
        .backend
        .set_tunnel_enabled(tunnel_id, payload.enabled)
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "id": tunnel_id,
                "enabled": payload.enabled,
            })),
        )
            .into_response(),
        Err(error) => {
            let detail = format!("{error:#}");
            // 只记录后端错误链，不含令牌。
            tracing::warn!(tunnel_id, error = %detail, "隧道运行时启停失败");
            if is_port_conflict(&detail) {
                error_response(
                    StatusCode::CONFLICT,
                    "监听端口已被占用，请调整监听地址后重试",
                )
            } else {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "隧道状态更新失败，请查看服务端日志",
                )
            }
        }
    }
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
}

fn is_port_conflict(detail: &str) -> bool {
    let lowered = detail.to_ascii_lowercase();
    [
        "address already in use",
        "address in use",
        "eaddrinuse",
        "os error 10048",
        "only one usage of each socket address",
        "端口已被占用",
        "端口被占用",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
}

async fn api_not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, "接口不存在")
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

// ---------------------------------------------------------------------------
// 静态资源（全部内嵌，无外部依赖）
// ---------------------------------------------------------------------------

async fn index() -> Response {
    asset(assets::INDEX_HTML, "text/html; charset=utf-8", HTML_CACHE)
}

async fn app_css() -> Response {
    asset(assets::APP_CSS, "text/css; charset=utf-8", ASSET_CACHE)
}

async fn app_js() -> Response {
    asset(
        assets::APP_JS,
        "text/javascript; charset=utf-8",
        ASSET_CACHE,
    )
}

async fn favicon() -> Response {
    asset(assets::FAVICON_SVG, "image/svg+xml", ASSET_CACHE)
}

async fn static_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, HTML_CACHE),
        ],
        NOT_FOUND_HTML,
    )
        .into_response()
}

fn asset(body: &'static str, content_type: &'static str, cache: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (header::CACHE_CONTROL, HeaderValue::from_static(cache)),
        ],
        body,
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// 站点与证书 API
// ---------------------------------------------------------------------------

async fn get_listeners<B: AdminBackend>(State(state): State<WebState<B>>) -> Response {
    Json(state.backend.listener_stats()).into_response()
}

async fn get_acme<B: AdminBackend>(
    State(state): State<WebState<B>>,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = require_admin_principal(&headers, &state) {
        return response;
    }
    Json(state.backend.acme_summary()).into_response()
}

async fn list_sites<B: AdminBackend>(
    State(state): State<WebState<B>>,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = require_admin_principal(&headers, &state) {
        return response;
    }
    Json(state.backend.list_sites().await).into_response()
}

async fn list_certs<B: AdminBackend>(
    State(state): State<WebState<B>>,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = require_admin_principal(&headers, &state) {
        return response;
    }
    Json(state.backend.list_certificates().await).into_response()
}

/// `POST /api/sites`，请求体见 [`SiteInput`]。
async fn upsert_site<B: AdminBackend>(
    State(state): State<WebState<B>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    if let Some(response) = require_admin_principal(&headers, &state) {
        return response;
    }
    let body = match require_json_body(&headers, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let input: crate::backend::SiteInput = match serde_json::from_slice(&body) {
        Ok(input) => input,
        Err(error) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!("站点 JSON 无效：{error}"),
            );
        }
    };
    match state.backend.upsert_site(input).await {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "站点写入失败");
            error_response(StatusCode::BAD_REQUEST, &format!("{error:#}"))
        }
    }
}

async fn remove_site<B: AdminBackend>(
    State(state): State<WebState<B>>,
    Path(domain): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = require_admin_principal(&headers, &state) {
        return response;
    }
    match state.backend.remove_site(domain.clone()).await {
        Ok(true) => (StatusCode::OK, Json(json!({ "ok": true, "domain": domain }))).into_response(),
        Ok(false) => error_response(StatusCode::NOT_FOUND, "未找到该站点"),
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "站点删除失败");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "站点删除失败")
        }
    }
}

#[derive(Deserialize)]
struct UploadCertPayload {
    domain: String,
    cert_pem: String,
    key_pem: String,
}

/// `POST /api/certs/upload`：上传证书与私钥。
///
/// **私钥只在本次请求体内出现**：不回显、不记录到日志、不进响应。
async fn upload_cert<B: AdminBackend>(
    State(state): State<WebState<B>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    if let Some(response) = require_admin_principal(&headers, &state) {
        return response;
    }
    let body = match require_json_body(&headers, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let payload: UploadCertPayload = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(error) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!("证书 JSON 无效：{error}"),
            );
        }
    };
    if payload.cert_pem.trim().is_empty() || payload.key_pem.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "证书与私钥都不能为空");
    }
    match state
        .backend
        .upload_certificate(
            payload.domain.trim().to_owned(),
            payload.cert_pem,
            payload.key_pem,
        )
        .await
    {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(error) => {
            // 只记录错误摘要，绝不把私钥写进日志
            let detail = format!("{error:#}");
            tracing::warn!(error = %detail, "证书上传失败");
            error_response(StatusCode::BAD_REQUEST, &detail)
        }
    }
}

#[derive(Deserialize)]
struct SelfSignedPayload {
    domain: String,
}

async fn self_signed_cert<B: AdminBackend>(
    State(state): State<WebState<B>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    if let Some(response) = require_admin_principal(&headers, &state) {
        return response;
    }
    let body = match require_json_body(&headers, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let payload: SelfSignedPayload = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(error) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!("请求 JSON 无效：{error}"),
            );
        }
    };
    match state
        .backend
        .generate_self_signed(payload.domain.trim().to_owned())
        .await
    {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "自签证书生成失败");
            error_response(StatusCode::BAD_REQUEST, &format!("{error:#}"))
        }
    }
}

async fn reload_certs<B: AdminBackend>(
    State(state): State<WebState<B>>,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = require_admin_principal(&headers, &state) {
        return response;
    }
    match state.backend.reload_certificates().await {
        Ok(count) => (StatusCode::OK, Json(json!({ "ok": true, "loaded": count }))).into_response(),
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "证书重载失败");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "证书重载失败")
        }
    }
}

async fn remove_cert<B: AdminBackend>(
    State(state): State<WebState<B>>,
    Path(domain): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = require_admin_principal(&headers, &state) {
        return response;
    }
    match state.backend.remove_certificate(domain.clone()).await {
        Ok(true) => (StatusCode::OK, Json(json!({ "ok": true, "domain": domain }))).into_response(),
        Ok(false) => error_response(StatusCode::NOT_FOUND, "未找到该证书"),
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "证书删除失败");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "证书删除失败")
        }
    }
}

/// 统一校验 `Content-Type` 并取出请求体。
fn require_json_body(
    headers: &HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Bytes, Response> {
    if !is_json_content_type(headers) {
        return Err(error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "请求必须使用 application/json",
        ));
    }
    match body {
        Ok(body) if body.is_empty() => Err(error_response(StatusCode::BAD_REQUEST, "请求体不能为空")),
        Ok(body) => Ok(body),
        Err(rejection) => Err(error_response(rejection.status(), "请求体读取失败")),
    }
}

#[derive(Deserialize)]
struct AcmeRequestPayload {
    domain: String,
}

/// ：**用户显式发起**的 ACME 申请。
///
/// 这是全系统唯一会联系 CA 的 HTTP 入口。前端必须由用户点击「开始申请」
/// 才会调用；后端不做任何自动触发。
async fn acme_request<B: AdminBackend>(
    State(state): State<WebState<B>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    if let Some(response) = require_admin_principal(&headers, &state) {
        return response;
    }
    let body = match require_json_body(&headers, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let payload: AcmeRequestPayload = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(error) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!("请求 JSON 无效：{error}"),
            );
        }
    };
    let domain = payload.domain.trim().to_owned();
    if domain.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "域名不能为空");
    }
    match state.backend.request_acme_certificate(domain).await {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "ACME 申请失败");
            error_response(StatusCode::BAD_REQUEST, &format!("{error:#}"))
        }
    }
}

// ---------------------------------------------------------------------------
// 登录 / 登出 / 身份查询
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct LoginPayload {
    username: String,
    password: String,
}

/// `POST /api/auth/login`：用户名密码换会话令牌。
///
/// 安全要点：
/// - 按 IP 限流（60 秒 10 次失败锁定）
/// - 密码比较在 `AccountStore` 内做常量时间比较
/// - 响应与日志都**不回显**密码或会话令牌（令牌只在成功响应体里返回一次）
async fn login_handler<B: AdminBackend>(
    State(state): State<WebState<B>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match require_json_body(&headers, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let payload: LoginPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "请求 JSON 无效，应为 {\"username\":\"...\",\"password\":\"...\"}",
            )
        }
    };

    // 限流用的 IP：优先 X-Forwarded-For 首个（反代场景），否则用占位
    let ip = client_ip(&headers);

    if !state.throttle.check(ip) {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "登录失败次数过多，请稍后再试",
        );
    }

    if !state.accounts.is_enabled() {
        return error_response(
            StatusCode::NOT_FOUND,
            "未启用用户名密码登录（仅支持管理令牌）",
        );
    }

    match state.accounts.authenticate(&payload.username, &payload.password) {
        Some(principal) => {
            state.throttle.record_success(ip);
            let token = state.sessions.create(principal.clone());
            tracing::info!(principal = %principal.display(), "登录成功");
            (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "token": token,
                    "is_admin": principal.is_admin(),
                })),
            )
                .into_response()
        }
        None => {
            state.throttle.record_failure(ip);
            // 不区分「用户不存在」与「密码错误」
            tracing::warn!(username_len = payload.username.len(), "登录失败");
            error_response(StatusCode::UNAUTHORIZED, "用户名或密码错误")
        }
    }
}

/// `POST /api/auth/logout`：撤销当前会话令牌。
async fn logout_handler<B: AdminBackend>(
    State(state): State<WebState<B>>,
    headers: HeaderMap,
) -> Response {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(bearer_credentials)
        .map(str::to_owned);
    match token {
        Some(t) if state.sessions.revoke(&t) => {
            (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
        }
        _ => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
    }
}

/// `GET /api/whoami`：返回当前主体信息（供前端决定显示什么）。
async fn whoami<B: AdminBackend>(
    State(state): State<WebState<B>>,
    headers: HeaderMap,
) -> Response {
    match resolve_principal(&headers, &state) {
        Some(principal) => Json(json!({
            "principal": principal.display(),
            "is_admin": principal.is_admin(),
            "visible_clients": principal.visible_clients(),
        }))
        .into_response(),
        None => error_response(StatusCode::UNAUTHORIZED, "未授权"),
    }
}

/// 取客户端 IP（用于登录限流）。
///
/// 优先 `X-Forwarded-For` 首个值（反向代理场景），否则退回连接地址占位。
fn client_ip(headers: &HeaderMap) -> std::net::IpAddr {
    if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = value.split(',').next() {
            if let Ok(ip) = first.trim().parse() {
                return ip;
            }
        }
    }
    // 无法确定时用全零地址（所有此类请求共享一个限流桶，
    // 宁可更严格也不放过暴力破解）
    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
}
