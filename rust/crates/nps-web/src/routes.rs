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
const API_BODY_LIMIT: usize = 16 * 1024;

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
    let state = WebState { backend, token };

    let api = Router::new()
        .route("/status", get(get_status::<B>))
        .route("/tunnels/{id}/state", post(set_tunnel_state::<B>))
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
    /// 管理令牌。刻意不实现 `Debug`，避免误打印。
    token: Arc<str>,
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

    if !authorized(request.headers(), &state.token) {
        let mut response = error_response(StatusCode::UNAUTHORIZED, "未授权：缺少或无效的管理令牌");
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"nps-admin\""),
        );
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static(API_CACHE));
        return response;
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

fn authorized(headers: &HeaderMap, expected: &str) -> bool {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    let Some(provided) = bearer_credentials(value) else {
        return false;
    };
    constant_time_eq(provided.as_bytes(), expected.as_bytes())
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

async fn get_status<B: AdminBackend>(State(state): State<WebState<B>>) -> Response {
    let snapshot = state.backend.snapshot().await;
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
