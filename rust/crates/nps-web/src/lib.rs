//! NPS Rust 管理界面。
//!
//! 该 crate 提供两件事：
//! 1. 通过 `include_str!` 内嵌到单一二进制中的管理页面（中文、无外部资源、无 Node 构建）；
//! 2. 受 Bearer 令牌保护的只读状态 API 与隧道启停 API。
//!
//! 安全边界：
//! - 管理令牌由调用方（`nps-app` / `main`）从环境变量 `NPS_ADMIN_TOKEN` 读取后传入，
//!   本 crate 不读取、不写死、不打印令牌；
//! - 所有 `/api` 路由都要求 `Authorization: Bearer <token>`，不接受 Cookie 认证；
//! - 不输出任何 CORS 头，跨站变更请求会被拒绝；
//! - 前端只把令牌放在 `sessionStorage`，不向本服务以外的地址发起请求。

mod assets;
mod backend;
mod routes;

pub use backend::{
    AcmeIssueResult, AcmeSummary, AdminBackend, CertView, ListenerView, SiteInput, SiteRouteView,
    SiteView,
};
pub use routes::{router, router_with_backend};
