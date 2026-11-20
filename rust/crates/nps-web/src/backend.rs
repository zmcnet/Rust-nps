//! 管理 API 对 `nps-server` 的最小依赖面。
//!
//! 生产路径直接使用 [`nps_server::Server`]；测试路径使用同形状的内存实现，
//! 这样路由层可以在不依赖 `nps-server` 构造方式的前提下被完整测试。
//!
//! 站点 / 证书相关的返回值一律用本模块定义的 DTO，
//! **绝不把私钥**或任何密钥材料暴露给 Web 层。

use std::future::Future;

use nps_server::{Server, ServerSnapshot};
use serde::{Deserialize, Serialize};

/// 管理界面需要后端提供的能力。
pub trait AdminBackend: Clone + Send + Sync + 'static {
    /// 获取当前只读快照。
    fn snapshot(&self) -> impl Future<Output = ServerSnapshot> + Send;

    /// 运行时启停指定隧道。`id` 不存在时应返回错误（路由层会先行检查）。
    fn set_tunnel_enabled(
        &self,
        id: u32,
        enabled: bool,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// 列出已部署证书（**不含私钥**）。
    fn list_certificates(&self) -> impl Future<Output = Vec<CertView>> + Send;

    /// 上传证书与私钥。实现方负责校验、落盘与热加载。
    fn upload_certificate(
        &self,
        domain: String,
        cert_pem: String,
        key_pem: String,
    ) -> impl Future<Output = anyhow::Result<CertView>> + Send;

    /// 生成自签证书（仅测试用途）。
    fn generate_self_signed(
        &self,
        domain: String,
    ) -> impl Future<Output = anyhow::Result<CertView>> + Send;

    /// 删除某域名的证书。删除后该域名握手会被拒绝。
    fn remove_certificate(
        &self,
        domain: String,
    ) -> impl Future<Output = anyhow::Result<bool>> + Send;

    /// 从磁盘重新加载证书目录（ACME 部署后或外部改动后调用）。
    fn reload_certificates(&self) -> impl Future<Output = anyhow::Result<usize>> + Send;

    /// 当前 ACME 配置摘要（是否可用、provider、挑战方式、自动续期）。
    fn acme_summary(&self) -> AcmeSummary;

    /// 各监听面的运行时统计。
    fn listener_stats(&self) -> ListenerView;

    /// 列出当前站点。
    fn list_sites(&self) -> impl Future<Output = Vec<SiteView>> + Send;

    /// 新增或更新站点（按域名）。
    fn upsert_site(&self, site: SiteInput)
        -> impl Future<Output = anyhow::Result<SiteView>> + Send;

    /// 删除站点。
    fn remove_site(&self, domain: String) -> impl Future<Output = anyhow::Result<bool>> + Send;

    /// **用户显式发起**的 ACME 证书申请。只有调用它才会联系 CA。
    fn request_acme_certificate(
        &self,
        domain: String,
    ) -> impl Future<Output = anyhow::Result<AcmeIssueResult>> + Send;
}

/// ACME 申请结果（管理页展示）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcmeIssueResult {
    pub domain: String,
    pub issued: bool,
    pub not_after: String,
    /// 预检/验证失败时的可操作原因
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// 站点对外视图。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteView {
    pub domain: String,
    pub client_id: i32,
    pub target: String,
    pub routes: Vec<SiteRouteView>,
    pub websocket: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteRouteView {
    pub prefix: String,
    pub target: String,
}

/// 站点写入请求（来自管理页）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteInput {
    pub domain: String,
    pub client_id: i32,
    pub target: String,
    #[serde(default)]
    pub routes: Vec<SiteRouteView>,
    #[serde(default = "default_true")]
    pub websocket: bool,
}

fn default_true() -> bool {
    true
}

/// 证书的对外视图。**没有任何私钥字段**。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertView {
    pub domain: String,
    /// `upload` / `self-signed` / `acme`
    pub source: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub days_remaining: i64,
    pub san: Vec<String>,
    /// 叶子证书 SHA-256 指纹（不是私钥）
    pub fingerprint_sha256: String,
    pub expired: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// ACME 状态摘要（管理页用来决定「申请」按钮是否可用）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcmeSummary {
    /// ACME 服务是否初始化成功
    pub available: bool,
    /// `letsencrypt` / `letsencrypt-staging` / `zerossl` / `custom`
    pub provider: String,
    /// `http-01` / `tls-alpn-01` / `dns-01`
    pub challenge: String,
    pub auto_renew: bool,
    /// 未配置邮箱时提示
    pub contact_email_set: bool,
}

/// 各监听面统计（管理页展示用）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerView {
    pub udp_tunnels: usize,
    pub udp_active_flows: u64,
    pub http_configured: bool,
    pub http_active_connections: u64,
    pub http_served_requests: u64,
    pub socks5_listeners: usize,
    pub socks5_active_connections: u64,
}

/// 把 serde 枚举转成它序列化后的字符串名（避免依赖各模块的私有方法）。
fn enum_name<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// 生产实现：直接转调 nps_server::Server
// ---------------------------------------------------------------------------

impl AdminBackend for Server {
    async fn snapshot(&self) -> ServerSnapshot {
        Server::snapshot(self).await
    }

    async fn set_tunnel_enabled(&self, id: u32, enabled: bool) -> anyhow::Result<()> {
        Server::set_tunnel_enabled(self, id, enabled).await
    }

    async fn list_certificates(&self) -> Vec<CertView> {
        let Some(store) = self.certificate_store() else {
            return Vec::new();
        };
        store.list().into_iter().map(cert_to_view).collect()
    }

    async fn upload_certificate(
        &self,
        domain: String,
        cert_pem: String,
        key_pem: String,
    ) -> anyhow::Result<CertView> {
        let store = self.certificate_store().ok_or_else(|| {
            anyhow::anyhow!("HTTPS 未启用（需配置 https_listen_addr 与 cert_dir）")
        })?;
        let info = store.put(
            &domain,
            &cert_pem,
            &key_pem,
            nps_server::tls::CertSource::Upload,
        )?;
        Ok(cert_to_view(info))
    }

    async fn generate_self_signed(&self, domain: String) -> anyhow::Result<CertView> {
        let store = self.certificate_store().ok_or_else(|| {
            anyhow::anyhow!("HTTPS 未启用（需配置 https_listen_addr 与 cert_dir）")
        })?;
        let info = store.put_self_signed(&domain)?;
        Ok(cert_to_view(info))
    }

    async fn remove_certificate(&self, domain: String) -> anyhow::Result<bool> {
        let Some(store) = self.certificate_store() else {
            return Ok(false);
        };
        Ok(store.remove(&domain)?)
    }

    async fn reload_certificates(&self) -> anyhow::Result<usize> {
        let Some(store) = self.certificate_store() else {
            return Ok(0);
        };
        Ok(store.reload()?)
    }

    fn acme_summary(&self) -> AcmeSummary {
        match self.acme() {
            Some(service) => {
                let cfg = service.client().config();
                AcmeSummary {
                    available: true,
                    provider: enum_name(&cfg.provider),
                    challenge: enum_name(&cfg.challenge),
                    auto_renew: cfg.renewal.enabled,
                    contact_email_set: cfg
                        .contact_email
                        .as_deref()
                        .is_some_and(|e| !e.trim().is_empty()),
                }
            }
            None => AcmeSummary {
                available: false,
                provider: String::new(),
                challenge: String::new(),
                auto_renew: false,
                contact_email_set: false,
            },
        }
    }

    async fn list_sites(&self) -> Vec<SiteView> {
        Server::list_sites(self)
            .await
            .into_iter()
            .map(site_to_view)
            .collect()
    }

    async fn upsert_site(&self, site: SiteInput) -> anyhow::Result<SiteView> {
        let domain = site.domain.trim().to_owned();
        if domain.is_empty() {
            anyhow::bail!("域名不能为空");
        }
        let mut model = nps_server::HttpSite::new(
            &domain,
            site.client_id,
            site.target.trim(),
        );
        if !site.routes.is_empty() {
            model = model.with_routes(
                site.routes
                    .iter()
                    .map(|r| nps_server::HttpRoute {
                        prefix: r.prefix.clone(),
                        target_addr: r.target.clone(),
                    })
                    .collect(),
            );
        }
        model = model.with_websocket(site.websocket);
        let view = site_to_view(model.clone());
        Server::upsert_site(self, model).await?;
        Ok(view)
    }

    async fn remove_site(&self, domain: String) -> anyhow::Result<bool> {
        Server::remove_site(self, &domain).await
    }

    async fn request_acme_certificate(
        &self,
        domain: String,
    ) -> anyhow::Result<AcmeIssueResult> {
        let service = self
            .acme()
            .ok_or_else(|| anyhow::anyhow!("ACME 服务不可用（服务端未初始化）"))?;
        let client = service.client();

        // 这是**唯一**会联系 CA 的入口：CertificateRequest::user 表达用户意图
        let request = nps_server::acme::CertificateRequest::user(vec![domain.clone()])?;
        let events = nps_server::acme::AcmeEvents::noop();

        match client.request_certificate(&request, &events).await {
            Ok(issued) => {
                let not_after = issued
                    .not_after
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs().to_string())
                    .unwrap_or_default();
                Ok(AcmeIssueResult {
                    domain,
                    issued: true,
                    not_after,
                    reason: None,
                })
            }
            Err(error) => Ok(AcmeIssueResult {
                domain,
                issued: false,
                not_after: String::new(),
                reason: Some(format!("{error}")),
            }),
        }
    }

    fn listener_stats(&self) -> ListenerView {
        let s = Server::listeners(self);
        ListenerView {
            udp_tunnels: s.udp_tunnels,
            udp_active_flows: s.udp_active_flows,
            http_configured: s.http_configured,
            http_active_connections: s.http_active_connections,
            http_served_requests: s.http_served_requests,
            socks5_listeners: s.socks5_listeners,
            socks5_active_connections: s.socks5_active_connections,
        }
    }
}

fn site_to_view(site: nps_server::HttpSite) -> SiteView {
    SiteView {
        domain: site.domain,
        client_id: site.client_id,
        target: site.target,
        routes: site
            .routes
            .into_iter()
            .map(|r| SiteRouteView {
                prefix: r.prefix,
                target: r.target_addr,
            })
            .collect(),
        websocket: site.websocket,
    }
}

fn cert_to_view(info: nps_server::tls::CertInfo) -> CertView {
    CertView {
        domain: info.domain,
        source: enum_name(&info.source),
        issuer: info.issuer,
        not_before: info.not_before,
        not_after: info.not_after,
        days_remaining: info.days_remaining,
        san: info.san,
        fingerprint_sha256: info.fingerprint_sha256,
        expired: info.expired,
        last_error: info.last_error,
    }
}
