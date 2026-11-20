//! tcpTrans（透明代理）接线测试。
//!
//! 平台差异语义：`SO_ORIGINAL_DST` 只在 Linux 可用（原版 Windows 同样是
//! 空实现）。因此测试分两类：
//! - **所有平台**：配置校验、快照可见性、平台不支持时的诚实降级；
//! - **仅 Linux**（CI/真机补跑）：`iptables REDIRECT` 指入后的端到端转发，
//!   见模块底部注释。

use nps_server::{Server, ServerConfig, TcpTransTunnelConfig, TcpTunnelConfig};
use tokio::net::TcpListener;

const VKEY: &str = "tcptrans-wiring-vkey-9d31aa";

fn config(trans: Vec<TcpTransTunnelConfig>) -> ServerConfig {
    ServerConfig {
        bridge_addr: "127.0.0.1:0".into(),
        web_addr: "127.0.0.1:0".into(),
        clients: vec![nps_server::ClientConfig {
            id: 1,
            name: "npc".into(),
            vkey: VKEY.into(),
            rate_limit: 0,
            flow_limit: 0,
            crypt: false,
            compress: false,
            web_username: None,
            web_password: None,
        }],
        tcp_trans_tunnels: trans,
        ..Default::default()
    }
}

async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

fn trans_cfg(id: u32, port: u16) -> TcpTransTunnelConfig {
    TcpTransTunnelConfig {
        id,
        name: "transparent".into(),
        client_id: 1,
        listen_addr: format!("127.0.0.1:{port}"),
        enabled: true,
    }
}

/// 平台支持标志与编译目标一致（探测层自检）
#[test]
fn supported_flag_matches_platform() {
    assert_eq!(nps_server::transparent::supported(), cfg!(target_os = "linux"));
}

/// tcpTrans 隧道出现在快照里；不支持的平台上是「未启用 + 明确原因」。
#[tokio::test]
async fn snapshot_reports_tcp_trans_tunnel() {
    let port = free_port().await;
    let server = Server::start(config(vec![trans_cfg(1, port)])).await.unwrap();

    let snap = server.snapshot().await;
    let t = snap.tunnels.iter().find(|t| t.id == 1).expect("tcpTrans 隧道应出现在快照");
    assert_eq!(t.name, "transparent");
    assert_eq!(t.listen_addr, format!("127.0.0.1:{port}"));

    if nps_server::transparent::supported() {
        // Linux：正常监听
        assert!(t.enabled, "Linux 上 tcpTrans 应正常启用");
        assert!(t.bound_addr.is_some());
    } else {
        // 其它平台：不绑定监听，但给出可操作的失败原因（原版 Windows 同样是空实现）
        assert!(!t.enabled, "非 Linux 上 tcpTrans 不应启用");
        let reason = t.last_error.as_deref().unwrap_or_default();
        assert!(
            reason.contains("Linux"),
            "last_error 应说明平台限制，实际: {reason:?}"
        );
        // 未启用的隧道不会被 bind（bind 循环只处理 enabled=true 的隧道），
        // 这里不再做端口探测：本机 Windows 的保留端口段可能让 connect 挂起。
    }

    server.shutdown().await;
}

/// 配置校验：id 与 TCP 隧道冲突、引用不存在的客户端、地址非法都要在启动时报错。
#[tokio::test]
async fn config_validation_rejects_bad_tcp_trans() {
    let port = free_port().await;
    let mut cfg = config(Vec::new());
    cfg.tunnels = vec![TcpTunnelConfig {
        id: 1,
        name: "tcp".into(),
        client_id: 1,
        listen_addr: format!("127.0.0.1:{port}"),
        target_addr: "127.0.0.1:9".into(),
        enabled: true,
        target_addrs: Vec::new(),
        health_check: None,
    }];

    // 与 TCP 隧道 id 冲突
    let mut bad = cfg.clone();
    bad.tcp_trans_tunnels = vec![trans_cfg(1, free_port().await)];
    assert!(Server::start(bad).await.is_err(), "id 冲突必须被拒绝");

    // 与 TCP 隧道监听同一地址
    let mut bad = cfg.clone();
    bad.tcp_trans_tunnels = vec![TcpTransTunnelConfig {
        id: 2,
        name: "t".into(),
        client_id: 1,
        listen_addr: format!("127.0.0.1:{port}"),
        enabled: true,
    }];
    assert!(Server::start(bad).await.is_err(), "监听地址冲突必须被拒绝");

    // 引用不存在的客户端
    let mut bad = cfg.clone();
    bad.tcp_trans_tunnels = vec![TcpTransTunnelConfig {
        id: 2,
        name: "t".into(),
        client_id: 99,
        listen_addr: format!("127.0.0.1:{}", free_port().await),
        enabled: true,
    }];
    assert!(Server::start(bad).await.is_err(), "未知客户端必须被拒绝");

    // listen_addr 非法
    let mut bad = cfg.clone();
    bad.tcp_trans_tunnels = vec![TcpTransTunnelConfig {
        id: 2,
        name: "t".into(),
        client_id: 1,
        listen_addr: "not-an-addr".into(),
        enabled: true,
    }];
    assert!(Server::start(bad).await.is_err(), "非法地址必须被拒绝");
}

// Linux 真机端到端（需要 iptables，本地无法自动化）：
//
//   iptables -t nat -A OUTPUT -p tcp --dport 8080 -j REDIRECT --to-ports <listen>
//   curl 127.0.0.1:8080
//
// 预期：rnps 经 REDIRECT 拿到原始目标 127.0.0.1:8080（或外网地址），
// 以 `Link::tcp(原始目标, 客户端源地址)` 向对应 client 建子流，
// npc 侧在该网络内拨号该目标。可用 `tools/interop/smoke.py` 同款
// 回显 npc 验证 Link.Host == 原始目标。
