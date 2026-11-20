//! 防漂移测试：守护 `rust/nps.example.json` 与 `ServerConfig` 的一致性。
//!
//! 示例配置是用户接触 NPS 的第一个模板。当 `ServerConfig`（config.rs /
//! file_service.rs / acme.rs）的字段、默认值或校验规则变化而示例没跟上时，
//! 本文件必须失败，逼着示例同步更新。
//!
//! 覆盖三件事：
//! 1. 文件是合法 JSON 且能反序列化为 `ServerConfig`（`_notes` / `_comment`
//!    注释键依赖 serde 忽略未知字段的行为；若将来给配置加上
//!    `deny_unknown_fields`，本测试会立刻失败，提示把注释迁去 README）；
//! 2. 示例必须通过 `ServerConfig::validate()`；
//! 3. 关键字段值与预期一致、每种子结构都有代表性示例——防止某次改动
//!    悄悄删掉或改坏示例段落。

use std::collections::HashSet;
use std::path::PathBuf;

use nps_server::{AcmeProvider, ServerConfig, TlsMode};

/// 示例配置路径：`CARGO_MANIFEST_DIR` = rust/crates/nps-server，示例在 rust/ 下
fn example_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../nps.example.json")
}

fn load_example() -> ServerConfig {
    let raw = std::fs::read_to_string(example_path())
        .expect("nps.example.json 必须存在于 rust/ 目录");
    serde_json::from_str(&raw)
        .expect("nps.example.json 必须是合法 JSON 且能反序列化为 ServerConfig")
}

#[test]
fn example_parses_and_validates() {
    let cfg = load_example();
    cfg.validate()
        .expect("nps.example.json 必须通过 ServerConfig::validate()");
}

/// 覆盖完整性：每种子结构都要有代表性示例，防止某个段落被悄悄删掉。
#[test]
fn example_covers_every_section() {
    let cfg = load_example();

    assert!(!cfg.clients.is_empty(), "clients 段缺失");
    assert!(!cfg.tunnels.is_empty(), "tunnels 段缺失");
    assert!(!cfg.udp_tunnels.is_empty(), "udp_tunnels 段缺失");
    assert!(!cfg.http_sites.is_empty(), "http_sites 段缺失");
    assert!(!cfg.file_tunnels.is_empty(), "file_tunnels 段缺失");
    assert!(!cfg.secret_tunnels.is_empty(), "secret_tunnels 段缺失");
    assert!(!cfg.socks5_listeners.is_empty(), "socks5_listeners 段缺失");
    assert!(!cfg.tcp_trans_tunnels.is_empty(), "tcp_trans_tunnels 段缺失");
    assert!(!cfg.ip_limit.is_empty(), "ip_limit 段缺失");

    // Option 字段的代表性示例
    assert!(cfg.http_listen_addr.is_some(), "http_listen_addr 缺失");
    assert!(cfg.https_listen_addr.is_some(), "https_listen_addr 缺失");
    assert!(cfg.p2p_listen_addr.is_some(), "p2p_listen_addr 缺失");
    assert!(
        cfg.web_username.is_some() && cfg.web_password.is_some(),
        "web_username / web_password 缺失"
    );
    assert!(cfg.acme.contact_email.is_some(), "acme 段缺失");

    // 嵌套能力的代表性示例
    assert!(
        cfg.tunnels.iter().any(|t| t.health_check.is_some()),
        "health_check 示例缺失"
    );
    assert!(
        cfg.tunnels.iter().any(|t| !t.target_addrs.is_empty()),
        "target_addrs 多目标示例缺失"
    );
    assert!(
        cfg.tunnels.iter().any(|t| !t.enabled),
        "enabled=false 示例缺失"
    );
    assert!(
        cfg.http_sites.iter().any(|s| !s.routes.is_empty()),
        "http routes 示例缺失"
    );
    assert!(
        cfg.socks5_listeners.iter().any(|s| !s.users.is_empty()),
        "socks5 users 示例缺失"
    );
}

/// 关键取值稳定性：示例改动应当是有意的，改示例时同步更新这里的断言。
#[test]
fn example_key_values_match() {
    let cfg = load_example();

    assert_eq!(cfg.bridge_addr, "127.0.0.1:61024");
    assert_eq!(cfg.web_addr, "127.0.0.1:61880");

    assert_eq!(cfg.clients.len(), 3, "clients 示例应有 3 个客户端");
    assert_eq!(cfg.tunnels.len(), 3, "tunnels 示例应有 3 条 TCP 隧道");
    assert_eq!(cfg.udp_tunnels.len(), 1);
    assert_eq!(cfg.http_sites.len(), 2);
    assert_eq!(cfg.file_tunnels.len(), 1);
    assert_eq!(cfg.secret_tunnels.len(), 1);
    assert_eq!(cfg.socks5_listeners.len(), 1);
    assert_eq!(cfg.tcp_trans_tunnels.len(), 1);

    // 客户端示例：限速 / 加密 / 受限 Web 登录
    let office = cfg.clients.iter().find(|c| c.id == 1).expect("示例必须包含 id=1 的客户端");
    assert_eq!(office.rate_limit, 1024);
    assert_eq!(office.flow_limit, 1048576);
    assert!(office.crypt);
    assert!(!office.compress);
    assert_eq!(office.web_username.as_deref(), Some("office-admin"));

    // TCP 隧道示例：单目标、多目标 + 健康检查、停用
    let ssh = cfg.tunnels.iter().find(|t| t.id == 1).expect("示例必须包含 id=1 的 TCP 隧道");
    assert_eq!(ssh.listen_addr, "127.0.0.1:61022");
    assert_eq!(ssh.target_addr, "127.0.0.1:22");
    assert!(ssh.enabled);
    assert!(ssh.health_check.is_none());

    let web_farm = cfg.tunnels.iter().find(|t| t.id == 2).expect("示例必须包含 id=2 的 TCP 隧道");
    assert_eq!(web_farm.listen_addr, "127.0.0.1:61280");
    assert_eq!(
        web_farm.target_addrs,
        vec!["192.168.1.10:8080", "192.168.1.11:8080", "192.168.1.12:8080"]
    );
    let hc = web_farm.health_check.as_ref().expect("id=2 必须带健康检查");
    assert_eq!(hc.timeout_secs, 3);
    assert_eq!(hc.max_failed, 3);
    assert_eq!(hc.interval_secs, 10);
    assert_eq!(hc.kind, "http");
    assert_eq!(hc.http_url, "/healthz");

    let db = cfg.tunnels.iter().find(|t| t.id == 3).expect("示例必须包含 id=3 的 TCP 隧道");
    assert!(!db.enabled);

    // UDP 隧道示例
    let dns = &cfg.udp_tunnels[0];
    assert_eq!(dns.listen_addr, "127.0.0.1:61053");
    assert_eq!(dns.idle_timeout_secs, 600);
    assert_eq!(dns.max_sessions, 512);

    // HTTP 站点示例：覆盖 tls_mode 两种代表值（证书绝不自动申请，acme 也只是待用户触发）
    let blog = cfg.http_sites.iter().find(|s| s.id == 20).expect("示例必须包含 id=20 的站点");
    assert_eq!(blog.domain, "blog.example.com");
    assert_eq!(blog.tls_mode, TlsMode::Off);
    let docs = cfg.http_sites.iter().find(|s| s.id == 21).expect("示例必须包含 id=21 的站点");
    assert_eq!(docs.tls_mode, TlsMode::Acme);

    // SOCKS5 / secret / tcpTrans 示例
    assert_eq!(cfg.socks5_listeners[0].listen_addr, "127.0.0.1:61080");
    assert!(cfg.secret_tunnels[0].password.len() >= 12, "secret 示例密码应足够长");
    let trans = &cfg.tcp_trans_tunnels[0];
    assert_eq!(trans.listen_addr, "127.0.0.1:61611");
    assert_eq!(trans.client_id, 1);
    assert!(trans.enabled);

    // conf 注册默认关闭（攻击面），给出保守默认值
    assert!(!cfg.conf_register);
    assert_eq!(cfg.conf_max_tunnels, 32);
    assert_eq!(cfg.conf_listen_host, "0.0.0.0");

    assert_eq!(cfg.flow_store_interval, 5);
    assert_eq!(cfg.p2p_listen_addr.as_deref(), Some("127.0.0.1:61901"));

    // ACME 示例：Let's Encrypt / 到期前 30 天续期
    assert_eq!(cfg.acme.provider, AcmeProvider::LetsEncrypt);
    assert_eq!(cfg.acme.renew_before_days, 30);
}

/// 产品硬约束在示例中的体现：vkey 不允许空 / 默认弱值 / 重复；
/// 配置文件不得出现 admin_token 字段（token 只走环境变量 NPS_ADMIN_TOKEN）。
#[test]
fn example_respects_vkey_and_token_policy() {
    let cfg = load_example();

    let forbidden = ["123", "123456", "password", "vkey"];
    let mut seen = HashSet::new();
    for c in &cfg.clients {
        let vkey = c.vkey.trim();
        assert!(!vkey.is_empty(), "客户端 {} 的 vkey 为空", c.id);
        for bad in forbidden {
            assert!(
                !vkey.eq_ignore_ascii_case(bad),
                "客户端 {} 使用了禁止的默认 vkey: {vkey}",
                c.id
            );
        }
        assert!(vkey.len() >= 16, "示例 vkey 应足够长（>=16 字符）: {vkey}");
        assert!(seen.insert(vkey.to_owned()), "示例 vkey 重复: {vkey}");
    }

    let raw = std::fs::read_to_string(example_path()).unwrap();
    assert!(
        !raw.contains("\"admin_token\""),
        "示例不得包含 admin_token 字段（管理 token 只走环境变量 NPS_ADMIN_TOKEN）"
    );
}
