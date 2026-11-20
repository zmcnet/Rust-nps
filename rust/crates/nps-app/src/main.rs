use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{anyhow, bail, Context, Result};
use nps_server::{Server, ServerConfig};
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

const HELP: &str = "Rust-nps — rnps 服务端（TCP 兼容预览版）

用法:
  rnps --config <配置文件.json>
  rnps --help
  rnps --version

选项:
  -c, --config <路径>  JSON 配置文件（默认 nps.json）
  -h, --help           显示帮助
  -V, --version        显示版本

环境变量:
  NPS_ADMIN_TOKEN     管理令牌，至少 24 字节，必须设置
  RUST_LOG            日志级别，默认 info

原版 npc 与 Rust-nps 的 rnpc 均可通过 TCP 桥接模式连接。
当前预览版只支持配置中定义的 TCP 隧道。
配置示例见 nps.example.json。Ctrl+C 停止服务并关闭连接。
";

enum Command {
    Run(PathBuf),
    Help,
    Version,
}

fn parse_args(args: impl IntoIterator<Item = OsString>) -> Result<Command> {
    let mut args = args.into_iter();
    let mut config_path = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--help" | "-h") => return Ok(Command::Help),
            Some("--version" | "-V") => return Ok(Command::Version),
            Some("--config" | "-c") => {
                if config_path.is_some() {
                    bail!("--config 只能指定一次");
                }
                let value = args.next().context("--config 后需要配置文件路径")?;
                if value.is_empty() {
                    bail!("配置文件路径不能为空");
                }
                config_path = Some(PathBuf::from(value));
            }
            _ => bail!("未知参数；运行 rnps --help 查看用法"),
        }
    }
    Ok(Command::Run(
        config_path.unwrap_or_else(|| PathBuf::from("nps.json")),
    ))
}

async fn run(config_path: PathBuf) -> Result<()> {
    let admin_token = std::env::var("NPS_ADMIN_TOKEN")
        .context("请先设置 NPS_ADMIN_TOKEN，使用至少 24 字节的随机管理令牌")?;
    if admin_token.len() < 24 || admin_token.bytes().any(|byte| byte.is_ascii_control()) {
        bail!("NPS_ADMIN_TOKEN 必须至少 24 字节，且不能包含控制字符");
    }

    let metadata = tokio::fs::metadata(&config_path)
        .await
        .with_context(|| format!("无法读取配置文件 {}", config_path.display()))?;
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        bail!("配置必须是大小不超过 1 MiB 的 JSON 文件");
    }
    let contents = tokio::fs::read(&config_path)
        .await
        .with_context(|| format!("无法读取配置文件 {}", config_path.display()))?;
    let config: ServerConfig = serde_json::from_slice(&contents).map_err(|error| {
        anyhow!(
            "配置格式无效（第 {} 行，第 {} 列），请对照 nps.example.json",
            error.line(),
            error.column()
        )
    })?;

    // 先绑定管理端口，启动失败时不遗留隧道监听器。
    let web_listener = TcpListener::bind(&config.web_addr)
        .await
        .context("无法绑定管理端口，请检查 web_addr 和端口占用")?;
    let web_addr = web_listener.local_addr()?;
    let server = Server::start(config).await?;
    let router = match nps_web::router(server.clone(), admin_token) {
        Ok(router) => router,
        Err(error) => {
            server.shutdown().await;
            return Err(error);
        }
    };

    info!(bridge = %server.bridge_addr(), web = %web_addr, "NPS Rust 服务已启动");
    info!("当前支持原版 npc 的 TCP 桥接；按 Ctrl+C 停止");

    let shutdown_server = server.clone();
    let result = axum::serve(web_listener, router)
        .with_graceful_shutdown(async move {
            if let Err(error) = tokio::signal::ctrl_c().await {
                error!(%error, "无法监听 Ctrl+C，开始关闭服务");
            }
            shutdown_server.shutdown().await;
        })
        .await;
    server.shutdown().await;
    result.context("管理服务运行失败")
}

#[tokio::main]
async fn main() -> ExitCode {
    let command = match parse_args(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    match command {
        Command::Help => {
            print!("{HELP}");
            return ExitCode::SUCCESS;
        }
        Command::Version => {
            println!(
                "rnps {} (Rust-nps, TCP compatibility preview)",
                env!("CARGO_PKG_VERSION")
            );
            return ExitCode::SUCCESS;
        }
        Command::Run(config_path) => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
                )
                .with_target(false)
                .init();
            match run(config_path).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("启动或运行失败: {error:#}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}
