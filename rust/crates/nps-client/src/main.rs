use std::process::ExitCode;

use nps_client::cli::{parse_args, Command, HELP};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    let command = match parse_args(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("rnpc: {error}");
            eprintln!("运行 rnpc help 查看用法");
            return ExitCode::from(error.exit_code());
        }
    };

    match command {
        Command::Help => {
            print!("{HELP}");
            ExitCode::SUCCESS
        }
        Command::Version => {
            println!(
                "rnpc {} (Rust-nps, legacy core {})",
                env!("CARGO_PKG_VERSION"),
                nps_proto::CORE_VERSION
            );
            ExitCode::SUCCESS
        }
        Command::UnsupportedSubcommand(name) => {
            // 已识别但尚未实现的子命令：明确拒绝，不静默当成运行参数。
            eprintln!("rnpc: 子命令 {name} 尚未实现（退出码 2）");
            eprintln!("运行 rnpc help 查看已支持的子命令");
            ExitCode::from(nps_client::cli::EXIT_CONFIG)
        }
        Command::UnknownSubcommand(name) => {
            eprintln!("rnpc: 未知子命令 {name}");
            eprintln!("运行 rnpc help 查看用法");
            ExitCode::from(nps_client::cli::EXIT_CONFIG)
        }
        Command::Run(config) => run_client(config).await,
    }
}

async fn run_client(config: nps_client::cli::RunConfig) -> ExitCode {
    // RUST_LOG 优先；否则使用 -log_level 归一化后的级别。
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(config.log_level.clone()));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    tracing::info!(
        target = %config.server_label(),
        "Rust-nps 客户端 rnpc 启动"
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        tracing::info!("收到 Ctrl+C，正在优雅关闭");
        let _ = shutdown_tx.send(true);
    });

    match nps_client::client::run(config, shutdown_rx).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rnpc: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

/// Ctrl+C（Unix 上同时支持 SIGTERM），用于触发优雅关闭。
async fn wait_for_shutdown_signal() {
    #[cfg(windows)]
    {
        match tokio::signal::windows::ctrl_break() {
            Ok(mut ctrl_break) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = ctrl_break.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }

    #[cfg(not(windows))]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
}
