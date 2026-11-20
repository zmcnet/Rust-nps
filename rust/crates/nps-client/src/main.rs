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
        Command::Install(args) => {
            let root = nps_client::instance::data_root();
            let self_exe = match std::env::current_exe() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("rnpc: 无法获取自身路径: {e}");
                    return ExitCode::from(nps_client::commands::EXIT_RUNTIME);
                }
            };
            let channel = match nps_client::commands::ChannelChoice::parse(&args.channel) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("rnpc: {e}");
                    return ExitCode::from(nps_client::commands::EXIT_CONFIG);
                }
            };
            let opts = nps_client::commands::InstallOptions {
                name: args.name,
                server: args.server,
                port: args.port,
                vkey: args.vkey,
                channel,
                no_autostart: args.no_autostart,
                no_path: args.no_path,
                npc_alias: args.npc_alias,
            };
            match nps_client::commands::cmd_install(&root, &opts, &self_exe) {
                Ok(code) => ExitCode::from(code),
                Err(e) => {
                    eprintln!("rnpc: 安装失败: {e:#}");
                    ExitCode::from(nps_client::commands::EXIT_CONFIG)
                }
            }
        }
        Command::Uninstall { name, keep_config } => {
            let root = nps_client::instance::data_root();
            match nps_client::commands::cmd_uninstall(&root, &name, keep_config) {
                Ok(code) => ExitCode::from(code),
                Err(e) => {
                    eprintln!("rnpc: {e:#}");
                    ExitCode::from(nps_client::commands::EXIT_NO_INSTANCE)
                }
            }
        }
        Command::Change(args) => {
            let root = nps_client::instance::data_root();
            match nps_client::commands::cmd_change(
                &root,
                &args.name,
                args.server.as_deref(),
                args.port,
                args.vkey.as_deref(),
                args.restart,
            ) {
                Ok(code) => ExitCode::from(code),
                Err(e) => {
                    eprintln!("rnpc: {e:#}");
                    ExitCode::from(nps_client::commands::EXIT_NO_INSTANCE)
                }
            }
        }
        Command::Update(args) => {
            let root = nps_client::instance::data_root();
            let feed = args.feed.or_else(|| std::env::var("RNPC_UPDATE_FEED").ok());
            match nps_client::commands::cmd_update(
                &root,
                &args.name,
                feed.as_deref(),
                args.check_only,
            ) {
                Ok(nps_client::commands::UpdateOutcome::NoFeed) => {
                    println!("未配置更新源（--feed 或 RNPC_UPDATE_FEED），跳过二进制更新");
                    ExitCode::SUCCESS
                }
                Ok(nps_client::commands::UpdateOutcome::UpToDate) => {
                    println!("已是最新版本");
                    ExitCode::SUCCESS
                }
                Ok(nps_client::commands::UpdateOutcome::NewVersionAvailable { version }) => {
                    println!("发现新版本 {version}（--check-only，未更新）");
                    ExitCode::SUCCESS
                }
                Ok(nps_client::commands::UpdateOutcome::Updated { version, backup }) => {
                    println!("已更新到 {version}");
                    println!("旧版本备份: {}", backup.display());
                    ExitCode::SUCCESS
                }
                Ok(nps_client::commands::UpdateOutcome::Blocked { reason }) => {
                    eprintln!("拒绝更新：{reason}");
                    ExitCode::from(nps_client::commands::EXIT_CONFIG)
                }
                Err(e) => {
                    eprintln!("rnpc: 更新失败: {e:#}");
                    ExitCode::from(nps_client::commands::EXIT_RUNTIME)
                }
            }
        }
        Command::List => {
            let root = nps_client::instance::data_root();
            match nps_client::commands::cmd_list(&root) {
                Ok(rows) if rows.is_empty() => {
                    println!("还没有安装任何实例。用 rnpc install 创建。");
                    ExitCode::SUCCESS
                }
                Ok(rows) => {
                    println!("{:<16} {:<24} {:<12} {:<8} {}", "实例", "服务端", "自启通道", "状态", "PID");
                    for r in rows {
                        println!(
                            "{:<16} {:<24} {:<12} {:<8} {}",
                            r.name,
                            r.server,
                            r.channel,
                            if r.running { "运行中" } else { "已停止" },
                            r.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_owned())
                        );
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("rnpc: {e:#}");
                    ExitCode::from(nps_client::commands::EXIT_RUNTIME)
                }
            }
        }
        Command::Status { name } => {
            let root = nps_client::instance::data_root();
            match nps_client::commands::cmd_status(&root, &name) {
                Ok(text) => {
                    print!("{text}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("rnpc: {e:#}");
                    ExitCode::from(nps_client::commands::EXIT_NO_INSTANCE)
                }
            }
        }
        Command::Process {
            action,
            name,
            timeout,
        } => {
            let root = nps_client::instance::data_root();
            let timeout = std::time::Duration::from_secs(timeout);
            let result = match action {
                nps_client::cli::ProcessAction::Start => {
                    nps_client::process::start(&root, &name).map(|pid| {
                        println!("实例 {name} 已启动（PID {pid}）");
                    })
                }
                nps_client::cli::ProcessAction::Stop => {
                    nps_client::process::stop(&root, &name, timeout).map(|stopped| {
                        if stopped {
                            println!("实例 {name} 已停止");
                        } else {
                            println!("实例 {name} 本就没有在运行");
                        }
                    })
                }
                nps_client::cli::ProcessAction::Restart => {
                    nps_client::process::restart(&root, &name, timeout).map(|pid| {
                        println!("实例 {name} 已重启（PID {pid}）");
                    })
                }
            };
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    let text = format!("{e:#}");
                    eprintln!("rnpc: {text}");
                    if text.contains("仅 Windows") {
                        ExitCode::from(nps_client::cli::EXIT_UNSUPPORTED)
                    } else if text.contains("未安装") {
                        ExitCode::from(nps_client::commands::EXIT_NO_INSTANCE)
                    } else {
                        ExitCode::from(nps_client::commands::EXIT_RUNTIME)
                    }
                }
            }
        }
        Command::Logs { name, lines, follow } => {
            let root = nps_client::instance::data_root();
            match nps_client::commands::cmd_logs(&root, &name, lines, follow) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("rnpc: {e:#}");
                    ExitCode::from(nps_client::commands::EXIT_NO_INSTANCE)
                }
            }
        }
        Command::Channel {
            action,
            name,
            channel,
        } => {
            let root = nps_client::instance::data_root();
            let result = match action {
                nps_client::cli::ChannelAction::List => {
                    nps_client::commands::cmd_channel_list(&root, &name).map(|t| print!("{t}"))
                }
                other => {
                    let Some(cname) = channel.as_deref() else {
                        eprintln!("rnpc: channel {} 需要 --channel <名字>", match other {
                            nps_client::cli::ChannelAction::Install => "install",
                            nps_client::cli::ChannelAction::Remove => "remove",
                            nps_client::cli::ChannelAction::List => "list",
                        });
                        return ExitCode::from(nps_client::commands::EXIT_CONFIG);
                    };
                    let Some(ch) = nps_client::autostart::Channel::parse(cname) else {
                        eprintln!("rnpc: 未知通道 {cname:?}（可选 service/task-start/task-logon/run-key）");
                        return ExitCode::from(nps_client::commands::EXIT_CONFIG);
                    };
                    match other {
                        nps_client::cli::ChannelAction::Install => {
                            nps_client::commands::cmd_channel_install(&root, &name, ch)
                        }
                        nps_client::cli::ChannelAction::Remove => {
                            nps_client::commands::cmd_channel_remove(&name, ch)
                        }
                        nps_client::cli::ChannelAction::List => unreachable!(),
                    }
                }
            };
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    let text = format!("{e:#}");
                    eprintln!("rnpc: {text}");
                    if text.contains("管理员权限") {
                        ExitCode::from(nps_client::commands::EXIT_PERMISSION)
                    } else {
                        ExitCode::from(nps_client::commands::EXIT_RUNTIME)
                    }
                }
            }
        }
        Command::Doctor => {
            let root = nps_client::instance::data_root();
            print!("{}", nps_client::commands::cmd_doctor(&root));
            ExitCode::SUCCESS
        }
        Command::Path { action } => {
            let root = nps_client::instance::data_root();
            let bin = nps_client::path_env::bin_dir_of(&root);
            let result = match action {
                nps_client::cli::PathAction::Add => nps_client::path_env::register(&bin)
                    .map(|s| format!("PATH 注册结果: {s:?}")),
                nps_client::cli::PathAction::Remove => nps_client::path_env::unregister(&bin)
                    .map(|s| format!("PATH 移除结果: {s:?}")),
                nps_client::cli::PathAction::Status => nps_client::path_env::is_registered(&bin)
                    .map(|yes| {
                        format!("{} 在用户 PATH 中: {}", bin.display(), if yes { "是" } else { "否" })
                    }),
            };
            match result {
                Ok(text) => {
                    println!("{text}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("rnpc: {e:#}");
                    ExitCode::from(nps_client::commands::EXIT_RUNTIME)
                }
            }
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
