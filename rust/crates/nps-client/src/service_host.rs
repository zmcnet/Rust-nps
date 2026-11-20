//! `rnpc service-host --name <name>`：Windows 服务的 SCM 入口（**内部使用**）。
//!
//! 这个子命令不由用户直接调用，而是由服务控制管理器（SCM）在启动服务时拉起。
//! [`crate::autostart`] 的 `service` 通道注册的 binPath 就是
//! `"<绝对路径>" service-host --name <name>`。
//!
//! # 为什么需要它
//!
//! 服务进程必须向 SCM 上报状态转换，否则 SCM 会在默认 30 秒后判定服务启动失败：
//!
//! ```text
//! SERVICE_START_PENDING → SERVICE_RUNNING
//! SERVICE_STOP_PENDING  → SERVICE_STOPPED
//! ```
//!
//! 并处理 `SERVICE_CONTROL_STOP` / `SERVICE_CONTROL_SHUTDOWN`。这段逻辑无法与
//! 前台 `run` 共用——前台没有 SCM 句柄。
//!
//! # 与前台运行的关系
//!
//! 连接逻辑完全复用 [`crate::client::run`]，只是生命周期由 SCM 驱动：
//! 收到 STOP 时通过 `watch` 通道通知客户端优雅退出。
//!
//! # 非 Windows
//!
//! 直接返回错误（服务通道仅 Windows 有）。

use anyhow::Result;

/// 服务入口。`name` 是实例名（不是服务名；服务名由 [`crate::autostart`] 计算）。
pub fn run(name: String) -> Result<()> {
    #[cfg(windows)]
    {
        win::run(name)
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        anyhow::bail!("service-host 仅 Windows 支持（Linux 请用 systemd）")
    }
}

#[cfg(windows)]
mod win {
    use std::ffi::OsString;
    use std::sync::OnceLock;
    use std::time::Duration;

    use anyhow::{Context, Result};
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_dispatcher;

    /// SCM 通过 dispatcher 回调进来，拿不到命令行参数，因此实例名走进程内静态。
    ///
    /// 进程由 SCM 单独拉起、只承载一个服务，所以这里用 `OnceLock` 是安全的。
    static INSTANCE: OnceLock<String> = OnceLock::new();

    /// 服务状态上报的等待提示（毫秒）。
    const PENDING_HINT_MS: u64 = 5_000;

    pub(super) fn run(name: String) -> Result<()> {
        crate::instance::validate_instance_name(&name).context("实例名非法")?;
        let service = crate::autostart::service_name_of(&name);
        INSTANCE
            .set(name)
            .map_err(|_| anyhow::anyhow!("service-host 只能启动一次"))?;

        // 第三个参数是传递给 SCM 的命令行参数（这里不需要，实例名已从 CLI 得到）。
        service_dispatcher::start(service.as_str(), ffi_service_main)
            .context("向 SCM 注册服务入口失败（本程序可能不是由 SCM 启动的）")?;
        Ok(())
    }

    windows_service::define_windows_service!(ffi_service_main, service_main);

    fn service_main(_arguments: Vec<OsString>) {
        // 服务没有控制台，日志走 tracing（由外层 subscriber 写到实例日志）。
        if let Err(error) = run_service() {
            tracing::error!(error = %format!("{error:#}"), "服务运行失败");
        }
    }

    fn run_service() -> Result<()> {
        let name = INSTANCE
            .get()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("internal: 实例名未设置"))?;

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        // 控制处理器：SCM 发 STOP/SHUTDOWN 时通知客户端退出。
        let handler = move |control: ServiceControl| -> ServiceControlHandlerResult {
            match control {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = shutdown_tx.send(true);
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };
        let status_handle = service_control_handler::register(
            crate::autostart::service_name_of(&name).as_str(),
            handler,
        )
        .context("注册服务控制处理器失败")?;

        // START_PENDING → RUNNING
        status_handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::StartPending,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 1,
                wait_hint: Duration::from_millis(PENDING_HINT_MS),
                process_id: None,
            })
            .context("上报 START_PENDING 失败")?;

        // 连接逻辑与前台 `run --name` 完全一致。
        let config = crate::cli::RunConfig {
            target: crate::cli::Target::Instance { name: name.clone() },
            conn_type: crate::cli::ConnType::Tcp,
            log_level: "info".to_owned(),
        };

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("创建 Tokio 运行时失败")?;

        status_handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Running,
                controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })
            .context("上报 RUNNING 失败")?;

        // 客户端以「无 vkey 也可」的方式运行；连接失败会重连，不立刻退出。
        let result = runtime.block_on(crate::client::run(config, shutdown_rx));

        // STOP_PENDING → STOPPED
        status_handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::StopPending,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 1,
                wait_hint: Duration::from_millis(PENDING_HINT_MS),
                process_id: None,
            })
            .ok();

        let exit = match result {
            Ok(()) => ServiceExitCode::Win32(0),
            Err(error) => {
                tracing::error!(error = %error, "客户端运行结束于错误");
                ServiceExitCode::ServiceSpecific(1)
            }
        };

        // 最后一步：上报 STOPPED。这一步**必须**用 status handle 完成，
        // 否则 SCM 会认为服务卡在 STOP_PENDING。
        status_handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: exit,
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })
            .context("上报 STOPPED 失败")?;
        Ok(())
    }
}
