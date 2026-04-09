#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use std::process::{Child, Command, ExitStatus};
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(windows)]
use std::sync::Mutex;
#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
#[cfg(windows)]
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
#[cfg(windows)]
use windows_service::service_dispatcher;
#[cfg(windows)]
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::config::cli::RunArgs;

#[cfg(windows)]
static SHOULD_STOP: AtomicBool = AtomicBool::new(false);
#[cfg(windows)]
static CHILD: Mutex<Option<Child>> = Mutex::new(None);

#[cfg(windows)]
define_windows_service!(ffi_service_main, service_main);

#[cfg(windows)]
mod state {
    use std::sync::OnceLock;

    use crate::config::cli::RunArgs;

    pub static SERVICE_NAME: OnceLock<String> = OnceLock::new();
    pub static RUN_ARGS: OnceLock<RunArgs> = OnceLock::new();
}

#[cfg(windows)]
use windows_service::define_windows_service;

#[cfg(windows)]
pub fn install_service(service_name: &str, run_args: &RunArgs) -> anyhow::Result<()> {
    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let exe = std::env::current_exe()?;

    let mut launch_args: Vec<OsString> = vec![
        OsString::from("windows-service"),
        OsString::from("--service-supervisor"),
        OsString::from("--service-name"),
        OsString::from(service_name),
    ];
    launch_args.extend(run_args.to_cli_args());

    let service_info = ServiceInfo {
        name: OsString::from(service_name),
        display_name: OsString::from(service_name),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: launch_args,
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    manager.create_service(&service_info, ServiceAccess::QUERY_STATUS)?;
    tracing::info!("Installed Windows service: {}", service_name);
    Ok(())
}

#[cfg(windows)]
pub fn uninstall_service(service_name: &str) -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        service_name,
        ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE,
    )?;

    let status = service.query_status()?;
    if status.current_state != ServiceState::Stopped {
        anyhow::bail!(
            "Service '{}' is running. Please stop it first with: sc stop {}",
            service_name,
            service_name
        );
    }

    service.delete()?;
    tracing::info!("Uninstalled Windows service: {}", service_name);
    Ok(())
}

#[cfg(windows)]
pub fn run_as_service(service_name: String, run_args: RunArgs) -> anyhow::Result<()> {
    if state::SERVICE_NAME.set(service_name.clone()).is_err() {
        anyhow::bail!("SERVICE_NAME is already initialized");
    }
    if state::RUN_ARGS.set(run_args).is_err() {
        anyhow::bail!("RUN_ARGS is already initialized");
    }

    service_dispatcher::start(service_name, ffi_service_main).map_err(|e| anyhow::anyhow!(e))
}

#[cfg(windows)]
fn service_main(_arguments: Vec<OsString>) {
    if let Err(err) = run_service() {
        tracing::error!("Windows service failed: {}", err);
    }
}

#[cfg(windows)]
fn run_service() -> windows_service::Result<()> {
    SHOULD_STOP.store(false, Ordering::Relaxed);

    let service_name = state::SERVICE_NAME
        .get()
        .expect("SERVICE_NAME must be initialized")
        .clone();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                SHOULD_STOP.store(true, Ordering::Relaxed);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(service_name, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    })?;

    if let Err(err) = spawn_service_child() {
        tracing::error!(error = %format!("{err:#}"), "Failed to spawn Windows service child process");
        let failure_exit_code = ServiceExitCode::ServiceSpecific(1);
        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: failure_exit_code,
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;
        return Err(to_win_err(err));
    }

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    let mut service_exit_code = ServiceExitCode::Win32(0);

    loop {
        let child_exit = poll_child_exit();

        if SHOULD_STOP.load(Ordering::Relaxed) {
            match child_exit {
                Some(Ok(status)) => {
                    service_exit_code = log_child_exit(status);
                }
                Some(Err(err)) => {
                    tracing::error!(error = %err, "Failed to query Windows service child status during stop");
                    service_exit_code = ServiceExitCode::ServiceSpecific(1);
                }
                None => {
                    tracing::info!("Windows service stop requested; terminating child process");
                    kill_child_force();
                }
            }
            break;
        }

        match child_exit {
            Some(Ok(status)) => {
                service_exit_code = log_child_exit(status);
                break;
            }
            Some(Err(err)) => {
                tracing::error!(error = %err, "Failed to query Windows service child status");
                service_exit_code = ServiceExitCode::ServiceSpecific(1);
                break;
            }
            None => {}
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: service_exit_code,
        checkpoint: 0,
        wait_hint: Duration::from_secs(3),
        process_id: None,
    })?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: service_exit_code,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

#[cfg(windows)]
fn spawn_service_child() -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let run_args = state::RUN_ARGS.get().expect("RUN_ARGS must be initialized");

    let mut command = Command::new(exe);
    command.arg("windows-service").arg("--service-child");
    command.args(run_args.to_cli_args());

    let child = command.spawn()?;
    tracing::info!(pid = child.id(), "Spawned Windows service child process");
    let mut guard = CHILD.lock().expect("child mutex poisoned");
    *guard = Some(child);
    Ok(())
}

#[cfg(windows)]
fn poll_child_exit() -> Option<std::io::Result<ExitStatus>> {
    let mut guard = CHILD.lock().expect("child mutex poisoned");
    match guard.take() {
        Some(mut child) => match child.try_wait() {
            Ok(Some(status)) => Some(Ok(status)),
            Ok(None) => {
                *guard = Some(child);
                None
            }
            Err(err) => Some(Err(err)),
        },
        None => Some(Ok(success_exit_status())),
    }
}

#[cfg(windows)]
fn log_child_exit(status: ExitStatus) -> ServiceExitCode {
    match status.code() {
        Some(0) => {
            tracing::info!("Windows service child exited normally");
            ServiceExitCode::Win32(0)
        }
        Some(code) => {
            let code = code as u32;
            tracing::error!(exit_code = code, "Windows service child exited with failure");
            ServiceExitCode::ServiceSpecific(code)
        }
        None => {
            tracing::error!("Windows service child exited without an OS exit code");
            ServiceExitCode::ServiceSpecific(1)
        }
    }
}

#[cfg(windows)]
fn success_exit_status() -> ExitStatus {
    #[cfg(windows)]
    {
        std::os::windows::process::ExitStatusExt::from_raw(0)
    }
}

#[cfg(windows)]
fn kill_child_force() {
    let mut guard = CHILD.lock().expect("child mutex poisoned");
    if let Some(mut child) = guard.take() {
        tracing::info!(pid = child.id(), "Killing Windows service child process");
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(windows)]
fn to_win_err(err: anyhow::Error) -> windows_service::Error {
    windows_service::Error::Winapi(std::io::Error::other(err.to_string()))
}

#[cfg(windows)]
pub fn setup_file_logging() -> anyhow::Result<()> {
    use std::fs::OpenOptions;
    use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

    let exe_path = std::env::current_exe()?;
    let exe_dir = exe_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine exe directory"))?;

    let log_path = exe_dir.join("dfsnode-service.log");
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("info"))
        .with(
            fmt::layer()
                .with_writer(log_file)
                .with_ansi(false)
                .with_target(true)
                .with_thread_ids(false)
                .with_file(false)
                .with_line_number(false),
        )
        .init();

    Ok(())
}

#[cfg(not(windows))]
pub fn install_service(_service_name: &str, _run_args: &RunArgs) -> anyhow::Result<()> {
    anyhow::bail!("Windows service is not supported on this platform")
}

#[cfg(not(windows))]
pub fn uninstall_service(_service_name: &str) -> anyhow::Result<()> {
    anyhow::bail!("Windows service is not supported on this platform")
}

#[cfg(not(windows))]
pub fn run_as_service(_service_name: String, _run_args: RunArgs) -> anyhow::Result<()> {
    anyhow::bail!("Windows service is not supported on this platform")
}

#[cfg(not(windows))]
pub fn setup_file_logging() -> anyhow::Result<()> {
    Ok(())
}
