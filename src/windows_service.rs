//! Windows service wrapper.
//!
//! Lets the `numa.exe` binary act as a real Windows service registered with
//! the Service Control Manager (SCM). Invoked via `numa.exe --service` (the
//! form that `sc create … binPath=` uses).
//!
//! Interactive runs (`numa.exe`, `numa.exe run`, `numa.exe install`) do not
//! go through this module — they keep their existing console-attached
//! behaviour.

use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "Numa";

define_windows_service!(ffi_service_main, service_main);

/// Entry point the SCM hands control to after `StartServiceCtrlDispatcherW`.
/// Any panic here vanishes silently into the service host — log instead of
/// unwrapping.
fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        log::error!("numa service exited with error: {:?}", e);
    }
}

fn run_service() -> windows_service::Result<()> {
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    // Spin up a multi-threaded tokio runtime and run the server on it. A
    // dedicated thread runs the runtime so this function can return cleanly
    // once the SCM tells us to stop — we can't block the dispatcher thread
    // forever without preventing graceful shutdown.
    let config_path = service_config_path();
    let (server_done_tx, server_done_rx) = mpsc::channel::<()>();

    let server_thread = std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                log::error!("failed to build tokio runtime: {}", e);
                let _ = server_done_tx.send(());
                return;
            }
        };

        if let Err(e) = runtime.block_on(crate::serve::run(config_path)) {
            log::error!("numa serve exited with error: {}", e);
        }
        let _ = server_done_tx.send(());
    });

    // Wait for either SCM stop or server termination.
    loop {
        if shutdown_rx.recv_timeout(Duration::from_millis(500)).is_ok() {
            break;
        }
        if server_done_rx.try_recv().is_ok() {
            break;
        }
    }

    // The server's tokio runtime runs detached inside server_thread. Abandon
    // it — the process is about to report Stopped and the SCM will terminate
    // us if we linger. Future work: plumb a cancellation signal into
    // serve::run() for a clean teardown of listeners and in-flight queries.
    drop(server_thread);

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

/// Hand control to the SCM dispatcher. Blocks until the service stops.
/// Call only from the `--service` command path — interactive invocations
/// will hang here waiting for an SCM that isn't talking to them.
pub fn run_as_service() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

/// Path to the config file used when running under SCM. SCM launches the
/// service with SYSTEM's working directory (usually `C:\Windows\System32`),
/// so a relative `numa.toml` lookup won't find anything meaningful.
fn service_config_path() -> String {
    crate::data_dir()
        .join("numa.toml")
        .to_string_lossy()
        .into_owned()
}
