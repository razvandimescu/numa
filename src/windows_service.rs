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
        exit_code: ServiceExitCode::NO_ERROR,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    // Spin up a multi-threaded tokio runtime and run the server on it. A
    // dedicated thread runs the runtime so this function can return cleanly
    // once the SCM tells us to stop — we can't block the dispatcher thread
    // forever without preventing graceful shutdown.
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

        let served = crate::config::load_config(&crate::cli_config_path())
            .and_then(|load| runtime.block_on(crate::serve::run(load)));
        if let Err(e) = served {
            log::error!("numa serve exited with error: {}", e);
        }
        let _ = server_done_tx.send(());
    });

    // A server that stops without an SCM request has failed. Report it with a
    // non-zero exit code, or the SCM takes it as a clean stop and never runs
    // the restart policy. A panic on the server thread drops the sender without
    // a message, so anything but Empty means the server stopped.
    let exit_code = loop {
        if shutdown_rx.recv_timeout(Duration::from_millis(500)).is_ok() {
            break ServiceExitCode::NO_ERROR;
        }
        if !matches!(server_done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)) {
            break ServiceExitCode::ServiceSpecific(1);
        }
    };

    // The server's tokio runtime runs detached inside server_thread. Abandon
    // it — the process is about to report Stopped and the SCM will terminate
    // us if we linger. Future work: plumb a cancellation signal into
    // serve::run() for a clean teardown of listeners and in-flight queries.
    drop(server_thread);

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code,
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
