//! Termination signals. As PID 1 (containers) the kernel drops signals whose
//! disposition is still the default, so an explicit handler is what makes
//! `docker stop` and Ctrl-C work at all (issue #367).

/// Resolves on SIGINT or SIGTERM (Ctrl-C only on Windows).
pub async fn signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal as unix_signal, SignalKind};
        let mut term = match unix_signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("cannot listen for SIGTERM: {}", e);
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
