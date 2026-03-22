pub mod api;
pub mod blocklist;
pub mod buffer;
pub mod cache;
pub mod config;
pub mod ctx;
pub mod forward;
pub mod header;
pub mod lan;
pub mod override_store;
pub mod packet;
pub mod proxy;
pub mod query_log;
pub mod question;
pub mod record;
pub mod service_store;
pub mod stats;
pub mod system_dns;
pub mod tls;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

/// Shared config directory: ~/.config/numa/
/// Handles sudo (uses SUDO_USER) and launchd (falls back to /usr/local/var/numa/).
pub fn config_dir() -> std::path::PathBuf {
    // When run via sudo, SUDO_USER has the real user
    if let Ok(user) = std::env::var("SUDO_USER") {
        let home = if cfg!(target_os = "macos") {
            format!("/Users/{}", user)
        } else {
            format!("/home/{}", user)
        };
        return std::path::PathBuf::from(home).join(".config").join("numa");
    }

    // Normal user (not root)
    if let Ok(home) = std::env::var("HOME") {
        let path = std::path::PathBuf::from(&home);
        // /var/root on macOS is read-only (SIP), use /usr/local/var/numa instead
        if !home.starts_with("/var/root") && !home.starts_with("/root") {
            return path.join(".config").join("numa");
        }
    }

    // Running as root daemon (launchd/systemd) — use system-wide path
    std::path::PathBuf::from("/usr/local/var/numa")
}
