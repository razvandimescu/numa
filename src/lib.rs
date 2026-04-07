pub mod api;
pub mod blocklist;
pub mod buffer;
pub mod cache;
pub mod config;
pub mod ctx;
pub mod dnssec;
pub mod dot;
pub mod forward;
pub mod header;
pub mod lan;
pub mod override_store;
pub mod packet;
pub mod proxy;
pub mod query_log;
pub mod question;
pub mod record;
pub mod recursive;
pub mod service_store;
pub mod srtt;
pub mod stats;
pub mod system_dns;
pub mod tls;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

/// Shared config directory for persistent data (services.json, etc).
/// Unix: ~/.config/numa/ (or /usr/local/var/numa/ when running as root daemon)
/// Windows: %APPDATA%\numa
pub fn config_dir() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        std::path::PathBuf::from(
            std::env::var("APPDATA").unwrap_or_else(|_| "C:\\ProgramData".into()),
        )
        .join("numa")
    }
    #[cfg(not(windows))]
    {
        config_dir_unix()
    }
}

#[cfg(not(windows))]
fn config_dir_unix() -> std::path::PathBuf {
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
        if !home.starts_with("/var/root") && !home.starts_with("/root") {
            return path.join(".config").join("numa");
        }
    }

    // Running as root daemon (launchd/systemd) — use system-wide path
    std::path::PathBuf::from("/usr/local/var/numa")
}

/// Default system-wide data directory for TLS certs. Overridable via
/// `[server] data_dir = "..."` in numa.toml — this function only provides
/// the fallback when the config doesn't set it.
/// Unix: /usr/local/var/numa
/// Windows: %PROGRAMDATA%\numa
pub fn data_dir() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        std::path::PathBuf::from(
            std::env::var("PROGRAMDATA").unwrap_or_else(|_| "C:\\ProgramData".into()),
        )
        .join("numa")
    }
    #[cfg(not(windows))]
    {
        std::path::PathBuf::from("/usr/local/var/numa")
    }
}
