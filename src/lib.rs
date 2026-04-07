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
pub mod setup_phone;
pub mod srtt;
pub mod stats;
pub mod system_dns;
pub mod tls;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

/// Shared config directory for persistent data (services.json, etc).
/// Unix users: ~/.config/numa/
/// Linux root daemon: /var/lib/numa (FHS) — falls back to /usr/local/var/numa
///                    if a pre-v0.10.1 install already lives there.
/// macOS root daemon: /usr/local/var/numa (Homebrew prefix)
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
    daemon_data_dir()
}

/// Default system-wide data directory for TLS certs. Overridable via
/// `[server] data_dir = "..."` in numa.toml — this function only provides
/// the fallback when the config doesn't set it.
/// Linux: /var/lib/numa (FHS) — falls back to /usr/local/var/numa if a
///        pre-v0.10.1 install already has data there.
/// macOS: /usr/local/var/numa (Homebrew prefix)
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
        daemon_data_dir()
    }
}

/// Resolve the system-wide data directory for the running platform.
/// Honors backwards compatibility with pre-v0.10.1 installs that still
/// have their CA cert + services.json under `/usr/local/var/numa`.
#[cfg(not(windows))]
fn daemon_data_dir() -> std::path::PathBuf {
    #[cfg(target_os = "linux")]
    {
        std::path::PathBuf::from(resolve_linux_data_dir(
            std::path::Path::new("/usr/local/var/numa").exists(),
            std::path::Path::new("/var/lib/numa").exists(),
        ))
    }
    #[cfg(target_os = "macos")]
    {
        // macOS uses the Homebrew prefix convention; no FHS migration needed.
        std::path::PathBuf::from("/usr/local/var/numa")
    }
}

/// Extracted as a pure function so the migration logic is unit-testable
/// without touching the real filesystem.
#[cfg(any(target_os = "linux", test))]
fn resolve_linux_data_dir(legacy_exists: bool, fhs_exists: bool) -> &'static str {
    if legacy_exists && !fhs_exists {
        "/usr/local/var/numa"
    } else {
        "/var/lib/numa"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_data_dir_fresh_install_uses_fhs() {
        assert_eq!(resolve_linux_data_dir(false, false), "/var/lib/numa");
    }

    #[test]
    fn linux_data_dir_upgrading_install_keeps_legacy() {
        // Migration must keep legacy so the user doesn't lose their CA on upgrade.
        assert_eq!(resolve_linux_data_dir(true, false), "/usr/local/var/numa");
    }

    #[test]
    fn linux_data_dir_after_migration_uses_fhs() {
        assert_eq!(resolve_linux_data_dir(true, true), "/var/lib/numa");
    }

    #[test]
    fn linux_data_dir_only_fhs_uses_fhs() {
        assert_eq!(resolve_linux_data_dir(false, true), "/var/lib/numa");
    }
}
