pub mod api;
pub mod blocklist;
pub mod buffer;
pub mod cache;
pub mod config;
pub mod ctx;
pub mod dnssec;
pub mod doh;
pub mod dot;
pub mod forward;
pub mod header;
pub mod health;
pub mod lan;
pub mod mobile_api;
pub mod mobileconfig;
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

/// Detect the machine hostname via the `hostname` command. Returns the
/// full hostname (e.g., `macbook-pro.local`), or `"numa"` if the command
/// fails. Call sites that need the short form (e.g., mDNS instance
/// names) should truncate at the first `.`.
pub fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "numa".to_string())
}

/// Path to suggest to an interactive user when asking them to create
/// `numa.toml`. Prefers `$HOME/.config/numa/numa.toml` when HOME is set
/// (actionable without sudo); falls back to `config_dir()` otherwise.
///
/// Note: `config_dir()` routes interactive root to FHS (`/var/lib/numa`)
/// so that runtime state like `services.json` stays continuous with the
/// installed daemon. This helper exists specifically to give advisories
/// and `load_config` an XDG-aware path for user-authored config, without
/// moving runtime state out of FHS — see issue #81.
pub(crate) fn suggested_config_path() -> std::path::PathBuf {
    #[cfg(not(windows))]
    {
        resolve_suggested_config_path(std::env::var("HOME").ok().as_deref(), config_dir)
    }
    #[cfg(windows)]
    {
        config_dir().join("numa.toml")
    }
}

#[cfg(not(windows))]
fn resolve_suggested_config_path<F>(home: Option<&str>, fallback_dir: F) -> std::path::PathBuf
where
    F: FnOnce() -> std::path::PathBuf,
{
    if let Some(home) = home {
        if !home.is_empty() && home != "/" {
            return std::path::PathBuf::from(home)
                .join(".config")
                .join("numa")
                .join("numa.toml");
        }
    }
    fallback_dir().join("numa.toml")
}

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

    #[cfg(not(windows))]
    fn fhs() -> std::path::PathBuf {
        std::path::PathBuf::from("/var/lib/numa")
    }

    #[cfg(not(windows))]
    #[test]
    fn suggested_config_path_prefers_home() {
        assert_eq!(
            resolve_suggested_config_path(Some("/home/alice"), fhs),
            std::path::PathBuf::from("/home/alice/.config/numa/numa.toml"),
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn suggested_config_path_prefers_root_home_over_fhs() {
        // Interactive root: HOME=/root is a real user context, not a daemon signal.
        // Advisory must point where load_config will actually look — issue #81.
        assert_eq!(
            resolve_suggested_config_path(Some("/root"), fhs),
            std::path::PathBuf::from("/root/.config/numa/numa.toml"),
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn suggested_config_path_falls_back_when_home_unset() {
        assert_eq!(
            resolve_suggested_config_path(None, fhs),
            std::path::PathBuf::from("/var/lib/numa/numa.toml"),
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn suggested_config_path_falls_back_when_home_is_root() {
        // systemd services sometimes have HOME=/ — don't treat that as a real home.
        assert_eq!(
            resolve_suggested_config_path(Some("/"), fhs),
            std::path::PathBuf::from("/var/lib/numa/numa.toml"),
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn suggested_config_path_falls_back_when_home_is_empty() {
        assert_eq!(
            resolve_suggested_config_path(Some(""), fhs),
            std::path::PathBuf::from("/var/lib/numa/numa.toml"),
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn suggested_config_path_skips_fallback_when_home_valid() {
        // Happy path shouldn't probe the filesystem via config_dir().
        let called = std::cell::Cell::new(false);
        let fallback = || {
            called.set(true);
            std::path::PathBuf::from("/should/not/be/used")
        };
        let _ = resolve_suggested_config_path(Some("/home/alice"), fallback);
        assert!(
            !called.get(),
            "fallback must not be invoked when HOME is valid"
        );
    }
}
