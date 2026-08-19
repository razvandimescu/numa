use crate::config::{ConfigLoad, ServerConfig};
use serde::Deserialize;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

const DAEMON_TIMEOUT: Duration = Duration::from_millis(500);
const DEFAULTS_NOTE: &str = "file does not exist yet, defaults apply";

struct EffectiveConfigPath {
    path: String,
    from_daemon: bool,
    note: Option<String>,
}

impl EffectiveConfigPath {
    fn display(&self) -> String {
        match &self.note {
            Some(note) => format!("{} ({note})", self.path),
            None => self.path.clone(),
        }
    }
}

#[derive(Deserialize)]
struct StatsConfigPath {
    config_path: String,
    // Absent on daemons predating this field; assume the pre-existing behavior.
    #[serde(default = "default_true")]
    config_found: bool,
}

fn default_true() -> bool {
    true
}

pub fn print_config_path() -> Result<(), String> {
    let resolved = effective_config_path()?;
    println!("{}", resolved.path);
    if let Some(note) = &resolved.note {
        eprintln!("note: {note}");
    }
    Ok(())
}

pub fn edit_config() -> Result<(), String> {
    let resolved = effective_config_path()?;
    let path = Path::new(&resolved.path);
    ensure_writable(path)?;

    let (editor, args) = configured_editor();
    let status = Command::new(&editor)
        .args(&args)
        .arg(path)
        .status()
        .map_err(|error| format!("failed to start {editor}: {error}"))?;
    if !status.success() {
        return Err(format!("{editor} exited with status {status}"));
    }

    if resolved.from_daemon {
        eprintln!("note: restart numa to apply changes (numa service restart)");
    }
    Ok(())
}

pub(crate) fn service_config_path() -> Result<String, String> {
    effective_config_path().map(|resolved| resolved.display())
}

fn effective_config_path() -> Result<EffectiveConfigPath, String> {
    let local = crate::config::load_config(&crate::cli_config_path());
    resolve_effective_config_path(local, query_daemon_config_path)
}

fn resolve_effective_config_path<F>(
    local: crate::Result<ConfigLoad>,
    query_daemon: F,
) -> Result<EffectiveConfigPath, String>
where
    F: FnOnce(&ServerConfig) -> Result<StatsConfigPath, String>,
{
    let default_server = ServerConfig::default();
    let server = local
        .as_ref()
        .map(|loaded| &loaded.config.server)
        .unwrap_or(&default_server);

    match query_daemon(server) {
        Ok(stats) => Ok(EffectiveConfigPath {
            path: stats.config_path,
            from_daemon: true,
            note: (!stats.config_found).then(|| DEFAULTS_NOTE.to_string()),
        }),
        Err(probe_error) => {
            let loaded = local.map_err(|error| error.to_string())?;
            let mut note = format!("{probe_error}; resolved locally");
            if !loaded.found {
                note.push_str("; ");
                note.push_str(DEFAULTS_NOTE);
            }
            Ok(EffectiveConfigPath {
                path: loaded.path,
                from_daemon: false,
                note: Some(note),
            })
        }
    }
}

fn probe_addr(server: &ServerConfig) -> SocketAddr {
    let ip = match server.api_bind_addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        Ok(IpAddr::V6(ip)) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        Ok(ip) => ip,
        Err(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
    };
    SocketAddr::new(ip, server.api_port)
}

/// One plaintext GET against the daemon's API — a bare `TcpStream`, like the
/// liveness probe in system_dns.rs. `Connection: close` plus axum's sized
/// `Json` bodies make read-to-EOF safe, with the read timeout shrinking
/// toward a fixed deadline so a dribbling port squatter cannot hold us past
/// `DAEMON_TIMEOUT`.
fn query_daemon_config_path(server: &ServerConfig) -> Result<StatsConfigPath, String> {
    let addr = probe_addr(server);
    let deadline = Instant::now() + DAEMON_TIMEOUT;
    let mut stream = TcpStream::connect_timeout(&addr, DAEMON_TIMEOUT)
        .map_err(|_| format!("daemon not reachable at {addr}"))?;
    stream
        .set_write_timeout(Some(DAEMON_TIMEOUT))
        .and_then(|()| {
            let request =
                format!("GET /stats HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
            stream.write_all(request.as_bytes())
        })
        .map_err(|error| format!("daemon probe failed: {error}"))?;

    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || response.len() > 1 << 20 {
            return Err("daemon response timed out".to_string());
        }
        let _ = stream.set_read_timeout(Some(remaining));
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(error) => return Err(format!("daemon probe failed: {error}")),
        }
    }
    parse_stats_response(&response)
}

fn parse_stats_response(response: &[u8]) -> Result<StatsConfigPath, String> {
    let unexpected = || "unexpected daemon response".to_string();
    let text = std::str::from_utf8(response).map_err(|_| unexpected())?;
    let (head, body) = text.split_once("\r\n\r\n").ok_or_else(unexpected)?;
    let status = head.split_whitespace().nth(1).ok_or_else(unexpected)?;
    if status != "200" {
        return Err(format!("daemon returned HTTP {status}"));
    }
    let stats: StatsConfigPath = serde_json::from_str(body).map_err(|_| unexpected())?;
    if stats.config_path.is_empty() {
        return Err("daemon returned an empty config path".to_string());
    }
    Ok(stats)
}

fn ensure_writable(path: &Path) -> Result<(), String> {
    let probe = if path.exists() {
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map(|_| false)
    } else {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).map_err(|error| {
                if error.kind() == std::io::ErrorKind::PermissionDenied {
                    not_writable_message(path)
                } else {
                    format!("cannot create {}: {error}", parent.display())
                }
            })?;
        }
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map(|_| true)
    };
    match probe {
        Ok(created) => {
            if created {
                let _ = std::fs::remove_file(path);
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(not_writable_message(path))
        }
        Err(error) => Err(format!("cannot write {}: {error}", path.display())),
    }
}

fn not_writable_message(path: &Path) -> String {
    if cfg!(windows) {
        format!("{} is not writable", path.display())
    } else {
        format!("{} is not writable, re-run with sudo", path.display())
    }
}

fn configured_editor() -> (String, Vec<String>) {
    let value = ["VISUAL", "EDITOR"]
        .iter()
        .filter_map(|name| std::env::var(name).ok())
        .find(|value| !value.trim().is_empty())
        .unwrap_or_else(|| if cfg!(windows) { "notepad" } else { "vi" }.to_string());
    split_editor(&value)
}

fn split_editor(value: &str) -> (String, Vec<String>) {
    let mut parts = value.split_whitespace().map(str::to_string);
    let program = parts.next().unwrap_or_default();
    (program, parts.collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn local_config(path: &str, api_port: u16, found: bool) -> crate::Result<ConfigLoad> {
        let mut config = Config::default();
        config.server.api_port = api_port;
        Ok(ConfigLoad {
            config,
            path: path.to_string(),
            found,
        })
    }

    fn daemon_config(path: &str, found: bool) -> StatsConfigPath {
        StatsConfigPath {
            config_path: path.to_string(),
            config_found: found,
        }
    }

    #[test]
    fn daemon_path_takes_precedence() {
        let resolved =
            resolve_effective_config_path(local_config("/local/numa.toml", 6123, true), |server| {
                assert_eq!(server.api_port, 6123);
                Ok(daemon_config("/daemon/numa.toml", true))
            })
            .unwrap();

        assert_eq!(resolved.display(), "/daemon/numa.toml");
    }

    #[test]
    fn daemon_on_defaults_is_labeled() {
        let resolved =
            resolve_effective_config_path(local_config("/local/numa.toml", 5380, true), |_| {
                Ok(daemon_config("/daemon/numa.toml", false))
            })
            .unwrap();

        assert_eq!(
            resolved.display(),
            "/daemon/numa.toml (file does not exist yet, defaults apply)"
        );
    }

    #[test]
    fn local_fallback_is_labeled_with_probe_error() {
        let resolved =
            resolve_effective_config_path(local_config("/local/numa.toml", 5380, true), |_| {
                Err("daemon not reachable at 127.0.0.1:5380".to_string())
            })
            .unwrap();

        assert_eq!(
            resolved.display(),
            "/local/numa.toml (daemon not reachable at 127.0.0.1:5380; resolved locally)"
        );
    }

    #[test]
    fn local_fallback_without_file_is_labeled() {
        let resolved =
            resolve_effective_config_path(local_config("/local/numa.toml", 5380, false), |_| {
                Err("daemon not reachable at 127.0.0.1:5380".to_string())
            })
            .unwrap();

        assert_eq!(
            resolved.display(),
            "/local/numa.toml (daemon not reachable at 127.0.0.1:5380; resolved locally; \
             file does not exist yet, defaults apply)"
        );
    }

    #[test]
    fn probe_addr_targets_loopback_or_the_configured_bind_addr() {
        let mut server = ServerConfig {
            api_bind_addr: "0.0.0.0".to_string(),
            api_port: 6123,
            ..ServerConfig::default()
        };
        assert_eq!(probe_addr(&server).to_string(), "127.0.0.1:6123");
        server.api_bind_addr = "::".to_string();
        assert_eq!(probe_addr(&server).ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        server.api_bind_addr = "192.168.1.10".to_string();
        assert_eq!(probe_addr(&server).to_string(), "192.168.1.10:6123");
    }

    #[test]
    fn daemon_query_reads_config_path_from_stats() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let length = stream.read(&mut request).unwrap();
            assert!(request[..length].starts_with(b"GET /stats HTTP/1.1\r\n"));
            let body = br#"{"config_path":"/var/lib/numa/numa.toml","config_found":true}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });

        let config = ServerConfig {
            api_port: port,
            ..ServerConfig::default()
        };
        let stats = query_daemon_config_path(&config).unwrap();
        assert_eq!(stats.config_path, "/var/lib/numa/numa.toml");
        assert!(stats.config_found);
        server.join().unwrap();
    }

    #[test]
    fn missing_config_found_defaults_to_true() {
        let stats: StatsConfigPath =
            serde_json::from_str(r#"{"config_path":"/etc/numa.toml"}"#).unwrap();
        assert!(stats.config_found);
    }

    #[test]
    fn split_editor_handles_arguments() {
        assert_eq!(
            split_editor("code --wait"),
            ("code".to_string(), vec!["--wait".to_string()])
        );
        assert_eq!(split_editor("vi"), ("vi".to_string(), vec![]));
    }

    #[test]
    fn ensure_writable_accepts_missing_file_in_writable_dir() {
        let dir = std::env::temp_dir().join("numa-config-cli-test");
        let path = dir.join("nested").join("numa.toml");
        let _ = std::fs::remove_dir_all(&dir);
        ensure_writable(&path).unwrap();
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
