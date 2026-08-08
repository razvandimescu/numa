use crate::config::{ConfigLoad, ServerConfig};
use serde::Deserialize;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const DAEMON_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigPathSource {
    Daemon,
    Local,
}

#[derive(Debug, Eq, PartialEq)]
struct EffectiveConfigPath {
    path: String,
    source: ConfigPathSource,
}

impl EffectiveConfigPath {
    fn display(&self) -> String {
        match self.source {
            ConfigPathSource::Daemon => self.path.clone(),
            ConfigPathSource::Local => {
                format!("{} (daemon not running; resolved locally)", self.path)
            }
        }
    }
}

#[derive(Deserialize)]
struct StatsConfigPath {
    config_path: String,
}

pub fn print_config_path() -> Result<(), String> {
    let resolved = effective_config_path()?;
    println!("{}", resolved.display());
    Ok(())
}

pub fn edit_config() -> Result<(), String> {
    let resolved = effective_config_path()?;
    let path = Path::new(&resolved.path);
    if !config_is_writable(path)? {
        #[cfg(not(windows))]
        eprintln!(
            "warning: {} is not writable, re-run with sudo",
            path.display()
        );
        #[cfg(windows)]
        eprintln!("warning: {} is not writable", path.display());
        return Ok(());
    }

    let editor = configured_editor();
    let status = Command::new(&editor)
        .arg(path)
        .status()
        .map_err(|error| format!("failed to start {}: {error}", editor.to_string_lossy()))?;

    println!("{}", resolved.display());
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "{} exited with status {status}",
            editor.to_string_lossy()
        ))
    }
}

pub(crate) fn service_config_path() -> Result<String, String> {
    effective_config_path().map(|resolved| resolved.display())
}

fn effective_config_path() -> Result<EffectiveConfigPath, String> {
    let local = crate::config::load_config("numa.toml");
    resolve_effective_config_path(local, query_daemon_config_path)
}

fn resolve_effective_config_path<F>(
    local: crate::Result<ConfigLoad>,
    query_daemon: F,
) -> Result<EffectiveConfigPath, String>
where
    F: FnOnce(u16) -> Result<String, String>,
{
    let api_port = local
        .as_ref()
        .map(|loaded| loaded.config.server.api_port)
        .unwrap_or_else(|_| ServerConfig::default().api_port);

    if let Ok(path) = query_daemon(api_port) {
        return Ok(EffectiveConfigPath {
            path,
            source: ConfigPathSource::Daemon,
        });
    }

    let loaded = local.map_err(|error| error.to_string())?;
    Ok(EffectiveConfigPath {
        path: loaded.path,
        source: ConfigPathSource::Local,
    })
}

fn query_daemon_config_path(port: u16) -> Result<String, String> {
    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&address, DAEMON_TIMEOUT)
        .map_err(|error| format!("daemon connection failed: {error}"))?;
    stream
        .set_read_timeout(Some(DAEMON_TIMEOUT))
        .map_err(|error| format!("failed to set daemon read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(DAEMON_TIMEOUT))
        .map_err(|error| format!("failed to set daemon write timeout: {error}"))?;

    let request = format!(
        "GET /stats HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("failed to query daemon: {error}"))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| format!("failed to read daemon response: {error}"))?;
    let body = parse_http_response(&response)?;
    let stats: StatsConfigPath = serde_json::from_slice(&body)
        .map_err(|error| format!("invalid daemon response: {error}"))?;
    if stats.config_path.is_empty() {
        Err("daemon returned an empty config path".to_string())
    } else {
        Ok(stats.config_path)
    }
}

fn parse_http_response(response: &[u8]) -> Result<Vec<u8>, String> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "invalid daemon HTTP response".to_string())?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|error| format!("invalid daemon HTTP headers: {error}"))?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| "missing daemon HTTP status".to_string())?;
    if status != "200" {
        return Err(format!("daemon returned HTTP {status}"));
    }

    let body = &response[header_end + 4..];
    if headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.trim().eq_ignore_ascii_case("chunked")
        })
    }) {
        decode_chunked_body(body)
    } else {
        Ok(body.to_vec())
    }
}

fn decode_chunked_body(body: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoded = Vec::new();
    let mut remaining = body;
    loop {
        let line_end = remaining
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| "invalid chunked daemon response".to_string())?;
        let size_text = std::str::from_utf8(&remaining[..line_end])
            .map_err(|error| format!("invalid chunk size: {error}"))?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or_default(), 16)
            .map_err(|error| format!("invalid chunk size: {error}"))?;
        remaining = &remaining[line_end + 2..];
        if size == 0 {
            return Ok(decoded);
        }
        if remaining.len() < size + 2 || &remaining[size..size + 2] != b"\r\n" {
            return Err("truncated chunked daemon response".to_string());
        }
        decoded.extend_from_slice(&remaining[..size]);
        remaining = &remaining[size + 2..];
    }
}

fn config_is_writable(path: &Path) -> Result<bool, String> {
    if !path.exists() {
        return Ok(true);
    }
    match std::fs::OpenOptions::new().write(true).open(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(false),
        Err(error) => Err(format!(
            "failed to check whether {} is writable: {error}",
            path.display()
        )),
    }
}

fn configured_editor() -> OsString {
    std::env::var_os("EDITOR")
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var_os("VISUAL").filter(|value| !value.is_empty()))
        .unwrap_or_else(|| {
            if cfg!(windows) {
                OsString::from("notepad")
            } else {
                OsString::from("vi")
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::net::TcpListener;
    use std::thread;

    fn local_config(path: &str, api_port: u16) -> crate::Result<ConfigLoad> {
        let mut config = Config::default();
        config.server.api_port = api_port;
        Ok(ConfigLoad {
            config,
            path: path.to_string(),
            found: true,
        })
    }

    #[test]
    fn daemon_path_takes_precedence() {
        let resolved =
            resolve_effective_config_path(local_config("/local/numa.toml", 6123), |port| {
                assert_eq!(port, 6123);
                Ok("/daemon/numa.toml".to_string())
            })
            .unwrap();

        assert_eq!(resolved.display(), "/daemon/numa.toml");
    }

    #[test]
    fn local_fallback_is_labeled() {
        let resolved =
            resolve_effective_config_path(local_config("/local/numa.toml", 5380), |_| {
                Err("not running".to_string())
            })
            .unwrap();

        assert_eq!(
            resolved.display(),
            "/local/numa.toml (daemon not running; resolved locally)"
        );
    }

    #[test]
    fn daemon_query_reads_config_path_from_stats() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 512];
            let length = stream.read(&mut request).unwrap();
            assert!(request[..length].starts_with(b"GET /stats HTTP/1.1\r\n"));
            let body = br#"{"config_path":"/var/lib/numa/numa.toml"}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });

        assert_eq!(
            query_daemon_config_path(port).unwrap(),
            "/var/lib/numa/numa.toml"
        );
        server.join().unwrap();
    }

    #[test]
    fn chunked_stats_response_is_supported() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nf\r\n{\"config_path\":\r\n11\r\n\"/tmp/numa.toml\"}\r\n0\r\n\r\n";
        let body = parse_http_response(response).unwrap();
        let stats: StatsConfigPath = serde_json::from_slice(&body).unwrap();
        assert_eq!(stats.config_path, "/tmp/numa.toml");
    }
}
