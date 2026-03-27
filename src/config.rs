use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::path::Path;

use serde::Deserialize;

use crate::question::QueryType;
use crate::record::DnsRecord;
use crate::Result;

#[derive(Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub upstream: UpstreamConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub blocking: BlockingConfig,
    #[serde(default)]
    pub zones: Vec<ZoneRecord>,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub services: Vec<ServiceConfig>,
    #[serde(default)]
    pub lan: LanConfig,
    #[serde(default)]
    pub dnssec: DnssecConfig,
}

#[derive(Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_api_port")]
    pub api_port: u16,
    #[serde(default = "default_api_bind_addr")]
    pub api_bind_addr: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            bind_addr: default_bind_addr(),
            api_port: default_api_port(),
            api_bind_addr: default_api_bind_addr(),
        }
    }
}

fn default_api_bind_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_bind_addr() -> String {
    "0.0.0.0:53".to_string()
}

fn default_api_port() -> u16 {
    5380
}

#[derive(Deserialize, Default, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamMode {
    #[default]
    Forward,
    Recursive,
}

#[derive(Deserialize)]
pub struct UpstreamConfig {
    #[serde(default)]
    pub mode: UpstreamMode,
    #[serde(default = "default_upstream_addr")]
    pub address: String,
    #[serde(default = "default_upstream_port")]
    pub port: u16,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_root_hints")]
    pub root_hints: Vec<String>,
    #[serde(default = "default_prime_tlds")]
    pub prime_tlds: Vec<String>,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        UpstreamConfig {
            mode: UpstreamMode::default(),
            address: default_upstream_addr(),
            port: default_upstream_port(),
            timeout_ms: default_timeout_ms(),
            root_hints: default_root_hints(),
            prime_tlds: default_prime_tlds(),
        }
    }
}

fn default_prime_tlds() -> Vec<String> {
    vec![
        // gTLDs
        "com".into(),
        "net".into(),
        "org".into(),
        "info".into(),
        "io".into(),
        "dev".into(),
        "app".into(),
        "xyz".into(),
        "me".into(),
        // EU + European ccTLDs
        "eu".into(),
        "uk".into(),
        "de".into(),
        "fr".into(),
        "nl".into(),
        "it".into(),
        "es".into(),
        "pl".into(),
        "se".into(),
        "no".into(),
        "dk".into(),
        "fi".into(),
        "at".into(),
        "be".into(),
        "ie".into(),
        "pt".into(),
        "cz".into(),
        "ro".into(),
        "gr".into(),
        "hu".into(),
        "bg".into(),
        "hr".into(),
        "sk".into(),
        "si".into(),
        "lt".into(),
        "lv".into(),
        "ee".into(),
        "ch".into(),
        "is".into(),
        // Other major ccTLDs
        "co".into(),
        "br".into(),
        "au".into(),
        "ca".into(),
        "jp".into(),
    ]
}

fn default_root_hints() -> Vec<String> {
    vec![
        "198.41.0.4".into(),     // a.root-servers.net
        "199.9.14.201".into(),   // b.root-servers.net
        "192.33.4.12".into(),    // c.root-servers.net
        "199.7.91.13".into(),    // d.root-servers.net
        "192.203.230.10".into(), // e.root-servers.net
        "192.5.5.241".into(),    // f.root-servers.net
        "192.112.36.4".into(),   // g.root-servers.net
        "198.97.190.53".into(),  // h.root-servers.net
        "192.36.148.17".into(),  // i.root-servers.net
        "192.58.128.30".into(),  // j.root-servers.net
        "193.0.14.129".into(),   // k.root-servers.net
        "199.7.83.42".into(),    // l.root-servers.net
        "202.12.27.33".into(),   // m.root-servers.net
    ]
}

fn default_upstream_addr() -> String {
    String::new() // empty = auto-detect from system resolver
}
fn default_upstream_port() -> u16 {
    53
}
fn default_timeout_ms() -> u64 {
    3000
}

#[derive(Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
    #[serde(default = "default_min_ttl")]
    pub min_ttl: u32,
    #[serde(default = "default_max_ttl")]
    pub max_ttl: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            max_entries: default_max_entries(),
            min_ttl: default_min_ttl(),
            max_ttl: default_max_ttl(),
        }
    }
}

fn default_max_entries() -> usize {
    10000
}
fn default_min_ttl() -> u32 {
    60
}
fn default_max_ttl() -> u32 {
    86400
}

#[derive(Deserialize)]
pub struct ZoneRecord {
    pub domain: String,
    pub record_type: String,
    pub value: String,
    #[serde(default = "default_zone_ttl")]
    pub ttl: u32,
}

#[derive(Deserialize)]
pub struct BlockingConfig {
    #[serde(default = "default_blocking_enabled")]
    pub enabled: bool,
    #[serde(default = "default_blocklists")]
    pub lists: Vec<String>,
    #[serde(default = "default_refresh_hours")]
    pub refresh_hours: u64,
    #[serde(default)]
    pub allowlist: Vec<String>,
}

impl Default for BlockingConfig {
    fn default() -> Self {
        BlockingConfig {
            enabled: default_blocking_enabled(),
            lists: default_blocklists(),
            refresh_hours: default_refresh_hours(),
            allowlist: Vec::new(),
        }
    }
}

fn default_blocking_enabled() -> bool {
    true
}

fn default_blocklists() -> Vec<String> {
    vec!["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/pro.txt".to_string()]
}

fn default_refresh_hours() -> u64 {
    24
}

fn default_zone_ttl() -> u32 {
    300
}

#[derive(Deserialize, Clone)]
pub struct ProxyConfig {
    #[serde(default = "default_proxy_enabled")]
    pub enabled: bool,
    #[serde(default = "default_proxy_port")]
    pub port: u16,
    #[serde(default = "default_proxy_tls_port")]
    pub tls_port: u16,
    #[serde(default = "default_proxy_tld")]
    pub tld: String,
    #[serde(default = "default_proxy_bind_addr")]
    pub bind_addr: String,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            enabled: default_proxy_enabled(),
            port: default_proxy_port(),
            tls_port: default_proxy_tls_port(),
            tld: default_proxy_tld(),
            bind_addr: default_proxy_bind_addr(),
        }
    }
}

fn default_proxy_bind_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_proxy_enabled() -> bool {
    true
}
fn default_proxy_port() -> u16 {
    80
}
fn default_proxy_tls_port() -> u16 {
    443
}
fn default_proxy_tld() -> String {
    "numa".to_string()
}

#[derive(Deserialize, Clone)]
pub struct ServiceConfig {
    pub name: String,
    pub target_port: u16,
    #[serde(default)]
    pub routes: Vec<crate::service_store::RouteEntry>,
}

#[derive(Deserialize, Clone)]
pub struct LanConfig {
    #[serde(default = "default_lan_enabled")]
    pub enabled: bool,
    #[serde(default = "default_lan_broadcast_interval")]
    pub broadcast_interval_secs: u64,
    #[serde(default = "default_lan_peer_timeout")]
    pub peer_timeout_secs: u64,
}

impl Default for LanConfig {
    fn default() -> Self {
        LanConfig {
            enabled: default_lan_enabled(),
            broadcast_interval_secs: default_lan_broadcast_interval(),
            peer_timeout_secs: default_lan_peer_timeout(),
        }
    }
}

fn default_lan_enabled() -> bool {
    false
}
fn default_lan_broadcast_interval() -> u64 {
    30
}
fn default_lan_peer_timeout() -> u64 {
    90
}

#[derive(Deserialize, Clone, Default)]
pub struct DnssecConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub strict: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_disabled_by_default() {
        assert!(!LanConfig::default().enabled);
    }

    #[test]
    fn api_binds_localhost_by_default() {
        assert_eq!(ServerConfig::default().api_bind_addr, "127.0.0.1");
    }

    #[test]
    fn proxy_binds_localhost_by_default() {
        assert_eq!(ProxyConfig::default().bind_addr, "127.0.0.1");
    }

    #[test]
    fn empty_toml_gives_defaults() {
        let config: Config = toml::from_str("").unwrap();
        assert!(!config.lan.enabled);
        assert_eq!(config.server.api_bind_addr, "127.0.0.1");
        assert_eq!(config.proxy.bind_addr, "127.0.0.1");
        assert_eq!(config.server.api_port, ServerConfig::default().api_port);
    }

    #[test]
    fn lan_enabled_parses() {
        let config: Config = toml::from_str("[lan]\nenabled = true").unwrap();
        assert!(config.lan.enabled);
    }

    #[test]
    fn custom_bind_addrs_parse() {
        let toml = r#"
            [server]
            api_bind_addr = "0.0.0.0"
            [proxy]
            bind_addr = "0.0.0.0"
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.server.api_bind_addr, "0.0.0.0");
        assert_eq!(config.proxy.bind_addr, "0.0.0.0");
    }

    #[test]
    fn service_routes_parse_from_toml() {
        let toml = r#"
            [[services]]
            name = "app"
            target_port = 3000
            routes = [
                { path = "/api", port = 4000, strip = true },
                { path = "/static", port = 5000 },
            ]
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.services.len(), 1);
        assert_eq!(config.services[0].routes.len(), 2);
        assert!(config.services[0].routes[0].strip);
        assert!(!config.services[0].routes[1].strip); // default false
    }
}

pub struct ConfigLoad {
    pub config: Config,
    pub path: String,
    pub found: bool,
}

fn resolve_path(path: &str) -> String {
    // canonicalize gives the real absolute path for existing files;
    // for non-existent files, build an absolute path manually
    std::fs::canonicalize(path)
        .or_else(|_| std::env::current_dir().map(|cwd| cwd.join(path)))
        .unwrap_or_else(|_| Path::new(path).to_path_buf())
        .to_string_lossy()
        .to_string()
}

pub fn load_config(path: &str) -> Result<ConfigLoad> {
    // Try the given path first, then well-known locations (for service mode where cwd is /)
    let candidates: Vec<std::path::PathBuf> = {
        let p = Path::new(path);
        let mut v = vec![p.to_path_buf()];
        if p.is_relative() {
            let filename = p.file_name().unwrap_or(p.as_os_str());
            v.push(crate::config_dir().join(filename));
            v.push(crate::data_dir().join(filename));
        }
        v
    };

    for candidate in &candidates {
        match std::fs::read_to_string(candidate) {
            Ok(contents) => {
                let resolved = resolve_path(&candidate.to_string_lossy());
                let config: Config = toml::from_str(&contents)?;
                return Ok(ConfigLoad {
                    config,
                    path: resolved,
                    found: true,
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        }
    }

    // Show config_dir candidate as the "expected" path — it's actionable
    let display_path = candidates
        .get(1)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| resolve_path(path));
    log::info!("config not found, using defaults (create {})", display_path);
    Ok(ConfigLoad {
        config: Config::default(),
        path: display_path,
        found: false,
    })
}

pub type ZoneMap = HashMap<String, HashMap<QueryType, Vec<DnsRecord>>>;

pub fn build_zone_map(zones: &[ZoneRecord]) -> Result<ZoneMap> {
    let mut map: ZoneMap = HashMap::new();

    for zone in zones {
        let domain = zone.domain.to_lowercase();
        let (qtype, record) = match zone.record_type.to_uppercase().as_str() {
            "A" => {
                let addr: Ipv4Addr = zone
                    .value
                    .parse()
                    .map_err(|e| format!("invalid A record value '{}': {}", zone.value, e))?;
                (
                    QueryType::A,
                    DnsRecord::A {
                        domain: domain.clone(),
                        addr,
                        ttl: zone.ttl,
                    },
                )
            }
            "AAAA" => {
                let addr: Ipv6Addr = zone
                    .value
                    .parse()
                    .map_err(|e| format!("invalid AAAA record value '{}': {}", zone.value, e))?;
                (
                    QueryType::AAAA,
                    DnsRecord::AAAA {
                        domain: domain.clone(),
                        addr,
                        ttl: zone.ttl,
                    },
                )
            }
            "CNAME" => (
                QueryType::CNAME,
                DnsRecord::CNAME {
                    domain: domain.clone(),
                    host: zone.value.clone(),
                    ttl: zone.ttl,
                },
            ),
            "NS" => (
                QueryType::NS,
                DnsRecord::NS {
                    domain: domain.clone(),
                    host: zone.value.clone(),
                    ttl: zone.ttl,
                },
            ),
            "MX" => {
                let parts: Vec<&str> = zone.value.splitn(2, ' ').collect();
                if parts.len() != 2 {
                    return Err(
                        format!("MX value must be 'priority host', got '{}'", zone.value).into(),
                    );
                }
                let priority: u16 = parts[0]
                    .parse()
                    .map_err(|e| format!("invalid MX priority '{}': {}", parts[0], e))?;
                (
                    QueryType::MX,
                    DnsRecord::MX {
                        domain: domain.clone(),
                        priority,
                        host: parts[1].to_string(),
                        ttl: zone.ttl,
                    },
                )
            }
            other => {
                return Err(format!("unsupported record type '{}'", other).into());
            }
        };

        map.entry(domain)
            .or_default()
            .entry(qtype)
            .or_default()
            .push(record);
    }

    Ok(map)
}
