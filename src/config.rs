use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::path::Path;

use serde::Deserialize;

use crate::question::QueryType;
use crate::record::DnsRecord;
use crate::Result;

#[derive(Deserialize)]
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
}

#[derive(Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_api_port")]
    pub api_port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            bind_addr: default_bind_addr(),
            api_port: default_api_port(),
        }
    }
}

fn default_bind_addr() -> String {
    "0.0.0.0:53".to_string()
}

fn default_api_port() -> u16 {
    5380
}

#[derive(Deserialize)]
pub struct UpstreamConfig {
    #[serde(default = "default_upstream_addr")]
    pub address: String,
    #[serde(default = "default_upstream_port")]
    pub port: u16,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        UpstreamConfig {
            address: default_upstream_addr(),
            port: default_upstream_port(),
            timeout_ms: default_timeout_ms(),
        }
    }
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

pub fn load_config(path: &str) -> Result<Config> {
    if !Path::new(path).exists() {
        return Ok(Config {
            server: ServerConfig::default(),
            upstream: UpstreamConfig::default(),
            cache: CacheConfig::default(),
            blocking: BlockingConfig::default(),
            zones: Vec::new(),
        });
    }
    let contents = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&contents)?;
    Ok(config)
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
