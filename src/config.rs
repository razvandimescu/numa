use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

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
    #[serde(default)]
    pub dot: DotConfig,
    #[serde(default)]
    pub mobile: MobileConfig,
    #[serde(default)]
    pub forwarding: Vec<ForwardingRuleConfig>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct ForwardingRuleConfig {
    #[serde(deserialize_with = "string_or_vec")]
    pub suffix: Vec<String>,
    #[serde(deserialize_with = "string_or_vec")]
    pub upstream: Vec<String>,
}

impl ForwardingRuleConfig {
    fn to_runtime_rules(&self) -> Result<Vec<crate::system_dns::ForwardingRule>> {
        if self.upstream.is_empty() {
            return Err(format!(
                "forwarding rule for suffix {:?}: upstream must not be empty",
                self.suffix
            )
            .into());
        }
        let mut primary = Vec::with_capacity(self.upstream.len());
        for s in &self.upstream {
            let u = crate::forward::parse_upstream(s, 53, None)
                .map_err(|e| format!("forwarding rule for upstream '{}': {}", s, e))?;
            primary.push(u);
        }
        let pool = crate::forward::UpstreamPool::new(primary, vec![]);
        Ok(self
            .suffix
            .iter()
            .map(|s| crate::system_dns::ForwardingRule::new(s.clone(), pool.clone()))
            .collect())
    }
}

pub fn merge_forwarding_rules(
    config_rules: &[ForwardingRuleConfig],
    discovered: Vec<crate::system_dns::ForwardingRule>,
) -> Result<Vec<crate::system_dns::ForwardingRule>> {
    let mut merged: Vec<crate::system_dns::ForwardingRule> = Vec::new();
    for rule in config_rules {
        merged.extend(rule.to_runtime_rules()?);
    }
    merged.extend(discovered);
    Ok(merged)
}

#[derive(Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_api_port")]
    pub api_port: u16,
    #[serde(default = "default_api_bind_addr")]
    pub api_bind_addr: String,
    /// Where numa writes TLS material (CA, leaf certs, regenerated state).
    /// Defaults to `crate::data_dir()` (platform-specific system path) if unset.
    #[serde(default)]
    pub data_dir: Option<PathBuf>,
    /// Synthesize NODATA (NOERROR + empty answer) for AAAA queries, and
    /// strip `ipv6hint` from HTTPS/SVCB responses (RFC 9460). For IPv4-only
    /// networks where Happy Eyeballs fallback adds latency. Local zones,
    /// overrides, and the service proxy are not affected. Default false.
    #[serde(default)]
    pub filter_aaaa: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            bind_addr: default_bind_addr(),
            api_port: default_api_port(),
            api_bind_addr: default_api_bind_addr(),
            data_dir: None,
            filter_aaaa: false,
        }
    }
}

fn default_api_bind_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_bind_addr() -> String {
    "0.0.0.0:53".to_string()
}

pub const DEFAULT_API_PORT: u16 = 5380;

fn default_api_port() -> u16 {
    DEFAULT_API_PORT
}

#[derive(Deserialize, Default, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamMode {
    Auto,
    #[default]
    Forward,
    Recursive,
    Odoh,
}

impl UpstreamMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            UpstreamMode::Auto => "auto",
            UpstreamMode::Forward => "forward",
            UpstreamMode::Recursive => "recursive",
            UpstreamMode::Odoh => "odoh",
        }
    }

    /// Hedging duplicates the in-flight query against the same upstream to
    /// rescue tail latency. Beneficial for UDP/DoH/DoT (cheap retransmit /
    /// h2 stream multiplexing). For ODoH it doubles the relay's HPKE
    /// seal/unseal load and the sealed-byte footprint a passive observer
    /// can correlate, with no latency win — the relay hop dominates either
    /// way. Force-zero in oblivious mode regardless of `hedge_ms`.
    pub fn hedge_delay(self, hedge_ms: u64) -> Duration {
        match self {
            UpstreamMode::Odoh => Duration::ZERO,
            _ => Duration::from_millis(hedge_ms),
        }
    }
}

#[derive(Deserialize)]
pub struct UpstreamConfig {
    #[serde(default)]
    pub mode: UpstreamMode,
    #[serde(default, deserialize_with = "string_or_vec")]
    pub address: Vec<String>,
    #[serde(default = "default_upstream_port")]
    pub port: u16,
    #[serde(default, deserialize_with = "string_or_vec")]
    pub fallback: Vec<String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_hedge_ms")]
    pub hedge_ms: u64,
    #[serde(default = "default_root_hints")]
    pub root_hints: Vec<String>,
    #[serde(default = "default_prime_tlds")]
    pub prime_tlds: Vec<String>,
    #[serde(default = "default_srtt")]
    pub srtt: bool,

    /// Only used when `mode = "odoh"`. Full https:// URL of the relay
    /// endpoint (including path, e.g. `https://odoh-relay.numa.rs/relay`).
    #[serde(default)]
    pub relay: Option<String>,
    /// Only used when `mode = "odoh"`. Full https:// URL of the target
    /// resolver (`https://odoh.cloudflare-dns.com/dns-query`).
    #[serde(default)]
    pub target: Option<String>,
    /// Only used when `mode = "odoh"`. When true (the default), relay failure
    /// returns SERVFAIL instead of downgrading to the `fallback` upstream —
    /// a user who configured ODoH rarely wants a silent non-oblivious path.
    #[serde(default)]
    pub strict: Option<bool>,

    /// Bootstrap IP for the relay host, used when numa is its own system
    /// resolver (otherwise the ODoH HTTPS client loops resolving through
    /// itself). TLS still validates the cert against `relay`'s hostname.
    #[serde(default)]
    pub relay_ip: Option<IpAddr>,

    /// Same as `relay_ip` but for the target host.
    #[serde(default)]
    pub target_ip: Option<IpAddr>,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        UpstreamConfig {
            mode: UpstreamMode::default(),
            address: Vec::new(),
            port: default_upstream_port(),
            fallback: Vec::new(),
            timeout_ms: default_timeout_ms(),
            hedge_ms: default_hedge_ms(),
            root_hints: default_root_hints(),
            prime_tlds: default_prime_tlds(),
            srtt: default_srtt(),
            relay: None,
            target: None,
            strict: None,
            relay_ip: None,
            target_ip: None,
        }
    }
}

/// Parsed ODoH config fields. `mode = "odoh"` requires both URLs to be
/// present, to parse as `https://`, and to resolve to distinct hosts.
#[derive(Debug)]
pub struct OdohUpstream {
    pub relay_url: String,
    pub relay_host: String,
    pub target_host: String,
    pub target_path: String,
    pub strict: bool,
    pub relay_bootstrap: Option<SocketAddr>,
    pub target_bootstrap: Option<SocketAddr>,
}

impl OdohUpstream {
    /// Per-host IP overrides for the bootstrap resolver, lifted from
    /// `relay_ip`/`target_ip`. Keeps the "zero plain-DNS leak for ODoH
    /// endpoints" property when numa is its own system resolver.
    pub fn host_ip_overrides(&self) -> std::collections::BTreeMap<String, Vec<std::net::IpAddr>> {
        let mut out = std::collections::BTreeMap::new();
        if let Some(addr) = self.relay_bootstrap {
            out.entry(self.relay_host.clone())
                .or_insert_with(Vec::new)
                .push(addr.ip());
        }
        if let Some(addr) = self.target_bootstrap {
            out.entry(self.target_host.clone())
                .or_insert_with(Vec::new)
                .push(addr.ip());
        }
        out
    }
}

impl UpstreamConfig {
    /// Validate and extract ODoH-specific fields. Called during `load_config`
    /// so misconfigured ODoH fails fast at startup, the same care we take
    /// with the DNSSEC strict boot check.
    pub fn odoh_upstream(&self) -> Result<OdohUpstream> {
        let relay = self
            .relay
            .as_deref()
            .ok_or("mode = \"odoh\" requires upstream.relay")?;
        let target = self
            .target
            .as_deref()
            .ok_or("mode = \"odoh\" requires upstream.target")?;

        let relay_url = reqwest::Url::parse(relay)
            .map_err(|e| format!("upstream.relay invalid URL '{}': {}", relay, e))?;
        let target_url = reqwest::Url::parse(target)
            .map_err(|e| format!("upstream.target invalid URL '{}': {}", target, e))?;

        if relay_url.scheme() != "https" || target_url.scheme() != "https" {
            return Err("upstream.relay and upstream.target must both use https://".into());
        }
        let relay_host = relay_url
            .host_str()
            .ok_or("upstream.relay must include a host")?
            .to_string();
        let target_host = target_url
            .host_str()
            .ok_or("upstream.target must include a host")?
            .to_string();

        if relay_host == target_host {
            return Err(format!(
                "upstream.relay and upstream.target resolve to the same host ({}); the privacy property requires distinct operators",
                relay_host
            )
            .into());
        }
        if let Some(shared) = shared_registrable_domain(&relay_host, &target_host) {
            return Err(format!(
                "upstream.relay ({}) and upstream.target ({}) share the registrable domain ({}); the privacy property requires distinct operators",
                relay_host, target_host, shared
            )
            .into());
        }
        let target_path = if target_url.path().is_empty() {
            "/".to_string()
        } else {
            target_url.path().to_string()
        };

        let relay_port = relay_url.port_or_known_default().unwrap_or(443);
        let target_port = target_url.port_or_known_default().unwrap_or(443);

        Ok(OdohUpstream {
            relay_url: relay.to_string(),
            relay_host,
            target_host,
            target_path,
            strict: self.strict.unwrap_or(true),
            relay_bootstrap: self.relay_ip.map(|ip| SocketAddr::new(ip, relay_port)),
            target_bootstrap: self.target_ip.map(|ip| SocketAddr::new(ip, target_port)),
        })
    }
}

/// Returns the registrable domain (eTLD+1) shared by both hosts, if any.
/// Fails open on hosts the PSL can't parse (IP literals, bare TLDs).
fn shared_registrable_domain(relay_host: &str, target_host: &str) -> Option<String> {
    let relay = psl::domain(relay_host.as_bytes())?;
    let target = psl::domain(target_host.as_bytes())?;
    if relay.as_bytes() == target.as_bytes() {
        std::str::from_utf8(relay.as_bytes())
            .ok()
            .map(str::to_owned)
    } else {
        None
    }
}

fn string_or_vec<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Vec<String>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("string or array of strings")
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Self::Value, E> {
            Ok(vec![v.to_string()])
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut v = Vec::new();
            while let Some(s) = seq.next_element::<String>()? {
                v.push(s);
            }
            Ok(v)
        }
    }
    deserializer.deserialize_any(Visitor)
}

fn default_true() -> bool {
    true
}

fn default_srtt() -> bool {
    default_true()
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

fn default_upstream_port() -> u16 {
    53
}
fn default_timeout_ms() -> u64 {
    5000
}
/// Off by default: hedging fires a second upstream query, which silently
/// doubles the count at the provider — hurts quota'd DNS (NextDNS, Control
/// D). Opt in with `hedge_ms = 10` for tail-latency rescue on flaky nets
/// or handshake-slow DoT.
fn default_hedge_ms() -> u64 {
    0
}

#[derive(Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
    #[serde(default = "default_min_ttl")]
    pub min_ttl: u32,
    #[serde(default = "default_max_ttl")]
    pub max_ttl: u32,
    #[serde(default)]
    pub warm: Vec<String>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            max_entries: default_max_entries(),
            min_ttl: default_min_ttl(),
            max_ttl: default_max_ttl(),
            warm: Vec::new(),
        }
    }
}

fn default_max_entries() -> usize {
    100_000
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
    #[serde(default)]
    pub proxy_protocol: ProxyProtocolConfig,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            enabled: default_proxy_enabled(),
            port: default_proxy_port(),
            tls_port: default_proxy_tls_port(),
            tld: default_proxy_tld(),
            bind_addr: default_proxy_bind_addr(),
            proxy_protocol: ProxyProtocolConfig::default(),
        }
    }
}

/// PROXY protocol v2 settings for an L4-fronted listener.
///
/// Naming mirrors PowerDNS Recursor's `proxy-protocol-from` /
/// `proxy-protocol-maximum-size` for least operator surprise. An empty
/// `from` allowlist disables the feature on this listener.
#[derive(Deserialize, Clone, Debug)]
pub struct ProxyProtocolConfig {
    /// CIDR allowlist of TCP peers permitted to send PROXY v2 headers.
    /// Empty list = feature disabled. Non-empty = listener is in
    /// PROXY-required mode: connections from listed senders that omit
    /// the header are dropped, and connections from non-listed senders
    /// are dropped before any read.
    #[serde(default)]
    pub from: Vec<String>,

    /// Maximum declared PROXY v2 `addr_len`, in bytes. Default 512
    /// matches dnsdist's `setProxyProtocolMaximumPayloadSize` default.
    #[serde(default = "default_pp_max_size")]
    pub max_size: u16,

    /// Header read timeout, in milliseconds. Default 5000 matches
    /// hyper-server. Separate knob from TLS HANDSHAKE_TIMEOUT — different
    /// attack pattern (slowloris on the PROXY header).
    #[serde(default = "default_pp_header_timeout_ms")]
    pub header_timeout_ms: u64,
}

impl Default for ProxyProtocolConfig {
    fn default() -> Self {
        ProxyProtocolConfig {
            from: Vec::new(),
            max_size: default_pp_max_size(),
            header_timeout_ms: default_pp_header_timeout_ms(),
        }
    }
}

fn default_pp_max_size() -> u16 {
    512
}
fn default_pp_header_timeout_ms() -> u64 {
    5000
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

#[derive(Deserialize, Clone)]
pub struct DotConfig {
    #[serde(default = "default_dot_enabled")]
    pub enabled: bool,
    #[serde(default = "default_dot_port")]
    pub port: u16,
    #[serde(default = "default_dot_bind_addr")]
    pub bind_addr: String,
    /// Path to TLS certificate (PEM). If None, uses self-signed CA.
    #[serde(default)]
    pub cert_path: Option<PathBuf>,
    /// Path to TLS private key (PEM). If None, uses self-signed CA.
    #[serde(default)]
    pub key_path: Option<PathBuf>,
    #[serde(default)]
    pub proxy_protocol: ProxyProtocolConfig,
}

impl Default for DotConfig {
    fn default() -> Self {
        DotConfig {
            enabled: default_dot_enabled(),
            port: default_dot_port(),
            bind_addr: default_dot_bind_addr(),
            cert_path: None,
            key_path: None,
            proxy_protocol: ProxyProtocolConfig::default(),
        }
    }
}

fn default_dot_enabled() -> bool {
    true
}
fn default_dot_port() -> u16 {
    853
}
fn default_dot_bind_addr() -> String {
    "0.0.0.0".to_string()
}

/// Configuration for the mobile API — a persistent HTTP listener that
/// serves a read-only subset of routes (`/health`, `/ca.pem`,
/// `/mobileconfig`, `/ca.mobileconfig`) on a LAN-reachable port, for
/// consumption by the iOS/Android companion apps.
///
/// Unlike the main API (port 5380, localhost-only by default, supports
/// state-mutating routes), the mobile API is safe to expose on the LAN
/// because every route is idempotent and read-only.
#[derive(Deserialize, Clone)]
pub struct MobileConfig {
    /// If true, spawn the mobile API listener at startup. **Default false.**
    /// Opt-in because the listener binds to the LAN by default and exposes
    /// a few read-only endpoints to any device on the same network (`/health`,
    /// `/ca.pem`, `/mobileconfig`, `/ca.mobileconfig`). None of those are
    /// cryptographically sensitive (the CA private key is never served),
    /// but users should enable this explicitly rather than have a new
    /// LAN-reachable port appear after an upgrade.
    #[serde(default)]
    pub enabled: bool,
    /// Port for the mobile API. Default 8765.
    #[serde(default = "default_mobile_port")]
    pub port: u16,
    /// Bind address for the mobile API. Default "0.0.0.0" (all interfaces)
    /// so phones on the LAN can reach it. Set to "127.0.0.1" to restrict
    /// to localhost — useful if you're running behind another front-end.
    #[serde(default = "default_mobile_bind_addr")]
    pub bind_addr: String,
}

impl Default for MobileConfig {
    fn default() -> Self {
        MobileConfig {
            enabled: false,
            port: default_mobile_port(),
            bind_addr: default_mobile_bind_addr(),
        }
    }
}

fn default_mobile_port() -> u16 {
    8765
}

fn default_mobile_bind_addr() -> String {
    "0.0.0.0".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_disabled_by_default() {
        assert!(!LanConfig::default().enabled);
    }

    #[test]
    fn build_zone_map_accepts_ptr() {
        let zones = vec![ZoneRecord {
            domain: "1.0.168.192.in-addr.arpa".into(),
            record_type: "PTR".into(),
            value: "router.lan".into(),
            ttl: 300,
        }];
        let map = build_zone_map(&zones).expect("PTR must load");
        let records = map
            .get("1.0.168.192.in-addr.arpa")
            .and_then(|m| m.get(&QueryType::PTR))
            .expect("PTR record present");
        match &records[0] {
            DnsRecord::PTR { host, ttl, .. } => {
                assert_eq!(host, "router.lan");
                assert_eq!(*ttl, 300);
            }
            other => panic!("expected PTR, got {:?}", other),
        }
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
    fn filter_aaaa_defaults_false() {
        assert!(!ServerConfig::default().filter_aaaa);
    }

    #[test]
    fn filter_aaaa_parses_from_server_section() {
        let config: Config = toml::from_str("[server]\nfilter_aaaa = true").unwrap();
        assert!(config.server.filter_aaaa);
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

    #[test]
    fn address_string_parses_to_vec() {
        let config: Config = toml::from_str("[upstream]\naddress = \"1.2.3.4\"").unwrap();
        assert_eq!(config.upstream.address, vec!["1.2.3.4"]);
    }

    #[test]
    fn address_array_parses() {
        let config: Config =
            toml::from_str("[upstream]\naddress = [\"1.2.3.4\", \"5.6.7.8:5353\"]").unwrap();
        assert_eq!(config.upstream.address, vec!["1.2.3.4", "5.6.7.8:5353"]);
    }

    #[test]
    fn fallback_array_parses() {
        let config: Config =
            toml::from_str("[upstream]\nfallback = [\"8.8.8.8\", \"1.1.1.1\"]").unwrap();
        assert_eq!(config.upstream.fallback, vec!["8.8.8.8", "1.1.1.1"]);
    }

    #[test]
    fn fallback_string_parses_as_singleton_vec() {
        let config: Config =
            toml::from_str("[upstream]\nfallback = \"tls://1.1.1.1#cloudflare-dns.com\"").unwrap();
        assert_eq!(
            config.upstream.fallback,
            vec!["tls://1.1.1.1#cloudflare-dns.com"]
        );
    }

    #[test]
    fn empty_address_gives_empty_vec() {
        let config: Config = toml::from_str("").unwrap();
        assert!(config.upstream.address.is_empty());
        assert!(config.upstream.fallback.is_empty());
    }

    // ── [upstream] mode = "odoh" ────────────────────────────────────────

    #[test]
    fn odoh_config_parses_and_validates() {
        let toml = r#"
[upstream]
mode = "odoh"
relay = "https://odoh-relay.numa.rs/relay"
target = "https://odoh.cloudflare-dns.com/dns-query"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(config.upstream.mode, UpstreamMode::Odoh));
        let odoh = config.upstream.odoh_upstream().unwrap();
        assert_eq!(odoh.relay_url, "https://odoh-relay.numa.rs/relay");
        assert_eq!(odoh.target_host, "odoh.cloudflare-dns.com");
        assert_eq!(odoh.target_path, "/dns-query");
        assert!(odoh.strict, "strict defaults to true under mode=odoh");
    }

    #[test]
    fn odoh_strict_false_is_honoured() {
        let toml = r#"
[upstream]
mode = "odoh"
relay = "https://odoh-relay.numa.rs/relay"
target = "https://odoh.cloudflare-dns.com/dns-query"
strict = false
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(!config.upstream.odoh_upstream().unwrap().strict);
    }

    #[test]
    fn odoh_rejects_same_host_relay_and_target() {
        let toml = r#"
[upstream]
mode = "odoh"
relay = "https://odoh.example.com/relay"
target = "https://odoh.example.com/dns-query"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let err = config.upstream.odoh_upstream().unwrap_err().to_string();
        assert!(err.contains("same host"), "got: {err}");
    }

    #[test]
    fn odoh_rejects_shared_registrable_domain() {
        let toml = r#"
[upstream]
mode = "odoh"
relay = "https://r.cloudflare.com/relay"
target = "https://odoh.cloudflare.com/dns-query"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let err = config.upstream.odoh_upstream().unwrap_err().to_string();
        assert!(err.contains("registrable domain"), "got: {err}");
        assert!(err.contains("cloudflare.com"), "got: {err}");
    }

    #[test]
    fn odoh_rejects_shared_registrable_under_multi_label_suffix() {
        let toml = r#"
[upstream]
mode = "odoh"
relay = "https://a.foo.co.uk/relay"
target = "https://b.foo.co.uk/dns-query"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let err = config.upstream.odoh_upstream().unwrap_err().to_string();
        assert!(err.contains("foo.co.uk"), "got: {err}");
    }

    #[test]
    fn odoh_accepts_distinct_registrable_under_multi_label_suffix() {
        let toml = r#"
[upstream]
mode = "odoh"
relay = "https://relay.foo.co.uk/relay"
target = "https://target.bar.co.uk/dns-query"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.upstream.odoh_upstream().is_ok());
    }

    #[test]
    fn odoh_accepts_distinct_private_psl_suffix_subdomains() {
        // *.github.io is a public suffix, so foo.github.io and bar.github.io
        // are independent registrable domains — accept.
        let toml = r#"
[upstream]
mode = "odoh"
relay = "https://foo.github.io/relay"
target = "https://bar.github.io/dns-query"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.upstream.odoh_upstream().is_ok());
    }

    #[test]
    fn odoh_rejects_non_https() {
        let toml = r#"
[upstream]
mode = "odoh"
relay = "http://odoh-relay.numa.rs/relay"
target = "https://odoh.cloudflare-dns.com/dns-query"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let err = config.upstream.odoh_upstream().unwrap_err().to_string();
        assert!(err.contains("https"), "got: {err}");
    }

    #[test]
    fn odoh_missing_relay_rejected() {
        let toml = r#"
[upstream]
mode = "odoh"
target = "https://odoh.cloudflare-dns.com/dns-query"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let err = config.upstream.odoh_upstream().unwrap_err().to_string();
        assert!(err.contains("upstream.relay"), "got: {err}");
    }

    #[test]
    fn odoh_bootstrap_ips_parse_into_socket_addrs() {
        let toml = r#"
[upstream]
mode = "odoh"
relay = "https://odoh-relay.numa.rs/relay"
target = "https://odoh.cloudflare-dns.com/dns-query"
relay_ip = "178.104.229.30"
target_ip = "104.16.249.249"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let odoh = config.upstream.odoh_upstream().unwrap();
        assert_eq!(odoh.relay_host, "odoh-relay.numa.rs");
        assert_eq!(
            odoh.relay_bootstrap.unwrap().to_string(),
            "178.104.229.30:443"
        );
        assert_eq!(
            odoh.target_bootstrap.unwrap().to_string(),
            "104.16.249.249:443"
        );
    }

    #[test]
    fn odoh_bootstrap_ips_optional() {
        let toml = r#"
[upstream]
mode = "odoh"
relay = "https://odoh-relay.numa.rs/relay"
target = "https://odoh.cloudflare-dns.com/dns-query"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let odoh = config.upstream.odoh_upstream().unwrap();
        assert!(odoh.relay_bootstrap.is_none());
        assert!(odoh.target_bootstrap.is_none());
    }

    #[test]
    fn odoh_bootstrap_ip_rejects_garbage() {
        let toml = r#"
[upstream]
mode = "odoh"
relay = "https://odoh-relay.numa.rs/relay"
target = "https://odoh.cloudflare-dns.com/dns-query"
relay_ip = "not-an-ip"
"#;
        let err = toml::from_str::<Config>(toml).err().unwrap().to_string();
        assert!(err.contains("relay_ip"), "got: {err}");
    }

    #[test]
    fn odoh_bootstrap_uses_url_port_when_non_default() {
        let toml = r#"
[upstream]
mode = "odoh"
relay = "https://odoh-relay.numa.rs:8443/relay"
target = "https://odoh.cloudflare-dns.com/dns-query"
relay_ip = "178.104.229.30"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let odoh = config.upstream.odoh_upstream().unwrap();
        assert_eq!(
            odoh.relay_bootstrap.unwrap().to_string(),
            "178.104.229.30:8443"
        );
    }

    #[test]
    fn hedge_delay_zeroed_for_odoh_mode() {
        assert_eq!(
            UpstreamMode::Odoh.hedge_delay(50),
            Duration::ZERO,
            "ODoH mode must zero hedge regardless of configured hedge_ms"
        );
        assert_eq!(
            UpstreamMode::Forward.hedge_delay(50),
            Duration::from_millis(50),
            "non-ODoH modes honour configured hedge_ms"
        );
    }

    #[test]
    fn odoh_missing_target_rejected() {
        let toml = r#"
[upstream]
mode = "odoh"
relay = "https://odoh-relay.numa.rs/relay"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let err = config.upstream.odoh_upstream().unwrap_err().to_string();
        assert!(err.contains("upstream.target"), "got: {err}");
    }

    // ── issue #82: [[forwarding]] config section ────────────────────────

    #[test]
    fn forwarding_empty_by_default() {
        let config: Config = toml::from_str("").unwrap();
        assert!(config.forwarding.is_empty());
    }

    #[test]
    fn forwarding_parses_single_rule() {
        let toml = r#"
            [[forwarding]]
            suffix = "home.local"
            upstream = "100.90.1.63:5361"
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.forwarding.len(), 1);
        assert_eq!(config.forwarding[0].suffix, &["home.local"]);
        assert_eq!(config.forwarding[0].upstream, vec!["100.90.1.63:5361"]);
    }

    #[test]
    fn forwarding_parses_reverse_dns_zone() {
        let toml = r#"
            [[forwarding]]
            suffix = "168.192.in-addr.arpa"
            upstream = "100.90.1.63:5361"
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.forwarding.len(), 1);
        assert_eq!(config.forwarding[0].suffix, &["168.192.in-addr.arpa"]);
    }

    #[test]
    fn forwarding_parses_multiple_rules() {
        let toml = r#"
            [[forwarding]]
            suffix = "168.192.in-addr.arpa"
            upstream = "100.90.1.63:5361"

            [[forwarding]]
            suffix = "home.local"
            upstream = "10.0.0.1"
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.forwarding.len(), 2);
        assert_eq!(config.forwarding[1].upstream, vec!["10.0.0.1"]);
    }

    #[test]
    fn forwarding_parses_suffix_array() {
        let toml = r#"
            [[forwarding]]
            suffix = ["168.192.in-addr.arpa", "onsite"]
            upstream = "192.168.88.1"
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.forwarding.len(), 1);
        assert_eq!(
            config.forwarding[0].suffix,
            &["168.192.in-addr.arpa", "onsite"]
        );
    }

    #[test]
    fn forwarding_suffix_array_expands_to_multiple_runtime_rules() {
        let rule = ForwardingRuleConfig {
            suffix: vec!["168.192.in-addr.arpa".to_string(), "onsite".to_string()],
            upstream: vec!["192.168.88.1".to_string()],
        };
        let runtime = rule.to_runtime_rules().unwrap();
        assert_eq!(runtime.len(), 2);
        assert_eq!(runtime[0].suffix, "168.192.in-addr.arpa");
        assert_eq!(runtime[1].suffix, "onsite");
        assert_eq!(
            runtime[0].upstream.preferred(),
            runtime[1].upstream.preferred()
        );
    }

    #[test]
    fn forwarding_upstream_with_explicit_port() {
        let rule = ForwardingRuleConfig {
            suffix: vec!["home.local".to_string()],
            upstream: vec!["100.90.1.63:5361".to_string()],
        };
        let runtime = rule.to_runtime_rules().unwrap();
        assert_eq!(runtime.len(), 1);
        let preferred = runtime[0].upstream.preferred().unwrap();
        assert!(matches!(preferred, crate::forward::Upstream::Udp(_)));
        assert_eq!(preferred.to_string(), "100.90.1.63:5361");
        assert_eq!(runtime[0].suffix, "home.local");
    }

    #[test]
    fn forwarding_upstream_defaults_to_port_53() {
        let rule = ForwardingRuleConfig {
            suffix: vec!["home.local".to_string()],
            upstream: vec!["100.90.1.63".to_string()],
        };
        let runtime = rule.to_runtime_rules().unwrap();
        assert_eq!(
            runtime[0].upstream.preferred().unwrap().to_string(),
            "100.90.1.63:53"
        );
    }

    #[test]
    fn forwarding_invalid_upstream_returns_error() {
        let rule = ForwardingRuleConfig {
            suffix: vec!["home.local".to_string()],
            upstream: vec!["not-a-valid-host".to_string()],
        };
        assert!(rule.to_runtime_rules().is_err());
    }

    #[test]
    fn forwarding_upstream_accepts_dot_scheme() {
        let rule = ForwardingRuleConfig {
            suffix: vec!["google.com".to_string()],
            upstream: vec!["tls://9.9.9.9#dns.quad9.net".to_string()],
        };
        let runtime = rule
            .to_runtime_rules()
            .expect("tls:// upstream should parse");
        assert_eq!(runtime.len(), 1);
        assert_eq!(
            runtime[0].upstream.preferred().unwrap().to_string(),
            "tls://9.9.9.9:853#dns.quad9.net"
        );
    }

    #[test]
    fn forwarding_upstream_accepts_doh_scheme() {
        let rule = ForwardingRuleConfig {
            suffix: vec!["goog".to_string()],
            upstream: vec!["https://dns.quad9.net/dns-query".to_string()],
        };
        let runtime = rule
            .to_runtime_rules()
            .expect("https:// upstream should parse");
        assert_eq!(runtime.len(), 1);
        assert_eq!(
            runtime[0].upstream.preferred().unwrap().to_string(),
            "https://dns.quad9.net/dns-query"
        );
    }

    #[test]
    fn forwarding_config_rules_take_precedence_over_discovered() {
        let config_rules = vec![ForwardingRuleConfig {
            suffix: vec!["home.local".to_string()],
            upstream: vec!["10.0.0.1:53".to_string()],
        }];
        let discovered = vec![crate::system_dns::ForwardingRule::new(
            "home.local".to_string(),
            crate::forward::UpstreamPool::new(
                vec![crate::forward::Upstream::Udp(
                    "192.168.1.1:53".parse().unwrap(),
                )],
                vec![],
            ),
        )];
        let merged = merge_forwarding_rules(&config_rules, discovered).unwrap();
        let picked = crate::system_dns::match_forwarding_rule("host.home.local", &merged)
            .expect("rule should match");
        assert_eq!(picked.preferred().unwrap().to_string(), "10.0.0.1:53");
    }

    #[test]
    fn forwarding_merge_preserves_non_overlapping_discovered() {
        let config_rules = vec![ForwardingRuleConfig {
            suffix: vec!["home.local".to_string()],
            upstream: vec!["10.0.0.1:53".to_string()],
        }];
        let discovered = vec![crate::system_dns::ForwardingRule::new(
            "corp.example".to_string(),
            crate::forward::UpstreamPool::new(
                vec![crate::forward::Upstream::Udp(
                    "192.168.1.1:53".parse().unwrap(),
                )],
                vec![],
            ),
        )];
        let merged = merge_forwarding_rules(&config_rules, discovered).unwrap();
        assert_eq!(merged.len(), 2);
        let picked = crate::system_dns::match_forwarding_rule("host.corp.example", &merged)
            .expect("discovered rule should still match");
        assert_eq!(picked.preferred().unwrap().to_string(), "192.168.1.1:53");
    }

    #[test]
    fn forwarding_merge_suffix_array_expands_to_multiple_rules() {
        let config_rules = vec![ForwardingRuleConfig {
            suffix: vec!["a.local".to_string(), "b.local".to_string()],
            upstream: vec!["10.0.0.1:53".to_string()],
        }];
        let merged = merge_forwarding_rules(&config_rules, vec![]).unwrap();
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn forwarding_parses_upstream_array() {
        let toml = r#"
            [[forwarding]]
            suffix = "google.com"
            upstream = ["tls://9.9.9.9#dns.quad9.net", "tls://149.112.112.112#dns.quad9.net"]
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.forwarding.len(), 1);
        assert_eq!(config.forwarding[0].upstream.len(), 2);
    }

    #[test]
    fn forwarding_upstream_array_builds_pool_with_multiple_primaries() {
        let rule = ForwardingRuleConfig {
            suffix: vec!["google.com".to_string()],
            upstream: vec![
                "tls://9.9.9.9#dns.quad9.net".to_string(),
                "tls://149.112.112.112#dns.quad9.net".to_string(),
            ],
        };
        let runtime = rule.to_runtime_rules().unwrap();
        assert_eq!(runtime.len(), 1);
        let label = runtime[0].upstream.label();
        assert!(label.contains("+1 more"), "label was: {}", label);
    }

    #[test]
    fn forwarding_empty_upstream_array_errors() {
        let rule = ForwardingRuleConfig {
            suffix: vec!["home.local".to_string()],
            upstream: vec![],
        };
        assert!(rule.to_runtime_rules().is_err());
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
            // Interactive root and sudo'd users: always consult the XDG path
            // so `touch ~/.config/numa/numa.toml` works regardless of whether
            // config_dir() routed to FHS (issue #81).
            let suggested = crate::suggested_config_path();
            if !v.contains(&suggested) {
                v.push(suggested);
            }
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

    let display_path = crate::suggested_config_path().to_string_lossy().to_string();
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
            "PTR" => (
                QueryType::PTR,
                DnsRecord::PTR {
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
