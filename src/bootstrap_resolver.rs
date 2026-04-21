//! `reqwest` DNS resolver used by numa-originated HTTPS (DoH upstream, ODoH
//! relay/target, blocklist CDN). When numa is its own system resolver
//! (`/etc/resolv.conf → 127.0.0.1`, HAOS add-on, Pi-hole-style container),
//! the default `getaddrinfo` path loops back through numa before numa can
//! answer — a chicken-and-egg that deadlocks cold boot. See issue #122 and
//! `docs/implementation/bootstrap-resolver.md`.
//!
//! Resolution order per hostname:
//! 1. Per-hostname overrides (e.g. ODoH `relay_ip` / `target_ip`) → return
//!    immediately, no DNS query. Preserves ODoH's "zero plain-DNS leak"
//!    property for configured endpoints.
//! 2. Otherwise, query A + AAAA in parallel via UDP to IP-literal bootstrap
//!    servers, with TCP fallback on UDP timeout (for networks that block
//!    outbound UDP:53 — see memory: `project_network_udp_hostile.md`).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use log::{debug, info, warn};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::forward::{forward_tcp, forward_udp};
use crate::packet::DnsPacket;
use crate::question::QueryType;
use crate::record::DnsRecord;

const UDP_TIMEOUT: Duration = Duration::from_millis(800);
const TCP_TIMEOUT: Duration = Duration::from_millis(1500);
const DEFAULT_BOOTSTRAP: &[SocketAddr] = &[
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 53),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
];

pub struct NumaResolver {
    bootstrap: Vec<SocketAddr>,
    overrides: HashMap<String, Vec<IpAddr>>,
}

impl NumaResolver {
    /// Build a resolver from the configured `upstream.fallback` list and any
    /// per-hostname overrides (e.g. ODoH's `relay_ip`/`target_ip`).
    ///
    /// `fallback` entries are filtered to IP literals only — hostnames would
    /// re-introduce the self-loop inside the resolver itself. Empty or
    /// unusable fallback yields the hardcoded default (Quad9 + Cloudflare).
    pub fn new(fallback: &[String], overrides: HashMap<String, Vec<IpAddr>>) -> Self {
        let mut bootstrap: Vec<SocketAddr> = Vec::with_capacity(fallback.len());
        for entry in fallback {
            match crate::forward::parse_upstream_addr(entry, 53) {
                Ok(addr) => bootstrap.push(addr),
                Err(_) => {
                    warn!(
                        "bootstrap_resolver: skipping non-IP fallback '{}' \
                         (hostnames would re-enter the self-loop)",
                        entry
                    );
                }
            }
        }
        let source = if bootstrap.is_empty() {
            bootstrap = DEFAULT_BOOTSTRAP.to_vec();
            "default (no IP-literal in upstream.fallback)"
        } else {
            "upstream.fallback"
        };
        let ips: Vec<String> = bootstrap.iter().map(|s| s.ip().to_string()).collect();
        info!(
            "bootstrap resolver: {} via {} — used for numa-originated HTTPS hostname resolution",
            ips.join(", "),
            source
        );
        Self {
            bootstrap,
            overrides,
        }
    }

    #[cfg(test)]
    pub fn bootstrap(&self) -> &[SocketAddr] {
        &self.bootstrap
    }
}

impl Resolve for NumaResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let hostname = name.as_str().to_string();

        if let Some(ips) = self.overrides.get(&hostname) {
            let addrs: Vec<SocketAddr> =
                ips.iter().map(|ip| SocketAddr::new(*ip, 0)).collect();
            debug!(
                "bootstrap_resolver: override hit for {} → {:?}",
                hostname, ips
            );
            return Box::pin(
                async move { Ok(Box::new(addrs.into_iter()) as Addrs) },
            );
        }

        let bootstrap = self.bootstrap.clone();
        Box::pin(async move {
            let addrs = resolve_via_bootstrap(&hostname, &bootstrap).await?;
            debug!(
                "bootstrap_resolver: resolved {} → {} addr(s)",
                hostname,
                addrs.len()
            );
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

async fn resolve_via_bootstrap(
    hostname: &str,
    bootstrap: &[SocketAddr],
) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    let mut last_err: Option<String> = None;
    for &server in bootstrap {
        let q_a = DnsPacket::query(0xBEEF, hostname, QueryType::A);
        let q_aaaa = DnsPacket::query(0xBEF0, hostname, QueryType::AAAA);
        let (a_res, aaaa_res) = tokio::join!(
            query_with_tcp_fallback(&q_a, server),
            query_with_tcp_fallback(&q_aaaa, server),
        );

        let mut out = Vec::new();
        match a_res {
            Ok(pkt) => extract_addrs(&pkt, &mut out),
            Err(e) => last_err = Some(format!("{} A failed: {}", server, e)),
        }
        match aaaa_res {
            Ok(pkt) => extract_addrs(&pkt, &mut out),
            // AAAA is optional — many hosts return NXDOMAIN/empty. Don't
            // treat as the primary error if A succeeded.
            Err(e) => debug!("bootstrap {} AAAA for {} failed: {}", server, hostname, e),
        }
        if !out.is_empty() {
            return Ok(out);
        }
    }
    Err(last_err
        .unwrap_or_else(|| "no bootstrap servers reachable".into())
        .into())
}

async fn query_with_tcp_fallback(query: &DnsPacket, server: SocketAddr) -> crate::Result<DnsPacket> {
    match forward_udp(query, server, UDP_TIMEOUT).await {
        Ok(pkt) => Ok(pkt),
        Err(e) => {
            debug!(
                "bootstrap UDP {} failed ({}), falling back to TCP",
                server, e
            );
            forward_tcp(query, server, TCP_TIMEOUT).await
        }
    }
}

fn extract_addrs(pkt: &DnsPacket, out: &mut Vec<SocketAddr>) {
    for r in &pkt.answers {
        match r {
            DnsRecord::A { addr, .. } => out.push(SocketAddr::new(IpAddr::V4(*addr), 0)),
            DnsRecord::AAAA { addr, .. } => out.push(SocketAddr::new(IpAddr::V6(*addr), 0)),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn empty_fallback_uses_defaults() {
        let r = NumaResolver::new(&[], HashMap::new());
        let got: Vec<String> = r.bootstrap().iter().map(|s| s.to_string()).collect();
        assert_eq!(got, vec!["9.9.9.9:53", "1.1.1.1:53"]);
    }

    #[test]
    fn fallback_accepts_ip_literals_only() {
        let fallback = vec![
            "9.9.9.9".to_string(),
            "dns.quad9.net".to_string(),
            "1.1.1.1:5353".to_string(),
        ];
        let r = NumaResolver::new(&fallback, HashMap::new());
        let got: Vec<String> = r.bootstrap().iter().map(|s| s.to_string()).collect();
        assert_eq!(got, vec!["9.9.9.9:53", "1.1.1.1:5353"]);
    }

    #[test]
    fn override_returns_configured_ips_without_dns() {
        let mut overrides = HashMap::new();
        overrides.insert(
            "odoh-relay.example".to_string(),
            vec![IpAddr::V4(Ipv4Addr::new(178, 104, 229, 30))],
        );
        let r = NumaResolver::new(&[], overrides);
        let name: Name = "odoh-relay.example".parse().unwrap();
        let fut = r.resolve(name);
        let res = futures::executor::block_on(fut).unwrap();
        let addrs: Vec<_> = res.collect();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].ip(), IpAddr::V4(Ipv4Addr::new(178, 104, 229, 30)));
    }

    #[test]
    fn override_supports_multiple_ips_including_ipv6() {
        let mut overrides = HashMap::new();
        overrides.insert(
            "dual.example".to_string(),
            vec![
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
        );
        let r = NumaResolver::new(&[], overrides);
        let res = futures::executor::block_on(r.resolve("dual.example".parse().unwrap())).unwrap();
        let addrs: Vec<_> = res.collect();
        assert_eq!(addrs.len(), 2);
    }
}
