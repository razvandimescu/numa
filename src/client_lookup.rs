//! Client-name lookup: reverse-resolve (PTR) a client IP against a dedicated
//! upstream (typically the LAN router), like blocky's `clientLookup`.
//! Used only for display (query log API) — never on the query hot path.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::forward::{forward_query, parse_upstream, Upstream};
use crate::packet::DnsPacket;
use crate::question::QueryType;
use crate::record::DnsRecord;

#[derive(Deserialize, Clone, Debug, Default)]
pub struct ClientLookupConfig {
    /// Upstream to send PTR queries to (`IP`, `IP:PORT`, `tcp://…`, `tls://…`, `https://…`).
    pub upstream: Option<String>,
}

const TTL: Duration = Duration::from_secs(600);
const TIMEOUT: Duration = Duration::from_secs(1);
// ponytail: cleared wholesale at the cap; swap for LRU if churn matters.
const MAX_ENTRIES: usize = 4096;

pub struct ClientLookup {
    upstream: Upstream,
    cache: Mutex<HashMap<IpAddr, (Option<String>, Instant)>>,
}

impl ClientLookup {
    pub fn from_config(cfg: &ClientLookupConfig) -> Result<Option<Arc<Self>>, String> {
        let Some(s) = cfg.upstream.as_deref().filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        let upstream = parse_upstream(s, 53, None).map_err(|e| format!("upstream '{s}': {e}"))?;
        Ok(Some(Arc::new(Self {
            upstream,
            cache: Mutex::default(),
        })))
    }

    /// Hostname for `ip`, or `None` if the upstream has no PTR (negative results are cached too).
    pub async fn lookup(&self, ip: IpAddr) -> Option<String> {
        if let Some((name, at)) = self.cache.lock().unwrap().get(&ip) {
            if at.elapsed() < TTL {
                return name.clone();
            }
        }
        let name = self.query(ip).await;
        let mut cache = self.cache.lock().unwrap();
        if cache.len() >= MAX_ENTRIES {
            cache.clear();
        }
        cache.insert(ip, (name.clone(), Instant::now()));
        name
    }

    /// Display form for logs: `ip:port (name)` once the name is cached. Never
    /// waits: a miss returns the bare address and resolves in the background.
    pub fn label(self: &Arc<Self>, src: std::net::SocketAddr) -> String {
        let ip = src.ip();
        {
            let mut cache = self.cache.lock().unwrap();
            match cache.get(&ip) {
                Some((name, at)) if at.elapsed() < TTL => {
                    return match name {
                        Some(n) => format!("{src} ({n})"),
                        None => src.to_string(),
                    };
                }
                // placeholder so concurrent queries don't spawn duplicate lookups
                _ => {
                    cache.insert(ip, (None, Instant::now()));
                }
            }
        }
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let name = this.query(ip).await;
            this.cache
                .lock()
                .unwrap()
                .insert(ip, (name, Instant::now()));
        });
        src.to_string()
    }

    async fn query(&self, ip: IpAddr) -> Option<String> {
        let q = DnsPacket::query(crate::packet::random_id(), &ptr_name(ip), QueryType::PTR);
        let resp = match forward_query(&q, &self.upstream, TIMEOUT).await {
            Ok(r) => r,
            Err(e) => {
                log::warn!("client_lookup: PTR {} failed: {}", ptr_name(ip), e);
                return None;
            }
        };
        let name = resp.answers.into_iter().find_map(|r| match r {
            DnsRecord::PTR { host, .. } => Some(host.trim_end_matches('.').to_string()),
            _ => None,
        });
        if name.is_none() {
            log::debug!(
                "client_lookup: no PTR for {} ({})",
                ip,
                resp.header.rescode.as_str()
            );
        }
        name
    }
}

fn ptr_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::with_capacity(72);
            for b in v6.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", b & 0xf, b >> 4));
            }
            s + "ip6.arpa"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ptr_names() {
        assert_eq!(
            ptr_name("192.168.1.50".parse().unwrap()),
            "50.1.168.192.in-addr.arpa"
        );
        assert_eq!(
            ptr_name("2001:db8::1".parse().unwrap()),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    #[test]
    fn empty_config_disables() {
        assert!(ClientLookup::from_config(&Default::default())
            .unwrap()
            .is_none());
    }
}
