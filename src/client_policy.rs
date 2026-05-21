//! Per-client domain policies: block or allow specific domains for specific
//! client IPs. Each rule is a `BlocklistStore` scoped to a set of client CIDRs
//! — the matcher, normalizer, and allowlist semantics are the same as the
//! global adblock path, so policy rules and global blocking can't drift.
//!
//! Loopback bypass mirrors `allow_from`: stub resolvers on the same host
//! never hit the per-client path.

use std::collections::HashSet;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::Deserialize;

use crate::acl::parse_cidr_list;
use crate::blocklist::{normalize, BlocklistStore};

#[derive(Deserialize, Clone, Debug, Default)]
pub struct ClientPolicyConfig {
    #[serde(default)]
    pub clients: Vec<String>,
    #[serde(default)]
    pub block: Vec<String>,
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug)]
struct ClientPolicy {
    nets: Vec<IpNet>,
    store: BlocklistStore,
}

#[derive(Debug, Default)]
pub struct ClientPolicySet {
    rules: Vec<ClientPolicy>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Block,
    Allow,
    Passthrough,
}

impl ClientPolicySet {
    pub fn from_configs(configs: &[ClientPolicyConfig]) -> Result<Self, String> {
        let mut rules = Vec::with_capacity(configs.len());
        for (idx, cfg) in configs.iter().enumerate() {
            let ctx = format!("client_policy[{idx}].clients");
            if cfg.clients.is_empty() {
                return Err(format!("{ctx}: must list at least one CIDR or IP"));
            }
            if cfg.block.is_empty() && cfg.allow.is_empty() {
                return Err(format!(
                    "client_policy[{idx}]: must specify `block` or `allow` (or both)"
                ));
            }
            let blocks: HashSet<String> = cfg
                .block
                .iter()
                .map(|s| normalize(strip_wildcard(s)))
                .collect();
            let mut store = BlocklistStore::new();
            store.swap_domains(blocks, vec![]);
            for a in &cfg.allow {
                store.add_to_allowlist(strip_wildcard(a));
            }
            rules.push(ClientPolicy {
                nets: parse_cidr_list(&cfg.clients, &ctx)?,
                store,
            });
        }
        Ok(ClientPolicySet { rules })
    }

    pub fn is_enabled(&self) -> bool {
        !self.rules.is_empty()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// First matching rule wins. Within a rule, allow beats block (via the
    /// underlying `BlocklistStore` semantics).
    pub fn evaluate(&self, peer: IpAddr, qname: &str) -> Decision {
        if self.rules.is_empty() || peer.is_loopback() {
            return Decision::Passthrough;
        }
        for rule in &self.rules {
            if !rule.nets.iter().any(|n| n.contains(&peer)) {
                continue;
            }
            let r = rule.store.check(qname);
            if r.blocked {
                return Decision::Block;
            }
            if r.matched_rule.is_some() {
                return Decision::Allow;
            }
        }
        Decision::Passthrough
    }
}

fn strip_wildcard(s: &str) -> &str {
    s.strip_prefix("*.").unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(clients: &[&str], block: &[&str], allow: &[&str]) -> ClientPolicyConfig {
        ClientPolicyConfig {
            clients: clients.iter().map(|s| s.to_string()).collect(),
            block: block.iter().map(|s| s.to_string()).collect(),
            allow: allow.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn empty_set_passes_through() {
        let set = ClientPolicySet::default();
        assert!(!set.is_enabled());
        assert_eq!(
            set.evaluate(ip("192.168.1.50"), "example.com"),
            Decision::Passthrough
        );
    }

    #[test]
    fn blocks_matching_client() {
        let set =
            ClientPolicySet::from_configs(&[cfg(&["192.168.1.50/32"], &["youtube.com"], &[])])
                .unwrap();
        assert_eq!(
            set.evaluate(ip("192.168.1.50"), "m.youtube.com"),
            Decision::Block
        );
        assert_eq!(
            set.evaluate(ip("192.168.1.99"), "m.youtube.com"),
            Decision::Passthrough
        );
    }

    #[test]
    fn star_prefix_blocks_subdomains_and_apex() {
        let set =
            ClientPolicySet::from_configs(&[cfg(&["10.0.0.0/8"], &["*.tiktok.com"], &[])]).unwrap();
        assert_eq!(
            set.evaluate(ip("10.0.0.5"), "vm.tiktok.com"),
            Decision::Block
        );
        assert_eq!(set.evaluate(ip("10.0.0.5"), "tiktok.com"), Decision::Block);
    }

    #[test]
    fn allow_overrides_block_within_rule() {
        let set = ClientPolicySet::from_configs(&[cfg(
            &["192.168.1.50"],
            &["example.com"],
            &["safe.example.com"],
        )])
        .unwrap();
        assert_eq!(
            set.evaluate(ip("192.168.1.50"), "safe.example.com"),
            Decision::Allow
        );
        assert_eq!(
            set.evaluate(ip("192.168.1.50"), "ads.example.com"),
            Decision::Block
        );
    }

    #[test]
    fn first_matching_rule_wins() {
        let set = ClientPolicySet::from_configs(&[
            cfg(&["192.168.1.50"], &[], &["news.ycombinator.com"]),
            cfg(&["192.168.1.0/24"], &["news.ycombinator.com"], &[]),
        ])
        .unwrap();
        assert_eq!(
            set.evaluate(ip("192.168.1.50"), "news.ycombinator.com"),
            Decision::Allow
        );
        assert_eq!(
            set.evaluate(ip("192.168.1.99"), "news.ycombinator.com"),
            Decision::Block
        );
    }

    #[test]
    fn loopback_always_passthrough() {
        let set =
            ClientPolicySet::from_configs(&[cfg(&["127.0.0.0/8"], &["example.com"], &[])]).unwrap();
        assert_eq!(
            set.evaluate(ip("127.0.0.1"), "example.com"),
            Decision::Passthrough
        );
        assert_eq!(
            set.evaluate(ip("::1"), "example.com"),
            Decision::Passthrough
        );
    }

    #[test]
    fn ipv6_client_cidr() {
        let set =
            ClientPolicySet::from_configs(&[cfg(&["2001:db8::/32"], &["tracker.example"], &[])])
                .unwrap();
        assert_eq!(
            set.evaluate(ip("2001:db8::abcd"), "tracker.example"),
            Decision::Block
        );
        assert_eq!(
            set.evaluate(ip("2001:db9::abcd"), "tracker.example"),
            Decision::Passthrough
        );
    }

    #[test]
    fn rejects_empty_clients() {
        let err = ClientPolicySet::from_configs(&[cfg(&[], &["x.com"], &[])]).unwrap_err();
        assert!(err.contains("at least one CIDR"));
    }

    #[test]
    fn rejects_empty_block_and_allow() {
        let err = ClientPolicySet::from_configs(&[cfg(&["192.168.1.0/24"], &[], &[])]).unwrap_err();
        assert!(err.contains("`block` or `allow`"));
    }

    #[test]
    fn rejects_invalid_cidr() {
        let err =
            ClientPolicySet::from_configs(&[cfg(&["not-a-cidr"], &["x.com"], &[])]).unwrap_err();
        assert!(err.contains("invalid CIDR"));
    }
}
