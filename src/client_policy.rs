//! Per-client domain policies: block or allow specific domains for specific
//! client IPs. Each rule is a `BlocklistStore` scoped to a set of client CIDRs
//! — the matcher, normalizer, and allowlist semantics are the same as the
//! global adblock path, so policy rules and global blocking can't drift.
//!
//! Loopback bypass mirrors `allow_from`: stub resolvers on the same host
//! never hit the per-client path.

use std::net::IpAddr;

use serde::Deserialize;

use crate::acl::CidrMatcher;
use crate::blocklist::{parse_blocklist, BlocklistStore};

#[derive(Deserialize, Clone, Debug, Default)]
pub struct ClientPolicyConfig {
    #[serde(default)]
    pub from: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub block: Vec<String>,
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug)]
struct ClientPolicy {
    nets: CidrMatcher,
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
            let ctx = format!("client_policy[{idx}]");
            if cfg.from.is_empty() {
                return Err(format!("{ctx}.from: must list at least one CIDR or IP"));
            }
            // Reuse the global blocklist parser so per-client and global lists can't drift.
            let blocks = parse_blocklist(&cfg.block.join("\n"));
            let allows = parse_blocklist(&cfg.allow.join("\n"));
            if blocks.is_empty() && allows.is_empty() {
                return Err(format!(
                    "{ctx}: must specify at least one valid domain in `block` or `allow`"
                ));
            }
            let mut store = BlocklistStore::new();
            store.swap_domains(blocks, vec![]);
            for a in &allows {
                store.add_to_allowlist(a);
            }
            rules.push(ClientPolicy {
                nets: CidrMatcher::from_entries(&cfg.from, &cfg.exclude, &format!("{ctx}.from"))?,
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

    /// Rules layer in declaration order: the first rule with an explicit
    /// Block/Allow for `qname` wins; a client-matching rule silent on `qname`
    /// falls through to the next. Within a rule, allow beats block.
    pub fn evaluate(&self, peer: IpAddr, qname: &str) -> Decision {
        // Canonicalize so the loopback bypass also covers `::ffff:127.0.0.1`
        // from a dual-stack bind. Loopback wins over any `exclude` — a loopback
        // peer never reaches the matcher, so it cannot be filtered.
        let peer = peer.to_canonical();
        if self.rules.is_empty() || peer.is_loopback() {
            return Decision::Passthrough;
        }
        for rule in &self.rules {
            if !rule.nets.matches(peer) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(from: &[&str], block: &[&str], allow: &[&str]) -> ClientPolicyConfig {
        cfg_ex(from, &[], block, allow)
    }

    fn cfg_ex(
        from: &[&str],
        exclude: &[&str],
        block: &[&str],
        allow: &[&str],
    ) -> ClientPolicyConfig {
        ClientPolicyConfig {
            from: from.iter().map(|s| s.to_string()).collect(),
            exclude: exclude.iter().map(|s| s.to_string()).collect(),
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
    fn adblock_syntax_is_parsed_like_global_list() {
        // `||host^` and `$options` must be stripped, matching parse_blocklist.
        let set = ClientPolicySet::from_configs(&[cfg(
            &["10.0.0.0/8"],
            &["||tracker.com^", "ads.net$third-party"],
            &[],
        )])
        .unwrap();
        assert_eq!(set.evaluate(ip("10.0.0.5"), "tracker.com"), Decision::Block);
        assert_eq!(
            set.evaluate(ip("10.0.0.5"), "sub.tracker.com"),
            Decision::Block
        );
        assert_eq!(set.evaluate(ip("10.0.0.5"), "ads.net"), Decision::Block);
    }

    #[test]
    fn dotless_entry_does_not_blanket_block_a_tld() {
        // `*.com` normalizes to bare `com`, which parse_blocklist drops (no dot),
        // so it must NOT sinkhole the whole TLD; a valid sibling still blocks.
        let set = ClientPolicySet::from_configs(&[cfg(
            &["192.168.1.0/24"],
            &["*.com", "ads.example"],
            &[],
        )])
        .unwrap();
        assert_eq!(
            set.evaluate(ip("192.168.1.5"), "youtube.com"),
            Decision::Passthrough
        );
        assert_eq!(
            set.evaluate(ip("192.168.1.5"), "ads.example"),
            Decision::Block
        );
    }

    #[test]
    fn rule_with_only_invalid_domains_is_rejected() {
        // A rule whose lists parse to nothing (junk / dotless) errors at load
        // instead of silently becoming a no-op.
        assert!(
            ClientPolicySet::from_configs(&[cfg(&["10.0.0.0/8"], &["*", "com"], &[])]).is_err()
        );
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
    fn silent_rule_falls_through_to_later_rule() {
        // Rule 0 matches .50 but is silent on reddit → falls through to rule 1
        // (the /24), which blocks it. Rule 0 still owns its own domain.
        let set = ClientPolicySet::from_configs(&[
            cfg(&["192.168.1.50"], &["youtube.com"], &[]),
            cfg(&["192.168.1.0/24"], &["reddit.com"], &[]),
        ])
        .unwrap();
        assert_eq!(
            set.evaluate(ip("192.168.1.50"), "reddit.com"),
            Decision::Block
        );
        assert_eq!(
            set.evaluate(ip("192.168.1.50"), "youtube.com"),
            Decision::Block
        );
        // .99 only matches rule 1, which is silent on youtube → passthrough.
        assert_eq!(
            set.evaluate(ip("192.168.1.99"), "youtube.com"),
            Decision::Passthrough
        );
    }

    #[test]
    fn earlier_allow_beats_later_block() {
        // For an overlapping client, the earlier rule's explicit decision wins:
        // rule 0 allows the domain, the broader rule 1 blocks it → Allow.
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
        // IPv4-mapped loopback on a dual-stack bind must also pass through.
        assert_eq!(
            set.evaluate(ip("::ffff:127.0.0.1"), "example.com"),
            Decision::Passthrough
        );
    }

    #[test]
    fn ipv4_mapped_client_matches_v4_rule() {
        // Dual-stack `[::]` binds deliver IPv4 peers as `::ffff:a.b.c.d`;
        // an IPv4 CIDR rule must still match (regression for #239 follow-up).
        let set =
            ClientPolicySet::from_configs(&[cfg(&["192.168.1.50/32"], &["youtube.com"], &[])])
                .unwrap();
        assert_eq!(
            set.evaluate(ip("::ffff:192.168.1.50"), "m.youtube.com"),
            Decision::Block
        );
        assert_eq!(
            set.evaluate(ip("::ffff:192.168.1.99"), "m.youtube.com"),
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

    #[test]
    fn exclude_carves_a_host_out_of_the_range() {
        // "filter the whole /24 except my own device" — the driving use case.
        let set = ClientPolicySet::from_configs(&[cfg_ex(
            &["192.168.1.0/24"],
            &["192.168.1.254"],
            &["youtube.com"],
            &[],
        )])
        .unwrap();
        assert_eq!(
            set.evaluate(ip("192.168.1.50"), "youtube.com"),
            Decision::Block
        );
        // The excluded device is unfiltered: it matches no rule → passthrough.
        assert_eq!(
            set.evaluate(ip("192.168.1.254"), "youtube.com"),
            Decision::Passthrough
        );
    }

    #[test]
    fn excluded_v4_mapped_peer_is_unfiltered() {
        // Exclusion must survive dual-stack canonicalization too.
        let set = ClientPolicySet::from_configs(&[cfg_ex(
            &["192.168.1.0/24"],
            &["192.168.1.254"],
            &["youtube.com"],
            &[],
        )])
        .unwrap();
        assert_eq!(
            set.evaluate(ip("::ffff:192.168.1.254"), "youtube.com"),
            Decision::Passthrough
        );
        assert_eq!(
            set.evaluate(ip("::ffff:192.168.1.50"), "youtube.com"),
            Decision::Block
        );
    }
}
