//! Client-IP allowlist for DNS query surfaces. Loopback is always allowed
//! regardless of `allow_from` — local stub resolvers must keep working
//! even when the ACL is misconfigured. Under PROXY v2 the check runs on
//! the resolved client IP (post-header), not the L4 hop.

use std::net::IpAddr;

use ipnet::IpNet;
use log::warn;

pub(crate) fn parse_cidr_list(entries: &[String], context: &str) -> Result<Vec<IpNet>, String> {
    let mut nets = Vec::with_capacity(entries.len());
    for entry in entries {
        let net: IpNet = entry
            .parse()
            .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
            .map_err(|_| format!("invalid CIDR or IP in {context}: {entry:?}"))?;
        if matches!(&net, IpNet::V4(n) if n.prefix_len() == 0)
            || matches!(&net, IpNet::V6(n) if n.prefix_len() == 0)
        {
            warn!("{context} contains world-routable {entry} — any IP on the Internet will match");
        }
        nets.push(net);
    }
    Ok(nets)
}

/// Membership over an include set minus an exclude set, shared by `allow_from`
/// and per-client policy. Canonicalizes the peer once here so v4-mapped IPv6
/// (`::ffff:a.b.c.d`) from a dual-stack bind matches v4 CIDRs. Exclusion is set
/// subtraction (not longest-prefix), so it always wins. Loopback / empty-set
/// *policy* stays in the callers — they differ (allow vs passthrough).
#[derive(Clone, Debug, Default)]
pub(crate) struct CidrMatcher {
    include: Vec<IpNet>,
    exclude: Vec<IpNet>,
}

impl CidrMatcher {
    pub(crate) fn from_entries(
        include: &[String],
        exclude: &[String],
        context: &str,
    ) -> Result<Self, String> {
        Ok(CidrMatcher {
            include: parse_cidr_list(include, context)?,
            exclude: parse_cidr_list(exclude, &format!("{context} exclude"))?,
        })
    }

    pub(crate) fn matches(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        if self.exclude.iter().any(|n| n.contains(&ip)) {
            return false;
        }
        self.include.iter().any(|n| n.contains(&ip))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.include.is_empty()
    }
}

#[derive(Clone, Debug, Default)]
pub struct AllowFromAcl {
    matcher: CidrMatcher,
}

impl AllowFromAcl {
    pub fn from_entries(entries: &[String]) -> Result<Self, String> {
        Ok(AllowFromAcl {
            matcher: CidrMatcher::from_entries(entries, &[], "allow_from")?,
        })
    }

    pub fn allows(&self, peer: IpAddr) -> bool {
        // Dual-stack `[::]` binds deliver IPv4 clients as `::ffff:a.b.c.d`;
        // canonicalize so the loopback check matches (CidrMatcher canonicalizes
        // again for membership — idempotent).
        let peer = peer.to_canonical();
        if self.matcher.is_empty() || peer.is_loopback() {
            return true;
        }
        self.matcher.matches(peer)
    }

    /// Whether to admit a connection given its PROXY-v2 command kind. A LOCAL
    /// command is the front-end/LB probing for itself (already vetted by
    /// `proxy_protocol.from`) — it carries no client, so it bypasses the
    /// client allowlist.
    pub fn admits(&self, peer: IpAddr, local_command: bool) -> bool {
        local_command || self.allows(peer)
    }

    pub fn is_enabled(&self) -> bool {
        !self.matcher.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acl(entries: &[&str]) -> AllowFromAcl {
        AllowFromAcl::from_entries(&entries.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap()
    }

    fn matcher(include: &[&str], exclude: &[&str]) -> CidrMatcher {
        CidrMatcher::from_entries(
            &include.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &exclude.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "test",
        )
        .unwrap()
    }

    fn check_allows(a: &AllowFromAcl, cases: &[(&str, bool)]) {
        for &(peer, want) in cases {
            assert_eq!(a.allows(peer.parse().unwrap()), want, "{peer}");
        }
    }

    fn check_matches(m: &CidrMatcher, cases: &[(&str, bool)]) {
        for &(peer, want) in cases {
            assert_eq!(m.matches(peer.parse().unwrap()), want, "{peer}");
        }
    }

    #[test]
    fn empty_acl_allows_everything() {
        let a = AllowFromAcl::default();
        assert!(!a.is_enabled());
        check_allows(&a, &[("1.2.3.4", true), ("2001:db8::1", true)]);
    }

    /// Pure test: the LOCAL exemption can't be hit through a listener — the test
    /// peer is always loopback, which `allows` exempts regardless.
    #[test]
    fn local_command_bypasses_allow_from() {
        let a = AllowFromAcl {
            matcher: matcher(&["10.0.0.0/8"], &[]),
        };
        let outside: IpAddr = "192.0.2.1".parse().unwrap();
        let inside: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(
            a.admits(outside, true),
            "LOCAL command bypasses the allowlist"
        );
        assert!(!a.admits(outside, false), "real client outside is gated");
        assert!(a.admits(inside, false), "real client inside is admitted");
    }

    #[test]
    fn cidr_v4_allows_in_range_blocks_out_of_range() {
        let a = acl(&["192.168.0.0/16"]);
        assert!(a.is_enabled());
        check_allows(&a, &[("192.168.1.5", true), ("10.0.0.1", false)]);
    }

    #[test]
    fn cidr_v6_allows_in_range_blocks_out_of_range() {
        check_allows(
            &acl(&["2001:db8::/32"]),
            &[("2001:db8::5", true), ("2001:db9::5", false)],
        );
    }

    #[test]
    fn bare_ip_is_treated_as_host_route() {
        check_allows(
            &acl(&["10.1.2.3", "fe80::1"]),
            &[("10.1.2.3", true), ("10.1.2.4", false), ("fe80::1", true)],
        );
    }

    #[test]
    fn loopback_always_allowed_even_when_acl_is_set() {
        check_allows(
            &acl(&["192.168.1.0/24"]),
            &[("127.0.0.1", true), ("127.0.0.2", true), ("::1", true)],
        );
    }

    #[test]
    fn invalid_entry_rejects() {
        assert!(AllowFromAcl::from_entries(&["not-a-cidr".to_string()]).is_err());
        assert!(AllowFromAcl::from_entries(&["192.168.1.0/40".to_string()]).is_err());
    }

    #[test]
    fn ipv4_mapped_client_matches_v4_rule() {
        // Dual-stack `[::]` binds deliver IPv4 peers as `::ffff:a.b.c.d`;
        // an IPv4 CIDR allowlist must still match (and still reject out-of-range).
        check_allows(
            &acl(&["192.168.1.0/24"]),
            &[("::ffff:192.168.1.50", true), ("::ffff:10.0.0.1", false)],
        );
    }

    #[test]
    fn ipv4_mapped_loopback_always_allowed() {
        // IPv4-mapped loopback on a dual-stack bind must pass through too.
        check_allows(&acl(&["192.168.1.0/24"]), &[("::ffff:127.0.0.1", true)]);
    }

    #[test]
    fn mixed_v4_and_v6_entries() {
        check_allows(
            &acl(&["10.0.0.0/8", "2001:db8::/32", "172.16.0.5"]),
            &[
                ("10.1.2.3", true),
                ("2001:db8::abcd", true),
                ("172.16.0.5", true),
                ("8.8.8.8", false),
            ],
        );
    }

    #[test]
    fn exclude_subtracts_from_include() {
        check_matches(
            &matcher(&["192.168.1.0/24"], &["192.168.1.254"]),
            &[("192.168.1.50", true), ("192.168.1.254", false)],
        );
    }

    #[test]
    fn exclude_wins_over_nested_include() {
        // A more-specific include does not override an exclude — subtraction,
        // not longest-prefix.
        check_matches(
            &matcher(&["192.168.1.0/24", "192.168.1.254/32"], &["192.168.1.254"]),
            &[("192.168.1.254", false)],
        );
    }

    #[test]
    fn exclude_matches_v4_mapped_peer() {
        check_matches(
            &matcher(&["192.168.1.0/24"], &["192.168.1.254"]),
            &[
                ("::ffff:192.168.1.254", false),
                ("::ffff:192.168.1.50", true),
            ],
        );
    }

    #[test]
    fn empty_include_matches_nothing() {
        let m = CidrMatcher::default();
        assert!(m.is_empty());
        check_matches(&m, &[("192.168.1.1", false)]);
    }
}
