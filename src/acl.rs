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
        let peer = peer.to_canonical();
        if self.matcher.is_empty() || peer.is_loopback() {
            return true;
        }
        self.matcher.matches(peer)
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

    #[test]
    fn empty_acl_allows_everything() {
        let a = AllowFromAcl::default();
        assert!(!a.is_enabled());
        assert!(a.allows("1.2.3.4".parse().unwrap()));
        assert!(a.allows("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn cidr_v4_allows_in_range_blocks_out_of_range() {
        let a = acl(&["192.168.0.0/16"]);
        assert!(a.is_enabled());
        assert!(a.allows("192.168.1.5".parse().unwrap()));
        assert!(!a.allows("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn cidr_v6_allows_in_range_blocks_out_of_range() {
        let a = acl(&["2001:db8::/32"]);
        assert!(a.allows("2001:db8::5".parse().unwrap()));
        assert!(!a.allows("2001:db9::5".parse().unwrap()));
    }

    #[test]
    fn bare_ip_is_treated_as_host_route() {
        let a = acl(&["10.1.2.3", "fe80::1"]);
        assert!(a.allows("10.1.2.3".parse().unwrap()));
        assert!(!a.allows("10.1.2.4".parse().unwrap()));
        assert!(a.allows("fe80::1".parse().unwrap()));
    }

    #[test]
    fn loopback_always_allowed_even_when_acl_is_set() {
        let a = acl(&["192.168.1.0/24"]);
        assert!(a.allows("127.0.0.1".parse().unwrap()));
        assert!(a.allows("127.0.0.2".parse().unwrap()));
        assert!(a.allows("::1".parse().unwrap()));
    }

    #[test]
    fn invalid_entry_rejects() {
        assert!(AllowFromAcl::from_entries(&["not-a-cidr".to_string()]).is_err());
        assert!(AllowFromAcl::from_entries(&["192.168.1.0/40".to_string()]).is_err());
    }

    #[test]
    fn mixed_v4_and_v6_entries() {
        let a = acl(&["10.0.0.0/8", "2001:db8::/32", "172.16.0.5"]);
        assert!(a.allows("10.1.2.3".parse().unwrap()));
        assert!(a.allows("2001:db8::abcd".parse().unwrap()));
        assert!(a.allows("172.16.0.5".parse().unwrap()));
        assert!(!a.allows("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn allow_from_matches_v4_mapped_client() {
        // Dual-stack `[::]` binds deliver IPv4 peers as `::ffff:a.b.c.d`; the
        // canonicalization in CidrMatcher must let a v4 CIDR still match.
        let a = acl(&["192.168.0.0/16"]);
        assert!(a.allows("::ffff:192.168.1.5".parse().unwrap()));
        assert!(!a.allows("::ffff:10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn allow_from_v4_mapped_loopback_is_allowed() {
        // `::ffff:127.0.0.1` is not `Ipv6Addr::is_loopback`; canonicalizing
        // before the loopback check keeps a v4-mapped loopback bypassed.
        let a = acl(&["192.168.0.0/16"]);
        assert!(a.allows("::ffff:127.0.0.1".parse().unwrap()));
    }

    fn matcher(include: &[&str], exclude: &[&str]) -> CidrMatcher {
        CidrMatcher::from_entries(
            &include.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &exclude.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "test",
        )
        .unwrap()
    }

    #[test]
    fn exclude_subtracts_from_include() {
        let m = matcher(&["192.168.1.0/24"], &["192.168.1.254"]);
        assert!(m.matches("192.168.1.50".parse().unwrap()));
        assert!(!m.matches("192.168.1.254".parse().unwrap()));
    }

    #[test]
    fn exclude_wins_over_nested_include() {
        // A more-specific include does not override an exclude — subtraction,
        // not longest-prefix.
        let m = matcher(&["192.168.1.0/24", "192.168.1.254/32"], &["192.168.1.254"]);
        assert!(!m.matches("192.168.1.254".parse().unwrap()));
    }

    #[test]
    fn exclude_matches_v4_mapped_peer() {
        let m = matcher(&["192.168.1.0/24"], &["192.168.1.254"]);
        assert!(!m.matches("::ffff:192.168.1.254".parse().unwrap()));
        assert!(m.matches("::ffff:192.168.1.50".parse().unwrap()));
    }

    #[test]
    fn empty_include_matches_nothing() {
        let m = CidrMatcher::default();
        assert!(m.is_empty());
        assert!(!m.matches("192.168.1.1".parse().unwrap()));
    }
}
