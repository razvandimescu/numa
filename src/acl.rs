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

#[derive(Clone, Debug, Default)]
pub struct AllowFromAcl {
    nets: Vec<IpNet>,
}

impl AllowFromAcl {
    pub fn from_entries(entries: &[String]) -> Result<Self, String> {
        Ok(AllowFromAcl {
            nets: parse_cidr_list(entries, "allow_from")?,
        })
    }

    pub fn allows(&self, peer: IpAddr) -> bool {
        // Dual-stack `[::]` binds deliver IPv4 clients as `::ffff:a.b.c.d`;
        // canonicalize so IPv4 CIDR rules and the loopback check still match.
        let peer = peer.to_canonical();
        if self.nets.is_empty() || peer.is_loopback() {
            return true;
        }
        self.nets.iter().any(|n| n.contains(&peer))
    }

    pub fn is_enabled(&self) -> bool {
        !self.nets.is_empty()
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
    fn ipv4_mapped_client_matches_v4_rule() {
        // Dual-stack `[::]` binds deliver IPv4 peers as `::ffff:a.b.c.d`;
        // an IPv4 CIDR allowlist must still match (and still reject out-of-range).
        let a = acl(&["192.168.1.0/24"]);
        assert!(a.allows("::ffff:192.168.1.50".parse().unwrap()));
        assert!(!a.allows("::ffff:10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_loopback_always_allowed() {
        // IPv4-mapped loopback on a dual-stack bind must pass through too.
        let a = acl(&["192.168.1.0/24"]);
        assert!(a.allows("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn mixed_v4_and_v6_entries() {
        let a = acl(&["10.0.0.0/8", "2001:db8::/32", "172.16.0.5"]);
        assert!(a.allows("10.1.2.3".parse().unwrap()));
        assert!(a.allows("2001:db8::abcd".parse().unwrap()));
        assert!(a.allows("172.16.0.5".parse().unwrap()));
        assert!(!a.allows("8.8.8.8".parse().unwrap()));
    }
}
