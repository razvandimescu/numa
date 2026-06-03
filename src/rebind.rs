//! DNS rebinding protection (#240). Strips private/special-use addresses from
//! answers that came from an untrusted upstream path, so a public hostname
//! can't be rebound to an address inside the client's perimeter. Off by
//! default; opt-in via `[server] rebind_protect`. Local data (zones,
//! overrides, `.numa`, blocklist sinkhole) resolves on a different
//! `QueryPath` and never reaches this filter — see `resolve_query`.

use std::net::IpAddr;

use crate::acl::CidrMatcher;
use crate::packet::DnsPacket;
use crate::question::QueryType;
use crate::record::DnsRecord;

/// Built-in private/special-use ranges, used when `rebind_private_ranges` is
/// empty. Loopback (`127.0.0.0/8`, `::1`) is deliberately omitted: it collides
/// with the blocklist's `0.0.0.0` sinkhole and with DNSBLs that return
/// `127.0.0.x` as a positive signal. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) needs
/// no entry — `CidrMatcher` canonicalizes before matching, so a mapped private
/// address already matches the v4 ranges.
const DEFAULT_RANGES: &[&str] = &[
    "10.0.0.0/8",     // RFC 1918
    "172.16.0.0/12",  // RFC 1918
    "192.168.0.0/16", // RFC 1918
    "169.254.0.0/16", // RFC 3927 link-local
    "0.0.0.0/8",      // RFC 1122 "this host" — localhost-mapped on Linux/macOS
    "fc00::/7",       // RFC 4193 ULA
    "fe80::/10",      // RFC 4291 link-local
    "::/128",         // unspecified
];

#[derive(Clone, Debug, Default)]
pub struct RebindFilter {
    enabled: bool,
    ranges: CidrMatcher,
    allowlist: Vec<String>, // normalized: lowercase, no trailing dot
}

impl RebindFilter {
    pub fn new(
        enabled: bool,
        allowlist: &[String],
        custom_ranges: &[String],
    ) -> Result<Self, String> {
        let ranges = if custom_ranges.is_empty() {
            let defaults: Vec<String> = DEFAULT_RANGES.iter().map(|s| s.to_string()).collect();
            CidrMatcher::from_entries(&defaults, &[], "rebind_private_ranges")?
        } else {
            CidrMatcher::from_entries(custom_ranges, &[], "rebind_private_ranges")?
        };
        Ok(RebindFilter {
            enabled,
            ranges,
            allowlist: allowlist.iter().map(|d| normalize(d)).collect(),
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Strip private A/AAAA answers (and private SVCB/HTTPS address hints) from
    /// `response`. Returns the count of records removed or hint-scrubbed — 0 if
    /// disabled, allowlisted, or nothing private. The caller logs and clears
    /// `authed_data` when the count is > 0.
    pub fn apply(&self, qname: &str, response: &mut DnsPacket) -> usize {
        if !self.enabled || self.is_allowed(qname) {
            return 0;
        }
        let is_private = |ip: IpAddr| self.ranges.matches(ip);

        let before = response.answers.len();
        response.answers.retain(|r| match r {
            DnsRecord::A { addr, .. } => !is_private(IpAddr::V4(*addr)),
            DnsRecord::AAAA { addr, .. } => !is_private(IpAddr::V6(*addr)),
            _ => true,
        });
        let mut acted = before - response.answers.len();

        let https = QueryType::HTTPS.to_num();
        let svcb = QueryType::SVCB.to_num();
        for rec in &mut response.answers {
            if let DnsRecord::UNKNOWN { qtype, data, .. } = rec {
                if *qtype == https || *qtype == svcb {
                    if let Some(scrubbed) = crate::svcb::strip_private_hints(data, is_private) {
                        *data = scrubbed;
                        acted += 1;
                    }
                }
            }
        }
        acted
    }

    /// Exact-or-parent suffix match, mirroring `BlocklistStore` semantics:
    /// `example.com` covers `nas.example.com` but never `evilexample.com`.
    fn is_allowed(&self, qname: &str) -> bool {
        if self.allowlist.is_empty() {
            return false;
        }
        let q = normalize(qname);
        let mut d = q.as_str();
        loop {
            if self.allowlist.iter().any(|e| e == d) {
                return true;
            }
            match d.find('.') {
                Some(dot) => d = &d[dot + 1..],
                None => return false,
            }
        }
    }
}

fn normalize(domain: &str) -> String {
    domain.to_lowercase().trim_end_matches('.').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn filter(allowlist: &[&str]) -> RebindFilter {
        RebindFilter::new(
            true,
            &allowlist.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &[],
        )
        .unwrap()
    }

    fn a(addr: &str) -> DnsRecord {
        DnsRecord::A {
            domain: "host.example.".into(),
            addr: addr.parse::<Ipv4Addr>().unwrap(),
            ttl: 60,
        }
    }

    fn aaaa(addr: &str) -> DnsRecord {
        DnsRecord::AAAA {
            domain: "host.example.".into(),
            addr: addr.parse::<Ipv6Addr>().unwrap(),
            ttl: 60,
        }
    }

    fn packet(answers: Vec<DnsRecord>) -> DnsPacket {
        let mut p = DnsPacket::new();
        p.answers = answers;
        p
    }

    #[test]
    fn strips_rfc1918_v4() {
        let f = filter(&[]);
        let mut p = packet(vec![a("8.8.8.8"), a("192.168.1.1"), a("10.0.0.5")]);
        assert_eq!(f.apply("evil.com", &mut p), 2);
        assert_eq!(p.answers, vec![a("8.8.8.8")]);
    }

    #[test]
    fn strips_link_local_and_this_host() {
        let f = filter(&[]);
        let mut p = packet(vec![a("169.254.1.1"), a("0.0.0.0"), a("1.1.1.1")]);
        assert_eq!(f.apply("evil.com", &mut p), 2);
        assert_eq!(p.answers, vec![a("1.1.1.1")]);
    }

    #[test]
    fn strips_ula_and_link_local_v6() {
        let f = filter(&[]);
        let mut p = packet(vec![aaaa("2606:4700::1"), aaaa("fd00::1"), aaaa("fe80::1")]);
        assert_eq!(f.apply("evil.com", &mut p), 2);
        assert_eq!(p.answers, vec![aaaa("2606:4700::1")]);
    }

    #[test]
    fn strips_v4_mapped_private_v6() {
        // ::ffff:192.168.1.1 canonicalizes to the v4 range — no explicit
        // ::ffff:0:0/96 entry needed.
        let f = filter(&[]);
        let mut p = packet(vec![aaaa("::ffff:192.168.1.1"), aaaa("::ffff:8.8.8.8")]);
        assert_eq!(f.apply("evil.com", &mut p), 1);
        assert_eq!(p.answers, vec![aaaa("::ffff:8.8.8.8")]);
    }

    #[test]
    fn loopback_not_stripped_by_default() {
        let f = filter(&[]);
        let mut p = packet(vec![a("127.0.0.1")]);
        assert_eq!(f.apply("evil.com", &mut p), 0);
    }

    #[test]
    fn allowlist_suffix_exempts_subdomain_not_lookalike() {
        let f = filter(&["example.com"]);
        let mut nas = packet(vec![a("192.168.1.50")]);
        assert_eq!(f.apply("nas.example.com", &mut nas), 0, "subdomain exempt");

        let mut evil = packet(vec![a("192.168.1.50")]);
        assert_eq!(
            f.apply("evilexample.com", &mut evil),
            1,
            "lookalike not exempt"
        );
    }

    #[test]
    fn disabled_passes_through() {
        let f = RebindFilter::new(false, &[], &[]).unwrap();
        let mut p = packet(vec![a("192.168.1.1")]);
        assert_eq!(f.apply("evil.com", &mut p), 0);
        assert_eq!(p.answers.len(), 1);
    }

    #[test]
    fn custom_ranges_override_defaults() {
        // Only block ULA; RFC1918 v4 now passes.
        let f = RebindFilter::new(true, &[], &["fc00::/7".to_string()]).unwrap();
        let mut p = packet(vec![a("192.168.1.1"), aaaa("fd00::1")]);
        assert_eq!(f.apply("evil.com", &mut p), 1);
        assert_eq!(p.answers, vec![a("192.168.1.1")]);
    }

    #[test]
    fn invalid_custom_range_errors() {
        assert!(RebindFilter::new(true, &[], &["not-a-cidr".to_string()]).is_err());
    }
}
