//! DNS rebinding protection (#240): strip private/special-use addresses from
//! upstream answers so a public name can't resolve to an address inside the
//! client's perimeter. Off by default. Runs only on remote/cache paths; local
//! data (zones, overrides, `.numa`, sinkhole) is exempt by gating in `ctx.rs`.

use std::collections::HashSet;
use std::net::IpAddr;

use crate::acl::CidrMatcher;
use crate::blocklist::{find_in_set, normalize};
use crate::packet::DnsPacket;
use crate::question::QueryType;
use crate::record::DnsRecord;

/// Built-in private/special-use ranges, used when `rebind_private_ranges` is
/// empty. Loopback is included — it's a prime rebind target (localhost dev
/// servers, Docker/Electron dashboards); DNSBL/RBL users that resolve
/// `127.0.0.x` should allowlist those zones.
const DEFAULT_RANGES: &[&str] = &[
    "127.0.0.0/8",    // RFC 1122 loopback — the canonical rebind target
    "10.0.0.0/8",     // RFC 1918
    "172.16.0.0/12",  // RFC 1918
    "192.168.0.0/16", // RFC 1918
    "169.254.0.0/16", // RFC 3927 link-local
    "0.0.0.0/8",      // RFC 1122 "this host" — 0.0.0.0 routes to localhost on connect
    "fc00::/7",       // RFC 4193 ULA
    "fe80::/10",      // RFC 4291 link-local
    "::1/128",        // loopback
    "::/128",         // unspecified
];

#[derive(Clone, Debug, Default)]
pub struct RebindFilter {
    enabled: bool,
    ranges: CidrMatcher,
    allowlist: HashSet<String>, // normalized: lowercase, no trailing dot
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

    fn is_allowed(&self, qname: &str) -> bool {
        !self.allowlist.is_empty() && find_in_set(&normalize(qname), &self.allowlist).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(allowlist: &[&str]) -> RebindFilter {
        let allow: Vec<String> = allowlist.iter().map(|s| s.to_string()).collect();
        RebindFilter::new(true, &allow, &[]).unwrap()
    }

    fn a(addr: &str) -> DnsRecord {
        DnsRecord::A {
            domain: "host.example.".into(),
            addr: addr.parse().unwrap(),
            ttl: 60,
        }
    }

    fn aaaa(addr: &str) -> DnsRecord {
        DnsRecord::AAAA {
            domain: "host.example.".into(),
            addr: addr.parse().unwrap(),
            ttl: 60,
        }
    }

    /// Apply `f` to `answers` for `qname`; return (count stripped, survivors).
    fn run(f: &RebindFilter, qname: &str, answers: Vec<DnsRecord>) -> (usize, Vec<DnsRecord>) {
        let mut p = DnsPacket::new();
        p.answers = answers;
        let n = f.apply(qname, &mut p);
        (n, p.answers)
    }

    /// The common case: default ranges, no allowlist, throwaway public qname.
    fn strip(answers: Vec<DnsRecord>) -> (usize, Vec<DnsRecord>) {
        run(&filter(&[]), "evil.com", answers)
    }

    #[test]
    fn strips_rfc1918_v4() {
        let r = strip(vec![a("8.8.8.8"), a("192.168.1.1"), a("10.0.0.5")]);
        assert_eq!(r, (2, vec![a("8.8.8.8")]));
    }

    #[test]
    fn strips_link_local_and_this_host() {
        let r = strip(vec![a("169.254.1.1"), a("0.0.0.0"), a("1.1.1.1")]);
        assert_eq!(r, (2, vec![a("1.1.1.1")]));
    }

    #[test]
    fn strips_ula_and_link_local_v6() {
        let r = strip(vec![aaaa("2606:4700::1"), aaaa("fd00::1"), aaaa("fe80::1")]);
        assert_eq!(r, (2, vec![aaaa("2606:4700::1")]));
    }

    #[test]
    fn strips_v4_mapped_private_v6() {
        // ::ffff:192.168.1.1 canonicalizes to the v4 range — no explicit
        // ::ffff:0:0/96 entry needed.
        let r = strip(vec![aaaa("::ffff:192.168.1.1"), aaaa("::ffff:8.8.8.8")]);
        assert_eq!(r, (1, vec![aaaa("::ffff:8.8.8.8")]));
    }

    #[test]
    fn loopback_stripped_by_default() {
        assert_eq!(strip(vec![a("127.0.0.1"), aaaa("::1")]), (2, vec![]));
    }

    #[test]
    fn allowlisted_dnsbl_zone_keeps_127_response() {
        // RBL lookups legitimately resolve to 127.0.0.x; allowlisting the zone
        // exempts them from the loopback strip.
        let f = filter(&["spamhaus.org"]);
        assert_eq!(
            run(&f, "2.0.0.127.zen.spamhaus.org", vec![a("127.0.0.2")]).0,
            0
        );
    }

    #[test]
    fn allowlist_suffix_exempts_subdomain_not_lookalike() {
        let f = filter(&["example.com"]);
        let priv_a = vec![a("192.168.1.50")];
        assert_eq!(
            run(&f, "nas.example.com", priv_a.clone()).0,
            0,
            "subdomain exempt"
        );
        assert_eq!(
            run(&f, "evilexample.com", priv_a).0,
            1,
            "lookalike not exempt"
        );
    }

    #[test]
    fn disabled_passes_through() {
        let f = RebindFilter::new(false, &[], &[]).unwrap();
        assert_eq!(
            run(&f, "evil.com", vec![a("192.168.1.1")]),
            (0, vec![a("192.168.1.1")])
        );
    }

    #[test]
    fn custom_ranges_override_defaults() {
        // Only block ULA; RFC1918 v4 now passes.
        let f = RebindFilter::new(true, &[], &["fc00::/7".to_string()]).unwrap();
        let r = run(&f, "evil.com", vec![a("192.168.1.1"), aaaa("fd00::1")]);
        assert_eq!(r, (1, vec![a("192.168.1.1")]));
    }

    #[test]
    fn invalid_custom_range_errors() {
        assert!(RebindFilter::new(true, &[], &["not-a-cidr".to_string()]).is_err());
    }
}
