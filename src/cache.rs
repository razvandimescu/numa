use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::buffer::BytePacketBuffer;
use crate::packet::DnsPacket;
use crate::question::QueryType;
use crate::record::DnsRecord;
use crate::wire::WireMeta;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    /// Within TTL, no action needed.
    Fresh,
    /// Within TTL but <10% remaining — trigger background prefetch.
    NearExpiry,
    /// Past TTL but within stale window — serve with TTL=1, trigger background refresh.
    Stale,
}

impl Freshness {
    pub fn needs_refresh(self) -> bool {
        matches!(self, Freshness::NearExpiry | Freshness::Stale)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DnssecStatus {
    Secure,
    Insecure,
    Bogus,
    #[default]
    Indeterminate,
}

impl DnssecStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            DnssecStatus::Secure => "secure",
            DnssecStatus::Insecure => "insecure",
            DnssecStatus::Bogus => "bogus",
            DnssecStatus::Indeterminate => "indeterminate",
        }
    }
}

struct CacheEntry {
    wire: Vec<u8>,
    meta: WireMeta,
    inserted_at: Instant,
    ttl: Duration,
    dnssec_status: DnssecStatus,
}

const STALE_WINDOW: Duration = Duration::from_secs(3600);

/// RFC 9520 §3.2 bands a cached resolution failure at 1s..5min.
const FAILURE_TTL: u32 = 5;

/// RFC 2308 §5: one to three hours works well, beyond a day is problematic.
const NEGATIVE_MAX_TTL: u32 = 3600;

/// NXDOMAIN is an answer ("this name does not exist"); every other rcode
/// outside NOERROR is a resolution failure and gets its own short TTL.
fn is_failure(wire: &[u8]) -> bool {
    !matches!(crate::wire::rcode(wire), 0 | 3)
}

fn soa_negative_ttl(wire: &[u8]) -> Option<u32> {
    // NSCOUNT: only a reply with an authority section pays for the parse.
    if matches!(wire.get(8..10), None | Some([0, 0])) {
        return None;
    }
    let pkt = DnsPacket::from_buffer(&mut BytePacketBuffer::from_bytes(wire)).ok()?;
    pkt.authorities.iter().find_map(|r| match r {
        DnsRecord::SOA { ttl, minimum, .. } => Some((*ttl).min(*minimum)),
        _ => None,
    })
}

/// DNS cache with serve-stale (RFC 8767). Stores raw wire bytes.
pub struct DnsCache {
    entries: HashMap<String, HashMap<QueryType, CacheEntry>>,
    entry_count: usize,
    max_entries: usize,
    min_ttl: u32,
    max_ttl: u32,
}

impl DnsCache {
    pub fn new(max_entries: usize, min_ttl: u32, max_ttl: u32) -> Self {
        DnsCache {
            entries: HashMap::new(),
            entry_count: 0,
            max_entries,
            min_ttl,
            max_ttl,
        }
    }

    /// Look up cached wire bytes, patching ID and TTLs in the returned copy.
    /// Implements serve-stale (RFC 8767): expired entries within STALE_WINDOW
    /// are returned with TTL=1 and `stale=true` so callers can revalidate.
    pub fn lookup_wire(
        &self,
        domain: &str,
        qtype: QueryType,
        new_id: u16,
    ) -> Option<(Vec<u8>, DnssecStatus, Freshness)> {
        let type_map = self.entries.get(domain)?;
        let entry = type_map.get(&qtype)?;

        let elapsed = entry.inserted_at.elapsed();
        let (remaining, freshness) = if elapsed < entry.ttl {
            let secs = (entry.ttl - elapsed).as_secs() as u32;
            let f = if elapsed * 10 >= entry.ttl * 9 {
                Freshness::NearExpiry
            } else {
                Freshness::Fresh
            };
            (secs.max(1), f)
        } else if elapsed < entry.ttl + STALE_WINDOW
            && !entry.ttl.is_zero()
            && !is_failure(&entry.wire)
        {
            (1, Freshness::Stale)
        } else {
            return None;
        };

        let mut wire = entry.wire.clone();
        crate::wire::patch_id(&mut wire, new_id);
        crate::wire::patch_ttls(&mut wire, &entry.meta.ttl_offsets, remaining);

        Some((wire, entry.dnssec_status, freshness))
    }

    pub fn insert_wire(
        &mut self,
        domain: &str,
        qtype: QueryType,
        wire: &[u8],
        dnssec_status: DnssecStatus,
    ) {
        if crate::wire::is_truncated(wire) {
            return; // "ask again over TCP" is advice to one client, not an answer
        }

        let meta = match crate::wire::scan_ttl_offsets(wire) {
            Ok(m) => m,
            Err(_) => return, // malformed wire, skip
        };

        if self.entry_count >= self.max_entries {
            self.evict_expired();
            if self.entry_count >= self.max_entries {
                self.evict_stalest();
            }
        }

        // The failure TTL is deliberately outside the min_ttl/max_ttl clamp:
        // raising min_ttl to hold answers longer must not hold failures longer.
        let ttl = if is_failure(wire) {
            FAILURE_TTL
        } else if let Some(negative) = self.negative_ttl(wire, &meta) {
            negative
        } else {
            crate::wire::min_ttl_from_wire(wire, &meta)
                .unwrap_or(self.min_ttl)
                .clamp(self.min_ttl, self.max_ttl)
        };

        let type_map = if let Some(existing) = self.entries.get_mut(domain) {
            existing
        } else {
            self.entries.entry(domain.to_string()).or_default()
        };

        if !type_map.contains_key(&qtype) {
            self.entry_count += 1;
        }

        type_map.insert(
            qtype,
            CacheEntry {
                wire: wire.to_vec(),
                meta,
                inserted_at: Instant::now(),
                ttl: Duration::from_secs(ttl as u64),
                dnssec_status,
            },
        );
    }

    /// RFC 2308 §5. An NXDOMAIN without an SOA gets 0: it evicts the entry it
    /// replaces but is never served, not even stale.
    fn negative_ttl(&self, wire: &[u8], meta: &WireMeta) -> Option<u32> {
        let Some(soa_ttl) = soa_negative_ttl(wire) else {
            return (crate::wire::rcode(wire) == 3).then_some(0);
        };
        let ttl = crate::wire::min_ttl_from_wire(wire, meta).map_or(soa_ttl, |a| a.min(soa_ttl));
        Some(ttl.min(self.max_ttl).min(NEGATIVE_MAX_TTL))
    }

    /// Read-only lookup — expired entries are left in place (cleaned up on insert).
    pub fn lookup(&self, domain: &str, qtype: QueryType) -> Option<DnsPacket> {
        self.lookup_with_status(domain, qtype)
            .map(|(pkt, _, _)| pkt)
    }

    pub fn lookup_with_status(
        &self,
        domain: &str,
        qtype: QueryType,
    ) -> Option<(DnsPacket, DnssecStatus, Freshness)> {
        let (wire, status, freshness) = self.lookup_wire(domain, qtype, 0)?;
        let mut buf = BytePacketBuffer::from_bytes(&wire);
        let pkt = DnsPacket::from_buffer(&mut buf).ok()?;
        Some((pkt, status, freshness))
    }

    pub fn insert(&mut self, domain: &str, qtype: QueryType, packet: &DnsPacket) {
        self.insert_with_status(domain, qtype, packet, DnssecStatus::Indeterminate);
    }

    pub fn insert_with_status(
        &mut self,
        domain: &str,
        qtype: QueryType,
        packet: &DnsPacket,
        dnssec_status: DnssecStatus,
    ) {
        let mut buf = BytePacketBuffer::new();
        if packet.write(&mut buf).is_err() {
            return;
        }
        self.insert_wire(domain, qtype, buf.filled(), dnssec_status);
    }

    pub fn ttl_remaining(&self, domain: &str, qtype: QueryType) -> Option<(u32, u32)> {
        let type_map = self.entries.get(domain)?;
        let entry = type_map.get(&qtype)?;
        let elapsed = entry.inserted_at.elapsed();
        if elapsed >= entry.ttl {
            return None;
        }
        let total = entry.ttl.as_secs() as u32;
        let remaining = (entry.ttl - elapsed).as_secs() as u32;
        Some((remaining, total))
    }

    pub fn needs_warm(&self, domain: &str) -> bool {
        for qtype in [QueryType::A, QueryType::AAAA] {
            match self.ttl_remaining(domain, qtype) {
                None => return true,
                Some((remaining, total)) if remaining < total / 4 => return true,
                _ => {}
            }
        }
        false
    }

    pub fn len(&self) -> usize {
        self.entry_count
    }

    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.entry_count = 0;
    }

    pub fn heap_bytes(&self) -> usize {
        let outer_slot = std::mem::size_of::<u64>()
            + std::mem::size_of::<String>()
            + std::mem::size_of::<HashMap<QueryType, CacheEntry>>()
            + 1;
        let mut total = self.entries.capacity() * outer_slot;
        for (domain, type_map) in &self.entries {
            total += domain.capacity();
            let inner_slot = std::mem::size_of::<u64>()
                + std::mem::size_of::<QueryType>()
                + std::mem::size_of::<CacheEntry>()
                + 1;
            total += type_map.capacity() * inner_slot;
            for entry in type_map.values() {
                total += entry.wire.capacity()
                    + entry.meta.ttl_offsets.capacity() * std::mem::size_of::<usize>();
            }
        }
        total
    }

    pub fn remove(&mut self, domain: &str) {
        let domain_lower = domain.to_lowercase();
        if let Some(type_map) = self.entries.remove(&domain_lower) {
            self.entry_count -= type_map.len();
        }
    }

    pub fn list(&self) -> Vec<CacheInfo> {
        let mut result = Vec::new();
        for (domain, type_map) in &self.entries {
            for (qtype, entry) in type_map {
                let elapsed = entry.inserted_at.elapsed();
                if elapsed < entry.ttl {
                    let remaining = (entry.ttl - elapsed).as_secs() as u32;
                    result.push(CacheInfo {
                        domain: domain.clone(),
                        query_type: *qtype,
                        ttl_remaining: remaining,
                    });
                }
            }
        }
        result
    }

    fn evict_expired(&mut self) {
        let mut count = 0;
        self.entries.retain(|_, type_map| {
            let before = type_map.len();
            type_map.retain(|_, entry| entry.inserted_at.elapsed() < entry.ttl);
            count += before - type_map.len();
            !type_map.is_empty()
        });
        self.entry_count -= count;
    }

    /// Evict the single entry closest to (or furthest past) expiry.
    fn evict_stalest(&mut self) {
        let mut worst: Option<(String, QueryType, Duration)> = None;
        for (domain, type_map) in &self.entries {
            for (qtype, entry) in type_map {
                let age = entry.inserted_at.elapsed();
                let remaining = entry.ttl.saturating_sub(age);
                match &worst {
                    None => worst = Some((domain.clone(), *qtype, remaining)),
                    Some((_, _, w)) if remaining < *w => {
                        worst = Some((domain.clone(), *qtype, remaining));
                    }
                    _ => {}
                }
            }
        }
        if let Some((domain, qtype, _)) = worst {
            if let Some(type_map) = self.entries.get_mut(&domain) {
                if type_map.remove(&qtype).is_some() {
                    self.entry_count -= 1;
                }
                if type_map.is_empty() {
                    self.entries.remove(&domain);
                }
            }
        }
    }

    /// Backdate an entry so expiry paths can be exercised without sleeping.
    #[cfg(test)]
    fn age_entry(&mut self, domain: &str, qtype: QueryType, by: Duration) {
        let entry = self
            .entries
            .get_mut(domain)
            .and_then(|m| m.get_mut(&qtype))
            .expect("entry to age");
        entry.inserted_at = entry
            .inserted_at
            .checked_sub(by)
            .expect("monotonic clock older than the requested age");
    }
}

pub struct CacheInfo {
    pub domain: String,
    pub query_type: QueryType,
    pub ttl_remaining: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::DnsPacket;
    use crate::record::DnsRecord;

    #[test]
    fn insert_wire_refuses_a_truncated_answer() {
        // TC=1 carries no records and means "retry over TCP". Cached, it
        // answers every later client until it expires — and a client already
        // on TCP has no retry left (issue #191).
        let mut cache = DnsCache::new(100, 60, 3600);
        let query = DnsPacket::query(0x1234, "example.com", QueryType::A);
        let mut tc = DnsPacket::response_from(&query, crate::header::ResultCode::NOERROR);
        tc.header.truncated_message = true;
        let mut buf = crate::buffer::BytePacketBuffer::new();
        tc.write(&mut buf).unwrap();

        cache.insert_wire(
            "example.com",
            QueryType::A,
            buf.filled(),
            DnssecStatus::Indeterminate,
        );

        assert!(
            cache.lookup("example.com", QueryType::A).is_none(),
            "a truncated answer must not become the cached one"
        );
    }

    #[test]
    fn heap_bytes_grows_with_entries() {
        let mut cache = DnsCache::new(100, 1, 3600);
        let empty = cache.heap_bytes();
        let mut pkt = DnsPacket::new();
        pkt.answers.push(DnsRecord::A {
            domain: "example.com".into(),
            addr: "1.2.3.4".parse().unwrap(),
            ttl: 300,
        });
        cache.insert("example.com", QueryType::A, &pkt);
        assert!(cache.heap_bytes() > empty);
    }

    #[test]
    fn ttl_remaining_returns_values_for_fresh_entry() {
        let mut cache = DnsCache::new(100, 60, 3600);
        let mut pkt = DnsPacket::new();
        pkt.answers.push(DnsRecord::A {
            domain: "example.com".into(),
            addr: "1.2.3.4".parse().unwrap(),
            ttl: 300,
        });
        cache.insert("example.com", QueryType::A, &pkt);
        let (remaining, total) = cache.ttl_remaining("example.com", QueryType::A).unwrap();
        assert_eq!(total, 300);
        assert!(remaining <= 300);
        assert!(remaining > 0);
    }

    #[test]
    fn ttl_remaining_none_for_missing() {
        let cache = DnsCache::new(100, 1, 3600);
        assert!(cache.ttl_remaining("missing.com", QueryType::A).is_none());
    }

    #[test]
    fn needs_warm_true_when_missing() {
        let cache = DnsCache::new(100, 1, 3600);
        assert!(cache.needs_warm("missing.com"));
    }

    #[test]
    fn needs_warm_false_when_fresh() {
        let mut cache = DnsCache::new(100, 1, 3600);
        let mut pkt_a = DnsPacket::new();
        pkt_a.answers.push(DnsRecord::A {
            domain: "example.com".into(),
            addr: "1.2.3.4".parse().unwrap(),
            ttl: 300,
        });
        let mut pkt_aaaa = DnsPacket::new();
        pkt_aaaa.answers.push(DnsRecord::AAAA {
            domain: "example.com".into(),
            addr: "::1".parse().unwrap(),
            ttl: 300,
        });
        cache.insert("example.com", QueryType::A, &pkt_a);
        cache.insert("example.com", QueryType::AAAA, &pkt_aaaa);
        assert!(!cache.needs_warm("example.com"));
    }

    #[test]
    fn needs_warm_true_when_only_a_cached() {
        let mut cache = DnsCache::new(100, 1, 3600);
        let mut pkt = DnsPacket::new();
        pkt.answers.push(DnsRecord::A {
            domain: "example.com".into(),
            addr: "1.2.3.4".parse().unwrap(),
            ttl: 300,
        });
        cache.insert("example.com", QueryType::A, &pkt);
        // AAAA missing → needs warm
        assert!(cache.needs_warm("example.com"));
    }

    fn failure_wire(rcode: crate::header::ResultCode) -> Vec<u8> {
        let query = DnsPacket::query(0x1234, "claude.ai", QueryType::A);
        let resp = DnsPacket::response_from(&query, rcode);
        let mut buf = crate::buffer::BytePacketBuffer::new();
        resp.write(&mut buf).unwrap();
        buf.filled().to_vec()
    }

    fn insert_failure(cache: &mut DnsCache, rcode: crate::header::ResultCode) {
        let wire = failure_wire(rcode);
        cache.insert_wire(
            "claude.ai",
            QueryType::A,
            &wire,
            DnssecStatus::Indeterminate,
        );
    }

    #[test]
    fn a_failure_is_capped_at_the_rfc9520_ceiling() {
        // RFC 9520 §3.2 bands a cached resolution failure at 1s..5min. A
        // SERVFAIL carries no answers, so `min_ttl_from_wire` returns None and
        // the entry inherits `[cache] min_ttl` — one upstream blip pins a
        // healthy domain for an hour (issue #376).
        for rcode in [
            crate::header::ResultCode::SERVFAIL,
            crate::header::ResultCode::REFUSED,
        ] {
            let mut cache = DnsCache::new(100, 3600, 86400);
            insert_failure(&mut cache, rcode);

            let (_, total) = cache
                .ttl_remaining("claude.ai", QueryType::A)
                .expect("a failure is still cached, briefly");
            assert!(
                (1..=300).contains(&total),
                "a cached failure must live 1s..300s, got {total}s for {rcode:?}"
            );
        }
    }

    #[test]
    fn an_expired_failure_is_not_served_stale() {
        // Serve-stale (RFC 8767) exists to keep answering from an answer that
        // was once valid. A failure has nothing to serve, and the stale window
        // would extend it by another hour past its own TTL.
        let mut cache = DnsCache::new(100, 60, 3600);
        insert_failure(&mut cache, crate::header::ResultCode::SERVFAIL);
        cache.age_entry("claude.ai", QueryType::A, Duration::from_secs(120));

        assert!(
            cache.lookup_wire("claude.ai", QueryType::A, 0).is_none(),
            "an expired failure must not enter the serve-stale window"
        );
    }

    #[test]
    fn an_nxdomain_is_not_treated_as_a_failure() {
        // "this name does not exist" is an answer: it keeps the normal TTL
        // path and stays eligible for serve-stale.
        let mut cache = DnsCache::new(100, 60, 3600);
        let resp = negative_response(crate::header::ResultCode::NXDOMAIN, 900, 900);
        cache.insert("nope.claude.ai", QueryType::A, &resp);

        let (_, total) = cache
            .ttl_remaining("nope.claude.ai", QueryType::A)
            .expect("NXDOMAIN is cached");
        assert_eq!(total, 900, "NXDOMAIN must not take the failure TTL");
    }

    fn negative_response(
        rcode: crate::header::ResultCode,
        soa_ttl: u32,
        minimum: u32,
    ) -> DnsPacket {
        let query = DnsPacket::query(0x1234, "nope.claude.ai", QueryType::A);
        let mut resp = DnsPacket::response_from(&query, rcode);
        resp.authorities.push(DnsRecord::SOA {
            domain: "claude.ai".into(),
            mname: "ns1.claude.ai".into(),
            rname: "hostmaster.claude.ai".into(),
            serial: 1,
            refresh: 7200,
            retry: 3600,
            expire: 1209600,
            minimum,
            ttl: soa_ttl,
        });
        resp
    }

    #[test]
    fn nxdomain_ttl_comes_from_the_authority_soa() {
        for (soa_ttl, minimum, want) in [(900, 60, 60), (86400, 86400, NEGATIVE_MAX_TTL)] {
            let mut cache = DnsCache::new(100, 1800, 86400);
            let resp = negative_response(crate::header::ResultCode::NXDOMAIN, soa_ttl, minimum);
            cache.insert("nope.claude.ai", QueryType::A, &resp);

            let (_, total) = cache
                .ttl_remaining("nope.claude.ai", QueryType::A)
                .expect("NXDOMAIN is cached");
            assert_eq!(total, want, "SOA TTL {soa_ttl}, MINIMUM {minimum}");
        }
    }

    #[test]
    fn a_referral_without_an_soa_keeps_the_min_ttl_fallback() {
        // The shape `prime_tld_cache` stores: NOERROR, no answers, NS in authority.
        let mut cache = DnsCache::new(100, 60, 3600);
        let query = DnsPacket::query(0x1234, "www.claude.ai", QueryType::A);
        let mut resp = DnsPacket::response_from(&query, crate::header::ResultCode::NOERROR);
        resp.authorities.push(DnsRecord::NS {
            domain: "claude.ai".into(),
            host: "ns1.claude.ai".into(),
            ttl: 172800,
        });
        cache.insert("www.claude.ai", QueryType::A, &resp);

        let (_, total) = cache
            .ttl_remaining("www.claude.ai", QueryType::A)
            .expect("still cached");
        assert_eq!(total, 60, "an NS record is not a negative TTL");
    }

    #[test]
    fn a_negative_answer_that_may_not_be_cached_is_never_served() {
        // Skipping the insert would leave the expired answer for serve-stale.
        let nxdomain = crate::header::ResultCode::NXDOMAIN;
        let mut no_soa = negative_response(nxdomain, 900, 900);
        no_soa.authorities.clear();
        for resp in [negative_response(nxdomain, 900, 0), no_soa] {
            let mut cache = DnsCache::new(100, 60, 3600);
            let mut pkt = DnsPacket::new();
            pkt.answers.push(DnsRecord::A {
                domain: "nope.claude.ai".into(),
                addr: "1.2.3.4".parse().unwrap(),
                ttl: 300,
            });
            cache.insert("nope.claude.ai", QueryType::A, &pkt);
            cache.age_entry("nope.claude.ai", QueryType::A, Duration::from_secs(301));
            cache.insert("nope.claude.ai", QueryType::A, &resp);

            assert!(cache.lookup("nope.claude.ai", QueryType::A).is_none());
        }
    }

    #[test]
    fn a_cname_chain_expires_with_the_negative_answer_behind_it() {
        // RFC 2308 §2.1/§2.2: NOERROR+CNAME+SOA is NODATA.
        for (rcode, cname_ttl, minimum, want) in [
            (crate::header::ResultCode::NXDOMAIN, 30, 900, 30),
            (crate::header::ResultCode::NOERROR, 900, 20, 20),
        ] {
            let mut cache = DnsCache::new(100, 3600, 86400);
            let mut resp = negative_response(rcode, 900, minimum);
            resp.answers.push(DnsRecord::CNAME {
                domain: "nope.claude.ai".into(),
                host: "gone.claude.ai".into(),
                ttl: cname_ttl,
            });
            cache.insert("nope.claude.ai", QueryType::A, &resp);

            let (_, total) = cache
                .ttl_remaining("nope.claude.ai", QueryType::A)
                .expect("cached");
            assert_eq!(total, want, "{rcode:?}");
        }
    }
}
