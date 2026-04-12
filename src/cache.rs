use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::buffer::BytePacketBuffer;
use crate::packet::DnsPacket;
use crate::question::QueryType;
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
        } else if elapsed < entry.ttl + STALE_WINDOW {
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

        let min_ttl = crate::wire::min_ttl_from_wire(wire, &meta)
            .unwrap_or(self.min_ttl)
            .clamp(self.min_ttl, self.max_ttl);

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
                ttl: Duration::from_secs(min_ttl as u64),
                dnssec_status,
            },
        );
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
}
