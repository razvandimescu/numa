use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::packet::DnsPacket;
use crate::question::QueryType;
use crate::record::DnsRecord;

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
    packet: DnsPacket,
    inserted_at: Instant,
    ttl: Duration,
    dnssec_status: DnssecStatus,
}

/// DNS cache using a two-level map (domain -> query_type -> entry) so that
/// lookups can borrow `&str` instead of allocating a `String` key.
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

    /// Read-only lookup — expired entries are left in place (cleaned up on insert).
    pub fn lookup(&self, domain: &str, qtype: QueryType) -> Option<DnsPacket> {
        self.lookup_with_status(domain, qtype).map(|(pkt, _)| pkt)
    }

    pub fn lookup_with_status(
        &self,
        domain: &str,
        qtype: QueryType,
    ) -> Option<(DnsPacket, DnssecStatus)> {
        let type_map = self.entries.get(domain)?;
        let entry = type_map.get(&qtype)?;

        let elapsed = entry.inserted_at.elapsed();
        if elapsed >= entry.ttl {
            return None;
        }

        let remaining_secs = (entry.ttl - elapsed).as_secs() as u32;
        let remaining = remaining_secs.max(1);

        let mut packet = entry.packet.clone();
        adjust_ttls(&mut packet.answers, remaining);
        adjust_ttls(&mut packet.authorities, remaining);
        adjust_ttls(&mut packet.resources, remaining);

        Some((packet, entry.dnssec_status))
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
        if self.entry_count >= self.max_entries {
            self.evict_expired();
            if self.entry_count >= self.max_entries {
                return;
            }
        }

        let min_ttl = extract_min_ttl(&packet.answers)
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
                packet: packet.clone(),
                inserted_at: Instant::now(),
                ttl: Duration::from_secs(min_ttl as u64),
                dnssec_status,
            },
        );
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
}

pub struct CacheInfo {
    pub domain: String,
    pub query_type: QueryType,
    pub ttl_remaining: u32,
}

fn extract_min_ttl(records: &[DnsRecord]) -> Option<u32> {
    records.iter().map(|r| r.ttl()).min()
}

fn adjust_ttls(records: &mut [DnsRecord], new_ttl: u32) {
    for record in records.iter_mut() {
        record.set_ttl(new_ttl);
    }
}
