use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::packet::DnsPacket;
use crate::question::QueryType;
use crate::record::DnsRecord;

struct CacheEntry {
    packet: DnsPacket,
    inserted_at: Instant,
    ttl: Duration,
}

pub struct DnsCache {
    entries: HashMap<(String, QueryType), CacheEntry>,
    max_entries: usize,
    min_ttl: u32,
    max_ttl: u32,
    query_count: u64,
}

impl DnsCache {
    pub fn new(max_entries: usize, min_ttl: u32, max_ttl: u32) -> Self {
        DnsCache {
            entries: HashMap::new(),
            max_entries,
            min_ttl,
            max_ttl,
            query_count: 0,
        }
    }

    pub fn lookup(&mut self, domain: &str, qtype: QueryType) -> Option<DnsPacket> {
        self.query_count += 1;

        // Periodic eviction every 1000 queries
        if self.query_count % 1000 == 0 {
            self.evict_expired();
        }

        let key = (domain.to_string(), qtype);
        let entry = self.entries.get(&key)?;

        let elapsed = entry.inserted_at.elapsed();
        if elapsed >= entry.ttl {
            self.entries.remove(&key);
            return None;
        }

        let remaining_secs = (entry.ttl - elapsed).as_secs() as u32;
        let remaining = remaining_secs.max(1);

        let mut packet = entry.packet.clone();
        adjust_ttls(&mut packet.answers, remaining);
        adjust_ttls(&mut packet.authorities, remaining);
        adjust_ttls(&mut packet.resources, remaining);

        Some(packet)
    }

    pub fn insert(&mut self, domain: &str, qtype: QueryType, packet: &DnsPacket) {
        if self.entries.len() >= self.max_entries {
            self.evict_expired();
            // If still full after eviction, skip insertion
            if self.entries.len() >= self.max_entries {
                return;
            }
        }

        let min_ttl = extract_min_ttl(&packet.answers)
            .unwrap_or(self.min_ttl)
            .clamp(self.min_ttl, self.max_ttl);

        let key = (domain.to_string(), qtype);
        self.entries.insert(key, CacheEntry {
            packet: packet.clone(),
            inserted_at: Instant::now(),
            ttl: Duration::from_secs(min_ttl as u64),
        });
    }

    fn evict_expired(&mut self) {
        self.entries.retain(|_, entry| entry.inserted_at.elapsed() < entry.ttl);
    }
}

fn extract_min_ttl(records: &[DnsRecord]) -> Option<u32> {
    records.iter().map(|r| r.ttl()).min()
}

fn adjust_ttls(records: &mut [DnsRecord], new_ttl: u32) {
    for record in records.iter_mut() {
        record.set_ttl(new_ttl);
    }
}
