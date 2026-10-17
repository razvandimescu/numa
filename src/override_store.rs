use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use crate::buffer::canonical_name;
use crate::question::QueryType;
use crate::record::DnsRecord;
use crate::Result;

pub struct OverrideEntry {
    pub domain: String,
    pub target: String,
    pub record: DnsRecord,
    pub query_type: QueryType,
    pub ttl: u32,
    pub created_at: Instant,
    pub duration_secs: Option<u64>,
}

impl OverrideEntry {
    pub fn expires_at(&self) -> Option<Instant> {
        self.duration_secs
            .map(|d| self.created_at + std::time::Duration::from_secs(d))
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at()
            .map(|exp| Instant::now() >= exp)
            .unwrap_or(false)
    }

    pub fn remaining_secs(&self) -> Option<u64> {
        self.expires_at().map(|exp| {
            let now = Instant::now();
            if now >= exp {
                0
            } else {
                (exp - now).as_secs()
            }
        })
    }
}

pub struct OverrideStore {
    entries: HashMap<String, OverrideEntry>,
}

impl Default for OverrideStore {
    fn default() -> Self {
        Self::new()
    }
}

impl OverrideStore {
    pub fn new() -> Self {
        OverrideStore {
            entries: HashMap::new(),
        }
    }

    pub fn insert(
        &mut self,
        domain: &str,
        target: &str,
        ttl: u32,
        duration_secs: Option<u64>,
    ) -> Result<QueryType> {
        // Clean up expired entries on write
        self.entries.retain(|_, e| !e.is_expired());

        let domain =
            canonical_name(domain).map_err(|e| format!("invalid domain '{domain}': {e}"))?;
        let (qtype, record) = parse_target(&domain, target, ttl)?;

        self.entries.insert(
            domain.clone(),
            OverrideEntry {
                domain,
                target: target.to_string(),
                record,
                query_type: qtype,
                ttl,
                created_at: Instant::now(),
                duration_secs,
            },
        );

        Ok(qtype)
    }

    /// Hot path: assumes `domain` is already lowercased (the parser does this).
    /// Read-only — expired entries are left in place (cleaned up on write operations).
    pub fn lookup(&self, domain: &str) -> Option<DnsRecord> {
        let entry = self.entries.get(domain)?;
        if entry.is_expired() {
            return None;
        }
        Some(entry.record.clone())
    }

    pub fn get(&self, domain: &str) -> Option<&OverrideEntry> {
        let entry = self.entries.get(&canonical_name(domain).ok()?)?;
        if entry.is_expired() {
            return None;
        }
        Some(entry)
    }

    pub fn remove(&mut self, domain: &str) -> bool {
        canonical_name(domain).is_ok_and(|key| self.entries.remove(&key).is_some())
    }

    pub fn list(&self) -> Vec<&OverrideEntry> {
        self.entries.values().filter(|e| !e.is_expired()).collect()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn heap_bytes(&self) -> usize {
        let per_slot = std::mem::size_of::<u64>()
            + std::mem::size_of::<String>()
            + std::mem::size_of::<OverrideEntry>()
            + 1;
        let table = self.entries.capacity() * per_slot;
        let heap: usize = self
            .entries
            .iter()
            .map(|(k, v)| {
                k.capacity() + v.domain.capacity() + v.target.capacity() + v.record.heap_bytes()
            })
            .sum();
        table + heap
    }

    pub fn active_count(&self) -> usize {
        self.entries.values().filter(|e| !e.is_expired()).count()
    }
}

fn parse_target(domain: &str, target: &str, ttl: u32) -> Result<(QueryType, DnsRecord)> {
    if let Ok(addr) = target.parse::<Ipv4Addr>() {
        return Ok((
            QueryType::A,
            DnsRecord::A {
                domain: domain.to_string(),
                addr,
                ttl,
            },
        ));
    }

    if let Ok(addr) = target.parse::<Ipv6Addr>() {
        return Ok((
            QueryType::AAAA,
            DnsRecord::AAAA {
                domain: domain.to_string(),
                addr,
                ttl,
            },
        ));
    }

    Ok((
        QueryType::CNAME,
        DnsRecord::CNAME {
            domain: domain.to_string(),
            host: canonical_name(target).map_err(|e| format!("invalid target '{target}': {e}"))?,
            ttl,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heap_bytes_grows_with_entries() {
        let mut store = OverrideStore::new();
        let empty = store.heap_bytes();
        store.insert("example.com", "1.2.3.4", 300, None).unwrap();
        assert!(store.heap_bytes() > empty);
    }

    #[test]
    fn names_are_stored_as_the_wire_reads_them() {
        let mut store = OverrideStore::new();
        store.insert("NAS.lan.", "192.168.1.42", 60, None).unwrap();
        store.insert("app.lan", "NAS.lan.", 60, None).unwrap();

        assert!(store.lookup("nas.lan").is_some());
        assert!(store.get("Nas.Lan.").is_some());
        assert!(
            matches!(store.lookup("app.lan"), Some(DnsRecord::CNAME { host, .. }) if host == "nas.lan")
        );
        assert!(store.remove("nas.lan."));
    }

    #[test]
    fn unwritable_names_are_rejected() {
        let mut store = OverrideStore::new();
        let long_label = format!("{}.lan", "a".repeat(64));
        assert!(store.insert("app.lan", &long_label, 60, None).is_err());
        assert!(store.insert("app.lan", "x.ab\\", 60, None).is_err());
        assert!(store.insert(&long_label, "192.168.1.42", 60, None).is_err());
    }
}
