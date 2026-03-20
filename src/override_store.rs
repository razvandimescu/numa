use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

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
        let domain_lower = domain.to_lowercase();
        let (qtype, record) = parse_target(&domain_lower, target, ttl)?;

        self.entries.insert(
            domain_lower.clone(),
            OverrideEntry {
                domain: domain_lower,
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
    pub fn lookup(&mut self, domain: &str) -> Option<DnsRecord> {
        let entry = self.entries.get(domain)?;
        if entry.is_expired() {
            self.entries.remove(domain);
            return None;
        }
        Some(entry.record.clone())
    }

    pub fn get(&self, domain: &str) -> Option<&OverrideEntry> {
        let key = domain.to_lowercase();
        let entry = self.entries.get(&key)?;
        if entry.is_expired() {
            return None;
        }
        Some(entry)
    }

    pub fn remove(&mut self, domain: &str) -> bool {
        self.entries.remove(&domain.to_lowercase()).is_some()
    }

    pub fn list(&self) -> Vec<&OverrideEntry> {
        self.entries.values().filter(|e| !e.is_expired()).collect()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
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
            host: target.to_string(),
            ttl,
        },
    ))
}
