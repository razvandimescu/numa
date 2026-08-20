use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::SystemTime;

use crate::cache::DnssecStatus;
use crate::header::ResultCode;
use crate::question::QueryType;
use crate::stats::{QueryPath, Transport};

pub struct QueryLogEntry {
    /// Monotonic insertion sequence, stamped by `QueryLog::push` (1-based).
    /// Lets a polling consumer dedup exactly and detect gaps/restarts without a
    /// `since` filter. Set to 0 at construction; `push` overwrites it.
    pub seq: u64,
    pub timestamp: SystemTime,
    pub src_addr: SocketAddr,
    pub domain: String,
    pub query_type: QueryType,
    pub path: QueryPath,
    pub transport: Transport,
    pub rescode: ResultCode,
    pub latency_us: u64,
    pub dnssec: DnssecStatus,
    pub rebind_stripped: bool,
}

pub struct QueryLog {
    entries: VecDeque<QueryLogEntry>,
    capacity: usize,
    next_seq: u64,
}

impl QueryLog {
    pub fn new(capacity: usize) -> Self {
        QueryLog {
            entries: VecDeque::with_capacity(capacity),
            capacity,
            next_seq: 0,
        }
    }

    pub fn push(&mut self, mut entry: QueryLogEntry) {
        self.next_seq += 1;
        entry.seq = self.next_seq;
        if self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn heap_bytes(&self) -> usize {
        self.entries
            .iter()
            .map(|e| std::mem::size_of::<QueryLogEntry>() + e.domain.capacity())
            .sum()
    }

    pub fn query(&self, filter: &QueryLogFilter) -> Vec<&QueryLogEntry> {
        self.entries
            .iter()
            .rev()
            .filter(|e| {
                if let Some(ref domain) = filter.domain {
                    if !e.domain.contains(domain.as_str()) {
                        return false;
                    }
                }
                if let Some(qtype) = filter.query_type {
                    if e.query_type != qtype {
                        return false;
                    }
                }
                if let Some(path) = filter.path {
                    if e.path != path {
                        return false;
                    }
                }
                true
            })
            .take(filter.limit.unwrap_or(50))
            .collect()
    }
}

pub struct QueryLogFilter {
    pub domain: Option<String>,
    pub query_type: Option<QueryType>,
    pub path: Option<QueryPath>,
    pub limit: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heap_bytes_grows_with_entries() {
        let mut log = QueryLog::new(100);
        let empty = log.heap_bytes();
        log.push(entry("example.com"));
        assert!(log.heap_bytes() > empty);
    }

    fn entry(domain: &str) -> QueryLogEntry {
        QueryLogEntry {
            seq: 0,
            timestamp: SystemTime::now(),
            src_addr: "127.0.0.1:1234".parse().unwrap(),
            domain: domain.into(),
            query_type: QueryType::A,
            path: QueryPath::Forwarded,
            transport: Transport::Udp,
            rescode: ResultCode::NOERROR,
            latency_us: 500,
            dnssec: DnssecStatus::Indeterminate,
            rebind_stripped: false,
        }
    }

    #[test]
    fn push_stamps_monotonic_seq() {
        let mut log = QueryLog::new(2);
        for d in ["a", "b", "c"] {
            log.push(entry(d));
        }
        // Capacity 2: "a" was evicted, "b" and "c" remain with their stamped
        // seqs (2, 3) intact — seq is stamped at push, never derived from
        // position, so eviction does not renumber survivors.
        let filter = QueryLogFilter {
            domain: None,
            query_type: None,
            path: None,
            limit: Some(10),
        };
        let seqs: Vec<u64> = log.query(&filter).into_iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![3, 2]); // query() returns newest-first
    }
}
