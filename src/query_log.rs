use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::SystemTime;

use crate::header::ResultCode;
use crate::question::QueryType;
use crate::stats::QueryPath;

pub struct QueryLogEntry {
    pub timestamp: SystemTime,
    pub src_addr: SocketAddr,
    pub domain: String,
    pub query_type: QueryType,
    pub path: QueryPath,
    pub rescode: ResultCode,
    pub latency_us: u64,
}

pub struct QueryLog {
    entries: VecDeque<QueryLogEntry>,
    capacity: usize,
}

impl QueryLog {
    pub fn new(capacity: usize) -> Self {
        QueryLog {
            entries: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn push(&mut self, entry: QueryLogEntry) {
        if self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
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
                if let Some(since) = filter.since {
                    if e.timestamp < since {
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
    pub since: Option<SystemTime>,
    pub limit: Option<usize>,
}
