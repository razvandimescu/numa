use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use log::{error, info, warn};

use crate::cache::DnssecStatus;
use crate::header::ResultCode;
use crate::question::QueryType;
use crate::stats::{QueryPath, Transport};

#[derive(Clone, Debug)]
pub struct QueryLogEntry {
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

pub struct QueryLogFilter {
    pub domain: Option<String>,
    pub query_type: Option<QueryType>,
    pub path: Option<QueryPath>,
    pub since: Option<SystemTime>,
    pub limit: Option<usize>,
}

pub trait QueryLogBackend: Send + Sync {
    fn write_batch(&self, entries: &[QueryLogEntry]) -> Result<(), String>;
    fn query(&self, filter: &QueryLogFilter) -> Result<Vec<QueryLogEntry>, String>;
    fn len(&self) -> usize;
    fn heap_bytes(&self) -> usize;
}

// ==========================================
// 1. IN-MEMORY BACKEND
// ==========================================
pub struct MemoryBackend {
    entries: Mutex<VecDeque<QueryLogEntry>>,
    capacity: usize,
}

impl MemoryBackend {
    pub fn new(capacity: usize) -> Self {
        MemoryBackend {
            entries: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }
}

impl QueryLogBackend for MemoryBackend {
    fn write_batch(&self, entries: &[QueryLogEntry]) -> Result<(), String> {
        let mut queue = self.entries.lock().unwrap();
        for entry in entries {
            if queue.len() >= self.capacity {
                queue.pop_front();
            }
            queue.push_back(entry.clone());
        }
        Ok(())
    }

    fn query(&self, filter: &QueryLogFilter) -> Result<Vec<QueryLogEntry>, String> {
        let queue = self.entries.lock().unwrap();
        let results = queue
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
            .cloned()
            .collect();
        Ok(results)
    }

    fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    fn heap_bytes(&self) -> usize {
        let queue = self.entries.lock().unwrap();
        queue
            .iter()
            .map(|e| std::mem::size_of::<QueryLogEntry>() + e.domain.capacity())
            .sum()
    }
}

// ==========================================
// 2. SQLITE BACKEND
// ==========================================
pub struct SqliteBackend {
    conn: Mutex<rusqlite::Connection>,
}

impl SqliteBackend {
    pub fn new(db_path: &Path) -> Result<Self, String> {
        let conn = rusqlite::Connection::open(db_path)
            .map_err(|e| format!("failed to open sqlite DB: {e}"))?;
            
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS query_logs (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 timestamp INTEGER NOT NULL,
                 src_addr TEXT NOT NULL,
                 domain TEXT NOT NULL,
                 query_type TEXT NOT NULL,
                 path TEXT NOT NULL,
                 transport TEXT NOT NULL,
                 rescode TEXT NOT NULL,
                 latency_us INTEGER NOT NULL,
                 dnssec TEXT NOT NULL,
                 rebind_stripped INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_query_logs_timestamp ON query_logs(timestamp);
             CREATE INDEX IF NOT EXISTS idx_query_logs_domain ON query_logs(domain);
             CREATE INDEX IF NOT EXISTS idx_query_logs_path ON query_logs(path);"
        ).map_err(|e| format!("failed to initialize sqlite schema: {e}"))?;
        
        Ok(SqliteBackend {
            conn: Mutex::new(conn),
        })
    }
}

enum SqlParam {
    Text(String),
    Int(i64),
}

impl rusqlite::ToSql for SqlParam {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        match self {
            SqlParam::Text(s) => s.to_sql(),
            SqlParam::Int(i) => i.to_sql(),
        }
    }
}

impl QueryLogBackend for SqliteBackend {
    fn write_batch(&self, entries: &[QueryLogEntry]) -> Result<(), String> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(|e| format!("failed to start transaction: {e}"))?;
        
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO query_logs (
                    timestamp, src_addr, domain, query_type, path, 
                    transport, rescode, latency_us, dnssec, rebind_stripped
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            ).map_err(|e| format!("failed to prepare statement: {e}"))?;
            
            for entry in entries {
                let ts = entry.timestamp.duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as i64;
                let src = entry.src_addr.to_string();
                let qtype = entry.query_type.as_str().to_string();
                let path = entry.path.as_str().to_string();
                let transport = entry.transport.as_str().to_string();
                let rescode = entry.rescode.as_str().to_string();
                let latency = entry.latency_us as i64;
                let dnssec = entry.dnssec.as_str().to_string();
                let rebind = if entry.rebind_stripped { 1 } else { 0 };
                
                stmt.execute(rusqlite::params![
                    ts, src, entry.domain, qtype, path, 
                    transport, rescode, latency, dnssec, rebind
                ]).map_err(|e| format!("failed to execute insert: {e}"))?;
            }
        }
        
        tx.commit().map_err(|e| format!("failed to commit transaction: {e}"))?;
        Ok(())
    }

    fn query(&self, filter: &QueryLogFilter) -> Result<Vec<QueryLogEntry>, String> {
        let conn = self.conn.lock().unwrap();
        
        let mut query_str = "SELECT timestamp, src_addr, domain, query_type, path, transport, rescode, latency_us, dnssec, rebind_stripped FROM query_logs WHERE 1=1".to_string();
        let mut params = Vec::new();
        
        if let Some(ref domain) = filter.domain {
            query_str.push_str(" AND domain LIKE ?");
            params.push(SqlParam::Text(format!("%{}%", domain)));
        }
        
        if let Some(qtype) = filter.query_type {
            query_str.push_str(" AND query_type = ?");
            params.push(SqlParam::Text(qtype.as_str().to_string()));
        }
        
        if let Some(path) = filter.path {
            query_str.push_str(" AND path = ?");
            params.push(SqlParam::Text(path.as_str().to_string()));
        }
        
        if let Some(since) = filter.since {
            query_str.push_str(" AND timestamp >= ?");
            let ms = since.duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as i64;
            params.push(SqlParam::Int(ms));
        }
        
        query_str.push_str(" ORDER BY timestamp DESC LIMIT ?");
        let limit = filter.limit.unwrap_or(50) as i64;
        params.push(SqlParam::Int(limit));
        
        let mut stmt = conn.prepare(&query_str).map_err(|e| format!("failed to prepare query: {e}"))?;
        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
        
        let rows = stmt.query_map(param_refs.as_slice(), |row| {
            let ts_ms: i64 = row.get(0)?;
            let src_str: String = row.get(1)?;
            let domain: String = row.get(2)?;
            let qtype_str: String = row.get(3)?;
            let path_str: String = row.get(4)?;
            let transport_str: String = row.get(5)?;
            let rescode_str: String = row.get(6)?;
            let latency_us: i64 = row.get(7)?;
            let dnssec_str: String = row.get(8)?;
            let rebind_val: i32 = row.get(9)?;
            
            let timestamp = UNIX_EPOCH + Duration::from_millis(ts_ms as u64);
            let src_addr = src_str.parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
            let query_type = QueryType::parse_str(&qtype_str).unwrap_or(QueryType::UNKNOWN(0));
            let path = QueryPath::parse_str(&path_str).unwrap_or(QueryPath::UpstreamError);
            
            let transport = match transport_str.as_str() {
                "UDP" => Transport::Udp,
                "TCP" => Transport::Tcp,
                "DOT" => Transport::Dot,
                "DOH" => Transport::Doh,
                _ => Transport::Udp,
            };
            
            let rescode = match rescode_str.as_str() {
                "FORMERR" => ResultCode::FORMERR,
                "SERVFAIL" => ResultCode::SERVFAIL,
                "NXDOMAIN" => ResultCode::NXDOMAIN,
                "NOTIMP" => ResultCode::NOTIMP,
                "REFUSED" => ResultCode::REFUSED,
                _ => ResultCode::NOERROR,
            };
            
            let dnssec = match dnssec_str.as_str() {
                "secure" => DnssecStatus::Secure,
                "insecure" => DnssecStatus::Insecure,
                "bogus" => DnssecStatus::Bogus,
                _ => DnssecStatus::Indeterminate,
            };
            
            let rebind_stripped = rebind_val != 0;
            
            Ok(QueryLogEntry {
                timestamp,
                src_addr,
                domain,
                query_type,
                path,
                transport,
                rescode,
                latency_us: latency_us as u64,
                dnssec,
                rebind_stripped,
            })
        }).map_err(|e| format!("query execution failed: {e}"))?;
        
        let mut results = Vec::new();
        for row in rows {
            if let Ok(entry) = row {
                results.push(entry);
            }
        }
        
        Ok(results)
    }

    fn len(&self) -> usize {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM query_logs", [], |row| row.get(0))
            .unwrap_or(0)
    }

    fn heap_bytes(&self) -> usize {
        0
    }
}

// ==========================================
// 3. CORE QUERYLOG MANAGER
// ==========================================
pub struct QueryLog {
    tx: Option<mpsc::Sender<QueryLogEntry>>,
    backend: Option<Arc<dyn QueryLogBackend>>,
    enabled: bool,
}

impl QueryLog {
    pub fn new(config: &crate::config::QueryLogConfig, data_dir: &Path) -> Self {
        if !config.enabled {
            return QueryLog {
                tx: None,
                backend: None,
                enabled: false,
            };
        }

        let backend: Arc<dyn QueryLogBackend> = match config.db_type.as_str() {
            "sqlite" => {
                let path = if Path::new(&config.sqlite_path).is_absolute() {
                    PathBuf::from(&config.sqlite_path)
                } else {
                    data_dir.join(&config.sqlite_path)
                };
                match SqliteBackend::new(&path) {
                    Ok(b) => Arc::new(b),
                    Err(e) => {
                        error!("failed to create sqlite backend: {e}. Falling back to memory.");
                        Arc::new(MemoryBackend::new(1000))
                    }
                }
            }
            _ => {
                Arc::new(MemoryBackend::new(1000))
            }
        };

        let (tx, mut rx) = mpsc::channel::<QueryLogEntry>(10000);
        let backend_clone = backend.clone();
        let batch_size = config.buffer_size;
        let flush_interval = Duration::from_millis(config.flush_interval_ms);

        tokio::spawn(async move {
            let mut buffer = Vec::with_capacity(batch_size);
            let mut last_flush = std::time::Instant::now();

            loop {
                let elapsed = last_flush.elapsed();
                let timeout = flush_interval.checked_sub(elapsed).unwrap_or(Duration::from_millis(10));

                tokio::select! {
                    Some(entry) = rx.recv() => {
                        buffer.push(entry);
                        if buffer.len() >= batch_size {
                            if let Err(e) = backend_clone.write_batch(&buffer) {
                                error!("failed to write query log batch: {e}");
                            }
                            buffer.clear();
                            last_flush = std::time::Instant::now();
                        }
                    }
                    _ = tokio::time::sleep(timeout) => {
                        if !buffer.is_empty() {
                            if let Err(e) = backend_clone.write_batch(&buffer) {
                                error!("failed to write query log batch (timeout): {e}");
                            }
                            buffer.clear();
                            last_flush = std::time::Instant::now();
                        }
                    }
                }
            }
        });

        QueryLog {
            tx: Some(tx),
            backend: Some(backend),
            enabled: true,
        }
    }

    pub fn new_memory(capacity: usize) -> Self {
        let backend = Arc::new(MemoryBackend::new(capacity));
        let (tx, mut rx) = mpsc::channel::<QueryLogEntry>(10000);
        let backend_clone = backend.clone();
        
        tokio::spawn(async move {
            while let Some(entry) = rx.recv().await {
                let _ = backend_clone.write_batch(&[entry]);
            }
        });

        QueryLog {
            tx: Some(tx),
            backend: Some(backend),
            enabled: true,
        }
    }

    pub fn push(&self, entry: QueryLogEntry) {
        if !self.enabled {
            return;
        }
        if let Some(ref tx) = self.tx {
            let _ = tx.try_send(entry);
        }
    }

    pub fn query(&self, filter: &QueryLogFilter) -> Vec<QueryLogEntry> {
        if !self.enabled {
            return Vec::new();
        }
        if let Some(ref backend) = self.backend {
            backend.query(filter).unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    pub fn len(&self) -> usize {
        if !self.enabled {
            return 0;
        }
        self.backend.as_ref().map(|b| b.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn heap_bytes(&self) -> usize {
        if !self.enabled {
            return 0;
        }
        self.backend.as_ref().map(|b| b.heap_bytes()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heap_bytes_grows_with_entries() {
        let log = QueryLog::new_memory(100);
        let empty = log.heap_bytes();
        log.push(QueryLogEntry {
            timestamp: SystemTime::now(),
            src_addr: "127.0.0.1:1234".parse().unwrap(),
            domain: "example.com".into(),
            query_type: QueryType::A,
            path: QueryPath::Forwarded,
            transport: Transport::Udp,
            rescode: ResultCode::NOERROR,
            latency_us: 500,
            dnssec: DnssecStatus::Indeterminate,
            rebind_stripped: false,
        });
        
        std::thread::sleep(Duration::from_millis(50));
        assert!(log.heap_bytes() > empty);
    }
}

