use std::time::Instant;

pub struct ServerStats {
    queries_total: u64,
    queries_forwarded: u64,
    queries_cached: u64,
    queries_blocked: u64,
    queries_local: u64,
    upstream_errors: u64,
    started_at: Instant,
}

pub enum QueryPath {
    Local,
    Cached,
    Forwarded,
    Blocked,
    UpstreamError,
}

impl QueryPath {
    pub fn as_str(&self) -> &'static str {
        match self {
            QueryPath::Local => "LOCAL",
            QueryPath::Cached => "CACHED",
            QueryPath::Forwarded => "FORWARD",
            QueryPath::Blocked => "BLOCKED",
            QueryPath::UpstreamError => "SERVFAIL",
        }
    }
}

impl ServerStats {
    pub fn new() -> Self {
        ServerStats {
            queries_total: 0,
            queries_forwarded: 0,
            queries_cached: 0,
            queries_blocked: 0,
            queries_local: 0,
            upstream_errors: 0,
            started_at: Instant::now(),
        }
    }

    pub fn record(&mut self, path: QueryPath) -> u64 {
        self.queries_total += 1;
        match path {
            QueryPath::Local => self.queries_local += 1,
            QueryPath::Cached => self.queries_cached += 1,
            QueryPath::Forwarded => self.queries_forwarded += 1,
            QueryPath::Blocked => self.queries_blocked += 1,
            QueryPath::UpstreamError => self.upstream_errors += 1,
        }
        self.queries_total
    }

    pub fn total(&self) -> u64 {
        self.queries_total
    }

    pub fn log_summary(&self) {
        let uptime = self.started_at.elapsed();
        let hours = uptime.as_secs() / 3600;
        let mins = (uptime.as_secs() % 3600) / 60;
        let secs = uptime.as_secs() % 60;

        log::info!(
            "STATS | uptime {}h{}m{}s | total {} | fwd {} | cached {} | local {} | blocked {} | errors {}",
            hours, mins, secs,
            self.queries_total,
            self.queries_forwarded,
            self.queries_cached,
            self.queries_local,
            self.queries_blocked,
            self.upstream_errors,
        );
    }
}
