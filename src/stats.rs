use std::time::Instant;

/// Returns the process memory footprint in bytes, or 0 if unavailable.
/// macOS: phys_footprint (matches Activity Monitor). Linux: RSS from /proc/self/statm.
pub fn process_memory_bytes() -> usize {
    #[cfg(target_os = "macos")]
    {
        macos_rss()
    }
    #[cfg(target_os = "linux")]
    {
        linux_rss()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        0
    }
}

#[cfg(target_os = "macos")]
fn macos_rss() -> usize {
    use std::mem;
    extern "C" {
        fn mach_task_self() -> u32;
        fn task_info(
            target_task: u32,
            flavor: u32,
            task_info_out: *mut TaskVmInfo,
            task_info_count: *mut u32,
        ) -> i32;
    }
    // Partial task_vm_info_data_t — only fields up to phys_footprint.
    #[repr(C)]
    struct TaskVmInfo {
        virtual_size: u64,
        region_count: i32,
        page_size: i32,
        resident_size: u64,
        resident_size_peak: u64,
        device: u64,
        device_peak: u64,
        internal: u64,
        internal_peak: u64,
        external: u64,
        external_peak: u64,
        reusable: u64,
        reusable_peak: u64,
        purgeable_volatile_pmap: u64,
        purgeable_volatile_resident: u64,
        purgeable_volatile_virtual: u64,
        compressed: u64,
        compressed_peak: u64,
        compressed_lifetime: u64,
        phys_footprint: u64,
    }
    const TASK_VM_INFO: u32 = 22;
    let mut info: TaskVmInfo = unsafe { mem::zeroed() };
    let mut count = (mem::size_of::<TaskVmInfo>() / mem::size_of::<u32>()) as u32;
    let kr = unsafe { task_info(mach_task_self(), TASK_VM_INFO, &mut info, &mut count) };
    if kr == 0 {
        info.phys_footprint as usize
    } else {
        0
    }
}

#[cfg(target_os = "linux")]
fn linux_rss() -> usize {
    extern "C" {
        fn sysconf(name: i32) -> i64;
    }
    const SC_PAGESIZE: i32 = 30; // x86_64 + aarch64; differs on mips (28), sparc (29)
    let page_size = unsafe { sysconf(SC_PAGESIZE) };
    let page_size = if page_size > 0 {
        page_size as usize
    } else {
        4096
    };

    if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
        if let Some(rss_pages) = statm.split_whitespace().nth(1) {
            if let Ok(pages) = rss_pages.parse::<usize>() {
                return pages * page_size;
            }
        }
    }
    0
}

pub struct ServerStats {
    queries_total: u64,
    queries_forwarded: u64,
    queries_upstream: u64,
    queries_recursive: u64,
    queries_coalesced: u64,
    queries_cached: u64,
    queries_blocked: u64,
    queries_local: u64,
    queries_overridden: u64,
    upstream_errors: u64,
    transport_udp: u64,
    transport_tcp: u64,
    transport_dot: u64,
    transport_doh: u64,
    started_at: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
    Dot,
    Doh,
}

impl Transport {
    pub fn as_str(&self) -> &'static str {
        match self {
            Transport::Udp => "UDP",
            Transport::Tcp => "TCP",
            Transport::Dot => "DOT",
            Transport::Doh => "DOH",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryPath {
    Local,
    Cached,
    /// Matched a `[[forwarding]]` suffix rule.
    Forwarded,
    /// Resolved via the default `[upstream]` pool (no suffix match).
    Upstream,
    Recursive,
    Coalesced,
    Blocked,
    Overridden,
    UpstreamError,
}

impl QueryPath {
    pub fn as_str(&self) -> &'static str {
        match self {
            QueryPath::Local => "LOCAL",
            QueryPath::Cached => "CACHED",
            QueryPath::Forwarded => "FORWARD",
            QueryPath::Upstream => "UPSTREAM",
            QueryPath::Recursive => "RECURSIVE",
            QueryPath::Coalesced => "COALESCED",
            QueryPath::Blocked => "BLOCKED",
            QueryPath::Overridden => "OVERRIDE",
            QueryPath::UpstreamError => "SERVFAIL",
        }
    }

    pub fn parse_str(s: &str) -> Option<QueryPath> {
        if s.eq_ignore_ascii_case("LOCAL") {
            Some(QueryPath::Local)
        } else if s.eq_ignore_ascii_case("CACHED") {
            Some(QueryPath::Cached)
        } else if s.eq_ignore_ascii_case("FORWARD") {
            Some(QueryPath::Forwarded)
        } else if s.eq_ignore_ascii_case("UPSTREAM") {
            Some(QueryPath::Upstream)
        } else if s.eq_ignore_ascii_case("RECURSIVE") {
            Some(QueryPath::Recursive)
        } else if s.eq_ignore_ascii_case("COALESCED") {
            Some(QueryPath::Coalesced)
        } else if s.eq_ignore_ascii_case("BLOCKED") {
            Some(QueryPath::Blocked)
        } else if s.eq_ignore_ascii_case("OVERRIDE") {
            Some(QueryPath::Overridden)
        } else if s.eq_ignore_ascii_case("SERVFAIL") {
            Some(QueryPath::UpstreamError)
        } else {
            None
        }
    }
}

impl Default for ServerStats {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerStats {
    pub fn new() -> Self {
        ServerStats {
            queries_total: 0,
            queries_forwarded: 0,
            queries_upstream: 0,
            queries_recursive: 0,
            queries_coalesced: 0,
            queries_cached: 0,
            queries_blocked: 0,
            queries_local: 0,
            queries_overridden: 0,
            upstream_errors: 0,
            transport_udp: 0,
            transport_tcp: 0,
            transport_dot: 0,
            transport_doh: 0,
            started_at: Instant::now(),
        }
    }

    pub fn record(&mut self, path: QueryPath, transport: Transport) -> u64 {
        self.queries_total += 1;
        match path {
            QueryPath::Local => self.queries_local += 1,
            QueryPath::Cached => self.queries_cached += 1,
            QueryPath::Forwarded => self.queries_forwarded += 1,
            QueryPath::Upstream => self.queries_upstream += 1,
            QueryPath::Recursive => self.queries_recursive += 1,
            QueryPath::Coalesced => self.queries_coalesced += 1,
            QueryPath::Blocked => self.queries_blocked += 1,
            QueryPath::Overridden => self.queries_overridden += 1,
            QueryPath::UpstreamError => self.upstream_errors += 1,
        }
        match transport {
            Transport::Udp => self.transport_udp += 1,
            Transport::Tcp => self.transport_tcp += 1,
            Transport::Dot => self.transport_dot += 1,
            Transport::Doh => self.transport_doh += 1,
        }
        self.queries_total
    }

    pub fn total(&self) -> u64 {
        self.queries_total
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            uptime_secs: self.uptime_secs(),
            total: self.queries_total,
            forwarded: self.queries_forwarded,
            upstream: self.queries_upstream,
            recursive: self.queries_recursive,
            coalesced: self.queries_coalesced,
            cached: self.queries_cached,
            local: self.queries_local,
            overridden: self.queries_overridden,
            blocked: self.queries_blocked,
            errors: self.upstream_errors,
            transport_udp: self.transport_udp,
            transport_tcp: self.transport_tcp,
            transport_dot: self.transport_dot,
            transport_doh: self.transport_doh,
        }
    }

    pub fn log_summary(&self) {
        let uptime = self.started_at.elapsed();
        let hours = uptime.as_secs() / 3600;
        let mins = (uptime.as_secs() % 3600) / 60;
        let secs = uptime.as_secs() % 60;

        log::info!(
            "STATS | uptime {}h{}m{}s | total {} | fwd {} | upstream {} | recursive {} | coalesced {} | cached {} | local {} | override {} | blocked {} | errors {}",
            hours, mins, secs,
            self.queries_total,
            self.queries_forwarded,
            self.queries_upstream,
            self.queries_recursive,
            self.queries_coalesced,
            self.queries_cached,
            self.queries_local,
            self.queries_overridden,
            self.queries_blocked,
            self.upstream_errors,
        );
    }
}

pub struct StatsSnapshot {
    pub uptime_secs: u64,
    pub total: u64,
    pub forwarded: u64,
    pub upstream: u64,
    pub recursive: u64,
    pub coalesced: u64,
    pub cached: u64,
    pub local: u64,
    pub overridden: u64,
    pub blocked: u64,
    pub errors: u64,
    pub transport_udp: u64,
    pub transport_tcp: u64,
    pub transport_dot: u64,
    pub transport_doh: u64,
}
