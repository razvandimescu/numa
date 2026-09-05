use std::time::{Duration, SystemTime};

/// Exclusive upper bounds in milliseconds for end-to-end query latency
/// (client request received → response serialized).
///
/// Each completed query lands in exactly one bucket: `< bounds[0]`,
/// `< bounds[1]`, …, and `≥ bounds[last]`.
///
/// This is the only list to edit when changing the histogram — counters,
/// logs, `/stats`, and the dashboard all derive from it.
pub const LATENCY_BOUNDS_MS: &[u64] = &[1, 5, 10, 25, 50, 100, 250, 500, 1000];

fn format_latency_bound(ms: u64) -> String {
    if ms >= 1_000 && ms.is_multiple_of(1_000) {
        format!("{}s", ms / 1_000)
    } else {
        format!("{ms}ms")
    }
}

fn latency_bucket_label(le_ms: Option<u64>) -> String {
    match le_ms {
        Some(ms) => format!("<{}", format_latency_bound(ms)),
        None => format!(
            "≥{}",
            format_latency_bound(*LATENCY_BOUNDS_MS.last().unwrap_or(&0))
        ),
    }
}

/// One histogram bucket. `le_ms = None` is the overflow (`≥` last bound).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatencyBucket {
    pub le_ms: Option<u64>,
    pub count: u64,
}

impl LatencyBucket {
    pub fn label(&self) -> String {
        latency_bucket_label(self.le_ms)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatencyBuckets {
    counts: Vec<u64>,
}

impl Default for LatencyBuckets {
    fn default() -> Self {
        Self {
            counts: vec![0; LATENCY_BOUNDS_MS.len() + 1],
        }
    }
}

impl LatencyBuckets {
    pub fn record(&mut self, latency: Duration) {
        let us = latency.as_micros();
        let idx = LATENCY_BOUNDS_MS
            .iter()
            .position(|&ms| us < ms as u128 * 1_000)
            .unwrap_or(LATENCY_BOUNDS_MS.len());
        if let Some(slot) = self.counts.get_mut(idx) {
            *slot += 1;
        }
    }

    pub fn total(&self) -> u64 {
        self.counts.iter().sum()
    }

    pub fn buckets(&self) -> Vec<LatencyBucket> {
        let mut out: Vec<LatencyBucket> = LATENCY_BOUNDS_MS
            .iter()
            .enumerate()
            .map(|(i, &ms)| LatencyBucket {
                le_ms: Some(ms),
                count: self.counts.get(i).copied().unwrap_or(0),
            })
            .collect();
        out.push(LatencyBucket {
            le_ms: None,
            count: self.counts.last().copied().unwrap_or(0),
        });
        out
    }

    pub fn summary(&self) -> String {
        self.buckets()
            .into_iter()
            .map(|b| format!("{} {}", b.label(), b.count))
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn count_le_ms(&self, le_ms: Option<u64>) -> u64 {
        self.buckets()
            .into_iter()
            .find(|b| b.le_ms == le_ms)
            .map(|b| b.count)
            .unwrap_or(0)
    }
}

/// Returns the process memory footprint in bytes, or 0 if unavailable.
/// macOS: phys_footprint (matches Activity Monitor). Linux: RSS from /proc/self/statm.
/// Windows: WorkingSetSize (matches Task Manager).
pub fn process_memory_bytes() -> usize {
    #[cfg(target_os = "macos")]
    {
        macos_rss()
    }
    #[cfg(target_os = "linux")]
    {
        linux_rss()
    }
    #[cfg(windows)]
    {
        windows_working_set()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
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

#[cfg(windows)]
fn windows_working_set() -> usize {
    use std::mem;
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    let mut info: PROCESS_MEMORY_COUNTERS = unsafe { mem::zeroed() };
    let cb = mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    let ok = unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut info, cb) };
    if ok != 0 {
        info.WorkingSetSize
    } else {
        0
    }
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
    upstream_transport_udp: u64,
    upstream_transport_tcp: u64,
    upstream_transport_doh: u64,
    upstream_transport_dot: u64,
    upstream_transport_odoh: u64,
    pub(crate) proxy_v2_accepted: u64,
    pub(crate) proxy_v2_rejected_untrusted: u64,
    pub(crate) proxy_v2_rejected_signature: u64,
    pub(crate) proxy_v2_local_command: u64,
    pub(crate) proxy_v2_timeout: u64,
    rebind_stripped: u64,
    latency: LatencyBuckets,
    queries_refused: u64,
    started_at: SystemTime,
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

/// Wire protocol used for a forwarded upstream call. Orthogonal to
/// `QueryPath`: the path answers "where the answer came from"; this answers
/// "over what wire we spoke to the forwarder." Callers pass
/// `Option<UpstreamTransport>` — `None` for resolutions that never touched
/// a forwarder (cache/local/blocked) or for recursive mode, which has its
/// own counter via `QueryPath::Recursive`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UpstreamTransport {
    Udp,
    Tcp,
    Doh,
    Dot,
    Odoh,
}

impl UpstreamTransport {
    pub fn as_str(&self) -> &'static str {
        match self {
            UpstreamTransport::Udp => "UDP",
            UpstreamTransport::Tcp => "TCP",
            UpstreamTransport::Doh => "DOH",
            UpstreamTransport::Dot => "DOT",
            UpstreamTransport::Odoh => "ODOH",
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
    /// Turned away by aggregate admission control before any remote work.
    Refused,
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
            QueryPath::Refused => "REFUSED",
        }
    }

    /// Paths returning trusted local data (zones, overrides, sinkhole) — exempt
    /// from rebind protection. Exhaustive on purpose: a new `QueryPath` variant
    /// must choose a side here, so an untrusted source fails closed.
    pub fn returns_trusted_local_data(&self) -> bool {
        match self {
            QueryPath::Local | QueryPath::Overridden | QueryPath::Blocked => true,
            QueryPath::Cached
            | QueryPath::Forwarded
            | QueryPath::Upstream
            | QueryPath::Recursive
            | QueryPath::Coalesced
            | QueryPath::UpstreamError
            | QueryPath::Refused => false,
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
        } else if s.eq_ignore_ascii_case("REFUSED") {
            Some(QueryPath::Refused)
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
            upstream_transport_udp: 0,
            upstream_transport_tcp: 0,
            upstream_transport_doh: 0,
            upstream_transport_dot: 0,
            upstream_transport_odoh: 0,
            proxy_v2_accepted: 0,
            proxy_v2_rejected_untrusted: 0,
            proxy_v2_rejected_signature: 0,
            proxy_v2_local_command: 0,
            proxy_v2_timeout: 0,
            rebind_stripped: 0,
            latency: LatencyBuckets::default(),
            queries_refused: 0,
            started_at: SystemTime::now(),
        }
    }

    /// One per affected query (not per stripped RR), matching the other
    /// per-query counters in `queries.*`.
    pub fn record_rebind_stripped(&mut self) {
        self.rebind_stripped += 1;
    }

    pub fn record(
        &mut self,
        path: QueryPath,
        transport: Transport,
        upstream_transport: Option<UpstreamTransport>,
        latency: Duration,
    ) -> u64 {
        self.queries_total += 1;
        self.latency.record(latency);
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
            QueryPath::Refused => self.queries_refused += 1,
        }
        match transport {
            Transport::Udp => self.transport_udp += 1,
            Transport::Tcp => self.transport_tcp += 1,
            Transport::Dot => self.transport_dot += 1,
            Transport::Doh => self.transport_doh += 1,
        }
        if let Some(ut) = upstream_transport {
            match ut {
                UpstreamTransport::Udp => self.upstream_transport_udp += 1,
                UpstreamTransport::Tcp => self.upstream_transport_tcp += 1,
                UpstreamTransport::Doh => self.upstream_transport_doh += 1,
                UpstreamTransport::Dot => self.upstream_transport_dot += 1,
                UpstreamTransport::Odoh => self.upstream_transport_odoh += 1,
            }
        }
        self.queries_total
    }

    pub fn total(&self) -> u64 {
        self.queries_total
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().unwrap_or_default().as_secs()
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
            upstream_transport_udp: self.upstream_transport_udp,
            upstream_transport_tcp: self.upstream_transport_tcp,
            upstream_transport_doh: self.upstream_transport_doh,
            upstream_transport_dot: self.upstream_transport_dot,
            upstream_transport_odoh: self.upstream_transport_odoh,
            proxy_v2_accepted: self.proxy_v2_accepted,
            proxy_v2_rejected_untrusted: self.proxy_v2_rejected_untrusted,
            proxy_v2_rejected_signature: self.proxy_v2_rejected_signature,
            proxy_v2_local_command: self.proxy_v2_local_command,
            proxy_v2_timeout: self.proxy_v2_timeout,
            rebind_stripped: self.rebind_stripped,
            latency: self.latency.clone(),
            refused: self.queries_refused,
        }
    }

    pub fn log_summary(&self) {
        let uptime = self.started_at.elapsed().unwrap_or_default();
        let hours = uptime.as_secs() / 3600;
        let mins = (uptime.as_secs() % 3600) / 60;
        let secs = uptime.as_secs() % 60;

        log::info!(
            "STATS | uptime {}h{}m{}s | total {} | fwd {} | upstream {} | recursive {} | coalesced {} | cached {} | local {} | override {} | blocked {} | errors {} | up-udp {} | up-tcp {} | up-doh {} | up-dot {} | up-odoh {} | rebind {} | latency {}",
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
            self.upstream_transport_udp,
            self.upstream_transport_tcp,
            self.upstream_transport_doh,
            self.upstream_transport_dot,
            self.upstream_transport_odoh,
            self.rebind_stripped,
            self.latency.summary(),
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
    pub upstream_transport_udp: u64,
    pub upstream_transport_tcp: u64,
    pub upstream_transport_doh: u64,
    pub upstream_transport_dot: u64,
    pub upstream_transport_odoh: u64,
    pub proxy_v2_accepted: u64,
    pub proxy_v2_rejected_untrusted: u64,
    pub proxy_v2_rejected_signature: u64,
    pub proxy_v2_local_command: u64,
    pub proxy_v2_timeout: u64,
    pub rebind_stripped: u64,
    pub latency: LatencyBuckets,
    pub refused: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_buckets_are_exclusive() {
        let mut b = LatencyBuckets::default();
        b.record(Duration::from_micros(999));
        b.record(Duration::from_millis(1));
        b.record(Duration::from_millis(4));
        b.record(Duration::from_millis(9));
        b.record(Duration::from_millis(24));
        b.record(Duration::from_millis(49));
        b.record(Duration::from_millis(99));
        b.record(Duration::from_millis(249));
        b.record(Duration::from_millis(499));
        b.record(Duration::from_millis(999));
        b.record(Duration::from_secs(1));
        assert_eq!(b.count_le_ms(Some(1)), 1);
        assert_eq!(b.count_le_ms(Some(5)), 2);
        assert_eq!(b.count_le_ms(Some(10)), 1);
        assert_eq!(b.count_le_ms(Some(25)), 1);
        assert_eq!(b.count_le_ms(Some(50)), 1);
        assert_eq!(b.count_le_ms(Some(100)), 1);
        assert_eq!(b.count_le_ms(Some(250)), 1);
        assert_eq!(b.count_le_ms(Some(500)), 1);
        assert_eq!(b.count_le_ms(Some(1000)), 1);
        assert_eq!(b.count_le_ms(None), 1);
        assert_eq!(b.total(), 11);
        assert_eq!(b.buckets().len(), LATENCY_BOUNDS_MS.len() + 1);
    }

    #[test]
    fn record_increments_matching_latency_bucket() {
        let mut stats = ServerStats::new();
        stats.record(
            QueryPath::Cached,
            Transport::Udp,
            None,
            Duration::from_micros(120),
        );
        stats.record(
            QueryPath::Upstream,
            Transport::Udp,
            Some(UpstreamTransport::Udp),
            Duration::from_millis(42),
        );
        let snap = stats.snapshot();
        assert_eq!(snap.total, 2);
        assert_eq!(snap.cached, 1);
        assert_eq!(snap.upstream, 1);
        assert_eq!(snap.latency.count_le_ms(Some(1)), 1);
        assert_eq!(snap.latency.count_le_ms(Some(50)), 1);
        assert_eq!(snap.latency.total(), 2);
    }
}
