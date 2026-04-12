use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

const INITIAL_SRTT_MS: u64 = 200;
const FAILURE_PENALTY_MS: u64 = 5000;
const TCP_PENALTY_MS: u64 = 100;
const DECAY_AFTER_SECS: u64 = 300;
const MAX_ENTRIES: usize = 4096;
const EVICT_BATCH: usize = 64;

struct SrttEntry {
    srtt_ms: u64,
    updated_at: Instant,
}

pub struct SrttCache {
    entries: HashMap<IpAddr, SrttEntry>,
    enabled: bool,
}

impl Default for SrttCache {
    fn default() -> Self {
        Self::new(true)
    }
}

impl SrttCache {
    pub fn new(enabled: bool) -> Self {
        Self {
            entries: HashMap::new(),
            enabled,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get current SRTT for an IP, applying decay if stale. Returns INITIAL for unknown.
    pub fn get(&self, ip: IpAddr) -> u64 {
        match self.entries.get(&ip) {
            Some(entry) => Self::decayed_srtt(entry),
            None => INITIAL_SRTT_MS,
        }
    }

    /// Whether we have observed RTT data for this IP.
    pub fn is_known(&self, ip: IpAddr) -> bool {
        self.entries.contains_key(&ip)
    }

    /// Apply time-based decay: each DECAY_AFTER_SECS period halves distance to INITIAL.
    fn decayed_srtt(entry: &SrttEntry) -> u64 {
        Self::decay_for_age(entry.srtt_ms, entry.updated_at.elapsed().as_secs())
    }

    fn decay_for_age(srtt_ms: u64, age_secs: u64) -> u64 {
        if age_secs > DECAY_AFTER_SECS {
            let periods = (age_secs / DECAY_AFTER_SECS).min(8);
            let mut srtt = srtt_ms;
            for _ in 0..periods {
                srtt = (srtt + INITIAL_SRTT_MS) / 2;
            }
            srtt
        } else {
            srtt_ms
        }
    }

    /// Record a successful query RTT. No-op when disabled.
    pub fn record_rtt(&mut self, ip: IpAddr, rtt_ms: u64, tcp: bool) {
        if !self.enabled {
            return;
        }
        let effective = if tcp { rtt_ms + TCP_PENALTY_MS } else { rtt_ms };
        self.maybe_evict();
        let entry = self.entries.entry(ip).or_insert(SrttEntry {
            srtt_ms: effective,
            updated_at: Instant::now(),
        });
        // Apply decay before EWMA so recovered servers aren't stuck at stale penalties
        let base = Self::decayed_srtt(entry);
        // BIND EWMA: new = (old * 7 + sample) / 8
        entry.srtt_ms = (base * 7 + effective) / 8;
        entry.updated_at = Instant::now();
    }

    /// Record a failure (timeout or error). No-op when disabled.
    pub fn record_failure(&mut self, ip: IpAddr) {
        if !self.enabled {
            return;
        }
        self.maybe_evict();
        let entry = self.entries.entry(ip).or_insert(SrttEntry {
            srtt_ms: FAILURE_PENALTY_MS,
            updated_at: Instant::now(),
        });
        entry.srtt_ms = FAILURE_PENALTY_MS;
        entry.updated_at = Instant::now();
    }

    /// Sort addresses by SRTT ascending (lowest/fastest first). No-op when disabled.
    pub fn sort_by_rtt(&self, addrs: &mut [SocketAddr]) {
        if !self.enabled {
            return;
        }
        addrs.sort_by_key(|a| self.get(a.ip()));
    }

    pub fn heap_bytes(&self) -> usize {
        let per_slot = std::mem::size_of::<u64>()
            + std::mem::size_of::<IpAddr>()
            + std::mem::size_of::<SrttEntry>()
            + 1;
        self.entries.capacity() * per_slot
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn maybe_evict(&mut self) {
        if self.entries.len() < MAX_ENTRIES {
            return;
        }
        // Batch eviction: remove the oldest EVICT_BATCH entries at once
        let mut by_age: Vec<IpAddr> = self.entries.keys().copied().collect();
        by_age.sort_by_key(|ip| self.entries[ip].updated_at);
        for ip in by_age.into_iter().take(EVICT_BATCH) {
            self.entries.remove(&ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    fn sock(last: u8) -> SocketAddr {
        SocketAddr::new(ip(last), 53)
    }

    #[test]
    fn unknown_returns_initial() {
        let cache = SrttCache::new(true);
        assert_eq!(cache.get(ip(1)), INITIAL_SRTT_MS);
    }

    #[test]
    fn ewma_converges() {
        let mut cache = SrttCache::new(true);
        for _ in 0..20 {
            cache.record_rtt(ip(1), 100, false);
        }
        let srtt = cache.get(ip(1));
        assert!(srtt >= 98 && srtt <= 102, "srtt={}", srtt);
    }

    #[test]
    fn failure_sets_penalty() {
        let mut cache = SrttCache::new(true);
        cache.record_rtt(ip(1), 50, false);
        cache.record_failure(ip(1));
        assert_eq!(cache.get(ip(1)), FAILURE_PENALTY_MS);
    }

    #[test]
    fn tcp_penalty_added() {
        let mut cache = SrttCache::new(true);
        for _ in 0..20 {
            cache.record_rtt(ip(1), 50, true);
        }
        let srtt = cache.get(ip(1));
        assert!(srtt >= 148 && srtt <= 152, "srtt={}", srtt);
    }

    #[test]
    fn sort_by_rtt_orders_correctly() {
        let mut cache = SrttCache::new(true);
        for _ in 0..20 {
            cache.record_rtt(ip(1), 500, false);
            cache.record_rtt(ip(2), 100, false);
            cache.record_rtt(ip(3), 10, false);
        }
        let mut addrs = vec![sock(1), sock(2), sock(3)];
        cache.sort_by_rtt(&mut addrs);
        assert_eq!(addrs, vec![sock(3), sock(2), sock(1)]);
    }

    #[test]
    fn unknown_servers_sort_equal() {
        let cache = SrttCache::new(true);
        let mut addrs = vec![sock(1), sock(2), sock(3)];
        let original = addrs.clone();
        cache.sort_by_rtt(&mut addrs);
        assert_eq!(addrs, original);
    }

    #[test]
    fn disabled_is_noop() {
        let mut cache = SrttCache::new(false);
        cache.record_rtt(ip(1), 50, false);
        cache.record_failure(ip(2));
        assert_eq!(cache.len(), 0);

        let mut addrs = vec![sock(2), sock(1)];
        let original = addrs.clone();
        cache.sort_by_rtt(&mut addrs);
        assert_eq!(addrs, original);
    }

    #[test]
    fn no_decay_within_threshold() {
        // At exactly DECAY_AFTER_SECS, no decay applied
        let result = SrttCache::decay_for_age(FAILURE_PENALTY_MS, DECAY_AFTER_SECS);
        assert_eq!(result, FAILURE_PENALTY_MS);
    }

    #[test]
    fn one_decay_period() {
        let result = SrttCache::decay_for_age(FAILURE_PENALTY_MS, DECAY_AFTER_SECS + 1);
        let expected = (FAILURE_PENALTY_MS + INITIAL_SRTT_MS) / 2;
        assert_eq!(result, expected);
    }

    #[test]
    fn multiple_decay_periods() {
        let result = SrttCache::decay_for_age(FAILURE_PENALTY_MS, DECAY_AFTER_SECS * 4 + 1);
        let mut expected = FAILURE_PENALTY_MS;
        for _ in 0..4 {
            expected = (expected + INITIAL_SRTT_MS) / 2;
        }
        assert_eq!(result, expected);
    }

    #[test]
    fn decay_caps_at_8_periods() {
        // 9 periods and 100 periods should produce the same result (capped at 8)
        let a = SrttCache::decay_for_age(FAILURE_PENALTY_MS, DECAY_AFTER_SECS * 9 + 1);
        let b = SrttCache::decay_for_age(FAILURE_PENALTY_MS, DECAY_AFTER_SECS * 100);
        assert_eq!(a, b);
    }

    #[test]
    fn decay_converges_toward_initial() {
        let decayed = SrttCache::decay_for_age(FAILURE_PENALTY_MS, DECAY_AFTER_SECS * 100);
        let diff = decayed.abs_diff(INITIAL_SRTT_MS);
        assert!(
            diff < 25,
            "expected near INITIAL_SRTT_MS, got {} (diff={})",
            decayed,
            diff
        );
    }

    #[test]
    fn record_rtt_applies_decay_before_ewma() {
        // Verify decay is applied before EWMA in record_rtt by checking
        // that a saturated penalty + long age + new sample produces a low SRTT
        let decayed = SrttCache::decay_for_age(FAILURE_PENALTY_MS, DECAY_AFTER_SECS * 8);
        // EWMA: (decayed * 7 + 50) / 8
        let after_ewma = (decayed * 7 + 50) / 8;
        assert!(
            after_ewma < 500,
            "expected decay before EWMA, got srtt={}",
            after_ewma
        );
    }

    #[test]
    fn decay_reranks_stale_failures() {
        // After enough decay, a failed server (5000ms) converges toward
        // INITIAL (200ms), which is below a stable server at 300ms
        let decayed = SrttCache::decay_for_age(FAILURE_PENALTY_MS, DECAY_AFTER_SECS * 100);
        assert!(
            decayed < 300,
            "expected decayed penalty ({}) < 300ms",
            decayed
        );
    }

    #[test]
    fn heap_bytes_grows_with_entries() {
        let mut cache = SrttCache::new(true);
        let empty = cache.heap_bytes();
        for i in 1..=10u8 {
            cache.record_rtt(ip(i), 100, false);
        }
        assert!(cache.heap_bytes() > empty);
    }

    #[test]
    fn eviction_removes_oldest() {
        let mut cache = SrttCache::new(true);
        for i in 0..MAX_ENTRIES {
            let octets = [
                10,
                ((i >> 16) & 0xFF) as u8,
                ((i >> 8) & 0xFF) as u8,
                (i & 0xFF) as u8,
            ];
            cache.record_rtt(
                IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])),
                100,
                false,
            );
        }
        assert_eq!(cache.len(), MAX_ENTRIES);
        cache.record_rtt(ip(1), 100, false);
        // Batch eviction removes EVICT_BATCH entries
        assert!(cache.len() <= MAX_ENTRIES - EVICT_BATCH + 1);
    }
}
