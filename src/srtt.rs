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

    /// Apply time-based decay: each DECAY_AFTER_SECS period halves distance to INITIAL.
    fn decayed_srtt(entry: &SrttEntry) -> u64 {
        let age_secs = entry.updated_at.elapsed().as_secs();
        if age_secs > DECAY_AFTER_SECS {
            let periods = (age_secs / DECAY_AFTER_SECS).min(8);
            let mut srtt = entry.srtt_ms;
            for _ in 0..periods {
                srtt = (srtt + INITIAL_SRTT_MS) / 2;
            }
            srtt
        } else {
            entry.srtt_ms
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
