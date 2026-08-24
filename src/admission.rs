//! Aggregate admission control for cache-miss resolutions (issue #230).
//!
//! In-flight coalescing merges equal `(qname, qtype)` queries, so a flood of
//! *distinct* names slips past it and each name buys a task, an upstream
//! socket and, in recursive mode, a whole delegation walk. Per-resolution
//! budgets bound each of those individually and none of them collectively.
//!
//! This is the one ceiling every transport shares: UDP, TCP, DoT and DoH all
//! reach remote resolution through `ctx::resolve_remote`, which admits here.

use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::{Semaphore, SemaphorePermit};

pub struct ResolutionAdmission {
    permits: Semaphore,
    limit: usize,
    peak: AtomicUsize,
}

impl ResolutionAdmission {
    pub fn new(limit: usize) -> Self {
        Self {
            permits: Semaphore::new(Self::capacity(limit)),
            limit,
            peak: AtomicUsize::new(0),
        }
    }

    fn capacity(limit: usize) -> usize {
        if limit == 0 {
            Semaphore::MAX_PERMITS
        } else {
            limit
        }
    }

    /// A permit, or `None` when the resolver is already at capacity. Never
    /// queues: a waiter list is itself memory an attacker gets to grow, and
    /// a query held behind one is a query whose client has already retried.
    pub fn try_admit(&self) -> Option<SemaphorePermit<'_>> {
        let permit = self.permits.try_acquire().ok()?;
        self.peak.fetch_max(self.active(), Ordering::Relaxed);
        Some(permit)
    }

    pub fn active(&self) -> usize {
        Self::capacity(self.limit) - self.permits.available_permits()
    }

    pub fn peak(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    pub fn limit(&self) -> usize {
        self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_up_to_the_limit_then_refuses() {
        let admission = ResolutionAdmission::new(2);
        let a = admission.try_admit().expect("first");
        let b = admission.try_admit().expect("second");
        assert!(admission.try_admit().is_none(), "third is over the ceiling");
        assert_eq!(admission.active(), 2);

        drop(a);
        assert_eq!(admission.active(), 1);
        assert!(
            admission.try_admit().is_some(),
            "a freed permit is reusable"
        );
        drop(b);
    }

    #[test]
    fn peak_records_the_high_water_mark() {
        let admission = ResolutionAdmission::new(4);
        let held: Vec<_> = (0..3).filter_map(|_| admission.try_admit()).collect();
        assert_eq!(admission.peak(), 3);
        drop(held);
        assert_eq!(admission.active(), 0);
        assert_eq!(admission.peak(), 3, "peak survives the permits it recorded");
    }

    #[test]
    fn zero_disables_the_ceiling() {
        let admission = ResolutionAdmission::new(0);
        let held: Vec<_> = (0..1000).filter_map(|_| admission.try_admit()).collect();
        assert_eq!(held.len(), 1000);
        assert_eq!(admission.active(), 1000);
        assert_eq!(admission.limit(), 0);
    }
}
