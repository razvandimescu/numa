//! Aggregate admission control for cache-miss resolutions (issue #230).
//!
//! In-flight coalescing merges equal `(qname, qtype)` queries, so a flood of
//! *distinct* names slips past it and each name buys a task, an upstream
//! socket and, in recursive mode, a whole delegation walk. Per-resolution
//! budgets bound each of those individually and none of them collectively.
//!
//! This is the one ceiling every transport shares: UDP, TCP, DoT and DoH all
//! reach remote resolution through `ctx::resolve_remote`, which admits here.

use tokio::sync::{Semaphore, SemaphorePermit};

pub struct ResolutionAdmission {
    permits: Semaphore,
    limit: usize,
}

impl ResolutionAdmission {
    pub fn new(limit: usize) -> Self {
        let limit = limit.min(Semaphore::MAX_PERMITS);
        Self {
            permits: Semaphore::new(limit),
            limit,
        }
    }

    /// A permit, or `None` when the resolver is already at capacity. Never
    /// queues: a waiter list is itself memory an attacker gets to grow, and
    /// a query held behind one is a query whose client has already retried.
    pub fn try_admit(&self) -> Option<SemaphorePermit<'_>> {
        self.permits.try_acquire().ok()
    }

    pub fn active(&self) -> usize {
        self.limit - self.permits.available_permits()
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
    fn an_oversized_limit_clamps_instead_of_panicking() {
        let admission = ResolutionAdmission::new(usize::MAX);
        assert_eq!(admission.limit(), Semaphore::MAX_PERMITS);
        let _held = admission.try_admit().expect("admits");
        assert_eq!(admission.active(), 1);
    }
}
