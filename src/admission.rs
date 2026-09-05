//! Aggregate admission control for cache-miss resolutions (issue #230).
//!
//! Coalescing merges equal `(qname, qtype)` queries, so a flood of *distinct*
//! names slips past it: each name buys a task, an upstream socket and, in
//! recursive mode, a whole delegation walk. Per-resolution budgets bound each
//! of those individually and none of them collectively. This is the one
//! ceiling every transport shares, reached through `ctx::resolve_remote`.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub struct ResolutionAdmission {
    permits: Arc<Semaphore>,
    limit: usize,
}

impl ResolutionAdmission {
    pub fn new(limit: usize) -> Self {
        let limit = limit.min(Semaphore::MAX_PERMITS);
        Self {
            permits: Arc::new(Semaphore::new(limit)),
            limit,
        }
    }

    /// Never queues: a waiter list is itself memory an attacker gets to grow,
    /// and a query held behind one is a query whose client has already
    /// retried.
    fn try_admit(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.permits).try_acquire_owned().ok()
    }

    pub fn active(&self) -> usize {
        self.limit - self.permits.available_permits()
    }

    pub fn limit(&self) -> usize {
        self.limit
    }
}

/// One charge per client query, not per step: a CNAME chain and the DNSSEC
/// validation that follows it are the tail of the resolution that started
/// them, and turning a query away halfway through work already paid for is
/// amplification, not a ceiling.
#[derive(Default)]
pub struct QueryAdmission(Option<OwnedSemaphorePermit>);

impl QueryAdmission {
    /// Idempotent: later steps of the same query ride the first charge.
    pub fn admit(&mut self, admission: &ResolutionAdmission) -> bool {
        if self.0.is_none() {
            self.0 = admission.try_admit();
        }
        self.0.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_oversized_limit_clamps_instead_of_panicking() {
        let admission = ResolutionAdmission::new(usize::MAX);
        assert_eq!(admission.limit(), Semaphore::MAX_PERMITS);
        let _held = admission.try_admit().expect("admits");
        assert_eq!(admission.active(), 1);
    }

    #[test]
    fn a_query_is_charged_once_however_many_steps_it_takes() {
        let admission = ResolutionAdmission::new(1);
        let mut query = QueryAdmission::default();

        assert!(query.admit(&admission), "the first cache miss is charged");
        assert!(
            query.admit(&admission),
            "the CNAME target rides that charge"
        );
        assert!(query.admit(&admission), "so does validation after it");
        assert_eq!(admission.active(), 1, "one query, one permit");

        assert!(
            !QueryAdmission::default().admit(&admission),
            "a second query is still bound by the ceiling"
        );

        drop(query);
        assert_eq!(admission.active(), 0, "the permit comes back");
    }

    #[test]
    fn a_refused_query_holds_nothing() {
        let admission = ResolutionAdmission::new(1);
        let mut held = QueryAdmission::default();
        assert!(held.admit(&admission));

        let mut refused = QueryAdmission::default();
        assert!(!refused.admit(&admission));
        drop(refused);
        assert_eq!(
            admission.active(),
            1,
            "a refusal frees no permit it never took"
        );
        drop(held);
    }
}
