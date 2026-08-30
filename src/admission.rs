//! Aggregate admission control for cache-miss resolutions (issue #230).
//!
//! In-flight coalescing merges equal `(qname, qtype)` queries, so a flood of
//! *distinct* names slips past it and each name buys a task, an upstream
//! socket and, in recursive mode, a whole delegation walk. Per-resolution
//! budgets bound each of those individually and none of them collectively.
//!
//! This is the one ceiling every transport shares: UDP, TCP, DoT and DoH all
//! reach remote resolution through `ctx::resolve_remote`, which admits here.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Ceiling on how long one charge may hold its permit. The recursive budget
/// bounds *queries* (48), not *time*, so nameservers that answer slowly but
/// do answer stretch a single resolution to tens of seconds — long enough
/// that a few hundred such names pin the whole ceiling while every honest
/// client is turned away. Well past any answer a client still waits for.
pub const RESOLUTION_DEADLINE: Duration = Duration::from_secs(10);

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

/// One charge per client query, not per step. A CNAME chain and the DNSSEC
/// validation that follows it are the tail of the resolution that started
/// them: charging each step separately lets a single name spend several
/// permits, makes long chains likelier to be refused than short ones, and
/// turns a query away halfway through work already paid for — throwing that
/// work away is amplification, not a ceiling.
#[derive(Default)]
pub struct QueryAdmission(Option<OwnedSemaphorePermit>);

impl QueryAdmission {
    /// True once this query holds a permit. Idempotent: later steps of the
    /// same query ride the charge the first cache miss took.
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
        assert_eq!(admission.active(), 0);
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
