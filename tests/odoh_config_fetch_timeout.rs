//! The ODoH query budget must cover the whole exchange, including the target
//! config fetch. `attempt_query` wraps only the relay POST, and the production
//! client sets no `.timeout()` / `.connect_timeout()`, so a target whose TLS
//! handshake stalls hangs the query indefinitely.

use std::sync::Arc;
use std::time::{Duration, Instant};

use numa::forward::build_https_client;
use numa::odoh::{query_through_relay, OdohConfigCache};
use tokio::net::TcpListener;

const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Generous ceiling: whatever the fix bounds the fetch to, a stalled target
/// must not cost more than a couple of query budgets end to end.
const CEILING: Duration = Duration::from_secs(6);

const QUERY_WIRE: &[u8] =
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";

/// Accept connections and never send a byte, so a TLS client blocks forever
/// waiting for ServerHello.
async fn stalling_tls_endpoint() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });
    addr.to_string()
}

fn stalled_cache(target: String) -> Arc<OdohConfigCache> {
    Arc::new(OdohConfigCache::new(target, build_https_client()))
}

#[tokio::test]
async fn stalled_config_fetch_respects_query_timeout() {
    let cache = stalled_cache(stalling_tls_endpoint().await);
    let client = build_https_client();

    let start = Instant::now();
    let outcome = tokio::time::timeout(
        CEILING,
        query_through_relay(
            QUERY_WIRE,
            "https://relay.invalid/relay",
            "/dns-query",
            &client,
            &cache,
            QUERY_TIMEOUT,
        ),
    )
    .await;

    assert!(
        outcome.is_ok(),
        "query still hung after {CEILING:?} against a {QUERY_TIMEOUT:?} budget"
    );
    assert!(
        outcome.unwrap().is_err(),
        "a stalled target must not yield a config"
    );
    let elapsed = start.elapsed();
    assert!(
        elapsed < QUERY_TIMEOUT * 2,
        "returned in {elapsed:?}, well past the {QUERY_TIMEOUT:?} budget"
    );
}

/// `OdohConfigCache::get` holds `refresh_lock` across the fetch, so an
/// unbounded fetch stalls every query arriving in the cold/expired window,
/// not just the one that triggered it.
#[tokio::test]
async fn stalled_config_fetch_does_not_block_later_queries() {
    let cache = stalled_cache(stalling_tls_endpoint().await);

    let leader = tokio::spawn({
        let cache = cache.clone();
        async move { cache.get(Instant::now() + QUERY_TIMEOUT).await.map(|_| ()) }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    let followers: Vec<_> = (0..4)
        .map(|_| {
            let cache = cache.clone();
            tokio::spawn(async move { cache.get(Instant::now() + QUERY_TIMEOUT).await.map(|_| ()) })
        })
        .collect();

    let done = tokio::time::timeout(CEILING, async {
        for handle in followers.into_iter().chain([leader]) {
            assert!(
                handle.await.unwrap().is_err(),
                "a stalled target must not yield a config"
            );
        }
    })
    .await;

    assert!(
        done.is_ok(),
        "queries still blocked on the refresh lock after {CEILING:?}"
    );
}

/// A key-rotation retry re-enters `get()` carrying the original deadline, so a
/// caller can queue behind a fresher query holding the lock on a longer budget.
/// The lock wait must honour the waiter's own deadline, not the holder's.
#[tokio::test]
async fn short_deadline_does_not_wait_out_a_longer_lock_holder() {
    let cache = stalled_cache(stalling_tls_endpoint().await);

    let holder = tokio::spawn({
        let cache = cache.clone();
        async move {
            cache
                .get(Instant::now() + Duration::from_secs(5))
                .await
                .map(|_| ())
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let start = Instant::now();
    let late = cache.get(Instant::now() + Duration::from_millis(300)).await;
    let waited = start.elapsed();

    assert!(late.is_err(), "a stalled target must not yield a config");
    assert!(
        waited < Duration::from_secs(2),
        "waited {waited:?} for a 300ms budget: the lock wait ignored our deadline"
    );
    holder.abort();
}

/// Running out of budget says nothing about the target's health, so it must not
/// arm REFRESH_BACKOFF. Otherwise one impatient query (a key-rotation retry
/// re-entering with a near-spent deadline) blackholes a healthy target for the
/// next 60s of queries.
#[tokio::test]
async fn budget_exhaustion_does_not_arm_the_backoff() {
    let cache = stalled_cache(stalling_tls_endpoint().await);

    let impatient = cache.get(Instant::now() + Duration::from_millis(200)).await;
    assert!(
        impatient.is_err(),
        "a stalled target must not yield a config"
    );

    let next = cache
        .get(Instant::now() + Duration::from_millis(200))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        !next.contains("backoff active"),
        "our own timeout armed the backoff: {next}"
    );
}
