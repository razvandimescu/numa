---
title: Fixing DNS tail latency with a 5-line config and a 50-line function
description: We had periodic 40-140ms DoH spikes from hyper's dispatch channel. The fix was reqwest window tuning and request hedging — Dean & Barroso's "The Tail at Scale," applied to a DNS forwarder. Same ideas took our cold recursive p99 from 2.3 seconds to 538ms.
date: 2026-04-12
---

Numa forwards DNS queries over HTTPS using reqwest. When we benchmarked the DoH path, we found periodic 40-140ms latency spikes every ~100ms of wall clock, in an otherwise ~10ms distribution. The tail was dragging our average — median 10ms, mean 23ms.

<div class="hero-metrics">
<div class="metric-card">
<div class="metric-vs">DoH forwarding p99</div>
<div class="metric-value">113 → 71ms</div>
<div class="metric-label">window tuning + request hedging</div>
</div>
<div class="metric-card">
<div class="metric-vs">Cold recursive p99</div>
<div class="metric-value">2.3s → 538ms</div>
<div class="metric-label">NS caching, serve-stale, parallel queries</div>
</div>
<div class="metric-card">
<div class="metric-vs">Forwarding σ</div>
<div class="metric-value">31 → 13ms</div>
<div class="metric-label">random spikes become parallel races</div>
</div>
</div>

The fix was a 5-line reqwest config and a 50-line hedging function. This post is also an advertisement for Dean & Barroso's 2013 paper ["The Tail at Scale"](https://research.google/pubs/pub40801/) — a decade-old idea that still demolishes dispatch spikes.

---

## The cause: hyper's dispatch channel

Reqwest sits on top of hyper, which interposes an mpsc dispatch channel and a separate `ClientTask` between `.send()` and the h2 stream. We instrumented the forwarding path and confirmed: 100% of the spike time lives in the `send()` phase, and a parallel heartbeat task showed zero runtime lag during spikes. The tokio runtime was fine — the stall was internal to hyper's request scheduling.

Hickory-resolver doesn't have this issue. It holds `h2::SendRequest<Bytes>` directly and calls `ready().await; send_request()` in the caller's task — no channel, no scheduling dependency. We used it as a reference point throughout.

## Fix #1 — HTTP/2 window sizes

Reqwest inherits hyper's HTTP/2 defaults: 2 MB stream window, 5 MB connection window. For DNS responses (~200 bytes), that's ~10,000× oversized — unnecessary WINDOW_UPDATE frames, bloated bookkeeping on every poll, and different server-side scheduling behavior.

Setting both windows to the h2 spec default (64 KB) dropped our median from 13.3ms to 10.1ms:

```rust
reqwest::Client::builder()
    .use_rustls_tls()
    .http2_initial_stream_window_size(65_535)
    .http2_initial_connection_window_size(65_535)
    .http2_keep_alive_interval(Duration::from_secs(15))
    .http2_keep_alive_while_idle(true)
    .http2_keep_alive_timeout(Duration::from_secs(10))
    .pool_idle_timeout(Duration::from_secs(300))
    .pool_max_idle_per_host(1)
    .build()
```

**Any Rust code using reqwest for tiny-payload HTTP/2 workloads — DoH, API polling, metric scraping — is probably hitting this.**

## Fix #2 — Request hedging

["The Tail at Scale"](https://research.google/pubs/pub40801/) (Dean & Barroso, 2013): fire a request, and if it doesn't return within your P50 latency, fire the same request in parallel. First response wins.

The intuition: if 5% of requests spike due to independent random events, two parallel requests means only 0.25% of pairs spike on *both*. The tail collapses.

**The surprise: hedging against the same upstream works.** HTTP/2 multiplexes streams — two `send_request()` calls on one connection become independent h2 streams. If one stalls in the dispatch channel, the other keeps making progress.

```rust
pub async fn forward_with_hedging_raw(
    wire: &[u8],
    primary: &Upstream,
    secondary: &Upstream,
    hedge_delay: Duration,
    timeout_duration: Duration,
) -> Result<Vec<u8>> {
    let primary_fut = forward_query_raw(wire, primary, timeout_duration);
    tokio::pin!(primary_fut);
    let delay = sleep(hedge_delay);
    tokio::pin!(delay);

    // Phase 1: wait for primary to return OR the hedge delay.
    tokio::select! {
        result = &mut primary_fut => return result,
        _ = &mut delay => {}
    }

    // Phase 2: hedge delay expired — fire secondary, keep primary alive.
    let secondary_fut = forward_query_raw(wire, secondary, timeout_duration);
    tokio::pin!(secondary_fut);

    // First successful response wins.
    tokio::select! {
        r = primary_fut => r,
        r = secondary_fut => r,
    }
}
```

The [production version](https://github.com/razvandimescu/numa/blob/main/src/forward.rs#L267) adds error handling — if one leg fails, it waits for the other. In production, Numa passes the same `&Upstream` twice when only one is configured. We extended hedging to all protocols — UDP (rescues packet loss on WiFi), DoT (rescues TLS handshake stalls). Configurable via `hedge_ms`; set to 0 to disable.

**Caveat: hedging hurts on degraded networks.** When latency is consistently high (no random spikes, just slow), the hedge adds overhead with nothing to rescue. Hedging is a variance reducer, not a latency reducer — it only helps when spikes are *random*.

---

## Forwarding results

5 iterations × 101 domains × 10 rounds, 5,050 samples per method. Hickory-resolver included as a reference (it uses h2 directly, no dispatch channel):

| | Single | **Hedged** | Hickory (ref) |
|---|---|---|---|
| mean | 17.4ms | **14.3ms** | 16.8ms |
| median | 10.4ms | **10.2ms** | 13.3ms |
| p95 | 52.5ms | **28.6ms** | 37.7ms |
| p99 | 113.4ms | **71.3ms** | 98.1ms |
| σ | 30.6ms | **13.2ms** | 19.1ms |

The internal improvement: hedging cut p95 by 45%, p99 by 37%, σ by 57%. The exact margin vs hickory varies with network conditions; the σ reduction is consistent across runs.

## Recursive resolution: from 2.3 seconds to 538ms

Forwarding is one job. Recursive resolution — walking from root hints through TLD nameservers to the authoritative server — is a different one. We started 15× behind Unbound on cold recursive p99 and traced it to four root causes.

**1. Missing NS delegation caching.** We cached glue records (ns1's IP) but not the delegation itself. Every `.com` query walked from root. Fix: cache NS records from referral authority sections. (10 lines)

**2. Expired cache entries caused full cold resolutions.** Fix: serve-stale ([RFC 8767](https://www.rfc-editor.org/rfc/rfc8767)) — return expired entries with TTL=1 while revalidating in the background. (20 lines)

**3. 1,900ms wasted per unreachable server.** 800ms UDP timeout + unconditional 1,500ms TCP fallback. Fix: 400ms UDP, TCP only for truncation. (5 lines)

**4. Sequential NS queries on cold starts.** Fix: fire to the top 2 nameservers simultaneously. First response wins, SRTT recorded for both. Same hedging principle. (50 lines)

<div class="before-after">
<div class="ba-item">
<div class="ba-label">p99 before</div>
<div class="ba-value ba-before">2,367ms</div>
</div>
<div class="ba-arrow">&#8594;</div>
<div class="ba-item">
<div class="ba-label">p99 after</div>
<div class="ba-value ba-after">538ms</div>
</div>
<div class="ba-item ba-ref">
<div class="ba-label">Unbound (ref)</div>
<div class="ba-value">748ms</div>
</div>
</div>

Genuine cold benchmarks — unique subdomains, 1 query per domain, 5 iterations, 505 samples per server:

| | Baseline | Final | Unbound (ref) |
|---|---|---|---|
| p99 | 2,367ms | **538ms** | 748ms |
| σ | 254ms | **114ms** | 457ms |
| median | — | 77.6ms | 74.7ms |

Unbound wins median by ~4% — its C implementation and 19 years of recursive optimization give it an edge on raw speed. It also has features we don't yet: aggressive NSEC caching ([RFC 8198](https://www.rfc-editor.org/rfc/rfc8198)) and a persistent infra cache. Where hedging shines is the tail — domains with slow or unreachable nameservers, where parallel queries turn worst-case sequential timeouts into races.

Cache hits are tied across Numa, Unbound, and AdGuard Home — all serve at 0.1ms.

---

## Takeaways

The real hero of this post is Dean & Barroso. Hedging works because **spikes are random, and two random draws rarely both lose**. It's effective for any HTTP/2 client, any language, any forwarder topology. Nobody we know of ships it by default.

If you're building a Rust service that makes many small HTTP/2 requests to the same backend: check your flow control window sizes first, then implement hedging. Don't rewrite the client.

Benchmarks are in [`benches/recursive_compare.rs`](https://github.com/razvandimescu/numa/blob/main/benches/recursive_compare.rs) — run them yourself. If you're using reqwest for tiny-payload workloads and try the window size fix, I'd love to hear if you see the same improvement.

---

Numa is a DNS resolver that runs on your laptop or phone. DoH, DoT, .numa local domains, ad blocking, developer overrides, a REST API, and all the optimization work in this post. [github.com/razvandimescu/numa](https://github.com/razvandimescu/numa).
