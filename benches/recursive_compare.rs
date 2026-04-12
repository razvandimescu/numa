//! DoH forwarding benchmark: Numa vs hickory-resolver.
//!
//! Both forward to the same DoH upstream (Quad9).
//! Measures end-to-end resolution time through each implementation.
//!
//! Fairness:
//!   - Both reuse a single TLS connection (Numa via persistent server,
//!     Hickory via a shared resolver instance with cache_size=0).
//!   - Measurement order is alternated each round to cancel order bias.
//!   - Numa cache is flushed before each query.
//!   - 100 domains × 10 rounds for statistical confidence.
//!
//! Setup:
//!   1. Start a bench Numa instance:
//!      cargo run -- benches/numa-bench.toml
//!   2. Run:
//!      cargo bench --bench recursive_compare

use std::net::SocketAddr;
use std::time::{Duration, Instant};

const DOH_UPSTREAM: &str = "https://9.9.9.9/dns-query";
const NUMA_BENCH: &str = "127.0.0.1:5454";
const NUMA_API: u16 = 5381;

const DOMAINS: &[&str] = &[
    "example.com",
    "rust-lang.org",
    "kernel.org",
    "signal.org",
    "archlinux.org",
    "openbsd.org",
    "git-scm.com",
    "sqlite.org",
    "wireguard.com",
    "mozilla.org",
    "cloudflare.com",
    "google.com",
    "github.com",
    "stackoverflow.com",
    "wikipedia.org",
    "reddit.com",
    "amazon.com",
    "apple.com",
    "microsoft.com",
    "facebook.com",
    "twitter.com",
    "linkedin.com",
    "netflix.com",
    "spotify.com",
    "discord.com",
    "twitch.tv",
    "youtube.com",
    "instagram.com",
    "whatsapp.com",
    "telegram.org",
    "debian.org",
    "ubuntu.com",
    "fedoraproject.org",
    "nixos.org",
    "gentoo.org",
    "freebsd.org",
    "netbsd.org",
    "dragonflybsd.org",
    "illumos.org",
    "haiku-os.org",
    "python.org",
    "golang.org",
    "nodejs.org",
    "ruby-lang.org",
    "php.net",
    "swift.org",
    "kotlinlang.org",
    "scala-lang.org",
    "haskell.org",
    "elixir-lang.org",
    "erlang.org",
    "clojure.org",
    "julialang.org",
    "ziglang.org",
    "nim-lang.org",
    "dlang.org",
    "vlang.io",
    "crystal-lang.org",
    "racket-lang.org",
    "ocaml.org",
    "crates.io",
    "npmjs.com",
    "pypi.org",
    "rubygems.org",
    "packagist.org",
    "nuget.org",
    "maven.apache.org",
    "hex.pm",
    "hackage.haskell.org",
    "pkg.go.dev",
    "docker.com",
    "kubernetes.io",
    "prometheus.io",
    "grafana.com",
    "elastic.co",
    "datadog.com",
    "sentry.io",
    "pagerduty.com",
    "atlassian.com",
    "jetbrains.com",
    "gitlab.com",
    "bitbucket.org",
    "sourcehut.org",
    "codeberg.org",
    "launchpad.net",
    "savannah.gnu.org",
    "letsencrypt.org",
    "eff.org",
    "torproject.org",
    "privacyguides.org",
    "matrix.org",
    "element.io",
    "jitsi.org",
    "nextcloud.com",
    "syncthing.net",
    "tailscale.com",
    "mullvad.net",
    "proton.me",
    "duckduckgo.com",
    "brave.com",
    "vivaldi.com",
];

const ROUNDS: usize = 10;

fn main() {
    let diag = std::env::args().any(|a| a == "--diag");
    let direct = std::env::args().any(|a| a == "--direct");

    let rt = tokio::runtime::Runtime::new().unwrap();

    if diag {
        run_diag(&rt);
        return;
    }

    if direct {
        run_direct(&rt);
        return;
    }

    if std::env::args().any(|a| a == "--diag-clients") {
        run_diag_clients(&rt);
        return;
    }

    if std::env::args().any(|a| a == "--spike-trace") {
        run_spike_trace(&rt);
        return;
    }

    if std::env::args().any(|a| a == "--spike-phases") {
        run_spike_phases(&rt);
        return;
    }

    if std::env::args().any(|a| a == "--spike-heartbeat") {
        run_spike_heartbeat(&rt);
        return;
    }

    if std::env::args().any(|a| a == "--hedge") {
        run_hedge(&rt);
        return;
    }

    if std::env::args().any(|a| a == "--hedge-5x") {
        run_hedge_multi(&rt, 5);
        return;
    }

    if std::env::args().any(|a| a == "--vs-dnscrypt") {
        run_vs_dnscrypt(&rt, 5);
        return;
    }

    if std::env::args().any(|a| a == "--vs-unbound") {
        run_vs_unbound(&rt, 5);
        return;
    }

    let numa_addr: SocketAddr = NUMA_BENCH.parse().unwrap();

    println!("DoH Forwarding Benchmark: Numa vs hickory-resolver");
    println!("Both forwarding to {DOH_UPSTREAM}");
    println!("{} domains × {ROUNDS} rounds", DOMAINS.len());
    println!();

    // Verify bench Numa is reachable
    if rt.block_on(query_udp(numa_addr, "example.com")).is_none() {
        eprintln!("Bench Numa not responding on {numa_addr}");
        eprintln!();
        eprintln!("Start it with:");
        eprintln!("  cargo run -- benches/numa-bench.toml");
        std::process::exit(1);
    }

    // Build a shared Hickory resolver (reuses TLS connection, like Numa does)
    let resolver = rt.block_on(build_hickory_resolver());

    // Warm up both paths (TLS handshake, connection establishment)
    println!("Warming up connections...");
    for _ in 0..3 {
        rt.block_on(query_udp(numa_addr, "example.com"));
        rt.block_on(query_hickory_doh(&resolver, "example.com"));
    }
    flush_cache();

    println!(
        "{:<30}  {:>10}  {:>10}  {:>10}  {:>8}  {:>8}",
        "Domain", "Numa (ms)", "Hickory", "Delta", "σ Numa", "σ Hick"
    );
    println!("{}", "-".repeat(92));

    let mut numa_all = Vec::new();
    let mut hickory_all = Vec::new();
    let mut per_domain: Vec<(&str, f64, f64, f64, f64, f64)> = Vec::new();

    for domain in DOMAINS {
        let mut numa_times = Vec::with_capacity(ROUNDS);
        let mut hickory_times = Vec::with_capacity(ROUNDS);

        for round in 0..ROUNDS {
            flush_cache();
            std::thread::sleep(Duration::from_millis(10));

            // Alternate measurement order each round to cancel systematic bias
            if round % 2 == 0 {
                // Numa first
                let t = measure(&rt, || rt.block_on(query_udp(numa_addr, domain)));
                numa_times.push(t);
                let t = measure(&rt, || rt.block_on(query_hickory_doh(&resolver, domain)));
                hickory_times.push(t);
            } else {
                // Hickory first
                let t = measure(&rt, || rt.block_on(query_hickory_doh(&resolver, domain)));
                hickory_times.push(t);
                flush_cache();
                std::thread::sleep(Duration::from_millis(10));
                let t = measure(&rt, || rt.block_on(query_udp(numa_addr, domain)));
                numa_times.push(t);
            }
        }

        let numa_avg = mean(&numa_times);
        let hickory_avg = mean(&hickory_times);
        let numa_sd = stddev(&numa_times);
        let hickory_sd = stddev(&hickory_times);
        let delta = numa_avg - hickory_avg;

        numa_all.extend_from_slice(&numa_times);
        hickory_all.extend_from_slice(&hickory_times);
        per_domain.push((domain, numa_avg, hickory_avg, delta, numa_sd, hickory_sd));

        let delta_str = format_delta(delta);
        println!(
            "{:<30}  {:>7.1} ms  {:>7.1} ms  {:>7} ms  {:>5.1}ms  {:>5.1}ms",
            domain, numa_avg, hickory_avg, delta_str, numa_sd, hickory_sd
        );
    }

    println!("{}", "-".repeat(92));

    let numa_mean = mean(&numa_all);
    let hickory_mean = mean(&hickory_all);
    let delta_mean = numa_mean - hickory_mean;

    println!(
        "{:<30}  {:>7.1} ms  {:>7.1} ms  {:>7} ms  {:>5.1}ms  {:>5.1}ms",
        "OVERALL MEAN",
        numa_mean,
        hickory_mean,
        format_delta(delta_mean),
        stddev(&numa_all),
        stddev(&hickory_all),
    );

    // Median
    let numa_med = median(&mut numa_all);
    let hickory_med = median(&mut hickory_all);
    println!(
        "{:<30}  {:>7.1} ms  {:>7.1} ms  {:>7} ms",
        "MEDIAN",
        numa_med,
        hickory_med,
        format_delta(numa_med - hickory_med),
    );

    // P95
    let numa_p95 = percentile(&numa_all, 95.0);
    let hickory_p95 = percentile(&hickory_all, 95.0);
    println!(
        "{:<30}  {:>7.1} ms  {:>7.1} ms  {:>7} ms",
        "P95",
        numa_p95,
        hickory_p95,
        format_delta(numa_p95 - hickory_p95),
    );

    println!();
    let total_queries = DOMAINS.len() * ROUNDS;
    if numa_mean < hickory_mean {
        let pct = ((hickory_mean - numa_mean) / hickory_mean * 100.0).round();
        println!("Numa is ~{pct}% faster (mean over {total_queries} queries).");
    } else if hickory_mean < numa_mean {
        let pct = ((numa_mean - hickory_mean) / numa_mean * 100.0).round();
        println!("Hickory is ~{pct}% faster (mean over {total_queries} queries).");
    } else {
        println!("Both are equal (mean over {total_queries} queries).");
    }

    println!();
    println!("Methodology:");
    println!("  - Both forward to {DOH_UPSTREAM} over a reused TLS connection.");
    println!("  - Numa cache flushed before each query. Hickory cache disabled.");
    println!("  - Measurement order alternates each round to cancel order bias.");
    println!("  - {} domains × {ROUNDS} rounds = {total_queries} queries per resolver.", DOMAINS.len());
}

fn run_diag(rt: &tokio::runtime::Runtime) {
    println!("Hickory connection reuse diagnostic");
    println!("20 sequential queries to {DOH_UPSTREAM} via one shared resolver");
    println!("If conn is reused: query 1 slow (TLS handshake), rest fast.\n");

    let resolver = rt.block_on(build_hickory_resolver());

    let domains = [
        "example.com", "rust-lang.org", "kernel.org", "google.com", "github.com",
        "example.com", "rust-lang.org", "kernel.org", "google.com", "github.com",
        "example.com", "rust-lang.org", "kernel.org", "google.com", "github.com",
        "example.com", "rust-lang.org", "kernel.org", "google.com", "github.com",
    ];

    println!("{:>3}  {:<20}  {:>10}", "#", "Domain", "Time (ms)");
    println!("{}", "-".repeat(40));

    for (i, domain) in domains.iter().enumerate() {
        use hickory_resolver::proto::rr::RecordType;
        let start = Instant::now();
        let result = rt.block_on(resolver.lookup(*domain, RecordType::A));
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        match &result {
            Ok(lookup) => {
                let first = lookup.iter().next().map(|r| format!("{r}")).unwrap_or_default();
                println!("{:>3}  {:<20}  {:>7.1} ms  OK  {}", i + 1, domain, ms, first);
            }
            Err(e) => {
                println!("{:>3}  {:<20}  {:>7.1} ms  ERR {}", i + 1, domain, ms, e);
            }
        }
    }
}

/// Library-to-library comparison: Numa's forward_query_raw vs Hickory's resolver.lookup().
/// No UDP, no server pipeline — just the DoH forwarding call.
fn run_direct(rt: &tokio::runtime::Runtime) {
    println!("Direct DoH Forwarding: Numa forward_query_raw vs Hickory resolver.lookup()");
    println!("Both forwarding to {DOH_UPSTREAM} — no UDP, no server pipeline");
    println!("{} domains × {ROUNDS} rounds", DOMAINS.len());
    println!();

    // Build Numa's upstream (shared reqwest client, reuses HTTP/2 connection)
    let numa_upstream =
        numa::forward::parse_upstream(DOH_UPSTREAM, 443).expect("failed to parse upstream");
    let timeout = Duration::from_secs(10);

    // Build Hickory's resolver (shared, reuses HTTP/2 connection)
    let resolver = rt.block_on(build_hickory_resolver());

    // Warm up both
    println!("Warming up connections...");
    for _ in 0..3 {
        let wire = build_query_vec("example.com");
        let _ = rt.block_on(numa::forward::forward_query_raw(&wire, &numa_upstream, timeout));
        let _ = rt.block_on(query_hickory_doh(&resolver, "example.com"));
    }

    println!(
        "{:<30}  {:>10}  {:>10}  {:>10}  {:>8}  {:>8}",
        "Domain", "Numa (ms)", "Hickory", "Delta", "σ Numa", "σ Hick"
    );
    println!("{}", "-".repeat(92));

    let mut numa_all = Vec::new();
    let mut hickory_all = Vec::new();

    for domain in DOMAINS {
        let mut numa_times = Vec::with_capacity(ROUNDS);
        let mut hickory_times = Vec::with_capacity(ROUNDS);

        for round in 0..ROUNDS {
            let wire = build_query_vec(domain);

            if round % 2 == 0 {
                let w = wire.clone();
                let t = measure(rt, || {
                    rt.block_on(numa::forward::forward_query_raw(&w, &numa_upstream, timeout))
                });
                numa_times.push(t);
                let t = measure(rt, || rt.block_on(query_hickory_doh(&resolver, domain)));
                hickory_times.push(t);
            } else {
                let t = measure(rt, || rt.block_on(query_hickory_doh(&resolver, domain)));
                hickory_times.push(t);
                let w = wire.clone();
                let t = measure(rt, || {
                    rt.block_on(numa::forward::forward_query_raw(&w, &numa_upstream, timeout))
                });
                numa_times.push(t);
            }
        }

        let numa_avg = mean(&numa_times);
        let hickory_avg = mean(&hickory_times);
        let numa_sd = stddev(&numa_times);
        let hickory_sd = stddev(&hickory_times);
        let delta = numa_avg - hickory_avg;

        numa_all.extend_from_slice(&numa_times);
        hickory_all.extend_from_slice(&hickory_times);

        println!(
            "{:<30}  {:>7.1} ms  {:>7.1} ms  {:>7} ms  {:>5.1}ms  {:>5.1}ms",
            domain, numa_avg, hickory_avg, format_delta(delta), numa_sd, hickory_sd
        );
    }

    println!("{}", "-".repeat(92));
    let numa_mean = mean(&numa_all);
    let hickory_mean = mean(&hickory_all);
    println!(
        "{:<30}  {:>7.1} ms  {:>7.1} ms  {:>7} ms  {:>5.1}ms  {:>5.1}ms",
        "OVERALL MEAN", numa_mean, hickory_mean, format_delta(numa_mean - hickory_mean),
        stddev(&numa_all), stddev(&hickory_all),
    );
    let numa_med = median(&mut numa_all);
    let hickory_med = median(&mut hickory_all);
    println!(
        "{:<30}  {:>7.1} ms  {:>7.1} ms  {:>7} ms",
        "MEDIAN", numa_med, hickory_med, format_delta(numa_med - hickory_med),
    );
    let numa_p95 = percentile(&numa_all, 95.0);
    let hickory_p95 = percentile(&hickory_all, 95.0);
    println!(
        "{:<30}  {:>7.1} ms  {:>7.1} ms  {:>7} ms",
        "P95", numa_p95, hickory_p95, format_delta(numa_p95 - hickory_p95),
    );

    println!();
    let total_queries = DOMAINS.len() * ROUNDS;
    if numa_mean < hickory_mean {
        let pct = ((hickory_mean - numa_mean) / hickory_mean * 100.0).round();
        println!("Numa is ~{pct}% faster (mean over {total_queries} queries).");
    } else if hickory_mean < numa_mean {
        let pct = ((numa_mean - hickory_mean) / numa_mean * 100.0).round();
        println!("Hickory is ~{pct}% faster (mean over {total_queries} queries).");
    } else {
        println!("Both are equal (mean over {total_queries} queries).");
    }

    println!();
    println!("Methodology:");
    println!("  - Both forward to {DOH_UPSTREAM} over a reused TLS/HTTP2 connection.");
    println!("  - No UDP, no server pipeline, no cache — pure DoH forwarding.");
    println!("  - Numa: forward_query_raw (reqwest). Hickory: resolver.lookup (h2).");
    println!("  - {} domains × {ROUNDS} rounds = {total_queries} queries per implementation.", DOMAINS.len());
}

/// Per-query timing diagnostic: 20 queries each through reqwest and Hickory.
/// Shows whether reqwest has connection reuse issues or per-request overhead.
fn run_diag_clients(rt: &tokio::runtime::Runtime) {
    println!("Client diagnostic: reqwest vs Hickory per-query timing");
    println!("20 queries each to {DOH_UPSTREAM}\n");

    let upstream =
        numa::forward::parse_upstream(DOH_UPSTREAM, 443).expect("failed to parse upstream");
    let resolver = rt.block_on(build_hickory_resolver());
    let timeout = Duration::from_secs(10);

    // Warm both
    for _ in 0..3 {
        let w = build_query_vec("example.com");
        let _ = rt.block_on(numa::forward::forward_query_raw(&w, &upstream, timeout));
        let _ = rt.block_on(query_hickory_doh(&resolver, "example.com"));
    }

    let domains = [
        "example.com", "google.com", "github.com", "rust-lang.org", "cloudflare.com",
        "example.com", "google.com", "github.com", "rust-lang.org", "cloudflare.com",
        "example.com", "google.com", "github.com", "rust-lang.org", "cloudflare.com",
        "example.com", "google.com", "github.com", "rust-lang.org", "cloudflare.com",
    ];

    println!("{:>3}  {:<20}  {:>12}  {:>12}", "#", "Domain", "reqwest", "Hickory");
    println!("{}", "-".repeat(55));

    for (i, domain) in domains.iter().enumerate() {
        let wire = build_query_vec(domain);

        let start = Instant::now();
        let r_result = rt.block_on(numa::forward::forward_query_raw(&wire, &upstream, timeout));
        let r_ms = start.elapsed().as_secs_f64() * 1000.0;
        let r_ok = if r_result.is_ok() { "OK" } else { "FAIL" };

        let start = Instant::now();
        let h_result = rt.block_on(query_hickory_doh(&resolver, domain));
        let h_ms = start.elapsed().as_secs_f64() * 1000.0;
        let h_ok = if h_result.is_some() { "OK" } else { "FAIL" };

        println!(
            "{:>3}  {:<20}  {:>7.1} ms {}  {:>7.1} ms {}",
            i + 1, domain, r_ms, r_ok, h_ms, h_ok
        );
    }
}

/// Spike trace: fire 200 sequential queries through reqwest and log every one
/// with a timestamp. Analyze the distribution and find spike clusters.
fn run_spike_trace(rt: &tokio::runtime::Runtime) {
    println!("Spike trace: 200 sequential reqwest DoH queries");
    println!("Target: {DOH_UPSTREAM}\n");

    let upstream =
        numa::forward::parse_upstream(DOH_UPSTREAM, 443).expect("failed to parse upstream");
    let timeout = Duration::from_secs(10);

    // Warm
    for _ in 0..5 {
        let w = build_query_vec("example.com");
        let _ = rt.block_on(numa::forward::forward_query_raw(&w, &upstream, timeout));
    }

    // Run the entire 200-query loop inside ONE block_on to eliminate
    // per-query runtime re-entry overhead.
    let samples: Vec<(u128, f64)> = rt.block_on(async {
        let test_start = Instant::now();
        let mut s = Vec::with_capacity(200);
        for i in 0..200 {
            let domain = match i % 5 {
                0 => "example.com",
                1 => "google.com",
                2 => "github.com",
                3 => "rust-lang.org",
                _ => "cloudflare.com",
            };
            let wire = build_query_vec(domain);
            let req_start = Instant::now();
            let t_from_start_us = test_start.elapsed().as_micros();
            let _ = numa::forward::forward_query_raw(&wire, &upstream, timeout).await;
            let ms = req_start.elapsed().as_secs_f64() * 1000.0;
            s.push((t_from_start_us, ms));
        }
        s
    });

    // Compute stats
    let mut sorted_times: Vec<f64> = samples.iter().map(|(_, t)| *t).collect();
    sorted_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = sorted_times.len();
    let median = sorted_times[n / 2];
    let p90 = sorted_times[(n * 90) / 100];
    let p95 = sorted_times[(n * 95) / 100];
    let p99 = sorted_times[(n * 99) / 100];
    let max = sorted_times[n - 1];
    let mean: f64 = sorted_times.iter().sum::<f64>() / n as f64;

    println!("Distribution (n={}):", n);
    println!("  mean:   {:.1} ms", mean);
    println!("  median: {:.1} ms", median);
    println!("  p90:    {:.1} ms", p90);
    println!("  p95:    {:.1} ms", p95);
    println!("  p99:    {:.1} ms", p99);
    println!("  max:    {:.1} ms", max);
    println!();

    // Define spike threshold as 3x median
    let spike_threshold = median * 3.0;
    let spikes: Vec<(usize, u128, f64)> = samples
        .iter()
        .enumerate()
        .filter(|(_, (_, t))| *t > spike_threshold)
        .map(|(i, (ts, t))| (i, *ts, *t))
        .collect();

    println!("Spikes (> {:.1}ms, which is 3x median):", spike_threshold);
    println!("  count: {}", spikes.len());
    if spikes.is_empty() {
        return;
    }

    // Inter-spike gaps (time between spikes)
    let mut gaps_ms: Vec<f64> = Vec::new();
    for w in spikes.windows(2) {
        let gap_us = w[1].1 - w[0].1;
        gaps_ms.push(gap_us as f64 / 1000.0);
    }

    println!();
    println!("  {:>4}  {:>12}  {:>10}  {:>12}", "idx", "at (ms)", "latency", "gap from prev");
    for (i, ((idx, ts, latency), gap)) in spikes.iter().zip(
        std::iter::once(&0.0).chain(gaps_ms.iter())
    ).enumerate() {
        let _ = i;
        let gap_str = if *gap > 0.0 {
            format!("{:.0} ms", gap)
        } else {
            "-".to_string()
        };
        println!("  {:>4}  {:>9.1}     {:>6.1} ms  {:>12}", idx, *ts as f64 / 1000.0, latency, gap_str);
    }

    if !gaps_ms.is_empty() {
        let gap_mean: f64 = gaps_ms.iter().sum::<f64>() / gaps_ms.len() as f64;
        let mut gap_sorted = gaps_ms.clone();
        gap_sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let gap_median = gap_sorted[gap_sorted.len() / 2];
        println!();
        println!("  Inter-spike gap: mean={:.0}ms, median={:.0}ms", gap_mean, gap_median);
    }
}

/// Spike phases: time each step of the reqwest DoH call to find which phase
/// is slow during a spike. Reports (build+send, send->resp headers, body read).
fn run_spike_phases(rt: &tokio::runtime::Runtime) {
    println!("Spike phases: timing each phase of reqwest DoH call");
    println!("Target: {DOH_UPSTREAM}\n");

    // Build the same tuned client our forward_doh uses
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .http2_initial_stream_window_size(65_535)
        .http2_initial_connection_window_size(65_535)
        .http2_keep_alive_interval(Duration::from_secs(15))
        .http2_keep_alive_while_idle(true)
        .http2_keep_alive_timeout(Duration::from_secs(10))
        .pool_idle_timeout(Duration::from_secs(300))
        .pool_max_idle_per_host(1)
        .build()
        .unwrap();

    // Warm up
    for _ in 0..5 {
        let wire = build_query_vec("example.com");
        let _ = rt.block_on(async {
            client
                .post(DOH_UPSTREAM)
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .body(wire)
                .send()
                .await
                .ok()?
                .bytes()
                .await
                .ok()
        });
    }

    println!("{:>4}  {:>8}  {:>8}  {:>8}  {:>8}", "idx", "total", "build", "send", "body");
    println!("{}", "-".repeat(50));

    let samples: Vec<(f64, f64, f64, f64)> = rt.block_on(async {
        let mut s = Vec::with_capacity(200);
        for i in 0..200 {
            let domain = match i % 5 {
                0 => "example.com",
                1 => "google.com",
                2 => "github.com",
                3 => "rust-lang.org",
                _ => "cloudflare.com",
            };
            let wire = build_query_vec(domain);

            let t0 = Instant::now();
            // Phase 1: build the request
            let req = client
                .post(DOH_UPSTREAM)
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .body(wire);
            let t1 = Instant::now();
            // Phase 2: send() — this is the dispatch channel + round trip to headers
            let resp_result = req.send().await;
            let t2 = Instant::now();
            // Phase 3: read body
            let body_result = match resp_result {
                Ok(r) => r.bytes().await.ok().map(|b| b.len()),
                Err(_) => None,
            };
            let t3 = Instant::now();

            let build_ms = (t1 - t0).as_secs_f64() * 1000.0;
            let send_ms = (t2 - t1).as_secs_f64() * 1000.0;
            let body_ms = (t3 - t2).as_secs_f64() * 1000.0;
            let total_ms = (t3 - t0).as_secs_f64() * 1000.0;

            s.push((total_ms, build_ms, send_ms, body_ms));
            let _ = body_result;
        }
        s
    });

    // Compute distribution on total
    let mut totals: Vec<f64> = samples.iter().map(|s| s.0).collect();
    totals.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = totals[100];

    // Print spikes (> 3x median) with phase breakdown
    for (i, (total, build, send, body)) in samples.iter().enumerate() {
        if *total > median * 3.0 {
            println!(
                "{:>4}  {:>5.1} ms  {:>5.1} ms  {:>5.1} ms  {:>5.1} ms",
                i, total, build, send, body
            );
        }
    }

    // Summary: mean of each phase for spikes vs non-spikes
    let (spike_samples, normal_samples): (Vec<_>, Vec<_>) = samples
        .iter()
        .partition(|(t, _, _, _)| *t > median * 3.0);

    let phase_means = |samples: &[&(f64, f64, f64, f64)]| -> (f64, f64, f64, f64) {
        let n = samples.len() as f64;
        if n == 0.0 { return (0.0, 0.0, 0.0, 0.0); }
        let total: f64 = samples.iter().map(|s| s.0).sum::<f64>() / n;
        let build: f64 = samples.iter().map(|s| s.1).sum::<f64>() / n;
        let send: f64 = samples.iter().map(|s| s.2).sum::<f64>() / n;
        let body: f64 = samples.iter().map(|s| s.3).sum::<f64>() / n;
        (total, build, send, body)
    };

    let spike_refs: Vec<&(f64, f64, f64, f64)> = spike_samples.iter().copied().collect();
    let normal_refs: Vec<&(f64, f64, f64, f64)> = normal_samples.iter().copied().collect();
    let (s_total, s_build, s_send, s_body) = phase_means(&spike_refs);
    let (n_total, n_build, n_send, n_body) = phase_means(&normal_refs);

    println!();
    println!("Summary (mean ms):");
    println!(
        "  {:<8}  {:>8}  {:>8}  {:>8}  {:>8}",
        "", "total", "build", "send", "body"
    );
    println!(
        "  {:<8}  {:>5.1} ms  {:>5.1} ms  {:>5.1} ms  {:>5.1} ms  (n={})",
        "normal", n_total, n_build, n_send, n_body, normal_refs.len()
    );
    println!(
        "  {:<8}  {:>5.1} ms  {:>5.1} ms  {:>5.1} ms  {:>5.1} ms  (n={})",
        "spike", s_total, s_build, s_send, s_body, spike_refs.len()
    );
    println!();
    println!("Delta (spike - normal):");
    println!(
        "  build: {:+.1} ms,  send: {:+.1} ms,  body: {:+.1} ms",
        s_build - n_build,
        s_send - n_send,
        s_body - n_body
    );
}

/// Heartbeat probe: run a parallel task that ticks every 5ms and records
/// how long each tick actually takes. If the heartbeat stalls during a DoH
/// spike, it's a tokio scheduling issue (runtime can't poll tasks). If
/// heartbeat is fine while send() is stuck, it's internal to hyper/h2.
fn run_spike_heartbeat(rt: &tokio::runtime::Runtime) {
    use std::sync::{Arc, Mutex};

    println!("Spike heartbeat probe");
    println!("Running DoH queries + parallel 5ms heartbeat task\n");

    let upstream =
        numa::forward::parse_upstream(DOH_UPSTREAM, 443).expect("failed to parse upstream");
    let timeout = Duration::from_secs(10);

    // Warm up
    for _ in 0..5 {
        let w = build_query_vec("example.com");
        let _ = rt.block_on(numa::forward::forward_query_raw(&w, &upstream, timeout));
    }

    // Shared vecs: (relative_ms_from_start, event_kind, latency_ms)
    // event_kind: 0 = heartbeat, 1 = doh query
    type EventLog = Vec<(f64, u8, f64)>;
    let events: Arc<Mutex<EventLog>> = Arc::new(Mutex::new(Vec::with_capacity(2000)));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let test_start = Instant::now();

    rt.block_on(async {
        // Spawn heartbeat task
        let hb_events = Arc::clone(&events);
        let hb_stop = Arc::clone(&stop);
        let hb_start = test_start;
        let heartbeat = tokio::spawn(async move {
            let mut next_tick = Instant::now();
            let target = Duration::from_millis(5);
            while !hb_stop.load(std::sync::atomic::Ordering::Relaxed) {
                next_tick += target;
                // Sleep until the next scheduled tick
                let now = Instant::now();
                if next_tick > now {
                    tokio::time::sleep(next_tick - now).await;
                }
                // Measure how much we overshot the scheduled tick
                let actual = Instant::now();
                let lag_ms = if actual > next_tick {
                    (actual - next_tick).as_secs_f64() * 1000.0
                } else {
                    0.0
                };
                let t = (actual - hb_start).as_secs_f64() * 1000.0;
                if let Ok(mut e) = hb_events.lock() {
                    e.push((t, 0, lag_ms));
                }
            }
        });

        // Run 200 DoH queries and record their timings
        for i in 0..200 {
            let domain = match i % 5 {
                0 => "example.com",
                1 => "google.com",
                2 => "github.com",
                3 => "rust-lang.org",
                _ => "cloudflare.com",
            };
            let wire = build_query_vec(domain);
            let req_start = Instant::now();
            let _ = numa::forward::forward_query_raw(&wire, &upstream, timeout).await;
            let elapsed = req_start.elapsed().as_secs_f64() * 1000.0;
            let t = (req_start - test_start).as_secs_f64() * 1000.0;
            if let Ok(mut e) = events.lock() {
                e.push((t, 1, elapsed));
            }
        }

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = heartbeat.await;
    });

    let events = events.lock().unwrap();

    // Separate heartbeats and doh events
    let hb: Vec<(f64, f64)> = events
        .iter()
        .filter(|(_, k, _)| *k == 0)
        .map(|(t, _, l)| (*t, *l))
        .collect();
    let doh: Vec<(f64, f64)> = events
        .iter()
        .filter(|(_, k, _)| *k == 1)
        .map(|(t, _, l)| (*t, *l))
        .collect();

    // Heartbeat stats
    let mut hb_lags: Vec<f64> = hb.iter().map(|(_, l)| *l).collect();
    hb_lags.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let hb_n = hb_lags.len();
    let hb_median = hb_lags[hb_n / 2];
    let hb_p95 = hb_lags[(hb_n * 95) / 100];
    let hb_p99 = hb_lags[(hb_n * 99) / 100];
    let hb_max = hb_lags[hb_n - 1];

    // DoH stats
    let mut doh_latencies: Vec<f64> = doh.iter().map(|(_, l)| *l).collect();
    doh_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let doh_n = doh_latencies.len();
    let doh_median = doh_latencies[doh_n / 2];
    let doh_p95 = doh_latencies[(doh_n * 95) / 100];
    let doh_max = doh_latencies[doh_n - 1];

    println!("Heartbeat lag (tick overshoot, {}ms target):", 5);
    println!("  n:      {}", hb_n);
    println!("  median: {:.2} ms", hb_median);
    println!("  p95:    {:.2} ms", hb_p95);
    println!("  p99:    {:.2} ms", hb_p99);
    println!("  max:    {:.2} ms", hb_max);
    println!();
    println!("DoH latency:");
    println!("  n:      {}", doh_n);
    println!("  median: {:.1} ms", doh_median);
    println!("  p95:    {:.1} ms", doh_p95);
    println!("  max:    {:.1} ms", doh_max);
    println!();

    // Find DoH spikes and check heartbeat activity DURING each spike
    let doh_spike_threshold = doh_median * 3.0;
    let mut spikes_with_hb_lag = 0;
    let mut spikes_total = 0;
    let mut max_hb_during_any_spike = 0.0_f64;

    println!(
        "Correlation: during each DoH spike (>{:.1}ms), max heartbeat lag:",
        doh_spike_threshold
    );
    println!("  {:>6}  {:>10}  {:>18}", "doh_at", "doh_ms", "max_hb_lag_during");

    for (doh_t, doh_ms) in &doh {
        if *doh_ms > doh_spike_threshold {
            spikes_total += 1;
            // Find heartbeats that happened during this DoH query
            let spike_start = *doh_t;
            let spike_end = spike_start + *doh_ms;
            let mut max_hb = 0.0_f64;
            for (hb_t, hb_lag) in &hb {
                if *hb_t >= spike_start && *hb_t <= spike_end + 20.0 {
                    if *hb_lag > max_hb {
                        max_hb = *hb_lag;
                    }
                }
            }
            if max_hb > 5.0 {
                spikes_with_hb_lag += 1;
            }
            max_hb_during_any_spike = max_hb_during_any_spike.max(max_hb);
            println!(
                "  {:>5.0} ms  {:>7.1} ms  {:>14.2} ms",
                doh_t, doh_ms, max_hb
            );
        }
    }

    println!();
    println!("Conclusion:");
    if spikes_total == 0 {
        println!("  No DoH spikes in this run.");
    } else {
        let pct = (spikes_with_hb_lag as f64 / spikes_total as f64 * 100.0).round();
        println!(
            "  {}/{} spikes ({:.0}%) had concurrent heartbeat lag >5ms.",
            spikes_with_hb_lag, spikes_total, pct
        );
        println!("  Max heartbeat lag during any spike: {:.2}ms", max_hb_during_any_spike);
        println!();
        if max_hb_during_any_spike > 20.0 {
            println!("  → Heartbeat stalls during DoH spikes: tokio scheduling / OS thread issue.");
            println!("    The runtime can't poll ANY task — likely QoS demotion, GC pause,");
            println!("    or the worker thread is blocked somewhere.");
        } else {
            println!("  → Heartbeat runs normally during DoH spikes: internal to hyper/h2.");
            println!("    The runtime is fine, but send()'s await is stuck waiting for");
            println!("    the ClientTask to poll the dispatch channel.");
        }
    }
}

/// Hedging benchmark: tests four configurations against Hickory.
///   Single:        1 client → Quad9 (baseline)
///   Hedge-same:    hedge against same client/connection → Quad9
///   Hedge-dual:    hedge against 2 separate clients, both → Quad9 (same upstream, 2 HTTP/2 conns)
///   Hickory:       Hickory resolver → Quad9 (reference)
fn run_hedge(rt: &tokio::runtime::Runtime) {
    let hedge_delay = Duration::from_millis(10);

    println!("Hedging Benchmark (all paths → Quad9 only)");
    println!("Upstream: {}", DOH_UPSTREAM);
    println!("Hedge delay: {:?}", hedge_delay);
    println!("{} domains × {} rounds\n", DOMAINS.len(), ROUNDS);

    // Primary and secondary: two separate reqwest clients → same Quad9 URL.
    // This gives two independent HTTP/2 connections, so dispatch spikes
    // are uncorrelated (at most one stalls at a time).
    let primary_same =
        numa::forward::parse_upstream(DOH_UPSTREAM, 443).expect("failed to parse primary");
    let primary_dual =
        numa::forward::parse_upstream(DOH_UPSTREAM, 443).expect("failed to parse primary_dual");
    let secondary_dual =
        numa::forward::parse_upstream(DOH_UPSTREAM, 443).expect("failed to parse secondary_dual");
    let timeout = Duration::from_secs(10);

    let resolver = rt.block_on(build_hickory_resolver());

    // Warm up all paths (separate connections need their own TLS handshake)
    println!("Warming up connections...");
    for _ in 0..5 {
        let w = build_query_vec("example.com");
        let _ = rt.block_on(numa::forward::forward_query_raw(&w, &primary_same, timeout));
        let _ = rt.block_on(numa::forward::forward_query_raw(&w, &primary_dual, timeout));
        let _ = rt.block_on(numa::forward::forward_query_raw(&w, &secondary_dual, timeout));
        let _ = rt.block_on(query_hickory_doh(&resolver, "example.com"));
    }

    let mut single_all = Vec::new();
    let mut hedge_same_all = Vec::new();
    let mut hedge_dual_all = Vec::new();
    let mut hickory_all = Vec::new();

    println!(
        "{:<24}  {:>10}  {:>10}  {:>10}  {:>10}",
        "Domain", "Single", "Hedge-same", "Hedge-dual", "Hickory"
    );
    println!("{}", "-".repeat(78));

    for domain in DOMAINS {
        let mut single_times = Vec::with_capacity(ROUNDS);
        let mut hedge_same_times = Vec::with_capacity(ROUNDS);
        let mut hedge_dual_times = Vec::with_capacity(ROUNDS);
        let mut hickory_times = Vec::with_capacity(ROUNDS);

        for _ in 0..ROUNDS {
            let wire = build_query_vec(domain);

            let t = Instant::now();
            let _ = rt.block_on(numa::forward::forward_query_raw(&wire, &primary_same, timeout));
            single_times.push(t.elapsed().as_secs_f64() * 1000.0);

            let t = Instant::now();
            let _ = rt.block_on(numa::forward::forward_with_hedging_raw(
                &wire, &primary_same, &primary_same, hedge_delay, timeout,
            ));
            hedge_same_times.push(t.elapsed().as_secs_f64() * 1000.0);

            let t = Instant::now();
            let _ = rt.block_on(numa::forward::forward_with_hedging_raw(
                &wire, &primary_dual, &secondary_dual, hedge_delay, timeout,
            ));
            hedge_dual_times.push(t.elapsed().as_secs_f64() * 1000.0);

            let t = Instant::now();
            let _ = rt.block_on(query_hickory_doh(&resolver, domain));
            hickory_times.push(t.elapsed().as_secs_f64() * 1000.0);
        }

        single_all.extend_from_slice(&single_times);
        hedge_same_all.extend_from_slice(&hedge_same_times);
        hedge_dual_all.extend_from_slice(&hedge_dual_times);
        hickory_all.extend_from_slice(&hickory_times);

        println!(
            "{:<24}  {:>7.1} ms  {:>7.1} ms  {:>7.1} ms  {:>7.1} ms",
            domain,
            mean(&single_times),
            mean(&hedge_same_times),
            mean(&hedge_dual_times),
            mean(&hickory_times)
        );
    }

    println!("{}", "-".repeat(78));

    let stats = |all: &mut Vec<f64>| -> (f64, f64, f64, f64, f64) {
        let m = mean(all);
        let med = median(all);
        let p95 = percentile(all, 95.0);
        let p99 = percentile(all, 99.0);
        let sd = stddev(all);
        (m, med, p95, p99, sd)
    };

    let (s_m, s_med, s_p95, s_p99, s_sd) = stats(&mut single_all);
    let (hs_m, hs_med, hs_p95, hs_p99, hs_sd) = stats(&mut hedge_same_all);
    let (hd_m, hd_med, hd_p95, hd_p99, hd_sd) = stats(&mut hedge_dual_all);
    let (k_m, k_med, k_p95, k_p99, k_sd) = stats(&mut hickory_all);

    println!();
    println!(
        "{:<10}  {:>10}  {:>10}  {:>10}  {:>10}",
        "", "Single", "Hedge-same", "Hedge-dual", "Hickory"
    );
    println!(
        "{:<10}  {:>7.1} ms  {:>7.1} ms  {:>7.1} ms  {:>7.1} ms",
        "mean", s_m, hs_m, hd_m, k_m
    );
    println!(
        "{:<10}  {:>7.1} ms  {:>7.1} ms  {:>7.1} ms  {:>7.1} ms",
        "median", s_med, hs_med, hd_med, k_med
    );
    println!(
        "{:<10}  {:>7.1} ms  {:>7.1} ms  {:>7.1} ms  {:>7.1} ms",
        "p95", s_p95, hs_p95, hd_p95, k_p95
    );
    println!(
        "{:<10}  {:>7.1} ms  {:>7.1} ms  {:>7.1} ms  {:>7.1} ms",
        "p99", s_p99, hs_p99, hd_p99, k_p99
    );
    println!(
        "{:<10}  {:>7.1} ms  {:>7.1} ms  {:>7.1} ms  {:>7.1} ms",
        "σ", s_sd, hs_sd, hd_sd, k_sd
    );

    println!();
    println!("Hedge-same improvement over single:");
    println!("  mean: {:+.0}%, p95: {:+.0}%, p99: {:+.0}%",
        (hs_m - s_m) / s_m * 100.0,
        (hs_p95 - s_p95) / s_p95 * 100.0,
        (hs_p99 - s_p99) / s_p99 * 100.0);
    println!("Hedge-dual improvement over single:");
    println!("  mean: {:+.0}%, p95: {:+.0}%, p99: {:+.0}%",
        (hd_m - s_m) / s_m * 100.0,
        (hd_p95 - s_p95) / s_p95 * 100.0,
        (hd_p99 - s_p99) / s_p99 * 100.0);
}

/// Run the hedging benchmark N times and aggregate samples across all runs.
/// Also reports per-run stats to show drift.
fn run_hedge_multi(rt: &tokio::runtime::Runtime, iterations: usize) {
    let hedge_delay = Duration::from_millis(10);

    println!("Hedging Benchmark × {} iterations", iterations);
    println!("Upstream: {}", DOH_UPSTREAM);
    println!("Hedge delay: {:?}", hedge_delay);
    println!("{} domains × {} rounds per iteration\n", DOMAINS.len(), ROUNDS);

    let primary_same =
        numa::forward::parse_upstream(DOH_UPSTREAM, 443).expect("failed to parse");
    let primary_dual =
        numa::forward::parse_upstream(DOH_UPSTREAM, 443).expect("failed to parse");
    let secondary_dual =
        numa::forward::parse_upstream(DOH_UPSTREAM, 443).expect("failed to parse");
    let timeout = Duration::from_secs(10);

    let resolver = rt.block_on(build_hickory_resolver());

    // Warm up
    println!("Warming up...");
    for _ in 0..5 {
        let w = build_query_vec("example.com");
        let _ = rt.block_on(numa::forward::forward_query_raw(&w, &primary_same, timeout));
        let _ = rt.block_on(numa::forward::forward_query_raw(&w, &primary_dual, timeout));
        let _ = rt.block_on(numa::forward::forward_query_raw(&w, &secondary_dual, timeout));
        let _ = rt.block_on(query_hickory_doh(&resolver, "example.com"));
    }

    // Accumulated samples across all iterations
    let mut all_single = Vec::new();
    let mut all_hedge_same = Vec::new();
    let mut all_hedge_dual = Vec::new();
    let mut all_hickory = Vec::new();

    // Per-iteration summary stats
    let mut iter_stats: Vec<[(f64, f64, f64, f64, f64); 4]> = Vec::new();

    for iter in 1..=iterations {
        println!("  iteration {}/{}...", iter, iterations);

        let mut single = Vec::new();
        let mut hedge_same = Vec::new();
        let mut hedge_dual = Vec::new();
        let mut hickory = Vec::new();

        for domain in DOMAINS {
            for _ in 0..ROUNDS {
                let wire = build_query_vec(domain);

                let t = Instant::now();
                let _ = rt.block_on(numa::forward::forward_query_raw(&wire, &primary_same, timeout));
                single.push(t.elapsed().as_secs_f64() * 1000.0);

                let t = Instant::now();
                let _ = rt.block_on(numa::forward::forward_with_hedging_raw(
                    &wire, &primary_same, &primary_same, hedge_delay, timeout,
                ));
                hedge_same.push(t.elapsed().as_secs_f64() * 1000.0);

                let t = Instant::now();
                let _ = rt.block_on(numa::forward::forward_with_hedging_raw(
                    &wire, &primary_dual, &secondary_dual, hedge_delay, timeout,
                ));
                hedge_dual.push(t.elapsed().as_secs_f64() * 1000.0);

                let t = Instant::now();
                let _ = rt.block_on(query_hickory_doh(&resolver, domain));
                hickory.push(t.elapsed().as_secs_f64() * 1000.0);
            }
        }

        let stats = |v: &mut Vec<f64>| -> (f64, f64, f64, f64, f64) {
            (mean(v), median(v), percentile(v, 95.0), percentile(v, 99.0), stddev(v))
        };
        iter_stats.push([
            stats(&mut single),
            stats(&mut hedge_same),
            stats(&mut hedge_dual),
            stats(&mut hickory),
        ]);

        all_single.extend_from_slice(&single);
        all_hedge_same.extend_from_slice(&hedge_same);
        all_hedge_dual.extend_from_slice(&hedge_dual);
        all_hickory.extend_from_slice(&hickory);
    }

    println!();
    println!("=== Per-iteration medians (drift check) ===");
    println!(
        "{:<8}  {:>10}  {:>12}  {:>12}  {:>10}",
        "iter", "Single", "Hedge-same", "Hedge-dual", "Hickory"
    );
    for (i, s) in iter_stats.iter().enumerate() {
        println!(
            "{:<8}  {:>7.1} ms  {:>9.1} ms  {:>9.1} ms  {:>7.1} ms",
            i + 1,
            s[0].1,
            s[1].1,
            s[2].1,
            s[3].1
        );
    }

    println!();
    println!("=== Per-iteration p99 (drift check) ===");
    println!(
        "{:<8}  {:>10}  {:>12}  {:>12}  {:>10}",
        "iter", "Single", "Hedge-same", "Hedge-dual", "Hickory"
    );
    for (i, s) in iter_stats.iter().enumerate() {
        println!(
            "{:<8}  {:>7.1} ms  {:>9.1} ms  {:>9.1} ms  {:>7.1} ms",
            i + 1,
            s[0].3,
            s[1].3,
            s[2].3,
            s[3].3
        );
    }

    let final_stats = |v: &mut Vec<f64>| -> (f64, f64, f64, f64, f64) {
        (mean(v), median(v), percentile(v, 95.0), percentile(v, 99.0), stddev(v))
    };
    let (s_m, s_med, s_p95, s_p99, s_sd) = final_stats(&mut all_single);
    let (hs_m, hs_med, hs_p95, hs_p99, hs_sd) = final_stats(&mut all_hedge_same);
    let (hd_m, hd_med, hd_p95, hd_p99, hd_sd) = final_stats(&mut all_hedge_dual);
    let (k_m, k_med, k_p95, k_p99, k_sd) = final_stats(&mut all_hickory);

    println!();
    let total = iterations * DOMAINS.len() * ROUNDS;
    println!("=== Aggregated across all {} samples per method ===", total);
    println!();
    println!(
        "{:<10}  {:>10}  {:>12}  {:>12}  {:>10}",
        "", "Single", "Hedge-same", "Hedge-dual", "Hickory"
    );
    println!(
        "{:<10}  {:>7.1} ms  {:>9.1} ms  {:>9.1} ms  {:>7.1} ms",
        "mean", s_m, hs_m, hd_m, k_m
    );
    println!(
        "{:<10}  {:>7.1} ms  {:>9.1} ms  {:>9.1} ms  {:>7.1} ms",
        "median", s_med, hs_med, hd_med, k_med
    );
    println!(
        "{:<10}  {:>7.1} ms  {:>9.1} ms  {:>9.1} ms  {:>7.1} ms",
        "p95", s_p95, hs_p95, hd_p95, k_p95
    );
    println!(
        "{:<10}  {:>7.1} ms  {:>9.1} ms  {:>9.1} ms  {:>7.1} ms",
        "p99", s_p99, hs_p99, hd_p99, k_p99
    );
    println!(
        "{:<10}  {:>7.1} ms  {:>9.1} ms  {:>9.1} ms  {:>7.1} ms",
        "σ", s_sd, hs_sd, hd_sd, k_sd
    );

    println!();
    println!("Hedge-same vs Single:   mean {:+.0}%, p95 {:+.0}%, p99 {:+.0}%",
        (hs_m - s_m) / s_m * 100.0,
        (hs_p95 - s_p95) / s_p95 * 100.0,
        (hs_p99 - s_p99) / s_p99 * 100.0);
    println!("Hedge-dual vs Single:   mean {:+.0}%, p95 {:+.0}%, p99 {:+.0}%",
        (hd_m - s_m) / s_m * 100.0,
        (hd_p95 - s_p95) / s_p95 * 100.0,
        (hd_p99 - s_p99) / s_p99 * 100.0);
    println!("Hedge-same vs Hickory:  mean {:+.0}%, p95 {:+.0}%, p99 {:+.0}%",
        (hs_m - k_m) / k_m * 100.0,
        (hs_p95 - k_p95) / k_p95 * 100.0,
        (hs_p99 - k_p99) / k_p99 * 100.0);
}

/// Server-to-server benchmark: Numa vs dnscrypt-proxy vs Unbound.
/// All are full servers: UDP in, encrypted forwarding to Quad9.
/// Numa + dnscrypt: DoH (HTTPS). Unbound: DoT (TLS port 853).
fn run_vs_dnscrypt(rt: &tokio::runtime::Runtime, iterations: usize) {
    const DNSCRYPT_ADDR: &str = "127.0.0.1:5455";
    const UNBOUND_ADDR: &str = "127.0.0.1:5456";
    let numa_addr: SocketAddr = NUMA_BENCH.parse().unwrap();
    let dnscrypt_addr: SocketAddr = DNSCRYPT_ADDR.parse().unwrap();
    let unbound_addr: SocketAddr = UNBOUND_ADDR.parse().unwrap();

    println!("Server-to-Server: Numa vs dnscrypt-proxy vs Unbound");
    println!("Numa (DoH):          {}", NUMA_BENCH);
    println!("dnscrypt-proxy (DoH): {}", DNSCRYPT_ADDR);
    println!("Unbound (DoT):        {}", UNBOUND_ADDR);
    println!("All forwarding to Quad9 over encrypted transport");
    println!("{} domains × {} rounds × {} iterations\n",
        DOMAINS.len(), ROUNDS, iterations);

    // Verify all are up
    let servers: Vec<(&str, SocketAddr)> = vec![
        ("Numa", numa_addr),
        ("dnscrypt-proxy", dnscrypt_addr),
        ("Unbound", unbound_addr),
    ];
    for (name, addr) in &servers {
        if rt.block_on(query_udp(*addr, "example.com")).is_none() {
            eprintln!("{} not responding on {}", name, addr);
            std::process::exit(1);
        }
    }
    println!("All servers reachable.\n");

    // Warm up
    println!("Warming up...");
    for _ in 0..5 {
        for (_, addr) in &servers {
            let _ = rt.block_on(query_udp(*addr, "example.com"));
        }
    }

    let mut all_numa = Vec::new();
    let mut all_dnscrypt = Vec::new();
    let mut all_unbound = Vec::new();
    let mut iter_stats: Vec<[(f64, f64, f64, f64, f64); 3]> = Vec::new();

    for iter in 1..=iterations {
        println!("  iteration {}/{}...", iter, iterations);

        let mut numa = Vec::new();
        let mut dnscrypt = Vec::new();
        let mut unbound = Vec::new();

        for domain in DOMAINS {
            for round in 0..ROUNDS {
                flush_cache();
                std::thread::sleep(Duration::from_millis(5));

                // Rotate order: 3 servers, 3 possible orderings
                let order = round % 3;
                let mut measure = |addr: SocketAddr| -> f64 {
                    let t = Instant::now();
                    let _ = rt.block_on(query_udp(addr, domain));
                    t.elapsed().as_secs_f64() * 1000.0
                };

                match order {
                    0 => {
                        numa.push(measure(numa_addr));
                        dnscrypt.push(measure(dnscrypt_addr));
                        unbound.push(measure(unbound_addr));
                    }
                    1 => {
                        dnscrypt.push(measure(dnscrypt_addr));
                        unbound.push(measure(unbound_addr));
                        numa.push(measure(numa_addr));
                    }
                    _ => {
                        unbound.push(measure(unbound_addr));
                        numa.push(measure(numa_addr));
                        dnscrypt.push(measure(dnscrypt_addr));
                    }
                }
            }
        }

        let stats = |v: &mut Vec<f64>| -> (f64, f64, f64, f64, f64) {
            (mean(v), median(v), percentile(v, 95.0), percentile(v, 99.0), stddev(v))
        };
        iter_stats.push([stats(&mut numa), stats(&mut dnscrypt), stats(&mut unbound)]);

        all_numa.extend_from_slice(&numa);
        all_dnscrypt.extend_from_slice(&dnscrypt);
        all_unbound.extend_from_slice(&unbound);
    }

    println!();
    println!("=== Per-iteration medians ===");
    println!("{:<8}  {:>10}  {:>14}  {:>10}", "iter", "Numa", "dnscrypt-proxy", "Unbound");
    for (i, s) in iter_stats.iter().enumerate() {
        println!("{:<8}  {:>7.1} ms  {:>11.1} ms  {:>7.1} ms",
            i + 1, s[0].1, s[1].1, s[2].1);
    }

    println!();
    println!("=== Per-iteration p99 ===");
    println!("{:<8}  {:>10}  {:>14}  {:>10}", "iter", "Numa", "dnscrypt-proxy", "Unbound");
    for (i, s) in iter_stats.iter().enumerate() {
        println!("{:<8}  {:>7.1} ms  {:>11.1} ms  {:>7.1} ms",
            i + 1, s[0].3, s[1].3, s[2].3);
    }

    let stats = |v: &mut Vec<f64>| -> (f64, f64, f64, f64, f64) {
        (mean(v), median(v), percentile(v, 95.0), percentile(v, 99.0), stddev(v))
    };
    let (n_m, n_med, n_p95, n_p99, n_sd) = stats(&mut all_numa);
    let (d_m, d_med, d_p95, d_p99, d_sd) = stats(&mut all_dnscrypt);
    let (u_m, u_med, u_p95, u_p99, u_sd) = stats(&mut all_unbound);

    println!();
    let total = iterations * DOMAINS.len() * ROUNDS;
    println!("=== Aggregated ({} samples per method) ===", total);
    println!();
    println!("{:<10}  {:>10}  {:>14}  {:>10}", "", "Numa", "dnscrypt-proxy", "Unbound");
    println!("{:<10}  {:>7.1} ms  {:>11.1} ms  {:>7.1} ms", "mean", n_m, d_m, u_m);
    println!("{:<10}  {:>7.1} ms  {:>11.1} ms  {:>7.1} ms", "median", n_med, d_med, u_med);
    println!("{:<10}  {:>7.1} ms  {:>11.1} ms  {:>7.1} ms", "p95", n_p95, d_p95, u_p95);
    println!("{:<10}  {:>7.1} ms  {:>11.1} ms  {:>7.1} ms", "p99", n_p99, d_p99, u_p99);
    println!("{:<10}  {:>7.1} ms  {:>11.1} ms  {:>7.1} ms", "σ", n_sd, d_sd, u_sd);
    println!();

    println!("Numa vs dnscrypt-proxy:");
    println!("  mean: {:+.0}%, median: {:+.0}%, p99: {:+.0}%",
        (n_m - d_m) / d_m * 100.0, (n_med - d_med) / d_med * 100.0, (n_p99 - d_p99) / d_p99 * 100.0);
    println!("Numa vs Unbound:");
    println!("  mean: {:+.0}%, median: {:+.0}%, p99: {:+.0}%",
        (n_m - u_m) / u_m * 100.0, (n_med - u_med) / u_med * 100.0, (n_p99 - u_p99) / u_p99 * 100.0);
}

/// Numa vs Unbound: both forward over plain UDP to Quad9, caching enabled.
/// Truly equal transport — no TLS, no HTTP/2, pure forwarding + cache.
fn run_vs_unbound(rt: &tokio::runtime::Runtime, iterations: usize) {
    const UNBOUND_ADDR: &str = "127.0.0.1:5456";
    let numa_addr: SocketAddr = NUMA_BENCH.parse().unwrap();
    let unbound_addr: SocketAddr = UNBOUND_ADDR.parse().unwrap();

    println!("Numa vs Unbound (both plain UDP forwarding to Quad9, caching enabled)");
    println!("Numa:    {} → 9.9.9.9:53 UDP", NUMA_BENCH);
    println!("Unbound: {} → 9.9.9.9:53 UDP", UNBOUND_ADDR);
    println!("{} domains × {} rounds × {} iterations\n",
        DOMAINS.len(), ROUNDS, iterations);

    if rt.block_on(query_udp(numa_addr, "example.com")).is_none() {
        eprintln!("Numa not responding"); std::process::exit(1);
    }
    if rt.block_on(query_udp(unbound_addr, "example.com")).is_none() {
        eprintln!("Unbound not responding"); std::process::exit(1);
    }
    println!("Both servers reachable.\n");

    println!("Warming up...");
    for _ in 0..5 {
        let _ = rt.block_on(query_udp(numa_addr, "example.com"));
        let _ = rt.block_on(query_udp(unbound_addr, "example.com"));
    }

    let mut all_numa = Vec::new();
    let mut all_unbound = Vec::new();
    let mut iter_stats: Vec<[(f64, f64, f64, f64, f64); 2]> = Vec::new();

    for iter in 1..=iterations {
        println!("  iteration {}/{}...", iter, iterations);

        let mut numa = Vec::new();
        let mut unbound = Vec::new();

        for domain in DOMAINS {
            for round in 0..ROUNDS {
                // No cache flushing — both serve from cache after first hit
                let mut measure = |addr: SocketAddr| -> f64 {
                    let t = Instant::now();
                    let _ = rt.block_on(query_udp(addr, domain));
                    t.elapsed().as_secs_f64() * 1000.0
                };

                if round % 2 == 0 {
                    numa.push(measure(numa_addr));
                    unbound.push(measure(unbound_addr));
                } else {
                    unbound.push(measure(unbound_addr));
                    numa.push(measure(numa_addr));
                }
            }
        }

        let stats = |v: &mut Vec<f64>| -> (f64, f64, f64, f64, f64) {
            (mean(v), median(v), percentile(v, 95.0), percentile(v, 99.0), stddev(v))
        };
        iter_stats.push([stats(&mut numa), stats(&mut unbound)]);

        all_numa.extend_from_slice(&numa);
        all_unbound.extend_from_slice(&unbound);
    }

    println!();
    println!("=== Per-iteration medians ===");
    println!("{:<8}  {:>10}  {:>10}", "iter", "Numa", "Unbound");
    for (i, s) in iter_stats.iter().enumerate() {
        println!("{:<8}  {:>7.1} ms  {:>7.1} ms", i + 1, s[0].1, s[1].1);
    }

    println!();
    println!("=== Per-iteration p99 ===");
    println!("{:<8}  {:>10}  {:>10}", "iter", "Numa", "Unbound");
    for (i, s) in iter_stats.iter().enumerate() {
        println!("{:<8}  {:>7.1} ms  {:>7.1} ms", i + 1, s[0].3, s[1].3);
    }

    let stats = |v: &mut Vec<f64>| -> (f64, f64, f64, f64, f64) {
        (mean(v), median(v), percentile(v, 95.0), percentile(v, 99.0), stddev(v))
    };
    let (n_m, n_med, n_p95, n_p99, n_sd) = stats(&mut all_numa);
    let (u_m, u_med, u_p95, u_p99, u_sd) = stats(&mut all_unbound);

    println!();
    let total = iterations * DOMAINS.len() * ROUNDS;
    println!("=== Aggregated ({} samples per method) ===", total);
    println!();
    println!("{:<10}  {:>10}  {:>10}", "", "Numa", "Unbound");
    println!("{:<10}  {:>7.1} ms  {:>7.1} ms", "mean", n_m, u_m);
    println!("{:<10}  {:>7.1} ms  {:>7.1} ms", "median", n_med, u_med);
    println!("{:<10}  {:>7.1} ms  {:>7.1} ms", "p95", n_p95, u_p95);
    println!("{:<10}  {:>7.1} ms  {:>7.1} ms", "p99", n_p99, u_p99);
    println!("{:<10}  {:>7.1} ms  {:>7.1} ms", "σ", n_sd, u_sd);
    println!();

    println!("Numa vs Unbound:");
    println!("  mean:   {:+.1} ms ({:+.0}%)", n_m - u_m, (n_m - u_m) / u_m * 100.0);
    println!("  median: {:+.1} ms ({:+.0}%)", n_med - u_med, (n_med - u_med) / u_med * 100.0);
    println!("  p95:    {:+.1} ms ({:+.0}%)", n_p95 - u_p95, (n_p95 - u_p95) / u_p95 * 100.0);
    println!("  p99:    {:+.1} ms ({:+.0}%)", n_p99 - u_p99, (n_p99 - u_p99) / u_p99 * 100.0);
}

/// Build a DNS query as a Vec<u8> for use with forward_query_raw.
fn build_query_vec(domain: &str) -> Vec<u8> {
    let mut buf = vec![0u8; 512];
    let len = build_query(&mut buf, domain);
    buf.truncate(len);
    buf
}

fn measure<F: FnOnce() -> R, R>(_rt: &tokio::runtime::Runtime, f: F) -> f64 {
    let start = Instant::now();
    f();
    start.elapsed().as_secs_f64() * 1000.0
}

fn mean(v: &[f64]) -> f64 {
    v.iter().sum::<f64>() / v.len() as f64
}

fn stddev(v: &[f64]) -> f64 {
    let m = mean(v);
    let var = v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / v.len() as f64;
    var.sqrt()
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n % 2 == 0 {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    } else {
        v[n / 2]
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    let idx = (p / 100.0 * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn format_delta(delta: f64) -> String {
    if delta > 0.0 {
        format!("+{:.1}", delta)
    } else {
        format!("{:.1}", delta)
    }
}

/// Query a DNS server over UDP.
async fn query_udp(addr: SocketAddr, domain: &str) -> Option<()> {
    use tokio::net::UdpSocket;

    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let mut buf = vec![0u8; 512];
    let len = build_query(&mut buf, domain);

    sock.send_to(&buf[..len], addr).await.ok()?;

    let mut resp = vec![0u8; 4096];
    tokio::time::timeout(Duration::from_secs(10), sock.recv_from(&mut resp))
        .await
        .ok()?
        .ok()?;

    Some(())
}

/// Build a shared Hickory DoH resolver (reuses TLS connection across queries).
async fn build_hickory_resolver() -> hickory_resolver::TokioResolver {
    use hickory_resolver::config::*;

    let ns = NameServerConfig {
        socket_addr: "9.9.9.9:443".parse().unwrap(),
        protocol: hickory_proto::xfer::Protocol::Https,
        tls_dns_name: Some("dns.quad9.net".to_string()),
        trust_negative_responses: true,
        bind_addr: None,
        http_endpoint: Some("/dns-query".to_string()),
    };

    let config = ResolverConfig::from_parts(None, vec![], NameServerConfigGroup::from(vec![ns]));

    let mut opts = ResolverOpts::default();
    opts.cache_size = 0;
    opts.num_concurrent_reqs = 1;
    opts.timeout = Duration::from_secs(10);

    hickory_resolver::TokioResolver::builder_with_config(config, Default::default())
        .with_options(opts)
        .build()
}

/// Query using the shared Hickory resolver.
async fn query_hickory_doh(
    resolver: &hickory_resolver::TokioResolver,
    domain: &str,
) -> Option<()> {
    use hickory_resolver::proto::rr::RecordType;
    let _ = resolver.lookup(domain, RecordType::A).await.ok()?;
    Some(())
}

fn build_query(buf: &mut [u8], domain: &str) -> usize {
    let mut pos = 0;
    buf[pos..pos + 2].copy_from_slice(&0x1234u16.to_be_bytes());
    pos += 2;
    buf[pos..pos + 2].copy_from_slice(&0x0100u16.to_be_bytes());
    pos += 2;
    buf[pos..pos + 2].copy_from_slice(&1u16.to_be_bytes());
    pos += 2;
    buf[pos..pos + 6].fill(0);
    pos += 6;

    for label in domain.split('.') {
        buf[pos] = label.len() as u8;
        pos += 1;
        buf[pos..pos + label.len()].copy_from_slice(label.as_bytes());
        pos += label.len();
    }
    buf[pos] = 0;
    pos += 1;
    buf[pos..pos + 2].copy_from_slice(&1u16.to_be_bytes());
    pos += 2;
    buf[pos..pos + 2].copy_from_slice(&1u16.to_be_bytes());
    pos += 2;
    pos
}

fn flush_cache() {
    let _ = std::process::Command::new("curl")
        .args(["-s", "-X", "DELETE", &format!("http://127.0.0.1:{NUMA_API}/cache")])
        .output();
}
