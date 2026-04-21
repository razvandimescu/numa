//! DNS forwarding benchmark suite.
//!
//! Modes:
//!   (default)       Numa server (UDP) vs Hickory library (DoH) — the original benchmark
//!   --diag          Hickory connection reuse diagnostic (20 queries)
//!   --diag-clients  Per-query reqwest vs Hickory timing (20 queries)
//!   --direct        Library-to-library: Numa forward_query_raw vs Hickory resolver.lookup
//!   --hedge-5x      Hedging: single vs hedge-same vs hedge-dual vs Hickory (5 iterations)
//!   --vs-unbound    Server-to-server: Numa vs Unbound (plain UDP, caching)
//!   --vs-unbound-cold  Cold: Numa vs Unbound (unique subdomains, no cache hits)
//!   --vs-adguard    Server-to-server: Numa vs AdGuard Home (plain UDP, caching)
//!   --vs-nextdns    Server-to-cloud: Numa (local cache) vs NextDNS (remote, 45.90.28.0)
//!   --vs-dot        DoT server: Numa vs Unbound
//!   --vs-doh-servers DoH server: Numa vs Unbound (DoT upstream)
//!
//! Setup:
//!   1. Start a bench Numa instance: cargo run -- benches/numa-bench.toml
//!   2. Run: cargo bench --bench recursive_compare [-- --mode]

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
    let arg = |flag: &str| std::env::args().any(|a| a == flag);

    let rt = tokio::runtime::Runtime::new().unwrap();

    if arg("--diag") {
        return run_diag(&rt);
    }
    if arg("--diag-clients") {
        return run_diag_clients(&rt);
    }
    if arg("--direct") {
        return run_direct(&rt);
    }
    if arg("--hedge-5x") {
        return run_hedge_multi(&rt, 5);
    }
    if arg("--vs-unbound") {
        check_numa_mode(&rt, "forward");
        return run_server_comparison(&rt, "Unbound", "127.0.0.1:5456", 5, false);
    }
    if arg("--vs-unbound-cold") {
        check_numa_mode(&rt, "recursive");
        return run_server_comparison(&rt, "Unbound", "127.0.0.1:5456", 5, true);
    }
    if arg("--vs-dnscrypt") {
        check_numa_mode(&rt, "forward");
        return run_server_comparison(&rt, "dnscrypt-proxy", "127.0.0.1:5455", 5, false);
    }
    if arg("--vs-adguard") {
        check_numa_mode(&rt, "forward");
        return run_server_comparison(&rt, "AdGuard Home", "127.0.0.1:5457", 5, false);
    }
    if arg("--vs-nextdns") {
        check_numa_mode(&rt, "forward");
        return run_server_comparison(&rt, "NextDNS", "45.90.28.0:53", 5, false);
    }
    if arg("--vs-dot") {
        return run_dot_comparison(&rt, 5);
    }
    if arg("--vs-doh-servers") {
        return run_doh_comparison(&rt, 5);
    }

    // Default: Numa server (UDP) vs Hickory library (DoH)
    run_default(&rt);
}

// ── Generic 2-way comparison engine ─────────────────────────────

fn compare_two(
    rt: &tokio::runtime::Runtime,
    title: &str,
    name_a: &str,
    name_b: &str,
    measure_a: &dyn Fn(&str) -> f64,
    measure_b: &dyn Fn(&str) -> f64,
    iterations: usize,
) {
    compare_two_rounds(
        rt, title, name_a, name_b, measure_a, measure_b, iterations, ROUNDS,
    );
}

fn compare_two_rounds(
    rt: &tokio::runtime::Runtime,
    title: &str,
    name_a: &str,
    name_b: &str,
    measure_a: &dyn Fn(&str) -> f64,
    measure_b: &dyn Fn(&str) -> f64,
    iterations: usize,
    rounds: usize,
) {
    let flush = std::env::args().any(|a| a == "--flush");
    println!("{}", title);
    println!(
        "{} domains × {} rounds × {} iterations\n",
        DOMAINS.len(),
        rounds,
        iterations
    );

    let mut all_a = Vec::new();
    let mut all_b = Vec::new();
    let mut iter_stats: Vec<[(f64, f64, f64, f64, f64); 2]> = Vec::new();

    for iter in 1..=iterations {
        println!("  iteration {}/{}...", iter, iterations);
        let mut a = Vec::new();
        let mut b = Vec::new();

        for domain in DOMAINS {
            for round in 0..rounds {
                if flush {
                    flush_cache();
                    std::thread::sleep(Duration::from_millis(5));
                }
                if round % 2 == 0 {
                    a.push(measure_a(domain));
                    b.push(measure_b(domain));
                } else {
                    b.push(measure_b(domain));
                    a.push(measure_a(domain));
                }
            }
        }

        iter_stats.push([stats(&mut a), stats(&mut b)]);
        all_a.extend_from_slice(&a);
        all_b.extend_from_slice(&b);
    }

    print_results(
        name_a,
        name_b,
        &iter_stats,
        &mut all_a,
        &mut all_b,
        iterations,
        rounds,
    );
}

fn print_results(
    name_a: &str,
    name_b: &str,
    iter_stats: &[[(f64, f64, f64, f64, f64); 2]],
    all_a: &mut Vec<f64>,
    all_b: &mut Vec<f64>,
    iterations: usize,
    rounds: usize,
) {
    let w = name_a.len().max(name_b.len()).max(6);

    println!("\n=== Per-iteration medians ===");
    println!("{:<8}  {:>w$}  {:>w$}", "iter", name_a, name_b, w = w + 3);
    for (i, s) in iter_stats.iter().enumerate() {
        println!(
            "{:<8}  {:>w$.1} ms  {:>w$.1} ms",
            i + 1,
            s[0].1,
            s[1].1,
            w = w
        );
    }

    println!("\n=== Per-iteration p99 ===");
    println!("{:<8}  {:>w$}  {:>w$}", "iter", name_a, name_b, w = w + 3);
    for (i, s) in iter_stats.iter().enumerate() {
        println!(
            "{:<8}  {:>w$.1} ms  {:>w$.1} ms",
            i + 1,
            s[0].3,
            s[1].3,
            w = w
        );
    }

    let (a_m, a_med, a_p95, a_p99, a_sd) = stats(all_a);
    let (b_m, b_med, b_p95, b_p99, b_sd) = stats(all_b);

    let total = iterations * DOMAINS.len() * rounds;
    println!("\n=== Aggregated ({} samples per method) ===\n", total);
    println!("{:<10}  {:>w$}  {:>w$}", "", name_a, name_b, w = w + 3);
    println!("{:<10}  {:>w$.1} ms  {:>w$.1} ms", "mean", a_m, b_m, w = w);
    println!(
        "{:<10}  {:>w$.1} ms  {:>w$.1} ms",
        "median",
        a_med,
        b_med,
        w = w
    );
    println!(
        "{:<10}  {:>w$.1} ms  {:>w$.1} ms",
        "p95",
        a_p95,
        b_p95,
        w = w
    );
    println!(
        "{:<10}  {:>w$.1} ms  {:>w$.1} ms",
        "p99",
        a_p99,
        b_p99,
        w = w
    );
    println!("{:<10}  {:>w$.1} ms  {:>w$.1} ms", "σ", a_sd, b_sd, w = w);

    let pct = |a: f64, b: f64| {
        if b.abs() > 0.001 {
            (a - b) / b * 100.0
        } else {
            0.0
        }
    };
    println!("\n{} vs {}:", name_a, name_b);
    println!("  mean:   {:+.1} ms ({:+.0}%)", a_m - b_m, pct(a_m, b_m));
    println!(
        "  median: {:+.1} ms ({:+.0}%)",
        a_med - b_med,
        pct(a_med, b_med)
    );
    println!(
        "  p99:    {:+.1} ms ({:+.0}%)",
        a_p99 - b_p99,
        pct(a_p99, b_p99)
    );
}

// ── Modes ───────────────────────────────────────────────────────

/// Default: Numa server (UDP) vs Hickory library (DoH), cache flushed.
fn run_default(rt: &tokio::runtime::Runtime) {
    let numa_addr: SocketAddr = NUMA_BENCH.parse().unwrap();
    if rt.block_on(query_udp(numa_addr, "example.com")).is_none() {
        eprintln!("Bench Numa not responding on {numa_addr}");
        eprintln!("Start with: cargo run -- benches/numa-bench.toml");
        std::process::exit(1);
    }

    let resolver = rt.block_on(build_hickory_resolver());

    println!("Warming up...");
    for _ in 0..3 {
        rt.block_on(query_udp(numa_addr, "example.com"));
        rt.block_on(query_hickory_doh(&resolver, "example.com"));
    }
    flush_cache();

    compare_two(
        rt,
        &format!("DoH Forwarding: Numa server vs Hickory library\nBoth → {DOH_UPSTREAM}"),
        "Numa",
        "Hickory",
        &|domain| {
            flush_cache();
            std::thread::sleep(Duration::from_millis(10));
            let t = Instant::now();
            let _ = rt.block_on(query_udp(numa_addr, domain));
            t.elapsed().as_secs_f64() * 1000.0
        },
        &|domain| {
            let t = Instant::now();
            let _ = rt.block_on(query_hickory_doh(&resolver, domain));
            t.elapsed().as_secs_f64() * 1000.0
        },
        1,
    );
}

/// Library-to-library: Numa forward_query_raw vs Hickory resolver.lookup.
fn run_direct(rt: &tokio::runtime::Runtime) {
    let upstream = numa::forward::parse_upstream(DOH_UPSTREAM, 443, None).expect("failed to parse");
    let resolver = rt.block_on(build_hickory_resolver());
    let timeout = Duration::from_secs(10);

    println!("Warming up...");
    for _ in 0..3 {
        let w = build_query_vec("example.com");
        let _ = rt.block_on(numa::forward::forward_query_raw(&w, &upstream, timeout));
        let _ = rt.block_on(query_hickory_doh(&resolver, "example.com"));
    }

    compare_two(
        rt,
        &format!("Direct DoH: Numa forward_query_raw vs Hickory resolver.lookup\nBoth → {DOH_UPSTREAM}, no server pipeline"),
        "Numa", "Hickory",
        &|domain| {
            let w = build_query_vec(domain);
            let t = Instant::now();
            let _ = rt.block_on(numa::forward::forward_query_raw(&w, &upstream, timeout));
            t.elapsed().as_secs_f64() * 1000.0
        },
        &|domain| {
            let t = Instant::now();
            let _ = rt.block_on(query_hickory_doh(&resolver, domain));
            t.elapsed().as_secs_f64() * 1000.0
        },
        5,
    );
}

/// Server-to-server: Numa vs another server, both on plain UDP.
/// When `cold` is true, each query uses a unique random subdomain so neither
/// server can answer from its record cache (NS delegation caching still applies).
fn run_server_comparison(
    rt: &tokio::runtime::Runtime,
    other_name: &str,
    other_addr: &str,
    iterations: usize,
    cold: bool,
) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    // Unique prefix per process so re-runs don't hit stale cache entries
    let run_id = std::process::id();

    let numa_addr: SocketAddr = NUMA_BENCH.parse().unwrap();
    let other: SocketAddr = other_addr.parse().unwrap();

    for (name, addr) in [("Numa", numa_addr), (other_name, other)] {
        if rt.block_on(query_udp(addr, "example.com")).is_none() {
            eprintln!("{name} not responding on {addr}");
            std::process::exit(1);
        }
    }

    if cold {
        flush_cache(); // flush Numa's record cache
    }

    println!("Warming up...");
    for _ in 0..5 {
        let _ = rt.block_on(query_udp(numa_addr, "example.com"));
        let _ = rt.block_on(query_udp(other, "example.com"));
    }

    let tag = if cold {
        "cold, unique subdomains"
    } else {
        "caching"
    };

    let rounds = if cold { 1 } else { ROUNDS };

    compare_two_rounds(
        rt,
        &format!("Server-to-Server: Numa vs {other_name} (UDP, {tag})"),
        "Numa",
        other_name,
        &|domain| {
            let d = if cold {
                format!(
                    "r{}-c{}.{}",
                    run_id,
                    COUNTER.fetch_add(1, Ordering::Relaxed),
                    domain
                )
            } else {
                domain.to_string()
            };
            let t = Instant::now();
            let _ = rt.block_on(query_udp(numa_addr, &d));
            t.elapsed().as_secs_f64() * 1000.0
        },
        &|domain| {
            let d = if cold {
                format!(
                    "r{}-c{}.{}",
                    run_id,
                    COUNTER.fetch_add(1, Ordering::Relaxed),
                    domain
                )
            } else {
                domain.to_string()
            };
            let t = Instant::now();
            let _ = rt.block_on(query_udp(other, &d));
            t.elapsed().as_secs_f64() * 1000.0
        },
        iterations,
        rounds,
    );
}

/// DoT server comparison: Numa vs Unbound.
fn run_dot_comparison(rt: &tokio::runtime::Runtime, iterations: usize) {
    const NUMA_DOT: &str = "127.0.0.1:8530";
    const UNBOUND_DOT: &str = "127.0.0.1:8531";

    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls_config = build_insecure_tls_config();

    for (name, addr) in [("Numa", NUMA_DOT), ("Unbound", UNBOUND_DOT)] {
        match rt.block_on(query_dot_once(addr, "example.com", &tls_config)) {
            Ok(_) => println!("{name} DoT: OK"),
            Err(e) => {
                eprintln!("{name} DoT not responding on {addr}: {e}");
                std::process::exit(1);
            }
        }
    }

    println!("Warming up...");
    for _ in 0..3 {
        let _ = rt.block_on(query_dot_once(NUMA_DOT, "example.com", &tls_config));
        let _ = rt.block_on(query_dot_once(UNBOUND_DOT, "example.com", &tls_config));
    }

    compare_two(
        rt,
        "DoT Server: Numa vs Unbound (both DoT→clients, forwarding to Quad9)",
        "Numa",
        "Unbound",
        &|domain| {
            let t = Instant::now();
            let _ = rt.block_on(query_dot_once(NUMA_DOT, domain, &tls_config));
            t.elapsed().as_secs_f64() * 1000.0
        },
        &|domain| {
            let t = Instant::now();
            let _ = rt.block_on(query_dot_once(UNBOUND_DOT, domain, &tls_config));
            t.elapsed().as_secs_f64() * 1000.0
        },
        iterations,
    );
}

/// DoH server comparison: Numa vs Unbound (both DoH→clients, DoT upstream).
fn run_doh_comparison(rt: &tokio::runtime::Runtime, iterations: usize) {
    const NUMA_DOH: &str = "https://127.0.0.1:8443/dns-query";
    const UNBOUND_DOH: &str = "https://127.0.0.1:8445/dns-query";

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .danger_accept_invalid_certs(true)
        .http2_initial_stream_window_size(65_535)
        .http2_initial_connection_window_size(65_535)
        .pool_idle_timeout(Duration::from_secs(300))
        .build()
        .unwrap();

    for (name, url, host) in [
        ("Numa", NUMA_DOH, Some("numa.numa")),
        ("Unbound", UNBOUND_DOH, None),
    ] {
        let w = build_query_vec("example.com");
        match rt.block_on(query_doh_server(&client, url, &w, host)) {
            Ok(_) => println!("{name} DoH: OK"),
            Err(e) => {
                eprintln!("{name} DoH not responding: {e}");
                std::process::exit(1);
            }
        }
    }

    println!("Warming up...");
    for _ in 0..5 {
        let w = build_query_vec("example.com");
        let _ = rt.block_on(query_doh_server(&client, NUMA_DOH, &w, Some("numa.numa")));
        let _ = rt.block_on(query_doh_server(&client, UNBOUND_DOH, &w, None));
    }

    compare_two(
        rt,
        "DoH Server: Numa vs Unbound (both DoH→clients, DoT upstream)",
        "Numa",
        "Unbound",
        &|domain| {
            let w = build_query_vec(domain);
            let t = Instant::now();
            let _ = rt.block_on(query_doh_server(&client, NUMA_DOH, &w, Some("numa.numa")));
            t.elapsed().as_secs_f64() * 1000.0
        },
        &|domain| {
            let w = build_query_vec(domain);
            let t = Instant::now();
            let _ = rt.block_on(query_doh_server(&client, UNBOUND_DOH, &w, None));
            t.elapsed().as_secs_f64() * 1000.0
        },
        iterations,
    );
}

/// Hedging: single vs hedge-same vs hedge-dual vs Hickory.
/// This is the one mode that compares 4 contenders, not 2.
fn run_hedge_multi(rt: &tokio::runtime::Runtime, iterations: usize) {
    let hedge_delay = Duration::from_millis(10);
    let timeout = Duration::from_secs(10);

    println!("Hedging Benchmark × {iterations} iterations");
    println!("Upstream: {DOH_UPSTREAM}");
    println!("Hedge delay: {hedge_delay:?}");
    println!(
        "{} domains × {ROUNDS} rounds per iteration\n",
        DOMAINS.len()
    );

    let primary = numa::forward::parse_upstream(DOH_UPSTREAM, 443, None).expect("failed to parse");
    let primary_dual = numa::forward::parse_upstream(DOH_UPSTREAM, 443, None).expect("failed to parse");
    let secondary_dual = numa::forward::parse_upstream(DOH_UPSTREAM, 443, None).expect("failed to parse");
    let resolver = rt.block_on(build_hickory_resolver());

    println!("Warming up...");
    for _ in 0..5 {
        let w = build_query_vec("example.com");
        let _ = rt.block_on(numa::forward::forward_query_raw(&w, &primary, timeout));
        let _ = rt.block_on(numa::forward::forward_query_raw(&w, &primary_dual, timeout));
        let _ = rt.block_on(numa::forward::forward_query_raw(
            &w,
            &secondary_dual,
            timeout,
        ));
        let _ = rt.block_on(query_hickory_doh(&resolver, "example.com"));
    }

    let labels = ["Single", "Hedge-same", "Hedge-dual", "Hickory"];
    let mut all: [Vec<f64>; 4] = [vec![], vec![], vec![], vec![]];
    let mut iter_medians: Vec<[f64; 4]> = vec![];
    let mut iter_p99s: Vec<[f64; 4]> = vec![];

    for iter in 1..=iterations {
        println!("  iteration {iter}/{iterations}...");
        let mut samples: [Vec<f64>; 4] = [vec![], vec![], vec![], vec![]];

        for domain in DOMAINS {
            for _ in 0..ROUNDS {
                let w = build_query_vec(domain);

                let t = Instant::now();
                let _ = rt.block_on(numa::forward::forward_query_raw(&w, &primary, timeout));
                samples[0].push(t.elapsed().as_secs_f64() * 1000.0);

                let t = Instant::now();
                let _ = rt.block_on(numa::forward::forward_with_hedging_raw(
                    &w,
                    &primary,
                    &primary,
                    hedge_delay,
                    timeout,
                ));
                samples[1].push(t.elapsed().as_secs_f64() * 1000.0);

                let t = Instant::now();
                let _ = rt.block_on(numa::forward::forward_with_hedging_raw(
                    &w,
                    &primary_dual,
                    &secondary_dual,
                    hedge_delay,
                    timeout,
                ));
                samples[2].push(t.elapsed().as_secs_f64() * 1000.0);

                let t = Instant::now();
                let _ = rt.block_on(query_hickory_doh(&resolver, domain));
                samples[3].push(t.elapsed().as_secs_f64() * 1000.0);
            }
        }

        let s: Vec<_> = samples.iter_mut().map(|v| stats(v)).collect();
        iter_medians.push([s[0].1, s[1].1, s[2].1, s[3].1]);
        iter_p99s.push([s[0].3, s[1].3, s[2].3, s[3].3]);
        for (i, v) in samples.iter().enumerate() {
            all[i].extend_from_slice(v);
        }
    }

    println!("\n=== Per-iteration medians ===");
    println!(
        "{:<8}  {:>10}  {:>12}  {:>12}  {:>10}",
        "iter", labels[0], labels[1], labels[2], labels[3]
    );
    for (i, m) in iter_medians.iter().enumerate() {
        println!(
            "{:<8}  {:>7.1} ms  {:>9.1} ms  {:>9.1} ms  {:>7.1} ms",
            i + 1,
            m[0],
            m[1],
            m[2],
            m[3]
        );
    }

    println!("\n=== Per-iteration p99 ===");
    println!(
        "{:<8}  {:>10}  {:>12}  {:>12}  {:>10}",
        "iter", labels[0], labels[1], labels[2], labels[3]
    );
    for (i, p) in iter_p99s.iter().enumerate() {
        println!(
            "{:<8}  {:>7.1} ms  {:>9.1} ms  {:>9.1} ms  {:>7.1} ms",
            i + 1,
            p[0],
            p[1],
            p[2],
            p[3]
        );
    }

    let s: Vec<_> = all
        .iter_mut()
        .map(|v| {
            let (m, med, p95, p99, sd) = stats(v);
            [m, med, p95, p99, sd]
        })
        .collect();
    let total = iterations * DOMAINS.len() * ROUNDS;
    println!("\n=== Aggregated ({total} samples per method) ===\n");
    println!(
        "{:<10}  {:>10}  {:>12}  {:>12}  {:>10}",
        "", labels[0], labels[1], labels[2], labels[3]
    );
    for (row, idx) in [("mean", 0), ("median", 1), ("p95", 2), ("p99", 3), ("σ", 4)] {
        println!(
            "{:<10}  {:>7.1} ms  {:>9.1} ms  {:>9.1} ms  {:>7.1} ms",
            row, s[0][idx], s[1][idx], s[2][idx], s[3][idx]
        );
    }

    let pct = |a: f64, b: f64| {
        if b.abs() > 0.001 {
            (a - b) / b * 100.0
        } else {
            0.0
        }
    };
    println!(
        "\nHedge-same vs Single:  mean {:+.0}%, p95 {:+.0}%, p99 {:+.0}%",
        pct(s[1][0], s[0][0]),
        pct(s[1][2], s[0][2]),
        pct(s[1][3], s[0][3])
    );
    println!(
        "Hedge-same vs Hickory: mean {:+.0}%, p95 {:+.0}%, p99 {:+.0}%",
        pct(s[1][0], s[3][0]),
        pct(s[1][2], s[3][2]),
        pct(s[1][3], s[3][3])
    );
}

// ── Diagnostics (small, kept for debugging) ─────────────────────

fn run_diag(rt: &tokio::runtime::Runtime) {
    println!("Hickory connection reuse diagnostic\n20 queries to {DOH_UPSTREAM}\n");

    let resolver = rt.block_on(build_hickory_resolver());
    let domains = [
        "example.com",
        "rust-lang.org",
        "kernel.org",
        "google.com",
        "github.com",
        "example.com",
        "rust-lang.org",
        "kernel.org",
        "google.com",
        "github.com",
        "example.com",
        "rust-lang.org",
        "kernel.org",
        "google.com",
        "github.com",
        "example.com",
        "rust-lang.org",
        "kernel.org",
        "google.com",
        "github.com",
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
                let first = lookup
                    .iter()
                    .next()
                    .map(|r| format!("{r}"))
                    .unwrap_or_default();
                println!(
                    "{:>3}  {:<20}  {:>7.1} ms  OK  {}",
                    i + 1,
                    domain,
                    ms,
                    first
                );
            }
            Err(e) => println!("{:>3}  {:<20}  {:>7.1} ms  ERR {}", i + 1, domain, ms, e),
        }
    }
}

fn run_diag_clients(rt: &tokio::runtime::Runtime) {
    println!("Client diagnostic: reqwest vs Hickory (20 queries to {DOH_UPSTREAM})\n");

    let upstream = numa::forward::parse_upstream(DOH_UPSTREAM, 443, None).expect("failed to parse");
    let resolver = rt.block_on(build_hickory_resolver());
    let timeout = Duration::from_secs(10);

    for _ in 0..3 {
        let w = build_query_vec("example.com");
        let _ = rt.block_on(numa::forward::forward_query_raw(&w, &upstream, timeout));
        let _ = rt.block_on(query_hickory_doh(&resolver, "example.com"));
    }

    let domains = [
        "example.com",
        "google.com",
        "github.com",
        "rust-lang.org",
        "cloudflare.com",
        "example.com",
        "google.com",
        "github.com",
        "rust-lang.org",
        "cloudflare.com",
        "example.com",
        "google.com",
        "github.com",
        "rust-lang.org",
        "cloudflare.com",
        "example.com",
        "google.com",
        "github.com",
        "rust-lang.org",
        "cloudflare.com",
    ];

    println!(
        "{:>3}  {:<20}  {:>12}  {:>12}",
        "#", "Domain", "reqwest", "Hickory"
    );
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
            i + 1,
            domain,
            r_ms,
            r_ok,
            h_ms,
            h_ok
        );
    }
}

// ── Stats helpers ───────────────────────────────────────────────

fn stats(v: &mut [f64]) -> (f64, f64, f64, f64, f64) {
    if v.is_empty() {
        return (0.0, 0.0, 0.0, 0.0, 0.0);
    }
    let mean = v.iter().sum::<f64>() / v.len() as f64;
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    let median = if n % 2 == 0 {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    } else {
        v[n / 2]
    };
    let p95 = v[((n as f64 * 0.95).round() as usize).min(n - 1)];
    let p99 = v[((n as f64 * 0.99).round() as usize).min(n - 1)];
    let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
    (mean, median, p95, p99, var.sqrt())
}

// ── Query helpers ───────────────────────────────────────────────

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

async fn query_dot_once(
    addr: &str,
    domain: &str,
    tls_config: &std::sync::Arc<rustls::ClientConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    let connector = TlsConnector::from(tls_config.clone());
    let stream = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from("localhost")?;
    let mut tls = connector.connect(server_name, stream).await?;

    let mut buf = vec![0u8; 512];
    let len = build_query(&mut buf, domain);
    let msg = &buf[..len];

    let mut out = Vec::with_capacity(2 + msg.len());
    out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    out.extend_from_slice(msg);
    tls.write_all(&out).await?;

    let mut len_buf = [0u8; 2];
    tls.read_exact(&mut len_buf).await?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tls.read_exact(&mut resp).await?;
    Ok(())
}

async fn query_doh_server(
    client: &reqwest::Client,
    url: &str,
    wire: &[u8],
    host: Option<&str>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut req = client
        .post(url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(wire.to_vec());
    if let Some(h) = host {
        req = req.header("host", h);
    }
    let resp = req.send().await?.error_for_status()?;
    Ok(resp.bytes().await?.to_vec())
}

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

async fn query_hickory_doh(resolver: &hickory_resolver::TokioResolver, domain: &str) -> Option<()> {
    use hickory_resolver::proto::rr::RecordType;
    let _ = resolver.lookup(domain, RecordType::A).await.ok()?;
    Some(())
}

fn build_insecure_tls_config() -> std::sync::Arc<rustls::ClientConfig> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::DigitallySignedStruct;

    #[derive(Debug)]
    struct NoVerify;
    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
    std::sync::Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
            .with_no_client_auth(),
    )
}

// ── Wire helpers ────────────────────────────────────────────────

fn build_query_vec(domain: &str) -> Vec<u8> {
    let mut buf = vec![0u8; 512];
    let len = build_query(&mut buf, domain);
    buf.truncate(len);
    buf
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

fn check_numa_mode(rt: &tokio::runtime::Runtime, expected: &str) {
    let url = format!("http://127.0.0.1:{NUMA_API}/stats");
    let resp = match rt.block_on(async { reqwest::get(&url).await?.text().await }) {
        Ok(body) => body,
        Err(_) => {
            eprintln!("Bench Numa not responding on {NUMA_BENCH}");
            eprintln!("Start with: cargo run -- benches/numa-bench.toml");
            std::process::exit(1);
        }
    };
    let config = if expected == "recursive" {
        "benches/numa-bench-recursive.toml"
    } else {
        "benches/numa-bench.toml"
    };
    if !resp.contains(&format!("\"mode\":\"{expected}\"")) {
        eprintln!("This benchmark requires Numa in {expected} mode.");
        eprintln!("Restart with: cargo run -- {config}");
        std::process::exit(1);
    }
}

fn flush_cache() {
    let _ = std::process::Command::new("curl")
        .args([
            "-s",
            "-X",
            "DELETE",
            &format!("http://127.0.0.1:{NUMA_API}/cache"),
        ])
        .output();
}
