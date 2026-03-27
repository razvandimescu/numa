# Benchmarks

Numa has two benchmark suites measuring different layers of performance.

## Micro-benchmarks (`benches/`, criterion)

Nanosecond-precision measurement of individual operations on the hot path.
No running server required — these are pure Rust unit-level benchmarks.

```sh
cargo bench            # run all
cargo bench --bench hot_path      # parse, serialize, cache, clone
cargo bench --bench throughput    # pipeline QPS, buffer alloc
```

### What's measured

**hot_path** — individual operations:

| Benchmark | What it measures |
|-----------|-----------------|
| `buffer_parse` | Wire bytes → DnsPacket (typical response with 4 records) |
| `buffer_serialize` | DnsPacket → wire bytes |
| `packet_clone` | Full DnsPacket clone (what cache hit costs) |
| `cache_lookup_hit` | Cache lookup on a single-entry cache |
| `cache_lookup_hit_populated` | Cache lookup with 1000 entries |
| `cache_lookup_miss` | HashMap miss (baseline) |
| `cache_insert` | Insert into cache with packet clone |
| `round_trip_cached` | Full cached path: parse query → cache hit → serialize response |

**throughput** — pipeline capacity:

| Benchmark | What it measures |
|-----------|-----------------|
| `pipeline_throughput/N` | N cached queries end-to-end (parse → lookup → serialize) |
| `buffer_alloc` | BytePacketBuffer 4KB zero-init cost |

### Reading results

Criterion auto-compares against the previous run:

```
round_trip_cached  time: [710.5 ns 715.2 ns 720.1 ns]
                   change: [-2.48% -1.85% -1.21%] (p = 0.00 < 0.05)
                   Performance has improved.
```

- The three values are [lower bound, estimate, upper bound] of the mean
- `change` shows the delta vs the last saved baseline
- HTML reports with charts: `target/criterion/report/index.html`

To save a named baseline for comparison:

```sh
cargo bench -- --save-baseline before
# ... make changes ...
cargo bench -- --baseline before
```

## End-to-end benchmark (`bench/dns-bench.sh`)

Real-world latency comparison using `dig` against a running Numa instance
and public resolvers. Measures millisecond-level latency including network I/O.

```sh
# Start Numa first (default port 15353 for testing)
python3 bench/dns-bench.sh [port] [rounds]
python3 bench/dns-bench.sh 15353 20    # default
```

### What's measured

- **Numa (cold)**: cache flushed before each query — measures upstream forwarding
- **Numa (cached)**: queries hit cache — measures local processing
- **System / Google / Cloudflare / Quad9**: public resolver comparison

Results saved to `bench/results.json`.

### When to use which

| Question | Use |
|----------|-----|
| Did my code change make parsing faster? | `cargo bench --bench hot_path` |
| Is the cached path still sub-microsecond? | `cargo bench --bench hot_path` (round_trip_cached) |
| How many queries/sec can we handle? | `cargo bench --bench throughput` |
| Is Numa still competitive with system resolver? | `bench/dns-bench.sh` |
| Did upstream forwarding regress? | `bench/dns-bench.sh` |
