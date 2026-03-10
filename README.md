# dns_fun

A DNS forwarding/caching proxy written from scratch in Rust. Parses and serializes DNS wire protocol (RFC 1035), serves local zone records from TOML config, caches upstream responses with TTL-aware expiration, and logs every query with structured output.

No async runtime, no DNS libraries — just `std::net::UdpSocket` and manual packet parsing.

## Record Types

A, NS, CNAME, MX, AAAA

## Usage

```bash
# Run with default config (dns_fun.toml)
sudo cargo run

# Run with custom config path
sudo cargo run -- path/to/config.toml

# Test
dig @127.0.0.1 google.com
dig @127.0.0.1 mysite.local
```

Requires root/sudo for binding to port 53.

## Configuration

Edit `dns_fun.toml`:

```toml
[server]
bind_addr = "0.0.0.0:53"

[upstream]
address = "8.8.8.8"
port = 53
timeout_ms = 3000

[cache]
max_entries = 10000
min_ttl = 60        # floor: cache at least 60s
max_ttl = 86400     # ceiling: never cache longer than 24h

[[zones]]
domain = "mysite.local"
record_type = "A"
value = "127.0.0.1"
ttl = 60

[[zones]]
domain = "other.local"
record_type = "AAAA"
value = "::1"
ttl = 120
```

All sections are optional — sensible defaults are used if the config file is missing.

## Request Pipeline

```
Query -> Parse -> Local Zones -> Cache -> Upstream Forward -> Respond
```

1. **Local zones** — match against records defined in `[[zones]]`, respond immediately
2. **Cache** — return TTL-adjusted cached response if available
3. **Forward** — send query to upstream resolver, cache the response
4. **SERVFAIL** — returned to client on upstream failure

## Caching

- TTL derived from minimum TTL across answer records
- Clamped to configured `min_ttl`/`max_ttl` bounds
- TTLs in cached responses decrease over time (adjusted on serve)
- Lazy eviction on capacity overflow + periodic sweep every 1000 queries

## Logging

Controlled via `RUST_LOG` environment variable:

```bash
RUST_LOG=info sudo cargo run    # default — one line per query
RUST_LOG=debug sudo cargo run   # includes response details
RUST_LOG=warn sudo cargo run    # errors only
```

Log output:

```
2026-03-10T14:23:01.123Z INFO  192.168.1.5:41234 | A google.com | FORWARD | NOERROR | 12ms
2026-03-10T14:23:01.456Z INFO  192.168.1.5:41235 | A mysite.local | LOCAL | NOERROR | 0ms
2026-03-10T14:23:02.789Z INFO  192.168.1.5:41236 | A google.com | CACHED | NOERROR | 0ms
```

Stats summary (total, forwarded, cached, local, blocked, errors) logged every 1000 queries.

## Project Structure

```
src/
  main.rs       # startup, config load, UDP listen loop, request pipeline
  lib.rs        # module declarations, Error/Result type aliases
  buffer.rs     # BytePacketBuffer — 512-byte DNS wire format read/write
  header.rs     # DnsHeader, ResultCode
  question.rs   # DnsQuestion, QueryType
  record.rs     # DnsRecord (A, NS, CNAME, MX, AAAA, UNKNOWN)
  packet.rs     # DnsPacket — full DNS message parse/serialize
  config.rs     # TOML config loading, zone map builder
  cache.rs      # TTL-aware DNS response cache with lazy eviction
  forward.rs    # upstream forwarding, SERVFAIL builder
  stats.rs      # query counters and periodic summary
```

## Dependencies

```toml
toml = "0.8"
serde = { version = "1", features = ["derive"] }
log = "0.4"
env_logger = "0.11"
```
