# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

**Numa** — a portable DNS resolver with ad blocking, developer overrides, and a live dashboard. Built from scratch in Rust. Named after Numa Pompilius, the Roman king who established lasting institutions.

Today: DNS forwarding/caching proxy with ad blocking, ephemeral overrides, live dashboard, and system DNS integration.
Next: Self-sovereign DNS via pkarr/Mainline DHT.
Vision: Incentivized resolver network with staking, challenge-based auditing, and token economics.

## Build & Run

```bash
cargo build                         # compile
sudo cargo run                      # run with default config (numa.toml)
sudo cargo run -- path/to/config    # run with custom config path
RUST_LOG=debug sudo cargo run       # verbose logging
make lint                           # clippy + rustfmt check
```

Test with: `dig @127.0.0.1 google.com`

CLI commands:
```bash
numa help                           # show all commands
numa install                        # set system DNS to 127.0.0.1
numa uninstall                      # restore original DNS
numa service start                  # install as persistent service (launchd/systemd)
numa service stop                   # uninstall service + restore DNS
numa service status                 # check service status
```

Dashboard: http://numa.numa (or http://localhost:5380)

## Architecture

```
UDP :53 ──▶ handle_query()
              │
              ├─ 1. Override Store (ephemeral, auto-expiry)
              ├─ 2. .numa TLD (local service domains → 127.0.0.1)
              ├─ 3. Blocklist (385K+ domains, subdomain matching)
              ├─ 4. Local Zones (TOML config)
              ├─ 5. Cache (TTL-aware, lazy eviction)
              └─ 6. Upstream Forward (auto-detected from OS, conditional forwarding)

HTTP :80   ──▶ Reverse proxy for .numa domains (WebSocket support)
HTTP :5380 ──▶ Axum REST API (22 endpoints) + Dashboard
```

### Source Files

```
src/
  main.rs           # startup: load config, bind UDP, spawn API + proxy, blocklist download, per-query task loop
  lib.rs            # module declarations, Error/Result type aliases
  ctx.rs            # ServerCtx shared state + handle_query() pipeline
  api.rs            # Axum REST server (22 endpoints, port 5380) + embedded dashboard
  config.rs         # TOML config loading with defaults (server, upstream, cache, blocking, proxy, zones)
  proxy.rs          # HTTP reverse proxy for .numa domains (port 80, WebSocket upgrade support)
  service_store.rs  # ServiceStore — name-to-port mappings for local service proxy
  blocklist.rs      # BlocklistStore — HashSet<String>, download, parse, subdomain matching, check
  override_store.rs # OverrideStore — ephemeral domain overrides with auto-expiry
  query_log.rs      # ring buffer (VecDeque, 1000 entries) for recent queries
  cache.rs          # DnsCache — TTL-aware, lazy eviction every 1000 lookups
  forward.rs        # async UDP forwarding to upstream resolver
  stats.rs          # ServerStats counters + QueryPath enum (6 categories)
  system_dns.rs     # OS DNS discovery (scutil/resolv.conf), install/uninstall, service management
  buffer.rs         # BytePacketBuffer — 4096-byte DNS wire format I/O
  header.rs         # DnsHeader — 12-byte bitfield parsing/serialization
  question.rs       # DnsQuestion + QueryType enum (A, NS, CNAME, MX, AAAA)
  record.rs         # DnsRecord enum — wire format read/write per record type (filters UNKNOWN on write)
  packet.rs         # DnsPacket — header + questions + answers + authorities + resources
site/
  dashboard.html    # live dashboard (embedded at compile time via include_str!)
  index.html        # landing page (Roman Stone theme)
```

## Config

`numa.toml` at project root. Sections: `[server]`, `[upstream]`, `[cache]`, `[blocking]`, `[proxy]`, `[[services]]`, `[[zones]]`. Falls back to sensible defaults if file is missing. Upstream auto-detected from system resolver if not set.

## REST API

Dashboard: GET `/` (embedded HTML)
Override management: POST/GET/DELETE `/overrides`, POST `/overrides/environment`
Services: GET/POST `/services`, DELETE `/services/{name}`
Blocking: GET `/blocking/stats`, PUT `/blocking/toggle`, POST `/blocking/pause`, GET/POST `/blocking/allowlist`, GET `/blocking/check/{domain}`
Diagnostics: GET `/diagnose/{domain}`, `/query-log`, `/stats`, `/cache`, `/health`
Cache: DELETE `/cache`, `/cache/{domain}`

## Key Details

- Rust 2021 edition, async via `tokio` (rt-multi-thread)
- Deps: tokio, axum, hyper, hyper-util, serde, serde_json, toml, log, env_logger, reqwest, futures (zero DNS libraries)
- DNS buffer size: 4096 bytes (EDNS-compatible). UNKNOWN record types (e.g. OPT) filtered on serialization.
- `BytePacketBuffer::read_qname` handles label compression (pointer jumps)
- `type Error = Box<dyn std::error::Error + Send + Sync>` / `type Result<T>` aliased in `lib.rs`
- Shared state via `Arc<ServerCtx>` with `std::sync::Mutex` (sub-microsecond holds, never across `.await`)
- Cache: TTL clamped between `min_ttl` and `max_ttl`, lazy eviction every 1000 queries
- Blocklist: parsed outside lock, swapped atomically. `is_blocked()` takes `&self` (read-only).
- Upstream: auto-detected from `scutil --dns` (macOS) or `/etc/resolv.conf` (Linux). Falls back to Quad9.
- Conditional forwarding: Tailscale/VPN domains auto-routed to correct upstream.
- macOS service: launchd plist with KeepAlive + RunAtLoad. Use `launchctl bootstrap/bootout` (not load/unload).
- Logging controlled via `RUST_LOG` env var. Default: `info`
