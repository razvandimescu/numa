# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

A DNS forwarding/caching proxy in Rust. Serves local zone records from TOML config, caches upstream responses with TTL-based expiration, forwards unknown queries to an upstream resolver, and logs all queries with structured output.

## Build & Run

```bash
cargo build                         # compile
sudo cargo run                      # run with default config (dns_fun.toml)
sudo cargo run -- path/to/config    # run with custom config path
RUST_LOG=debug sudo cargo run       # verbose logging
```

Test with: `dig @127.0.0.1 google.com`

No tests or linter configured.

## Architecture

```
src/
  lib.rs        # module declarations, Error/Result type aliases
  main.rs       # startup, config load, UDP listen loop, request pipeline
  buffer.rs     # BytePacketBuffer — 512-byte DNS wire format read/write
  header.rs     # DnsHeader, ResultCode — 12-byte header bitfield parsing
  question.rs   # DnsQuestion, QueryType — query section (A, NS, CNAME, MX, AAAA)
  record.rs     # DnsRecord — resource record variants with read/write
  packet.rs     # DnsPacket — top-level: header + questions + answers + authorities + resources
  config.rs     # Config loading from TOML, zone map builder
  cache.rs      # DnsCache — TTL-aware cache with lazy eviction
  forward.rs    # forward_query() — sends query to upstream, build_servfail() — error response
  stats.rs      # ServerStats — query counters and periodic summary
```

## Request Pipeline

```
Query → Parse → Log → Local Zones → Cache → Upstream Forward (+ cache result) → Log → Respond
```

## Config

`dns_fun.toml` at project root. Sections: `[server]`, `[upstream]`, `[cache]`, `[[zones]]`. Falls back to sensible defaults if file is missing.

## Logging

Controlled via `RUST_LOG` env var. Default level: `info` (one structured line per query). `debug` adds response details. Stats summary every 1000 queries.

## Key Details

- Rust 2018 edition, deps: `serde`, `toml`, `log`, `env_logger`
- DNS packet size limited to 512 bytes (standard UDP DNS)
- `BytePacketBuffer::read_qname` handles label compression (pointer jumps)
- `type Error = Box<dyn std::error::Error>` / `type Result<T>` aliased in `lib.rs`
- Cache: TTL clamped between `min_ttl` and `max_ttl`, lazy eviction every 1000 queries
