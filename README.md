# Numa

**DNS you own. Everywhere you go.**

Block ads and trackers. Override DNS for development. Cache for speed. A single portable binary built from scratch in Rust — no Raspberry Pi, no cloud, no account.

## Why

- **Ad blocking that travels with you** — 385K+ domains blocked out of the box. Works on any network: coffee shops, hotels, airports.
- **Developer overrides** — point any hostname to any IP with auto-revert. No more editing `/etc/hosts`.
- **Sub-millisecond caching** — cached lookups in 0ms. Faster than any public resolver.
- **Live dashboard** — real-time query stats, blocking controls, override management at `http://localhost:5380`.
- **Single binary, zero config** — just run it.

## Quick Start

```bash
cargo build
sudo cargo run                      # binds to port 53
```

Open the dashboard: **http://localhost:5380**

Test it:
```bash
dig @127.0.0.1 google.com           # normal resolution
dig @127.0.0.1 ads.google.com       # blocked → 0.0.0.0
```

## Resolution Pipeline

```
Query → Overrides → Blocklist → Local Zones → Cache → Upstream → Respond
```

1. **Overrides** — ephemeral, time-scoped redirects (highest priority)
2. **Blocklist** — 385K+ ad/tracker domains → returns `0.0.0.0` / `::`
3. **Local zones** — records defined in `[[zones]]` config
4. **Cache** — TTL-adjusted cached upstream responses (sub-ms)
5. **Forward** — query upstream resolver, cache the result
6. **SERVFAIL** — returned on upstream failure

## Dashboard

Live at `http://localhost:5380` when Numa is running:

- Total queries, cache hit rate, blocked count, uptime
- Resolution path breakdown (forward / cached / local / override / blocked)
- Scrolling query log with colored path tags
- Active overrides with create/edit/delete
- Blocking controls: toggle on/off, pause 5 minutes, one-click allowlist
- Cached domains list

## Configuration

`numa.toml` (all sections optional, sensible defaults if missing):

```toml
[server]
bind_addr = "0.0.0.0:53"
api_port = 5380

[upstream]
address = "8.8.8.8"
port = 53
timeout_ms = 3000

[cache]
max_entries = 10000
min_ttl = 60
max_ttl = 86400

[blocking]
enabled = true
lists = [
  "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/pro.txt",
]
refresh_hours = 24
allowlist = []

[[zones]]
domain = "mysite.local"
record_type = "A"
value = "127.0.0.1"
ttl = 60
```

## HTTP API

REST API on port 5380 (18 endpoints):

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Live dashboard |
| `/overrides` | POST | Create override(s) |
| `/overrides` | GET | List active overrides |
| `/overrides` | DELETE | Clear all overrides |
| `/overrides/environment` | POST | Batch load overrides |
| `/overrides/{domain}` | GET | Get specific override |
| `/overrides/{domain}` | DELETE | Remove specific override |
| `/blocking/stats` | GET | Blocklist stats (domains loaded, sources, enabled) |
| `/blocking/toggle` | PUT | Enable/disable blocking |
| `/blocking/pause` | POST | Pause blocking for N minutes |
| `/blocking/allowlist` | GET | List allowlisted domains |
| `/blocking/allowlist` | POST | Add domain to allowlist |
| `/blocking/allowlist/{domain}` | DELETE | Remove from allowlist |
| `/diagnose/{domain}` | GET | Trace resolution path |
| `/query-log` | GET | Recent queries (filterable) |
| `/stats` | GET | Server statistics |
| `/cache` | GET | List cached entries |
| `/cache` | DELETE | Flush cache |
| `/cache/{domain}` | DELETE | Flush specific domain |
| `/health` | GET | Health check |

## How It Compares

| | Pi-hole | NextDNS | Cloudflare | Numa |
|---|---|---|---|---|
| Ad blocking | Yes | Yes | Limited | 385K+ domains |
| Portable | No (Raspberry Pi) | Cloud only | Cloud only | Single binary |
| Developer overrides | No | No | No | REST API + auto-expiry |
| Data stays local | Yes | Cloud | Cloud | 100% local |
| Zero config | Complex setup | Yes | Yes | Works out of the box |
| Self-sovereign DNS | No | No | No | pkarr/DHT roadmap |

## Use Cases

**Block ads everywhere** — Run Numa on your laptop. Your ad blocker works on any network.

**Mock external services** — `Point api.stripe.com to localhost:8080 for 30 minutes`

**Provision dev environments** — Create overrides for `db.dev`, `api.dev`, `cache.dev`

**Debug DNS** — `/diagnose/example.com` traces the full resolution path

## Docker

```bash
docker build -t numa .
docker run -p 53:53/udp -p 5380:5380 numa
```

## Dependencies

```
tokio, axum, serde, serde_json, toml, log, env_logger, reqwest
```

Zero external DNS libraries. Wire protocol (RFC 1035) parsed from scratch.

## License

MIT
