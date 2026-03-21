# Numa

**DNS you own. Everywhere you go.**

Block ads and trackers. Override DNS for development. Name your local services. Cache for speed. A single portable binary built from scratch in Rust — no Raspberry Pi, no cloud, no account.

![Numa dashboard](assets/hero-demo.gif)

## Why

- **Ad blocking that travels with you** — 385K+ domains blocked out of the box. Works on any network: coffee shops, hotels, airports.
- **Developer overrides** — point any hostname to any IP with auto-revert. No more editing `/etc/hosts`.
- **Local service proxy** — access `https://frontend.numa` instead of `localhost:5173`. Auto-generated TLS certs, WebSocket support for HMR.
- **Sub-millisecond caching** — cached lookups in 0ms. Faster than any public resolver.
- **Live dashboard** — real-time query stats, blocking controls, override management, local services at `http://numa.numa` (or `localhost:5380`).
- **Single binary, zero config** — just run it.

## Quick Start

### From source

```bash
git clone https://github.com/razvandimescu/numa.git
cd numa
cargo build
sudo cargo run                      # binds to port 53, downloads blocklists on first run
```

### Docker

```bash
docker build -t numa .
docker run -p 53:53/udp -p 5380:5380 numa
```

### Try it

Open the dashboard: **http://numa.numa** (or `http://localhost:5380`)

```bash
dig @127.0.0.1 google.com           # ✓ resolves normally
dig @127.0.0.1 ads.google.com       # ✗ blocked → 0.0.0.0
```

Set Numa as your system DNS (all traffic goes through Numa):
```bash
sudo cargo run -- install           # saves current DNS, sets system to 127.0.0.1
sudo cargo run -- uninstall         # restores original DNS settings

# Or if installed to PATH:
sudo cp target/release/numa /usr/local/bin/
sudo numa install
sudo numa uninstall
```

Create an override:
```bash
curl -X POST http://localhost:5380/overrides \
  -H 'Content-Type: application/json' \
  -d '{"domain":"api.dev","target":"127.0.0.1","ttl":60,"duration_secs":300}'

dig @127.0.0.1 api.dev              # → 127.0.0.1 (auto-reverts in 5 min)
```

## Local Service Proxy

Name your local dev services with `.numa` domains instead of remembering port numbers:

```bash
# Register a service via API
curl -X POST http://localhost:5380/services \
  -H 'Content-Type: application/json' \
  -d '{"name":"frontend","target_port":5173}'

# Now access it by name
open http://frontend.numa            # → proxied to localhost:5173
```

Or configure in `numa.toml`:
```toml
[[services]]
name = "frontend"
target_port = 5173

[[services]]
name = "api"
target_port = 8000
```

- `numa.numa` is pre-configured — the dashboard itself, accessible without remembering the port
- **HTTPS with green lock** — auto-generated local CA + per-service TLS certs. `sudo numa install` trusts the CA in your system keychain.
- WebSocket support — Vite/webpack HMR works through the proxy
- Health checks — dashboard shows green/red status for each service
- Services persist across restarts (`~/.config/numa/services.json`)
- Manage via dashboard UI or REST API

## Resolution Pipeline

```
Query → Overrides → .numa TLD → Blocklist → Local Zones → Cache → Upstream → Respond
```

1. **Overrides** — ephemeral, time-scoped redirects (highest priority)
2. **`.numa` TLD** — synthetic domains for local services → returns `127.0.0.1`
3. **Blocklist** — 385K+ ad/tracker domains → returns `0.0.0.0` / `::`
4. **Local zones** — records defined in `[[zones]]` config
5. **Cache** — TTL-adjusted cached upstream responses (sub-ms)
6. **Forward** — query upstream resolver, cache the result
7. **SERVFAIL** — returned on upstream failure

## Dashboard

Live at `http://localhost:5380` when Numa is running:

- Total queries, cache hit rate, blocked count, uptime
- Resolution path breakdown (forward / cached / local / override / blocked)
- Scrolling query log with colored path tags
- Active overrides with create/edit/delete
- Local services with health status and add/remove
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

[proxy]
enabled = true
port = 80
tld = "numa"

[[services]]
name = "frontend"
target_port = 5173

[[zones]]
domain = "mysite.local"
record_type = "A"
value = "127.0.0.1"
ttl = 60
```

## HTTP API

REST API on port 5380 (22 endpoints):

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Live dashboard |
| `/overrides` | POST | Create override(s) |
| `/overrides` | GET | List active overrides |
| `/overrides` | DELETE | Clear all overrides |
| `/overrides/environment` | POST | Batch load overrides |
| `/overrides/{domain}` | GET | Get specific override |
| `/overrides/{domain}` | DELETE | Remove specific override |
| `/services` | GET | List local services (with health status) |
| `/services` | POST | Register a local service |
| `/services/{name}` | DELETE | Remove a local service |
| `/blocking/stats` | GET | Blocklist stats (domains loaded, sources, enabled) |
| `/blocking/toggle` | PUT | Enable/disable blocking |
| `/blocking/pause` | POST | Pause blocking for N minutes |
| `/blocking/allowlist` | GET | List allowlisted domains |
| `/blocking/allowlist` | POST | Add domain to allowlist |
| `/blocking/allowlist/{domain}` | DELETE | Remove from allowlist |
| `/blocking/check/{domain}` | GET | Check if domain is blocked |
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
| Local service proxy | No | No | No | `.numa` domains + HTTPS + WebSocket |
| Data stays local | Yes | Cloud | Cloud | 100% local |
| Zero config | Complex setup | Yes | Yes | Works out of the box |
| Self-sovereign DNS | No | No | No | pkarr/DHT roadmap |

## Use Cases

**Block ads everywhere** — Run Numa on your laptop. Your ad blocker works on any network.

**Name your local services** — `frontend.numa` instead of `localhost:5173`. CORS-friendly, HMR-compatible.

**Mock external services** — `Point api.stripe.com to localhost:8080 for 30 minutes`

**Provision dev environments** — Create overrides for `db.dev`, `api.dev`, `cache.dev`

**Debug DNS** — `/diagnose/example.com` traces the full resolution path

## Built From Scratch

Zero external DNS libraries. RFC 1035 wire protocol parsed by hand. Dependencies: `tokio`, `axum`, `serde`, `toml`, `reqwest` (for blocklist downloads).

## Roadmap

- [x] DNS proxy core — forwarding, caching, local zones
- [x] Developer overrides — REST API with auto-expiry
- [x] Ad blocking — 385K+ domains, dashboard, allowlist
- [x] System DNS auto-discovery — Tailscale, VPN split-DNS
- [x] System DNS auto-configuration — `numa install` / `numa uninstall`
- [x] Local service proxy — `.numa` domains with HTTP/HTTPS reverse proxy, auto TLS, WebSocket
- [ ] pkarr integration — resolve Ed25519 keys via Mainline DHT (15M nodes)
- [ ] Global `.numa` names — self-publish, DHT-backed, first-come-first-served
- [ ] Audit protocol — challenge-based verification of resolver honesty
- [ ] Numa Network — proof-of-service consensus, NUMA token, paid `.numa` domains
- [ ] `.onion` bridge — human-readable `.numa` names for Tor hidden services

## License

MIT
