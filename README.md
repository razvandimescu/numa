# Numa

**DNS you own. Everywhere you go.**

A portable DNS resolver in a single binary. Block ads on any network, name your local services (`frontend.numa`), and override any hostname with auto-revert — all from your laptop, no cloud account or Raspberry Pi required.

Built from scratch in Rust. Zero DNS libraries. RFC 1035 wire protocol parsed by hand.

![Numa dashboard](assets/hero-demo.gif)

## Quick Start

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/razvandimescu/numa/main/install.sh | sh

# Run (port 53 requires root)
sudo numa

# Try it
dig @127.0.0.1 google.com           # ✓ resolves normally
dig @127.0.0.1 ads.google.com       # ✗ blocked → 0.0.0.0
```

Open the dashboard: **http://localhost:5380**

Or build from source:
```bash
git clone https://github.com/razvandimescu/numa.git && cd numa
cargo build --release
sudo ./target/release/numa
```

## Why Numa

- **Ad blocking that travels with you** — 385K+ domains blocked via [Hagezi Pro](https://github.com/hagezi/dns-blocklists). Works on any network: coffee shops, hotels, airports.
- **Local service proxy** — `https://frontend.numa` instead of `localhost:5173`. Auto-generated TLS certs, WebSocket support for HMR. Like `/etc/hosts` but with a dashboard and auto-revert.
- **Developer overrides** — point any hostname to any IP, auto-reverts after N minutes. REST API with 22 endpoints.
- **Sub-millisecond caching** — cached lookups in 0ms. Faster than any public resolver.
- **Live dashboard** — real-time stats, query log, blocking controls, service management.
- **macOS + Linux** — `numa install` configures system DNS, `numa service start` runs as launchd/systemd service.

## Local Service Proxy

Name your local dev services with `.numa` domains:

```bash
curl -X POST localhost:5380/services \
  -H 'Content-Type: application/json' \
  -d '{"name":"frontend","target_port":5173}'

open http://frontend.numa            # → proxied to localhost:5173
```

- **HTTPS with green lock** — auto-generated local CA + per-service TLS certs
- **WebSocket** — Vite/webpack HMR works through the proxy
- **Health checks** — dashboard shows green/red status per service
- **Persistent** — services survive restarts
- Or configure in `numa.toml`:

```toml
[[services]]
name = "frontend"
target_port = 5173
```

## How It Compares

| | Pi-hole | AdGuard Home | NextDNS | Cloudflare | Numa |
|---|---|---|---|---|---|
| Ad blocking | Yes | Yes | Yes | Limited | 385K+ domains |
| Portable (travels with laptop) | No (appliance) | No (appliance) | Cloud only | Cloud only | Single binary |
| Developer overrides | No | No | No | No | REST API + auto-expiry |
| Local service proxy | No | No | No | No | `.numa` + HTTPS + WS |
| Data stays local | Yes | Yes | Cloud | Cloud | 100% local |
| Zero config | Complex | Docker/setup | Yes | Yes | Works out of the box |
| Self-sovereign DNS | No | No | No | No | pkarr/DHT roadmap |

## How It Works

```
Query → Overrides → .numa TLD → Blocklist → Local Zones → Cache → Upstream
```

No DNS libraries. The wire protocol — headers, labels, compression pointers, record types — is parsed and serialized by hand. Runs on `tokio` + `axum`, async per-query task spawning.

[Full API reference (22 endpoints)](docs/development-plan.md) · [Configuration reference](numa.toml)

## Roadmap

- [x] DNS proxy core — forwarding, caching, local zones
- [x] Developer overrides — REST API with auto-expiry
- [x] Ad blocking — 385K+ domains, live dashboard, allowlist
- [x] System integration — macOS + Linux, launchd/systemd, Tailscale/VPN auto-discovery
- [x] Local service proxy — `.numa` domains, HTTP/HTTPS proxy, auto TLS, WebSocket
- [ ] pkarr integration — self-sovereign DNS via Mainline DHT (15M nodes)
- [ ] Global `.numa` names — self-publish, DHT-backed, first-come-first-served

## License

MIT
