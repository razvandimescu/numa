# Numa

[![CI](https://github.com/razvandimescu/numa/actions/workflows/ci.yml/badge.svg)](https://github.com/razvandimescu/numa/actions)
[![crates.io](https://img.shields.io/crates/v/numa.svg)](https://crates.io/crates/numa)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**DNS you own. Everywhere you go.** — [numa.rs](https://numa.rs)

A portable DNS resolver in a single binary. Block ads on any network, name your local services (`frontend.numa`), and override any hostname with auto-revert — all from your laptop, no cloud account or Raspberry Pi required.

Built from scratch in Rust. Zero DNS libraries. RFC 1035 wire protocol parsed by hand. Caching, ad blocking, and local service domains out of the box. Optional recursive resolution from root nameservers with full DNSSEC chain-of-trust validation, plus a DNS-over-TLS listener for encrypted client connections (iOS Private DNS, systemd-resolved, etc.). One ~8MB binary, everything embedded.

![Numa dashboard](assets/hero-demo.gif)

## Quick Start

```bash
# macOS
brew install razvandimescu/tap/numa

# Linux
curl -fsSL https://raw.githubusercontent.com/razvandimescu/numa/main/install.sh | sh

# Windows — download from GitHub Releases
# All platforms
cargo install numa
```

```bash
sudo numa                              # run in foreground (port 53 requires root/admin)
```

Open the dashboard: **http://numa.numa** (or `http://localhost:5380`)

Set as system DNS:

| Platform | Install | Uninstall |
|----------|---------|-----------|
| macOS | `sudo numa install` | `sudo numa uninstall` |
| Linux | `sudo numa install` | `sudo numa uninstall` |
| Windows | `numa install` (admin) + reboot | `numa uninstall` (admin) + reboot |

On macOS and Linux, numa runs as a system service (launchd/systemd). On Windows, numa auto-starts on login via registry.

## Local Services

Name your dev services instead of remembering port numbers:

```bash
curl -X POST localhost:5380/services \
  -d '{"name":"frontend","target_port":5173}'
```

Now `https://frontend.numa` works in your browser — green lock, valid cert, WebSocket passthrough for HMR. No mkcert, no nginx, no `/etc/hosts`.

Add path-based routing (`app.numa/api → :5001`), share services across machines via LAN discovery, or configure everything in [`numa.toml`](numa.toml).

## Ad Blocking & Privacy

385K+ domains blocked via [Hagezi Pro](https://github.com/hagezi/dns-blocklists). Works on any network — coffee shops, hotels, airports. Travels with your laptop.

Three resolution modes:

- **`forward`** (default) — transparent proxy to your existing system DNS. Everything works as before, just with caching and ad blocking on top. Captive portals, VPNs, corporate DNS — all respected.
- **`recursive`** — resolve directly from root nameservers. No upstream dependency, no single entity sees your full query pattern. Add `[dnssec] enabled = true` for full chain-of-trust validation.
- **`auto`** — probe root servers on startup, recursive if reachable, encrypted DoH fallback if blocked.

DNSSEC validates the full chain of trust: RRSIG signatures, DNSKEY verification, DS delegation, NSEC/NSEC3 denial proofs. [Read how it works →](https://numa.rs/blog/posts/dnssec-from-scratch.html)

**DNS-over-TLS listener** (RFC 7858) — accept encrypted queries on port 853 from strict clients like iOS Private DNS, systemd-resolved, or stubby. Self-signed CA generated automatically, or bring your own cert via `[dot] cert_path` / `key_path` in `numa.toml`. ALPN `"dot"` is advertised and enforced; a handshake with mismatched ALPN is rejected as a cross-protocol confusion defense.

## LAN Discovery

Run Numa on multiple machines. They find each other automatically via mDNS:

```
Machine A (192.168.1.5)              Machine B (192.168.1.20)
┌──────────────────────┐             ┌──────────────────────┐
│ Numa                 │    mDNS     │ Numa                 │
│  - api (port 8000)   │◄───────────►│  - grafana (3000)    │
│  - frontend (5173)   │  discovery  │                      │
└──────────────────────┘             └──────────────────────┘
```

From Machine B: `curl http://api.numa` → proxied to Machine A's port 8000. Enable with `numa lan on`.

**Hub mode**: run one instance with `bind_addr = "0.0.0.0:53"` and point other devices' DNS to it — they get ad blocking + `.numa` resolution without installing anything.

## How It Compares

| | Pi-hole | AdGuard Home | Unbound | Numa |
|---|---|---|---|---|
| Local service proxy + auto TLS | — | — | — | `.numa` domains, HTTPS, WebSocket |
| LAN service discovery | — | — | — | mDNS, zero config |
| Developer overrides (REST API) | — | — | — | Auto-revert, scriptable |
| Recursive resolver | — | — | Yes | Yes, with SRTT selection |
| DNSSEC validation | — | — | Yes | Yes (RSA, ECDSA, Ed25519) |
| Ad blocking | Yes | Yes | — | 385K+ domains |
| Web admin UI | Full | Full | — | Dashboard |
| Encrypted upstream (DoH) | Needs cloudflared | Yes | — | Native |
| Encrypted clients (DoT listener) | Needs stunnel sidecar | Yes | Yes | Native (RFC 7858) |
| Portable (laptop) | No (appliance) | No (appliance) | Server | Single binary, macOS/Linux/Windows |
| Community maturity | 56K stars, 10 years | 33K stars | 20 years | New |

## Performance

691ns cached round-trip. ~2.0M qps throughput. Zero heap allocations in the hot path. Recursive queries average 237ms after SRTT warmup (12x improvement over round-robin). ECDSA P-256 DNSSEC verification: 174ns. [Benchmarks →](bench/)

## Learn More

- [Blog: Implementing DNSSEC from Scratch in Rust](https://numa.rs/blog/posts/dnssec-from-scratch.html)
- [Blog: I Built a DNS Resolver from Scratch](https://numa.rs/blog/posts/dns-from-scratch.html)
- [Configuration reference](numa.toml) — all options documented inline
- [REST API](src/api.rs) — 27 endpoints across overrides, cache, blocking, services, diagnostics

## Roadmap

- [x] DNS forwarding, caching, ad blocking, developer overrides
- [x] `.numa` local domains — auto TLS, path routing, WebSocket proxy
- [x] LAN service discovery — mDNS, cross-machine DNS + proxy
- [x] DNS-over-HTTPS — encrypted upstream
- [x] DNS-over-TLS listener — encrypted client connections (RFC 7858, ALPN strict)
- [x] Recursive resolution + DNSSEC — chain-of-trust, NSEC/NSEC3
- [x] SRTT-based nameserver selection
- [ ] pkarr integration — self-sovereign DNS via Mainline DHT
- [ ] Global `.numa` names — DHT-backed, no registrar

## License

MIT
