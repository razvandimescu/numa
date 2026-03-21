# Numa Development Plan

*March 2026*

## Vision

**"DNS you own. Everywhere you go."**

Numa is a portable DNS resolver that gives you control over your DNS — ad blocking, developer overrides, local service proxy, caching — in a single binary that travels with your laptop. No Raspberry Pi, no cloud account, no data leaving your machine.

Long-term: self-sovereign DNS via pkarr/DHT, then an incentivized decentralized resolver network.

## Current State (v0.2-dev)

**Completed — 7 feature layers:**

1. **DNS proxy core** — async tokio, forwarding, TTL-aware caching (sub-ms), local zones, 4096-byte EDNS buffer. Recognizes A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV, HTTPS query types.
2. **Developer overrides** — ephemeral DNS overrides with auto-expiry, REST API (22+ endpoints)
3. **Ad blocking** — 385K+ domains via Hagezi Pro (gzip download), allowlist with dashboard UI, pause/unpause/toggle, domain check, sources display with refresh timestamp
4. **System integration** — auto-detect upstream (falls back to Quad9), conditional forwarding (Tailscale/VPN), `numa install/uninstall`, `numa service start/stop/restart/status` for launchd/systemd
5. **Local service proxy** — `.numa` TLD for local dev services (`frontend.numa` → `localhost:5173`). HTTP reverse proxy on :80 with WebSocket upgrade (HMR). Services persisted to `~/.config/numa/services.json`.
6. **Local TLS** — auto-generated CA + wildcard `*.numa` cert. HTTPS proxy on :443 via rustls. `numa install` trusts CA in macOS Keychain / Linux ca-certificates.
7. **Distribution** — install script, GitHub Actions release (4 targets), `make deploy` for dev cycle (build → copy → codesign → restart)

**Dashboard features:**
- Stats row (queries, cache hit rate, blocked, overrides, uptime)
- Resolution paths bar chart
- Query log with domain + path filtering (200 entries, scrollable)
- Blocking panel (domain check, sources with refresh age, allowlist management)
- Active Overrides (with subtitle: "Redirect any domain to any IP. Temporary, DNS-only.")
- Local Services (with subtitle: "Give localhost apps clean .numa URLs. Persistent, with HTTP proxy.")
- Health dots and proxy route display for services
- Cached domains list
- Blocking controls: toggle, pause 5m / unpause

**Dogfooding:** Running as system DNS on macOS daily.

## Strategic Positioning

| Competitor | Their model | Numa's advantage |
|---|---|---|
| Pi-hole | Network appliance (Raspberry Pi) | Single binary, portable, no hardware |
| NextDNS | Cloud service, subscription | Local-first, no account, data stays on machine |
| Cloudflare 1.1.1.1 | Centralized cloud | No phone-home, full control, open source |
| AdGuard Home | Network appliance | Portable, developer-focused features |
| `/etc/hosts` | Manual file editing | Auto-expiry, REST API, dashboard, blocklists |

**Unique combination**: Portable ad blocking + developer DNS overrides + local service proxy + sovereignty roadmap. No competitor offers all four.

## Three-Layer Adoption Funnel

```
Layer 1: Ad Blocking         → mainstream users (everyone wants this)
Layer 2: Developer Tools     → technical users (.numa domains, overrides — switching cost)
Layer 3: Decentralized DNS   → sovereignty crowd (long-term moat)
```

---

## Completed Phases

### Phase 0: DNS Proxy Core — DONE
Async tokio runtime, modular architecture, forwarding, caching, local zones.

### Phase 1: Ad Blocking — DONE
385K+ domains, dashboard with blocking controls, allowlist, pause/toggle, domain check.

### Phase 2: System Integration — DONE
Auto-detect upstream, conditional forwarding, install/uninstall, launchd/systemd services.

### Phase 3: Local Service Proxy — DONE
`.numa` domains, HTTP reverse proxy on :80, WebSocket upgrade, service persistence.

### Phase 4: Local TLS — DONE
Auto-generated CA, wildcard `*.numa` cert, HTTPS proxy on :443, OS trust store integration.

---

## Next Phases

### Phase 5: Launch Preparation

- [ ] Hero GIF/screenshot for README (`scripts/record-demo.sh` ready)
- [ ] Comparison table screenshot
- [ ] Blog post: "Why I replaced Pi-hole with a single binary"
- [ ] 5 beta testers validate install → use flow
- [ ] Homebrew tap, AUR package

### Phase 6: Show HN Launch

- **Show HN**: "Numa — Portable DNS with ad blocking and .numa local domains, built from scratch in Rust"
- Reddit: r/selfhosted, r/rust, r/homelab, r/privacy
- Ship as GitHub Release v0.2.0
- Target: 200+ stars day 1

### Phase 7: Developer Features Marketing

- Blog post series: override use cases, .numa proxy workflows
- `numa override` CLI shortcut: `numa override api.dev 127.0.0.1 30m`
- `.numa.toml` project file (committed to repos, team-level service names)
- Integration examples with Docker, CI pipelines

### Phase 8: Pkarr Integration (Months 6-8)

- Add `pkarr-client` crate dependency (DHT resolution)
- Detect z-base32 TLDs (52-char) in DNS pipeline → DHT lookup
- Translate `simple-dns` records → Numa `DnsRecord` types
- Cache pkarr results in Numa DNS cache
- New `QueryPath::Pkarr` variant in stats
- Config: `[pkarr] enabled = true`
- API: `GET /pkarr/resolve/{z32key}` for debugging

### Phase 9: .numa Global Names (Months 8-10)

- Self-publishing: `numa register myblog` → generates keypair, publishes to DHT
- DHT-based name claims: `sha1("numa-claim:myblog")` → SignedPacket with owner + records
- First-come-first-served via timestamps (no chain needed initially)
- Background republish task (every hour, keeps names alive on DHT)
- Key management: keypairs stored at config dir
- Human-readable `.numa` names that resolve globally across all Numa instances

### Phase 10: Audit Protocol (Months 10-12)

- Challenge-based auditing: auditor nodes send test queries to verify resolver honesty
- Reputation scores for nodes (correct resolution, latency, uptime)
- Service score: `queries_resolved × w1 + names_republished × w2 + audits_passed × w3`
- Dashboard: node reputation and audit results

### Phase 11: Network Economics (Month 12+)

- NUMA token: earned by running nodes, spent on name registration
- Proof-of-service consensus (block production weighted by service score, not hash power)
- Lightweight chain for name ownership only (DNS records stay on DHT)
- Paid `.numa` names: $1-5/month, revenue split among republishing nodes
- Staking and slashing for node operators
- Full details: `docs/numa-network-economics.md`

### Phase 12: .onion Bridge

- Human-readable `.numa` names for Tor hidden services
- `protonmail.numa` → `protonmailrmez3lot...onion`
- Proxy routes through Tor SOCKS5 (localhost:9050)
- Combined with Numa's auto TLS: `https://protonmail.numa` with green lock
- Curated registry (git-based initially) + DHT propagation

---

## Near-term Feature Ideas (backlog)

- **Configurable blocklist sources** — dashboard UI to add/remove list URLs, preset picker (Hagezi Light/Pro/Ultimate)
- **Blocklist search** — search the 385K loaded domains from dashboard
- **Custom block rules** — user-defined individual domains to block, persisted
- **Request logging through proxy** — lightweight Charles Proxy for .numa traffic
- **Environment switching** — `api.numa` → local vs staging with one click
- **Per-source domain counts** — show how many domains each blocklist contributes
- **Firefox NSS trust** — auto-add CA to Firefox's cert store via `certutil`
- **`.numa.toml` project file** — committed to repos, team-level service names on clone

---

## Success Metrics

| Milestone | Target | Status |
|---|---|---|
| Ad blocking MVP | 100K+ domains, dashboard stats | Done |
| System integration | One-command install, auto-configure DNS | Done |
| Local service proxy | .numa domains with HTTP + HTTPS proxy | Done |
| Show HN launch | 200+ stars day 1, front page 4+ hours | Upcoming |
| Month 1 post-launch | 1000+ stars, awesome-selfhosted listing | — |
| Pkarr resolution | 100 z-base32 domains resolvable | — |
| .numa self-publishing | 1,000 globally resolvable .numa names | — |
| Token launch | 10,000 Numa installations, 5,000 names | — |
| .onion bridge | 100 mapped Tor hidden services | — |
