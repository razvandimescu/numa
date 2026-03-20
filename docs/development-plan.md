# Numa Development Plan

*March 2026*

## Vision

**"DNS you own. Everywhere you go."**

Numa is a portable DNS resolver that gives you control over your DNS — ad blocking, developer overrides, caching — in a single binary that travels with your laptop. No Raspberry Pi, no cloud account, no data leaving your machine.

Long-term: self-sovereign DNS via pkarr/DHT, then an incentivized decentralized resolver network.

## Current State (v0.2-dev)

**Completed:**
- DNS forwarding + TTL-aware caching (sub-ms cached lookups)
- Ephemeral overrides with auto-expiry via REST API
- Live web dashboard (stats, query log, override management with create/edit/delete)
- DNS-level ad blocking — 385K+ domains blocked via Hagezi Pro blocklist
  - Subdomain matching (blocks `ads.tracker.example.com` if `tracker.example.com` is in blocklist)
  - Correct AAAA responses (`::` for IPv6 queries, `0.0.0.0` for A queries)
  - One-click allowlist from dashboard query log
  - Pause blocking (5 min) and toggle on/off from dashboard header
  - Auto-download on startup, background refresh every 24h
  - Lock-free hot path: blocklist parsed outside lock, swapped in sub-microsecond
  - Adblock filter syntax support (`||domain^$options`)
- Blocking API: `/blocking/stats`, `/blocking/toggle`, `/blocking/pause`, `/blocking/allowlist`, `/blocking/check/{domain}`
- Domain check search box in dashboard sidebar
- Query log filtering by domain and path (client-side, instant)
- Diagnose endpoint includes blocklist check in pipeline
- System DNS auto-detection (no Google default, falls back to Quad9)
- Conditional forwarding auto-discovery (Tailscale, VPN split-DNS)
- `numa install/uninstall` — set/restore system DNS
- `numa service start/stop/status` — launchd (macOS) + systemd (Linux) with auto-restart
- Service start/stop couples DNS configuration automatically
- Install script (`curl | sh`) + GitHub Actions release workflow (4 platform targets)
- EDNS fix: 4096-byte buffer, filter UNKNOWN records on serialization
- Startup banner with system info (DNS, API, upstream, zones, cache, blocking, routing)
- Performance benchmarks (`bench/dns-bench.sh`) — Numa cached: 0ms, vs Google/Cloudflare: 15-22ms
- Single binary, zero DNS libraries, async tokio
- MIT license, CI via GitHub Actions
- Dogfooding as system DNS on macOS

## Strategic Positioning

| Competitor | Their model | Numa's advantage |
|---|---|---|
| Pi-hole | Network appliance (Raspberry Pi) | Single binary, portable, no hardware |
| NextDNS | Cloud service, subscription | Local-first, no account, data stays on your machine |
| Cloudflare 1.1.1.1 | Centralized cloud | No phone-home, full control, open source |
| AdGuard Home | Network appliance | Portable, developer-focused features |
| `/etc/hosts` | Manual file editing | Auto-expiry, REST API, dashboard, blocklists |

**Unique combination**: Portable ad blocking + developer DNS overrides + sovereignty roadmap. No competitor offers all three.

## Three-Layer Adoption Funnel

```
Layer 1: Ad Blocking        → mainstream users (everyone wants this)
Layer 2: Developer Overrides → technical users (power feature, switching cost)
Layer 3: Decentralized DNS   → sovereignty crowd (long-term moat)
```

Each layer is independently valuable. Users enter at Layer 1, discover Layer 2, and stay for Layer 3.

---

## Phase 1: Ad Blocking (Weeks 1-4) — COMPLETED

**Goal**: Numa blocks ads and trackers out of the box, with a beautiful dashboard showing what it blocked.

**Status**: Done. 385K+ domains blocked, dashboard with blocking controls, one-click allowlist, pause/toggle, correct AAAA handling, lock-free hot path.

### 1.1 Blocklist Engine (Week 1-2)

**Blocklist loader**
- Download standard blocklist files on first run
- Parse into `HashSet<String>` for O(1) domain lookup
- Default lists:
  - [Hagezi Multi Pro](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/pro.txt) (~170K domains)
  - [OISD Small](https://small.oisd.nl/domainswild) (balanced, low false positives)
- Store parsed blocklist in `ServerCtx` alongside existing state
- Persist downloaded lists to `~/.numa/blocklists/` for offline use

**Block check in resolution pipeline**
```
Query → Overrides → Blocklist → Local Zones → Cache → Upstream
```
- If domain (or parent domain) is in blocklist → return `0.0.0.0` / `::`
- Record as `QueryPath::Blocked` (already wired in stats)
- Allowlist takes precedence over blocklist

**Config**
```toml
[blocking]
enabled = true
lists = [
  "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/pro.txt",
  "https://small.oisd.nl/domainswild",
]
refresh_hours = 24
allowlist = []
```

**Dependencies**
- Add `reqwest` (with rustls, no OpenSSL) for HTTP downloads

### 1.2 Allowlist & Controls (Week 2)

- Allowlist in config (`blocking.allowlist = ["analytics.example.com"]`)
- Runtime allowlist via API (persisted to `~/.numa/allowlist.txt`)
- "Pause blocking for N minutes" — temporary disable with auto-resume

### 1.3 API Endpoints (Week 2)

```
GET    /blocking/stats          → { enabled, domains_loaded, lists, last_refresh }
POST   /blocking/pause          → { minutes: 5 } — pause blocking temporarily
POST   /blocking/allowlist      → { domain: "..." } — add to allowlist
DELETE /blocking/allowlist/{d}  → remove from allowlist
POST   /blocking/refresh        → trigger re-download of lists
PUT    /blocking/toggle         → enable/disable blocking
```

### 1.4 Dashboard Integration (Week 3)

- **Blocked count stat card** (alongside queries, cache, overrides, uptime)
- **Top blocked domains** panel (most frequently blocked, shareable/screenshottable)
- **Blocked percentage** in resolution paths bar chart (already wired)
- **One-click allowlist**: click a blocked domain in the query log → "Allow" button → adds to allowlist
- **Pause button** in dashboard header — "Pause 5m" for quick debugging
- **Blocking toggle** — on/off switch in header

### 1.5 Background Refresh (Week 3)

- Tokio background task: re-download blocklists every `refresh_hours`
- Atomic swap of the `HashSet` — no downtime during refresh
- Log count of domains loaded per list

### 1.6 Polish (Week 4)

- Subdomain matching: block `tracker.example.com` if `example.com` is in blocklist
- CNAME cloaking awareness (if upstream returns CNAME, check the CNAME target too)
- Startup log: "Loaded 170,432 blocked domains from 2 lists"
- First-run experience: if no config exists, download default lists automatically

---

## Phase 2: System Integration (Weeks 5-6)

**Goal**: Zero-friction install. Run one command, Numa becomes your DNS.

### 2.1 Auto-Discovery of System DNS

- Parse `scutil --dns` (macOS) to discover conditional forwarding rules
- Auto-detect Tailscale, VPN split-DNS, mDNS domains
- Build forwarding rules: `*.ts.net → 100.100.100.100`, etc.
- Linux: parse `systemd-resolved` or `/etc/resolv.conf`

### 2.2 System DNS Auto-Configuration

- `numa install` command: sets system DNS to `127.0.0.1`
- `numa uninstall` command: restores original DNS settings
- macOS: `networksetup -setdnsservers`
- Linux: systemd-resolved or `/etc/resolv.conf`
- Store original settings for clean revert

### 2.3 Install Script

```bash
curl -sSL https://get.numa.dev/install.sh | sh
```
- Detect OS/arch, download binary from GitHub Releases
- Homebrew tap: `brew install razvandimescu/tap/numa`
- AUR package for Arch Linux

### 2.4 Service Mode

- `numa service install` — install as launchd (macOS) / systemd (Linux) service
- Auto-start on boot, restart on crash
- `numa service status/stop/start`

---

## Phase 3: Launch (Weeks 7-8)

**Goal**: Maximum impact public launch.

### 3.1 Pre-Launch (Week 7)

- [ ] README rewrite: hero GIF, one-liner, install command, "Why Numa?" section
- [ ] Comparison table in README (vs Pi-hole, NextDNS, AdGuard, Cloudflare)
- [ ] Terminal demo GIF (install → run → browse → dashboard shows blocked queries)
- [ ] Blog post: "Why I replaced Pi-hole with a single binary"
- [ ] Build-in-public Twitter threads (2 weeks before launch)
- [ ] 5 beta testers validate the install → use flow

### 3.2 Launch Day (Week 8)

- **Show HN**: "Numa — Portable DNS with ad blocking, built from scratch in Rust"
- Respond to every comment for 6 hours
- Reddit posts (spaced 24h): r/selfhosted, r/rust, r/homelab, r/privacy
- Ship as GitHub Release v0.2.0 with changelog

### 3.3 Post-Launch (Weeks 9-12)

- Fix bugs reported by community (priority #1)
- Deep technical blog post: "Building a DNS resolver from scratch in Rust"
- PR to awesome-selfhosted, awesome-rust
- YouTube terminal demo
- Crates.io publish

---

## Phase 4: Developer Features Marketing (Months 3-4)

**Goal**: Activate the developer segment. Users who installed for ad blocking discover the power features.

- Blog post series: override use cases (mock APIs, staging environments, CI/CD)
- CLI companion or shell aliases for common patterns
- Integration examples with Docker, CI pipelines
- `numa override` CLI shortcut: `numa override api.dev 127.0.0.1 30m`

---

## Phase 5: Decentralized DNS (Months 6-12)

**Goal**: Build the long-term moat. Self-sovereign DNS via pkarr/Mainline DHT.

- pkarr spike: resolve pkarr names via DHT
- Publish endpoint: users can publish their own DNS records to DHT
- Re-publish daemon: keep records alive
- Key management: ed25519 keypairs for domain ownership
- Fallback: pkarr → traditional DNS if DHT lookup fails

*Details in `docs/authoritative-roadmap.md`*

---

## Phase 6: Network Economics (Month 12+)

**Goal**: Incentivized resolver network — only if Phase 5 validates demand.

- Resolver staking (skin in the game)
- Challenge-based auditing (verify resolver honesty)
- Decentralized blocklist governance (community votes on what gets blocked)
- Token economics design

*Only pursue if decentralized layer has organic demand. Premature tokenization kills projects.*

---

## Success Metrics

| Milestone | Target | Timeline |
|---|---|---|
| Ad blocking MVP | Blocks 100K+ domains, dashboard shows stats | Week 2 |
| v0.2.0 release | Full ad blocking + allowlist + dashboard | Week 4 |
| System integration | One-command install, auto-configure DNS | Week 6 |
| Show HN launch | 200+ stars day 1, front page 4+ hours | Week 8 |
| Month 1 post-launch | 1000+ stars, awesome-selfhosted listing | Week 12 |
| Month 3 | 2000+ stars, first external contributors | Month 3 |
| Month 6 | pkarr prototype working | Month 6 |

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Aggressive blocking breaks sites | Users uninstall | Conservative default list, one-click allowlist, pause button |
| macOS restricts system DNS changes | Install flow breaks | Support DoH proxy mode as fallback |
| Browser DoH bypasses local DNS | Blocking stops working | Offer local DoH endpoint browsers can use |
| Feature creep across 3 layers | Nothing ships well | Ruthless sequencing — finish each phase before starting next |
| Competitor fast-follow | Lose first-mover window | Move fast, build community, ship decentralized layer (true moat) |

---

## Architecture Impact

### New modules needed
```
src/
  blocklist.rs    # BlocklistStore — HashSet<String>, download, parse, refresh
  system_dns.rs   # Auto-discover system DNS config (scutil/systemd-resolved)
  cli.rs          # CLI commands (install, uninstall, service, override)
```

### Modified modules
```
src/ctx.rs        # Add blocklist check to handle_query() pipeline
src/config.rs     # Add [blocking] config section
src/api.rs        # Add /blocking/* endpoints, serve dashboard
src/main.rs       # Background refresh task, CLI dispatch
site/dashboard.html  # Blocked stats, allowlist UI, pause button
```

### New dependencies
```
reqwest = { version = "0.12", features = ["rustls-tls"], default-features = false }
clap = { version = "4", features = ["derive"] }  # CLI argument parsing (Phase 2)
```
