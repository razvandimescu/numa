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

### Phase 8: Decentralized DNS (Months 6-12)

- pkarr spike: resolve pkarr names via Mainline DHT
- Publish endpoint: users publish DNS records to DHT
- Re-publish daemon, key management
- Human-readable aliases for pkarr domains

### Phase 9: Network Economics (Month 12+)

- Resolver staking, challenge-based auditing
- Decentralized blocklist governance
- Token economics — only if Phase 8 validates demand

---

## Near-term Feature Ideas (backlog)

- **Configurable blocklist sources** — dashboard UI to add/remove list URLs, preset picker (Hagezi Light/Pro/Ultimate)
- **Blocklist search** — search the 385K loaded domains from dashboard
- **Custom block rules** — user-defined individual domains to block, persisted
- **Request logging through proxy** — lightweight Charles Proxy for .numa traffic
- **Environment switching** — `api.numa` → local vs staging with one click
- **Per-source domain counts** — show how many domains each blocklist contributes
- **Firefox NSS trust** — auto-add CA to Firefox's cert store via `certutil`

---

## Success Metrics

| Milestone | Target | Status |
|---|---|---|
| Ad blocking MVP | 100K+ domains, dashboard stats | Done |
| System integration | One-command install, auto-configure DNS | Done |
| Local service proxy | .numa domains with HTTP + HTTPS proxy | Done |
| Show HN launch | 200+ stars day 1, front page 4+ hours | Upcoming |
| Month 1 post-launch | 1000+ stars, awesome-selfhosted listing | — |
| Month 6 | pkarr prototype working | — |
