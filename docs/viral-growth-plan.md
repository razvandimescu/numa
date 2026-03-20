# Numa Viral Growth Plan

## Context

Numa is a DNS resolver built from scratch in Rust with zero DNS libraries, ephemeral overrides via REST API, and a vision for decentralized self-sovereign DNS. The project has strong technical foundations (~2200 LOC, 15 modules, async tokio, MIT license) and polished landing pages, but hasn't been publicly launched yet. This plan synthesizes viral growth research into a concrete, prioritized execution strategy to maximize Numa's impact at launch and sustain growth afterward.

---

## The Viral Recipe (Distilled)

Five ingredients that matter most for developer tools, in order:

| # | Ingredient | Why it works | Numa status |
|---|-----------|-------------|-------------|
| 1 | **Sub-60s time-to-value** | Every extra step loses 40-60% of visitors | Partial — needs one-command install |
| 2 | **Visual proof** | Developers scroll past text-only READMEs | Missing — no GIF, no dashboard |
| 3 | **Screenshottable artifact** | Users share what looks impressive (Pi-hole playbook) | Missing — DNS is invisible |
| 4 | **Sharp positioning** | Must fit in one sentence people repeat | Strong — "DNS resolver from scratch in Rust, zero libraries" |
| 5 | **Narrative arc** | Gives people a reason to follow, not just star | Strong — today/next/vision layers |

**Amplifiers**: "Written in Rust" signal, comparison anchors ("like Pi-hole but decentralized"), educational content ("how DNS actually works"), sovereignty/privacy narrative, single binary deployment.

**Killers**: Complex install, broken first-run, feature creep in positioning, no visual proof, astroturfing, corporate smell.

---

## Execution Plan

### Track A: Technical Virality Assets (build these)

#### A1. One-Command Install Script
**Priority**: P0 — the single biggest friction reducer
- Shell installer: `curl -sSL https://get.numa.dev/install.sh | sh`
  - Detect OS/arch, download correct binary from GitHub Releases
  - Print colored success message with next steps
- Homebrew tap: `brew install razvandimescu/tap/numa`
- Docker one-liner: `docker run -p 53:53/udp -p 5380:5380 numa`
- **Files**: new `install.sh` at repo root, Homebrew formula repo, update README

#### A2. Web Dashboard (the Pi-hole playbook)
**Priority**: P0 — transforms invisible infrastructure into shareable screenshots
- Embed a lightweight web UI served alongside the REST API on port 5380
- Single HTML page (no build step, consistent with site/ approach)
- **Must-have panels**:
  - Live query counter (total resolved, queries/sec)
  - Cache hit rate gauge (percentage, color-coded)
  - Query log stream (last N queries, live-updating)
  - Active overrides list with countdown timers
  - Resolution path breakdown (pie/donut: override/zone/cache/upstream)
  - Top queried domains
  - Latency sparkline (avg resolve time)
- **Design**: Match the stone.html aesthetic (terracotta/olive, Instrument Serif headings, JetBrains Mono for data)
- **Implementation**: Serve static HTML from `src/api.rs` at `GET /`, use SSE or polling against existing `/stats`, `/query-log`, `/cache`, `/overrides` endpoints
- **Files**: `site/dashboard.html`, modifications to `src/api.rs`

#### A3. Terminal Demo GIF
**Priority**: P0 — goes at top of README
- 30-second recording using [VHS](https://github.com/charmbracelet/vhs) or asciinema:
  1. `numa` starts (show clean startup banner with ASCII art)
  2. `dig @127.0.0.1 google.com` → instant response
  3. `curl -X POST localhost:5380/overrides -d '{"domain":"test.dev","ip":"127.0.0.1","ttl":300}'`
  4. `dig @127.0.0.1 test.dev` → resolves to 127.0.0.1
  5. Show dashboard screenshot
- **Files**: `demo.tape` (VHS script), `assets/demo.gif`, README update

#### A4. Startup Banner & CLI Polish
**Priority**: P1 — creates visual identity in terminals
- Clean ASCII banner on startup:
  ```
  ╔═══════════════════════════════════════╗
  ║  NUMA  DNS that governs itself        ║
  ║  Listening on 0.0.0.0:53             ║
  ║  API at http://localhost:5380        ║
  ║  Dashboard at http://localhost:5380  ║
  ╚═══════════════════════════════════════╝
  ```
- Colored log output (query path indicators: 🟢 cache hit, 🟡 upstream, 🔵 override, 🟣 zone)
- **Files**: `src/main.rs`

#### A5. Benchmarks
**Priority**: P1 — concrete numbers people share and debate
- Add `benches/` directory with criterion benchmarks
- Key metrics: queries/second, p50/p99 latency, cache hit performance
- Comparison against system resolver, Pi-hole, CoreDNS (when possible)
- Publish results in README and blog post
- **Files**: `benches/dns_bench.rs`, Cargo.toml update, README update

---

### Track B: Content & Distribution (write/publish these)

#### B1. README Overhaul
**Priority**: P0 — the landing page of GitHub
- **Hero section**: One-liner + install command + demo GIF
- **"Why Numa?"** section: 3 bullet points (sovereignty, developer overrides, from-scratch transparency)
- **Comparison table**: vs Pi-hole, AdGuard Home, CoreDNS, Cloudflare (position on: self-sovereign domains, developer overrides, zero DNS libs, privacy guarantees, incentivized operators)
- **Quick start**: 3 commands max
- **Architecture diagram**: ASCII or Mermaid
- Badges: CI status, license, crates.io (when published), "built from scratch" custom badge

#### B2. "I Built a DNS Resolver from Scratch in Rust" Blog Post
**Priority**: P0 — inherently viral educational content
- **Structure**:
  1. Why I did this (motivation, the problem with centralized DNS)
  2. How DNS actually works (wire protocol, 512-byte packets, label compression)
  3. The architecture (resolution pipeline, no libraries, what I learned)
  4. What's next (pkarr, DHT, decentralized network)
- **Publish**: Personal blog → cross-post to Dev.to, Hashnode
- **Timing**: 1 week before Show HN launch (builds awareness)

#### B3. Build-in-Public Twitter/X Campaign (2-4 weeks pre-launch)
**Priority**: P1
- Thread topics:
  - "I'm building a DNS resolver from scratch in Rust. Here's why."
  - "TIL: DNS label compression is wild. Here's how it works." (with diagram)
  - "What 2200 lines of Rust taught me about DNS"
  - "Why your DNS resolver is a single point of control" (the sovereignty pitch)
  - Architecture decisions, benchmark results, interesting edge cases
- Engage with Rust community, self-hosted community, DNS/networking accounts
- Share dashboard screenshots as they're built

#### B4. Show HN Launch
**Priority**: P0 — the primary launch event
- **Title**: "Show HN: Numa – DNS resolver from scratch in Rust (zero DNS libraries)"
- **Post body**: Problem → what it does → key differentiators → what's next → links
- **Timing**: Tuesday-Thursday, 8-10 AM US Eastern
- **Prep**: Have 3-5 people test the full install → use flow beforehand
- **Launch day**: Respond to every comment within minutes for first 6 hours

#### B5. Reddit Distribution (Day 2-3 post-launch)
- r/selfhosted — "I built a self-hosted DNS resolver with ephemeral overrides"
- r/rust — "Show r/rust: DNS resolver from scratch, zero DNS libraries"
- r/homelab — "New DNS tool for homelabbers with REST API and auto-expiring overrides"
- r/commandline, r/networking — targeted posts
- Space 24h apart, genuine tone, engage with all comments

#### B6. Awesome Lists & Long-tail
- PR to: awesome-selfhosted, awesome-rust, awesome-networking
- Crates.io publish
- Docker Hub listing with good description

---

### Track C: Community & Sustainability

#### C1. GitHub Repo Polish
- Issue templates (bug report, feature request)
- "Good first issue" labels on 5-10 starter tasks
- CONTRIBUTING.md
- GitHub Discussions enabled
- Release v0.1.0 with proper changelog

#### C2. Discord/Community
- Create Discord server (or use GitHub Discussions initially)
- Channels: #general, #help, #development, #showcase
- Link from README and landing page

---

## Execution Timeline

```
Week -4 to -2:  Track A (A1-A4) — Build install script, dashboard, demo GIF, CLI polish
Week -2 to -1:  Track B (B1-B3) — README overhaul, blog post draft, start Twitter threads
                Track C (C1) — GitHub repo polish, v0.1.0 release
Week 0 (Launch): B4 (Show HN) — Tuesday-Thursday morning
Week 0+1-3:     B5 (Reddit), B6 (awesome lists)
Week 2-4:       B2 publish (deep blog post), A5 (benchmarks)
Ongoing:        Twitter presence, community engagement, respond to all issues/PRs
```

---

## What to Build First (Implementation Order)

If we're implementing these in code, the priority order is:

1. **A2: Dashboard** — highest impact, makes DNS visible and shareable
2. **A4: Startup banner** — quick win, improves first-run experience
3. **A1: Install script** — reduces friction to near-zero
4. **B1: README overhaul** — converts GitHub visitors to users
5. **A3: Demo GIF** — requires the above to look good in the recording
6. **A5: Benchmarks** — provides concrete numbers for launch content

---

## Success Metrics

- **Launch day**: 200+ GitHub stars, front page HN for 4+ hours
- **Week 1**: 500+ stars, 50+ Docker pulls, 10+ issues opened
- **Month 1**: 1000+ stars, appearing in awesome-selfhosted, first external contributor
- **Month 3**: 2000+ stars, community Discord active, blog post ranking for "DNS resolver Rust"

---

## Key Insight

The #1 lesson from viral developer tools: **make the invisible visible**. DNS is invisible infrastructure. Pi-hole proved that giving DNS a face (dashboard, stats, blocked-ad counter) is the viral unlock. Numa's dashboard isn't just a feature — it's the primary virality mechanism. Every screenshot of that dashboard is an advertisement. Every "look at my DNS stats" Reddit post is organic marketing. Build the dashboard first, make it beautiful, and the sharing follows naturally.
