# Launch Drafts

## Lessons Learned

**r/selfhosted** (0 upvotes, hostile) — "replaces Pi-hole" framing triggered
defensive comparisons. Audience protects their stack.

**r/programare** (26 upvotes, 22 comments, 12K views, 90.6% ratio) — worked
because it led with technical achievement. But: "what does this offer over
/etc/hosts?" and "mature solutions exist (dnsmasq, nginx)" were the top
objections. Tool-replacement angle falls flat with generalist audiences.

**r/webdev** — removed by moderators (self-promotion rules).

Key takeaways:

- Lead with what's *unique*, not what it *replaces*
- Write like explaining to a colleague, not marketing copy
- Pick ONE hook per community — don't try to be everything
- Triple-check the GitHub link works before posting
- Authentic tone > polished bullets
- Agree with "just use X" — then show what X can't do
- Don't oversell the pkarr/token vision — one sentence max
- Benchmark request from r/programare (Mydocalm) — warm follow-up content

---

## Launch Order

~~0. **r/programare** — done (2026-03-21). 12K views, 26 upvotes, 22 comments.~~
~~1. **r/webdev** — removed by moderators.~~

~~2. **r/degoogle** — done~~
~~3. **r/node** — done~~

4. **r/coolgithubprojects** — zero friction, just post the repo
~~5. **r/sideproject** — done (2026-03-29)~~
6. **r/dns** — technical DNS audience, recursive + DNSSEC angle
7. **Show HN** — Tuesday-Thursday, 9-10 AM ET
8. **r/rust** — same day as HN, technical deep-dive
9. **r/commandline** — 24h after HN
10. **r/selfhosted** — only if HN hits front page, lead with recursive + LAN discovery
11. **r/programare follow-up** — benchmark post + recursive/DNSSEC update

---

## Community Drafts

### Show HN

**Title (72 chars):**
Show HN: I built a DNS resolver from scratch in Rust – no DNS libraries

**Body:**

I wanted to understand how DNS actually works at the wire level, so I built
a resolver from scratch. No dns libraries — the RFC 1035 protocol (headers,
labels, compression pointers, record types) is all hand-parsed. It started
as a learning project and turned into something I use daily as my system DNS.

What it does today:

- **Forward mode by default** — transparent proxy to your existing DNS with
  caching and ad blocking. Changes nothing about your network.
- **Full recursive resolver** — set `mode = "recursive"` and it resolves from
  root nameservers. No upstream dependency. CNAME chasing, TLD priming, SRTT.
- **DNSSEC validation** — chain-of-trust verification from root KSK.
  RSA/SHA-256, ECDSA P-256, Ed25519. Sets the AD bit on verified responses.
- **Ad blocking** — ~385K+ domains via Hagezi Pro, works on any network
- **DNS-over-HTTPS** — encrypted upstream (Quad9, Cloudflare, or any
  provider) as an alternative to recursive mode
- **`.numa` local domains** — register `frontend.numa → localhost:5173` and
  it creates both the DNS record and an HTTP/HTTPS reverse proxy with
  auto-generated TLS certs. WebSocket passthrough works (Vite HMR).
- **LAN service discovery** — run Numa on two machines, they find each other
  via UDP multicast. Zero config.
- **Developer overrides** — point any hostname to any IP, auto-reverts
  after N minutes. REST API for scripting.

Single binary, macOS + Linux. `sudo numa install` and it's your system DNS —
forward mode by default, recursive when you're ready.

The interesting technical bits: the recursive resolver walks root → TLD →
authoritative with iterative queries, caching NS/DS/DNSKEY records at each
hop. DNSSEC validation verifies RRSIG signatures against DNSKEY, walks the
chain via DS records up to the hardcoded root trust anchor. ECDSA P-256
verification takes 174ns (benchmarked with criterion). Cold-cache validation
for a new domain is ~90ms, with only 1 network fetch needed (TLD chain is
pre-warmed on startup). SRTT-based nameserver selection learns which
servers respond fastest — average recursive query drops from 2.8s to
237ms after warmup (12x).

It also handles hostile networks: if your ISP blocks UDP port 53,
Numa detects this after 3 failures and switches all
queries to TCP automatically. Resets when you change networks. RFC 7816
query minimization means root servers only see the TLD, not your full
query.

The DNS cache adjusts TTLs on read (remaining time, not original). Each
query is an async tokio task. EDNS0 with DO bit and 1232-byte payload
(DNS Flag Day 2020).

Longer term I want to add pkarr/DHT resolution for self-sovereign DNS,
but that's future work.

https://github.com/razvandimescu/numa

---

### r/rust

**Title:** I built a recursive DNS resolver from scratch in Rust — DNSSEC, no DNS libraries

**Body:**

I've been building a DNS resolver in Rust as a learning project that became
my daily driver. The entire DNS wire protocol is implemented by hand —
no `trust-dns`, no `hickory-dns`, no `simple-dns`. Headers, label sequences,
compression pointers, EDNS, all of it.

Some things I found interesting while building this:

**Recursive resolution** — iterative queries from root hints, walking
root → TLD → authoritative. CNAME chasing, A+AAAA glue extraction from
additional sections, referral depth limits. TLD priming pre-warms NS + DS +
DNSKEY for 34 gTLDs + EU ccTLDs on startup.

**DNSSEC chain-of-trust** — the most involved part. Verify RRSIG signatures
against DNSKEY, walk DS records up to the hardcoded root KSK (key tag 20326).
Uses `ring` for crypto: RSA/SHA-256, ECDSA P-256 (174ns per verify), Ed25519.
RFC 3110 RSA keys need converting to PKCS#1 DER for ring — wrote an ASN.1
encoder for that. RRSIG time validity checks per RFC 4035 §5.3.1.

**NSEC/NSEC3 denial proofs** — proving a name *doesn't* exist is harder than
proving it does. NSEC uses canonical DNS name ordering to prove gap coverage.
NSEC3 uses iterated SHA-1 hashing + base32hex + a 3-part closest encloser
proof (RFC 5155 §8.4). Both require authority-section RRSIG verification.

**Wire protocol parsing** — DNS uses a binary format with label compression
(pointers back into the packet via 2-byte offsets). Parsing this correctly
is surprisingly tricky because pointers can chain. I use a `BytePacketBuffer`
that tracks position and handles jumps.

**Performance** — TLD chain pre-warming means cold-cache DNSSEC validation
needs ~1 DNSKEY fetch (down from 5). Referral DS piggybacking caches DS
from authority sections during resolution. ECDSA P-256 verify: 174ns.
RSA/SHA-256: 10.9µs. DS verify: 257ns.

**LAN service discovery** — Numa instances on the same network find each
other via UDP multicast. The tricky part was self-filtering: I initially
filtered by IP, but two instances on the same host share an IP. Switched to
a per-process instance ID (`pid ^ nanos`).

**Auto TLS** — generates a local CA + per-service certs using `rcgen`.
`numa install` trusts the CA in the OS keychain. HTTPS proxy via `rustls` +
`tokio-rustls`.

Single binary, no runtime dependencies. Uses `tokio`, `axum` (REST
API/dashboard), `hyper` (reverse proxy), `ring` (DNSSEC crypto), `reqwest`
(DoH), `socket2` (multicast), `rcgen` + `rustls` (TLS).

Happy to discuss any of the implementation decisions.

https://github.com/razvandimescu/numa

---

### r/degoogle

**Title:** I replaced cloud DNS with a recursive resolver — resolves from root, no upstream, DNSSEC

**Body:**

I wanted a DNS setup with zero cloud dependency. No NextDNS account,
no Cloudflare dashboard, no Pi-hole appliance, no upstream resolver seeing
my queries. Just a single binary on my laptop that resolves everything
itself.

Built one in Rust. What it does:

- **Forward mode by default** — transparent proxy to your existing DNS with
  caching and ad blocking. Changes nothing about your network.
- **Recursive resolution** — set `mode = "recursive"` and it resolves directly
  from root nameservers. No Quad9, no Cloudflare, no upstream dependency.
  Each authoritative server only sees the query for its zone — no single
  entity sees your full browsing pattern.
- **DNSSEC validation** — verifies the chain of trust from root KSK.
  Responses are cryptographically verified — no one can tamper with them
  in transit.
- **System-level ad blocking** — Hagezi Pro list (~385K+ domains),
  works on any network. Coffee shop WiFi, airport, hotel.
- **ISP resistant** — in recursive mode, if UDP is blocked Numa switches
  to TCP automatically. Or set `mode = "auto"` to probe on startup and
  fall back to encrypted DoH if needed.
- **Query minimization** — root servers only see the TLD (.com), not
  your full domain. RFC 7816.
- **Zero telemetry, zero cloud** — all data stays on your machine. No
  account, no login, no analytics. Config is a single TOML file.
- **Local service naming** — bonus for developers: `https://app.numa`
  instead of `localhost:3000`, with auto-generated TLS certs

Single binary, macOS + Linux. `sudo numa install` and it's your system
DNS — forward mode by default, recursive when you're ready. No Docker,
no PHP, no external dependencies.

The DNS wire protocol is parsed from scratch — no DNS libraries. You can
read every line of code.

```
brew install razvandimescu/tap/numa
# or
cargo install numa
```

MIT license. https://github.com/razvandimescu/numa

---

### r/node

**Title:** I replaced localhost:5173 with frontend.numa — auto HTTPS, HMR works, no nginx

**Body:**

Running a Vite frontend on :5173, Express API on :3000, maybe docs on
:4000 — I could never remember which port was which. And CORS between
`localhost:5173` and `localhost:3000` is its own special hell.

How do you get named domains with HTTPS locally?

1. /etc/hosts + mkcert + nginx
2. dnsmasq + mkcert + Caddy
3. `sudo numa`

What it actually does:

```
curl -X POST localhost:5380/services \
  -d '{"name":"frontend","target_port":5173}'
```

Now `https://frontend.numa` works in my browser. Green lock, valid cert.

- **HMR works** — Vite, webpack, socket.io all pass through the proxy.
  No special config.
- **CORS solved** — `frontend.numa` and `api.numa` share the `.numa`
  cookie domain. Cross-service auth just works.
- **Path routing** — `app.numa/api → :3000`, `app.numa/auth → :3001`.
  Like nginx location blocks, zero config files.

No mkcert, no nginx.conf, no Caddyfile, no editing /etc/hosts.
Single binary, one command.

```
brew install razvandimescu/tap/numa
# or
cargo install numa
```

https://github.com/razvandimescu/numa

---

### r/dns

**Title:** Numa — recursive DNS resolver from scratch in Rust, DNSSEC, no DNS libraries

**Body:**

I built a recursive DNS resolver where the entire wire protocol (RFC 1035 —
headers, label compression, EDNS0) is hand-parsed. No `hickory-dns`,
no `trust-dns`.

What it does:
- Full recursive resolver from root hints (iterative queries, no upstream needed)
- DNSSEC chain-of-trust validation (RSA/SHA-256, ECDSA P-256, Ed25519)
- EDNS0 with DO bit, 1232-byte payload (DNS Flag Day 2020 compliant)
- DNS-over-HTTPS as an alternative upstream mode
- Ad blocking (~385K+ domains via Hagezi Pro)
- Conditional forwarding (auto-detects Tailscale/VPN split-DNS)
- Local zones, ephemeral overrides with auto-revert via REST API

DNSSEC implementation: DNSKEY/DS/RRSIG record parsing, canonical wire format
for signed data, key tag computation (RFC 4034), DS digest verification.
Chain walks from zone → TLD → root trust anchor. ECDSA P-256 signature
verification in 174ns. TLD chain pre-warmed on startup. Referral DS records
piggybacked from authority sections during resolution.

NSEC/NSEC3 authenticated denial of existence: NXDOMAIN gap proofs, NSEC3
closest encloser proofs (3-part per RFC 5155), NODATA type absence proofs,
authority-section RRSIG verification. Iteration cap at 500 for NSEC3 DoS
prevention.

What it doesn't do (yet): no authoritative zone serving (AXFR/NOTIFY).

Single binary, macOS + Linux. MIT license.

https://github.com/razvandimescu/numa

---

### Lobsters (invite-only)

**Title:** Numa — DNS resolver from scratch in Rust, no DNS libraries

**Body:**

I built a DNS resolver in Rust — RFC 1035 wire protocol parsed by hand,
no `trust-dns` or `hickory-dns`. Started as a learning project, became
my daily system DNS.

Beyond resolving, it does local `.numa` domains with auto HTTPS reverse
proxy (register `frontend.numa → localhost:5173`, get a green lock and
WebSocket passthrough), and LAN service discovery via UDP multicast —
two machines running Numa find each other's services automatically.

Implementation bits I found interesting: DNS label compression (chained
2-byte pointers back into the packet), browsers rejecting wildcard certs
under single-label TLDs (`*.numa` fails — need per-service SANs), and
`SO_REUSEPORT` on macOS for multiple processes binding the same multicast
port.

Set `mode = "recursive"` for DNSSEC-validated resolution from root
nameservers — no upstream, no middleman.

Single binary, macOS + Linux.

https://github.com/razvandimescu/numa

---

### r/coolgithubprojects

**Post type:** Image post with `hero-demo.gif`, GitHub link in first comment.

**Title:** Numa — portable DNS resolver built from scratch in Rust. Ad blocking, local HTTPS domains, LAN discovery, recursive resolution with DNSSEC. Single binary.

**First comment (post immediately):**

https://github.com/razvandimescu/numa

```
brew install razvandimescu/tap/numa && sudo numa
```

No DNS libraries — RFC 1035 wire protocol parsed by hand.
Recursive resolution from root nameservers with full DNSSEC
chain-of-trust validation. 385K+ blocked ad domains.
.numa local domains with auto TLS and WebSocket proxy.

---

### r/sideproject

**Title:** I built a DNS resolver from scratch in Rust — it's now my daily system DNS

**Body:**

Last year I wanted to understand how DNS actually works at the wire
level, so I started parsing RFC 1035 packets by hand. No DNS libraries,
no trust-dns, no hickory-dns — just bytes and the spec.

It turned into something I use every day. What it does now:

- **Ad blocking** on any network (coffee shops, airports) — 385K+
  domains blocked, travels with my laptop
- **Local service naming** — `https://frontend.numa` instead of
  `localhost:5173`, with auto-generated TLS certs and WebSocket
  passthrough for HMR
- **Recursive resolution** from root nameservers with DNSSEC
  chain-of-trust validation — set `mode = "recursive"` for full
  privacy, no upstream dependency, no single entity sees my query
  pattern
- **LAN discovery** — two machines running Numa find each other's
  services automatically via mDNS

Single Rust binary, ~8MB, MIT license. `sudo numa install` and it's your
system DNS — caching, ad blocking, .numa domains, zero config changes.

I wrote about the technical journey here:
- [I Built a DNS Resolver from Scratch](https://numa.rs/blog/posts/dns-from-scratch.html)
- [Implementing DNSSEC from Scratch](https://numa.rs/blog/posts/dnssec-from-scratch.html)

https://github.com/razvandimescu/numa

---

### r/webdev (Showoff Saturday — posted 2026-03-28)

**Title:** I replaced localhost:5173 with frontend.numa — shared cookie domain, auto HTTPS, no nginx

**Body:**

The port numbers weren't the real problem. It was CORS between
`localhost:5173` and `localhost:3000`, Secure cookies not setting over
HTTP, and service workers requiring a secure context.

I built a DNS resolver that gives local services named domains under a
shared TLD:

```
curl -X POST localhost:5380/services \
  -d '{"name":"frontend","target_port":5173}'
```

Now `https://frontend.numa` and `https://api.numa` share the `.numa`
cookie domain. Cross-service auth just works. Secure cookies set.
Service workers run.

What's under the hood:
- **Auto HTTPS** — generates a local CA + per-service TLS certs. Green
  lock, no mkcert.
- **WebSocket passthrough** — Vite/webpack HMR goes through the proxy.
  No special config.
- **Path routing** — `app.numa/api → :3000`, `app.numa/auth → :3001`.
  Like nginx location blocks.
- **Also a full DNS resolver** — forward mode with caching and ad
  blocking by default. Set `mode = "recursive"` for full DNSSEC-validated
  resolution from root nameservers.

Single Rust binary. `sudo numa install` and it's your system DNS — caching,
ad blocking, .numa domains. No nginx, no Caddy, no /etc/hosts.

```
brew install razvandimescu/tap/numa
# or
cargo install numa
```

https://github.com/razvandimescu/numa

**Lessons from r/node (2026-03-24):** "Can't remember 3 ports?" got
pushback — the CORS/cookie angle resonated more. Lead with what you
can't do without it, not what's annoying.

---

### r/commandline

**Title:** numa — local dev DNS with auto HTTPS and LAN service discovery, single Rust binary

**Body:**

I run 5-6 local services and wanted named domains with HTTPS instead of
remembering port numbers. Built a DNS resolver that handles `.numa`
domains:

```
curl -X POST localhost:5380/services \
  -d '{"name":"api","target_port":8000}'
```

Now `https://api.numa` resolves, proxies to localhost:8000, and has a
valid TLS cert. WebSocket passthrough works — Vite HMR goes through
the proxy fine.

The part I didn't expect to be useful: LAN service discovery. Two
machines running numa find each other via UDP multicast. I register
`api.numa` on my laptop, my teammate's numa instance picks it up
automatically. Zero config.

Also blocks ~385K+ ad domains since it's already your DNS resolver.
Portable — works on any network (coffee shops, airports). Set
`mode = "recursive"` for full DNSSEC-validated resolution from root
nameservers — no upstream dependency.

```
brew install razvandimescu/tap/numa
sudo numa
```

Single binary, DNS wire protocol parsed from scratch (no DNS libraries).

https://github.com/razvandimescu/numa

---

### r/selfhosted (only if Show HN hits front page)

**Title:** Numa — recursive resolver + ad blocking + LAN service discovery in one binary

**Body:**

I built a DNS resolver in Rust that I've been running as my system DNS.
Two features I'm most proud of:

**Recursive resolution + DNSSEC** — set `mode = "recursive"` and it resolves
from root nameservers, no upstream dependency. Chain-of-trust verification
(RSA, ECDSA, Ed25519), NSEC/NSEC3 denial proofs. No single entity sees your
full query pattern — each authoritative server only sees its zone's queries.

**LAN service discovery** — I register `api.numa → localhost:8000` on my
laptop. My colleague's machine, also running Numa, picks it up via UDP
multicast — `api.numa` resolves to my IP on his machine. Zero config.

The rest of what it does:
- **Ad blocking** — ~385K+ domains (Hagezi Pro), portable. Works on any
  network including coffee shops and airports.
- **DNS-over-HTTPS** — encrypted upstream as an alternative to recursive mode.
- **Auto HTTPS for local services** — generates a local CA + per-service
  TLS certs. `https://frontend.numa` with a green lock, WebSocket passthrough.
- **Hub mode** — point other devices' DNS to it, they get ad blocking +
  `.numa` resolution without installing anything.

Replaces Pi-hole + Unbound in one binary. No Raspberry Pi, no Docker, no PHP.

Single binary, macOS + Linux. Config is one optional TOML file.

**What it doesn't do (yet):** No web-based config editor (TOML + REST API).
DoT listener is in progress.

`brew install razvandimescu/tap/numa` or `cargo install numa`

https://github.com/razvandimescu/numa

---

## Preparation Checklist

- [ ] Verify GitHub repo is PUBLIC before any post
- [ ] Build some comment history on posting account first
- [ ] Post HN Tuesday-Thursday, 9-10 AM Eastern
- [ ] Respond to every comment within 2 hours for the first 6 hours
- [ ] Have fixes ready to ship within 24h for reported issues
- [ ] Don't oversell the pkarr/token vision — one sentence max

## Rules

- Verify GitHub repo is PUBLIC before every post
- Use an account with comment history, not a fresh one
- Respond to every comment within 2 hours
- Never be defensive — acknowledge valid criticism, redirect
- If someone says "just use X" — agree it works, explain what's *uniquely different*
- Lead with unique capabilities, not tool replacement

---

## Prepared Responses

**"What does this offer over /etc/hosts?"** *(actual r/programare objection)*
/etc/hosts is static and per-machine. Numa gives you: auto-revert after N
minutes (great for testing), a REST API so scripts can create/remove entries,
HTTPS reverse proxy with auto TLS, and LAN discovery so you don't have to
edit hosts on every device. Different tools for different problems.

**"Mature solutions already exist (dnsmasq, nginx, etc.)"** *(actual r/programare objection)*
Absolutely — and they're great. The thing they don't do: register a service
on machine A and have it automatically appear on machine B via multicast.
Numa integrates DNS + reverse proxy + TLS + discovery into one binary so
those pieces work together. If you only need DNS forwarding, dnsmasq is the
right tool.

**"Why not Pi-hole / AdGuard Home?"**
They're network appliances — need dedicated hardware or Docker. Numa is a
single binary on your laptop. When you move to a coffee shop, your ad
blocking comes with you. Plus the reverse proxy + LAN discovery.

**"Why from scratch / no DNS libraries?"**
Started as a learning project to understand the wire protocol. Turned out
having full control over the pipeline makes features like conditional
forwarding and override injection trivial — they're just steps in the
resolution chain.

**"Vibe coded / AI generated?"**
I use AI as a coding partner — same as using Stack Overflow or pair
programming. I make the architecture decisions, direct what gets built,
and review everything. The DNS wire protocol parser was the original
learning project I wrote by hand. Later features were built collaboratively
with AI assistance. You can read every line — nothing is opaque generated
slop.

**"Why sudo / why port 53?"**
Port 53 requires root on Unix. Numa only needs it for the UDP socket.
You can also bind to a high port for testing: `bind_addr = "127.0.0.1:5353"`.

**"What about .numa TLD conflicts?"**
The TLD is configurable in `numa.toml`. If `.numa` ever becomes official,
change it to anything else.

**"Does it support DoH/DoT?"**
DoH is built in — set `address = "https://9.9.9.9/dns-query"` in
`[upstream]` and your queries are encrypted. Or set `mode = "auto"` to
probe root servers and fall back to DoH if blocked. DoT listener support
is in progress (PR #25).

**"But Quad9/Cloudflare still sees my queries"**
In forward mode (the default), yes — your upstream resolver sees your queries.
Set `mode = "recursive"` and Numa resolves directly from root nameservers —
no single upstream sees your full query pattern. Each authoritative server
only sees the query relevant to its zone. Add `[dnssec] enabled = true` to
cryptographically verify responses.

**"Show me benchmarks / performance numbers"** *(actual r/programare request)*
Benchmark suite is in `benches/` (criterion). Cached round-trip: 691ns.
Pipeline throughput: ~2.0M qps. DNSSEC: ECDSA P-256 verify 174ns, RSA/SHA-256
10.9µs, DS verify 257ns. Cold-cache DNSSEC validation ~90ms (1 network fetch,
TLD chain pre-warmed). Full comparison against system resolver, Quad9,
Cloudflare, Google on the site.

**"Why not just use Unbound?"**
Numa supports recursive resolution with DNSSEC validation, same as Unbound
(`mode = "recursive"`). The difference:
Numa also has built-in ad blocking, a dashboard, `.numa` local domains with
auto HTTPS, LAN service discovery, and developer overrides. Unbound does
one thing well; Numa integrates six features into one binary.

**"Why not Technitium?"**
Technitium is the closest in features — recursive, DNSSEC, ad blocking,
dashboard. Good tool. Two differences: (1) Numa is a single static binary,
Technitium requires the .NET runtime; (2) Numa has developer tooling that
Technitium doesn't — `.numa` local domains with auto TLS reverse proxy,
path-based routing, LAN service discovery, ephemeral overrides with
auto-revert. Different audiences: Technitium targets server admins, Numa
targets developers on laptops.

**"Does it support Windows?"**
Yes. `numa install` in an admin terminal sets system DNS and auto-starts
numa on boot. Requires a reboot (Windows DNS Client holds port 53 at kernel
level). `numa uninstall` restores everything. Native Windows Service
integration is next.
