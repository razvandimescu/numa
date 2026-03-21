# Show HN Draft

## Title (77 chars)

Show HN: Numa – Ad-blocking DNS with .numa local domains, from scratch in Rust

## Body

Numa is a portable DNS resolver I built from scratch in Rust — no DNS libraries, the RFC 1035 wire protocol is parsed by hand. It runs as a single binary on your laptop and gives you:

- **Ad blocking** — 385K+ domains blocked out of the box (Hagezi Pro list). Works on any network you connect to.
- **`.numa` local domains** — `frontend.numa` instead of `localhost:5173`. HTTP/HTTPS reverse proxy with auto-generated TLS certs and WebSocket support (Vite HMR works).
- **Developer overrides** — point any hostname to any IP with auto-revert. Like `/etc/hosts` but with a REST API and a timer.

There's a live dashboard showing real-time query stats, blocked domains, resolution paths, and service health.

macOS and Linux. `sudo numa install` configures your system DNS, `sudo numa service start` runs it as a persistent service (launchd/systemd).

The longer-term plan is self-sovereign DNS via pkarr/Mainline DHT — so `.numa` names could eventually resolve globally across machines without any central authority. But today it's a practical tool for developers who want portable ad blocking and clean local URLs.

https://github.com/razvandimescu/numa

---

## Notes (not part of the post)

- Post Tuesday-Thursday, 9-10 AM Eastern
- Respond to every comment within 2 hours for the first 6 hours
- Have fixes ready to ship within 24h for reported issues
- Don't oversell the pkarr/token vision — one sentence is enough
- If asked "why not Pi-hole/AdGuard Home": portable, travels with laptop, .numa proxy, developer overrides
- If asked "why sudo": port 53 requires root, Numa only uses it for the UDP socket
- If asked "why from scratch": learning exercise that became useful, full control over the pipeline
