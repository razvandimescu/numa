# Windows Support — Implementation Plan

*March–April 2026*

## Phase 1: Run on Windows without system integration — DONE (v0.3.0)

- [x] Cross-platform `config_dir()` and `data_dir()`
- [x] `src/system_dns.rs` — Windows DNS discovery via `ipconfig /all`
- [x] Stubs for install/uninstall/service on unsupported OS
- [x] Multicast LAN discovery (`SO_REUSEPORT` skipped on Windows)
- [x] All deps compile on windows-msvc
- [x] CI: `check-windows` job (build + clippy)
- [x] Cross-platform LAN discovery tested: macOS ↔ Windows

## Phase 2: DNS configuration — DONE (PR #28)

- [x] `numa install` — set DNS to 127.0.0.1 via `netsh` for all active interfaces
- [x] `numa uninstall` — restore DNS from backup (DHCP or static with secondaries)
- [x] `ipconfig /all` parser — per-interface adapter name, DHCP status, DNS servers
- [x] Localization — German adapter/DHCP/DNS labels handled
- [x] Disconnected adapters — skipped
- [x] Backup — `%PROGRAMDATA%\numa\original-dns.json`
- [x] Dnscache — disable via registry on install, re-enable on uninstall (reboot required)
- [x] Auto-start — registry Run key (`HKLM\...\Run\Numa`) on install, removed on uninstall
- [x] UDP ConnectionReset — Windows ICMP error 10054 caught and ignored
- [x] IP validation — added to `discover_windows()`
- [x] CI: `cargo test` + binary artifact upload on Windows
- [ ] `README.md` — add Windows install instructions

## Phase 3: Full service integration (future)

### Windows Service

- Use `windows-service` crate to register Numa as a Windows Service
- `sc.exe create numa binPath=...` as alternative
- Auto-start on boot (SYSTEM context, no login required), auto-restart on crash
- Replace registry Run key with proper SCM integration

### CA trust

- `certutil.exe -addstore Root ca.pem` to trust Numa CA system-wide
- Reverse: `certutil.exe -delstore Root "Numa Local CA"`
- Needs admin elevation

### DHCP DNS detection

- Current `detect_dhcp_dns()` returns `None` on Windows
- Could parse `ipconfig /all` for "DHCP Server" + "DNS Servers" lines
- Or use WinAPI `GetNetworkParams()`
