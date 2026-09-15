# Recipes

Scenario-driven configs for common Numa deployments. Each recipe is self-contained: copy the snippet, adjust the marked fields, reload.

## Transport / encryption

- [DoH on the LAN](doh-on-lan.md) — expose Numa's built-in DNS-over-HTTPS to local clients.
- [dnsdist in front of Numa](dnsdist-front.md) — terminate public TLS externally, keep Numa on loopback.
- [ODoH upstream with bootstrap pinning](odoh-upstream.md) — oblivious DNS client mode without leaking the relay/target hostnames.

## System integration

- [Freeing port 53](port-53.md) — take the port back from dnsmasq, unbound, named, or Pi-hole, including dnsmasq under NetworkManager.

## Local network

- [Local DNS records and split DNS](local-dns-records.md) — name your LAN hosts on any domain, answer reverse lookups, hand an internal zone to another resolver.

Missing a scenario? Open an issue or PR — these are plain Markdown with no build step.
