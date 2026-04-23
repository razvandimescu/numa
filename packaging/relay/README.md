# Numa ODoH Relay — Docker deploy

Two-container deploy: Caddy terminates TLS (auto-provisioning a Let's Encrypt
cert via ACME) and reverse-proxies to a Numa relay running on an internal
Docker network. The relay never reads sealed payloads; Caddy never logs them.

## Prerequisites

- A host with public 80/443 reachable from the internet.
- A DNS record (`A` or `AAAA`) pointing your chosen hostname at the host.
- Docker + Docker Compose v2.

## Configure

Edit `Caddyfile` and replace `odoh-relay.example.com` with your hostname.
That hostname is what ACME validates against and what ODoH clients will
configure as their relay URL: `https://<hostname>/relay`.

## Deploy

```sh
docker compose up -d
docker compose logs -f caddy   # watch ACME provisioning
```

First boot takes a few seconds while Caddy obtains the cert. Subsequent
restarts reuse the cached cert from the `caddy_data` volume.

## Verify

```sh
curl https://<hostname>/health
# ok
# total 0
# forwarded_ok 0
# forwarded_err 0
# rejected_bad_request 0
```

Then point any ODoH client at `https://<hostname>/relay` and watch the
counters tick.
