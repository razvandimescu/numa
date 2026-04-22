# Numa ODoH Client — Docker deploy

Single-container deploy that runs Numa as an ODoH (RFC 9230) client: every
DNS query routes through an independent relay + target so neither operator
sees both your IP and your question. See the [ODoH integration doc][odoh]
for the full protocol and privacy trade-offs.

[odoh]: ../../docs/implementation/odoh-integration.md

## Prerequisites

- Docker + Docker Compose v2.
- Port 53 (UDP+TCP) free on the host — Numa listens there for DNS
  clients on your LAN.

## Configure

The shipped `numa.toml` points at Numa's own public relay
(`odoh-relay.numa.rs`) paired with Cloudflare's ODoH target
(`odoh.cloudflare-dns.com`). That's two independent operators with
distinct eTLD+1s — the default configuration passes Numa's same-operator
check and works out of the box.

To use a different relay or target, edit `numa.toml` and adjust the URLs.
The `relay` and `target` must resolve to distinct operators or Numa
refuses to start.

## Deploy

```sh
docker compose up -d
docker compose logs -f numa        # watch startup
```

The first query fires the bootstrap resolver + ODoH config fetch;
subsequent queries reuse the warm HTTP/2 connection.

## Point your devices at it

Set each device's DNS server to the IP of the Docker host. For a LAN-wide
rollout, set the DNS server in your router's DHCP config so every device
picks it up automatically.

Verify a query landed on the ODoH path:

```sh
dig @<host-ip> example.com
curl http://<host-ip>:5380/stats | jq '.upstream_transport.odoh'
```

`upstream_transport.odoh` should increment on each query.

## What this does NOT buy you

ODoH protects the *path*, not the content:

- **The target (Cloudflare here) still sees the question.** It just
  doesn't know it's you asking. If Cloudflare logs every ODoH query, the
  query is still visible — it's simply unattributed.
- **The relay is a trusted party for availability.** A malicious relay
  can drop or delay queries; it just can't read them.
- **Traffic analysis defeats small relays.** If you're the only client
  talking to a relay, timing alone re-identifies you. Shared, busy relays
  give better anonymity sets.

See the [ODoH integration doc][odoh] for more.

## Relay operator?

If you'd rather run your own relay (same binary, different mode), see
[`../relay/`](../relay/) — that package spins up a public-facing relay
with Caddy + ACME in front of it.
