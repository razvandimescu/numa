# dnsdist in front of Numa

For public DoH with a real (ACME-signed) cert, terminate TLS outside Numa and forward plain DNS (or loopback-only DoH) to the resolver. Cert renewal, rate-limiting, and load-balancing live in the front-end; Numa stays focused on resolution.

## When to use this

- Public hostname (`dns.example.com`) with a Let's Encrypt or internal PKI cert.
- You want a dedicated front-end for DoH/DoT/DoQ while Numa stays loopback-bound.
- You plan to run multiple Numa instances behind one endpoint.

## Architecture

```
 public 443/DoH  ┐
 public 853/DoT  ├─► dnsdist  ─►  127.0.0.1:53 (Numa UDP/TCP)
 public 443/DoQ  ┘
```

## dnsdist config

```lua
-- /etc/dnsdist/dnsdist.conf

newServer({address="127.0.0.1:53", name="numa", checkType="A", checkName="numa.rs.",
           useProxyProtocol=true})  -- preserves real client IPs (see below)

addDOHLocal(
  "0.0.0.0:443",
  "/etc/letsencrypt/live/dns.example.com/fullchain.pem",
  "/etc/letsencrypt/live/dns.example.com/privkey.pem",
  "/dns-query",
  {doTCP=true, reusePort=true}
)

addTLSLocal(
  "0.0.0.0:853",
  "/etc/letsencrypt/live/dns.example.com/fullchain.pem",
  "/etc/letsencrypt/live/dns.example.com/privkey.pem"
)

addAction(AllRule(), PoolAction("", false))
```

## ACL: who may recurse

dnsdist — not Numa — gates who reaches the resolver. Its default ACL is loopback plus the
RFC 1918 / ULA private ranges, so a fresh config is already closed to the internet even
though the listeners bind `0.0.0.0`. [`setACL()`](https://www.dnsdist.org/advanced/acl.html)
replaces that default, `addACL()` appends — widen it on purpose, never by accident.

```lua
-- Personal / LAN / Tailscale: restrict to your own ranges.
setACL({"127.0.0.0/8", "::1/128", "100.64.0.0/10", "192.168.0.0/16"})
```

Widening to `0.0.0.0/0` makes you a public open resolver — you inherit the load, abuse, and
query-log liability of every stranger who finds it. To give back to public DNS, run `numa
relay` instead: the ODoH relay carries no resolution and sees no queries. Numa as a
hardened *public recursive* resolver isn't turnkey yet (still needs response-rate limiting
with TC-slip, RFC 8482 ANY-refusal, DNS Cookies, and `allow_recursion` split from
`allow_query`), so keep the ACL scoped until then.

## Protecting the control plane (dashboard + REST API)

dnsdist fronts the *resolver* (`:53`/DoH/DoT), not Numa's HTTP control plane — the dashboard
and REST API on `api_port` (default 5380), which can rewrite blocklists and overrides. Treat
it as an admin panel; locking it down and exposing the resolver are independent decisions.

`api_bind_addr` defaults to `127.0.0.1`, and loopback is always allowed without a credential.
For a remote node, keep it there and reach it over a private network (Tailscale/WireGuard) or
an SSH tunnel.

Every non-loopback client needs a token, and one always exists: if you set neither
`api_token` nor `NUMA_API_TOKEN`, Numa mints one on first start, logs it once, and stores it
owner-only as `api_token` in `data_dir`. No deployment is unauthenticated, and none fails to
start over it — a resolver that won't run costs the host its DNS. To read one back:

```sh
cat /var/lib/numa/api_token                        # or data_dir/api_token
docker compose exec numa cat /var/lib/numa/api_token
```

Pin your own instead when you want it in config management:

```toml
[server]
api_bind_addr = "0.0.0.0"
api_token = "…"               # `openssl rand -hex 32`; or pass NUMA_API_TOKEN at runtime
```

Browsers get an HTTP Basic prompt (any username, token as the password); scripts send
`Authorization: Bearer <token>`. The token is drive-by protection, not encryption — the API
is plain HTTP. `/health` stays open for probes.

**Loopback is exempt from the token**, which makes one TLS-termination pattern a trap: a
same-host reverse proxy (nginx/caddy) pointed at `127.0.0.1:5380` connects *from* loopback,
so every request it forwards is treated as local and skips the token entirely. Don't do that.
For HTTPS with the token still enforced, bind the API to the node's own interface and point
the front proxy at *that* address, not loopback:

```toml
[server]
api_bind_addr = "10.0.0.6"     # the node's LAN/tailnet IP, not 127.0.0.1
api_token = "…"
```

Now the proxy's forwarded connection arrives as a non-loopback peer, so Numa checks the token
(pass the client's `Authorization` header straight through). Alternatively, let the front
proxy do the auth itself and keep the API on loopback.

The same trap has a second door: a front end on the *same host* reaching the dashboard through
Numa's `.numa` proxy on `:443` also arrives from loopback, and with PROXY protocol off (or a
`LOCAL` command) Numa has no truer address to attribute the request to. Run the front end on a
different host, or enable `[server.proxy_protocol]` so the real client IP survives the hop.

## Numa config

Unlike Unbound's dedicated `proxy-protocol-port`, Numa has **no separate proxy port**.
PROXY v2 is a *mode* on the existing `:53` listener, switched on by a non-empty `from`
allowlist — the listener keeps serving plain DNS, but now requires a PROXY header from
the trusted front-end.

```toml
[server.proxy_protocol]
from = ["127.0.0.1/32"]  # trust the local dnsdist front-end to prepend PROXY v2
header_timeout_ms = 5000

[proxy]
enabled   = true         # unrelated — keep if you still use *.numa service routing
bind_addr = "127.0.0.1"  # stays default
```

No changes to `[server]` bind — Numa keeps serving plain DNS on UDP/TCP 53, which dnsdist forwards with a PROXY v2 header prepended. Numa parses the header, records the real client IP in `/stats.proxy_protocol.*`, and answers as normal.

## Caveat: encrypted-PROXY backends

`useProxyProtocol=true` works because the dnsdist→Numa hop here is plain DNS. If you ever change `newServer` to a TLS backend (`tls="openssl"` etc.), dnsdist sends the PROXY header **inside** the TLS session ("encrypted PROXY"); Numa parses PROXY v2 *before* TLS, so the header is missed and queries fail. Stay on plain DNS to loopback, or front Numa with HAProxy / nginx-stream / a cloud L4 LB instead — see `tests/docker/pp2-numa/README.md` for the full write-up.

## Verify

```bash
kdig +https @dns.example.com example.com
kdig +tls  @dns.example.com example.com
```

Both should return clean answers. Numa's `/queries` API should show the request landing, sourced from the **real client IP** (not loopback), and `curl -s http://127.0.0.1:5380/stats | jq '.proxy_protocol'` should show `accepted` incrementing per query.
