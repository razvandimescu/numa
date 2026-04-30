# dnsdist L7 → numa: PROXY v2 over plain TCP

End-to-end harness for the dnsdist front-end deployment shape.
dnsdist accepts UDP+TCP/53 from clients, transmuxes every backend query
to TCP, and prepends a PROXY v2 header at connection open. numa parses
the PROXY header, runs the framed-DNS handler, and records the real
client IP via `/stats.proxy_protocol.*` counters.

```
host dig +udp ──UDP──> dnsdist :53 ──TCP+PROXY v2──> numa :53 ──forward──> 9.9.9.9
```

## Why this configuration

PROXY v2 on the plain-DNS hop requires either UDP PROXY v2 ingestion in
numa (deferred per PR #156's "Out of scope") *or* dnsdist forcing the
backend to TCP. The latter is a single config flag — `tcpOnly=true` on
`newServer` — and avoids per-datagram PROXY framing entirely. Clients
keep low-latency UDP, the PROXY-v2-bearing hop is 100% TCP, and numa's
existing TCP+PROXY support handles the rest.

```lua
newServer({
  address = '172.29.0.10:53',
  tcpOnly = true,
  useProxyProtocol = true,
})
```

## Run the smoke

```sh
./smoke.sh
```

Builds the local numa Dockerfile, starts dnsdist 2.0, runs `dig +udp`
queries through dnsdist, and asserts:

- `proxy_protocol.accepted` increments per query.
- `transport.tcp` increments (proves the dnsdist→numa hop is TCP).
- `transport.udp` does **not** grow on that hop (proves `tcpOnly=true`).
- No pp2 rejections or timeouts.

## Manual probe

```sh
docker compose up -d --build

# UDP from host → dnsdist → TCP+PROXY v2 → numa
dig +short @127.0.0.1 -p 15454 example.com

# numa stats — proxy_protocol.accepted grows with each query
curl -s http://127.0.0.1:15381/stats | jq '.proxy_protocol, .transport'

# pp2 trace
docker compose logs numa | grep -i pp2
```

## Tear down

```sh
docker compose down -v
```

## Comparison with the HAProxy harness

| | `pp2-numa/` (HAProxy) | `dnsdist-numa-l7/` (this) |
|---|---|---|
| Front-end | HAProxy 2.9 (L4 passthrough) | dnsdist 2.0 (L7 DNS-aware) |
| Numa transports exercised | DoT (:853) + plain TCP (:53) | Plain TCP (:53) |
| Client transport | TLS + raw TCP | UDP (transmuxed by dnsdist) |
| PROXY v2 source | `send-proxy-v2` (HAProxy) | `useProxyProtocol=true` (dnsdist) |
| Validates | DoT-terminating front-ends | DNS-aware UDP-in front-ends |

Run both for the full PR #156 coverage matrix.
