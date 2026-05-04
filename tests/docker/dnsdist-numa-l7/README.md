# dnsdist L7 → numa: PROXY v2 over UDP

End-to-end harness for the dnsdist front-end deployment shape with UDP
PROXY v2 on the backend hop. dnsdist accepts UDP+TCP/53 from clients,
forwards on the same transport, and prepends a PROXY v2 header to every
backend query — including per-datagram on UDP. numa parses the prefix,
recovers the real client IP, and runs the regular UDP query path.

```
host dig +udp ──UDP──> dnsdist :53 ──UDP+PROXY v2──> numa :53 ──forward──> 9.9.9.9
```

## Why this configuration

PR #156 shipped PROXY v2 on the plain-DNS TCP listener, with a
`tcpOnly = true` workaround required to keep dnsdist→numa entirely on
TCP. The follow-up landed UDP PROXY v2 ingestion in numa, so operators
can drop `tcpOnly` and let UDP carry the PROXY-tagged datagrams
directly. This harness validates that path.

```lua
newServer({
  address = '172.29.0.10:53',
  useProxyProtocol = true,
})
```

The `tcpOnly = true` recipe still works (numa accepts PROXY v2 on both
transports) — it's a useful fallback for sites that need to consolidate
all backend traffic on TCP for L4-firewall reasons.

## Run the smoke

```sh
./smoke.sh
```

Builds the local numa Dockerfile, starts dnsdist 2.0, runs `dig +udp`
queries through dnsdist, and asserts:

- `proxy_protocol.accepted` increments per query.
- `transport.udp` increments (proves the dnsdist→numa hop stays UDP).
- `transport.tcp` does **not** outpace UDP growth.
- No pp2 rejections or timeouts.

## Manual probe

```sh
docker compose up -d --build

# UDP from host → dnsdist → UDP+PROXY v2 → numa
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
| Numa transports exercised | DoT (:853) + plain TCP (:53) | Plain UDP (:53) |
| Client transport | TLS + raw TCP | UDP |
| PROXY v2 source | `send-proxy-v2` (HAProxy) | `useProxyProtocol=true` (dnsdist) |
| Validates | DoT-terminating front-ends | DNS-aware UDP PROXY v2 |

Run both for full transport coverage.
