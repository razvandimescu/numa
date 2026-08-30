# Local DNS records and split DNS

Give the boxes on your network real names, make reverse lookups resolve, and hand an internal domain to another resolver. This is the `[[zones]]` and `[[forwarding]]` equivalent of Pi-hole's *Local DNS Records* and *Conditional Forwarding*.

## When to use this

- You want `nas.home.lan` instead of `192.168.1.10`, on any domain you like.
- You want `nslookup 192.168.1.10` to answer, so `tcpdump` and access logs read properly.
- You have an internal domain served by your router or an AD domain controller, and Numa should hand those queries over instead of resolving them itself.

This is unrelated to `.numa` services, which are a reverse-proxy registry that happens to answer DNS. Use `[[zones]]` for plain name-to-address records.

## Name a host

```toml
[[zones]]
domain      = "nas.home.lan"
record_type = "A"              # A, AAAA, CNAME, PTR, NS, MX
value       = "192.168.1.10"
ttl         = 300
```

Any domain works, not just a local suffix. Zones are checked before the cache and before any upstream or recursive lookup, so a match never leaves the box.

## Reverse lookups

Reverse the address and append `in-addr.arpa`, so `192.168.1.1` becomes `1.1.168.192.in-addr.arpa`:

```toml
[[zones]]
domain      = "1.1.168.192.in-addr.arpa"
record_type = "PTR"
value       = "router.home.lan"
ttl         = 300
```

## Cover a subtree with a wildcard

```toml
[[zones]]
domain      = "*.home.lan"
record_type = "A"
value       = "192.168.1.10"
ttl         = 300
```

RFC 4592 rules apply. The leftmost label only, exact entries always win over the wildcard, the longest matching wildcard wins, and `*.home.lan` does not match `home.lan` itself.

A wildcard also stops the suffix leaking. Once `*.home.lan` exists, a query for an unrelated type under it answers NODATA locally rather than going upstream, which is what dnsmasq's `local=/home.lan/` does.

## Hand a domain to another resolver

For an internal zone that something else is authoritative for, forward it instead of listing every record. Include the reverse zone so PTR queries follow the same path:

```toml
[[forwarding]]
suffix   = ["home.lan", "1.168.192.in-addr.arpa"]
upstream = "192.168.1.1"
```

`upstream` also takes an array for failover, and accepts `tls://` and `https://` endpoints. See the commented `[[forwarding]]` examples in `numa.toml`.

Pick one approach per domain. Records you list in `[[zones]]` are answered locally and never reach the forwarding rule.

## Verify

```bash
dig @127.0.0.1 nas.home.lan +short
dig @127.0.0.1 -x 192.168.1.1 +short
```

## Caveat

These are `numa.toml` settings and take effect on restart. There is no API or dashboard page for them yet ([#335](https://github.com/razvandimescu/numa/issues/335)).
