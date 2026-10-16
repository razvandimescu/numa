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
record_type = "A"              # A, AAAA, CNAME, PTR, NS, MX, TXT
value       = "192.168.1.10"
ttl         = 300
```

Any domain works, not just a local suffix. Zones are checked before the cache and before any upstream or recursive lookup, so a match never leaves the box.

A name you list is answered by Numa for every record type. A type you did not list gets an empty answer, not the upstream one. This keeps IPv6 clients from going around an A record on a public name, the same as Unbound's default `transparent` local zone.

## Reverse lookups

Reverse the address and append `in-addr.arpa`, so `192.168.1.1` becomes `1.1.168.192.in-addr.arpa`:

```toml
[[zones]]
domain      = "1.1.168.192.in-addr.arpa"
record_type = "PTR"
value       = "router.home.lan"
ttl         = 300
```

## Mail and text records

```toml
[[zones]]
domain      = "home.lan"
record_type = "MX"
value       = "10 mail.home.lan"   # priority, then host

[[zones]]
domain      = "home.lan"
record_type = "TXT"
value       = "v=spf1 mx -all"
```

A TXT value is plain text, without zone-file quotes. Numa splits values longer than 255 bytes, such as DKIM keys, into 255-byte strings.

## Many records

A `[[zones]]` table takes four lines per record. For a long list, put the same records in an inline array, one record per line:

```toml
zones = [
  { domain = "nas.home.lan",              record_type = "A",   value = "192.168.1.10", ttl = 3600 },
  { domain = "*.dev.home.lan",            record_type = "A",   value = "192.168.1.20" },
  { domain = "home.lan",                  record_type = "MX",  value = "10 mail.home.lan" },
  { domain = "10.1.168.192.in-addr.arpa", record_type = "PTR", value = "nas.home.lan" },
]

[server]
# ...
```

Put the array before the first `[section]` header. After a header, TOML reads it as part of that section and Numa ignores the records. Use the array or `[[zones]]` tables, not both. TOML rejects the file with a duplicate key error.

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
