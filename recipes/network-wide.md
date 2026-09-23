# Network-wide Numa

Point every device on your network at one Numa instance, so they all get ad blocking and `.numa` service names without installing anything.

## When to use this

- You want blocking on phones, TVs and consoles that can't run Numa themselves.
- You added `router.numa` or `nas.numa` in the dashboard and want it to work from every device, not just the Numa host.

Numa does not serve DHCP. Your router keeps handing out addresses; you only change which DNS server it advertises.

## 1. Let other devices reach Numa

Give the Numa host a fixed address, either a DHCP reservation on the router or a static IP. Everything below assumes it is `192.168.1.5`.

On macOS and Linux, DNS already listens on all IPv4 interfaces (`0.0.0.0:53`). The `.numa` proxy and the dashboard listen on loopback by default, so open them to the LAN:

```toml
[server]
api_bind_addr = "0.0.0.0"      # dashboard from other devices

[proxy]
bind_addr = "0.0.0.0"          # router.numa etc. from other devices
```

Restart Numa (`sudo numa service restart`). The Docker image already binds both to `0.0.0.0`.

### Windows (untested)

On Windows, DNS listens only on `127.0.0.2:53`, where the system resolver forwards to it. Keep that address and add the host's LAN address:

```toml
[server]
bind_addr = ["127.0.0.2:53", "192.168.1.5:53"]
```

Apply the dashboard and proxy settings above as well, restart Numa, then allow inbound UDP and TCP port 53 in Windows Firewall. This configuration has not been tested; if the system resolver stops working after the change, remove the LAN address and open an issue.

## 2. Check it before touching the router

From another device:

```bash
dig @192.168.1.5 example.com +short     # an address
dig @192.168.1.5 router.numa +short     # 192.168.1.5, the Numa host
curl -sI http://router.numa --resolve router.numa:80:192.168.1.5 | head -1
```

If the first command times out, a firewall on the Numa host is dropping port 53.

## 3. Change the router's DNS

In the router's DHCP or LAN settings (not the WAN/internet settings), set the DNS server handed to clients to `192.168.1.5`. Devices pick it up when they renew their lease; reconnecting to Wi-Fi forces it.

Leave the secondary DNS empty, or set it to a second Numa instance. Do not put a public resolver like `1.1.1.1` there. Clients use both servers interchangeably, so blocking and `.numa` names would work only some of the time.

### IPv6

Many routers also advertise their own IPv6 DNS server (RDNSS or DHCPv6). Clients that use it bypass Numa for some or all lookups, which shows up as ads that come and go and `.numa` names that fail intermittently.

The simple fix is to turn off the router's IPv6 DNS advertisement. Clients then use Numa over IPv4 for every lookup, including AAAA records, so IPv6 connectivity is unaffected.

To serve DNS over IPv6 instead, first give Numa an IPv6 listener; by default it has none. Bind one stable address of the host, such as a ULA or static address, not a temporary one that rotates:

```toml
[server]
bind_addr = ["0.0.0.0:53", "[fd12::5]:53"]
```

On Windows, append `"[fd12::5]:53"` to the list from the Windows section instead. `[::]:53` does not work here: on Linux it collides with `0.0.0.0:53`. Restart Numa, check `dig @fd12::5 example.com +short` from another device, and only then set the router's IPv6 DNS to that address.

## 4. Confirm

Open the dashboard from any device (`http://192.168.1.5:5380`, or `http://numa.numa` once DNS points at Numa). Other devices ask for the API token: any username, and the password from `sudo numa token` on the Numa host. Their queries should appear in the query log with their own IPs.

## When the Numa host is down

Every device loses DNS until it comes back, the same as with any single resolver. Numa restarts itself under launchd/systemd, but a powered-off host is still an outage. Options, from least to most effort:

- Run Numa on something that stays on (a Pi, a NAS, a mini PC), not a laptop.
- Run a second Numa instance and set it as the router's secondary DNS. The two do not sync, so copy `numa.toml` and `services.json` between them when you change either.

## HTTPS on other devices

`http://router.numa` works everywhere. `https://` also needs Numa's local CA trusted on each device; on iPhone, `numa setup-phone` walks through it. Without it, browsers show a certificate warning.

## Exposed to the internet?

If the Numa host has a public address, set `allow_from` to your LAN ranges, or Numa becomes an open resolver:

```toml
[server]
allow_from = ["192.168.0.0/16", "fd00::/8"]
```
