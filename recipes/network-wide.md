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

### Windows

On Windows, DNS listens only on `127.0.0.2:53`, where the system resolver forwards to it. Keep that address and add the host's LAN address:

```toml
[server]
bind_addr = ["127.0.0.2:53", "192.168.1.5:53"]
```

At boot, Windows can start Numa before the network has its address. Numa then stops, and Windows restarts it every few seconds until the address is ready. The host has no DNS during that time. Versions before 0.25.0 are not restarted, so upgrade before you add the LAN address.

Apply the dashboard and proxy settings above as well, then restart Numa (`Restart-Service numa` in an admin PowerShell).

Windows Firewall blocks the service until you allow its ports: 53 for DNS, 80 and 443 for the `.numa` proxy, 5380 for the dashboard. `numa install` runs Numa from `C:\ProgramData\numa\bin`, so an "Allow" you clicked for a copy in Downloads does not cover it. In an admin PowerShell:

```powershell
New-NetFirewallRule -DisplayName Numa-UDP -Direction Inbound -Protocol UDP -LocalPort 53 -Profile Private -Action Allow
New-NetFirewallRule -DisplayName Numa-TCP -Direction Inbound -Protocol TCP -LocalPort 53,80,443,5380 -Profile Private -Action Allow
```

These rules apply only on networks marked Private. If Windows marked your home network Public, switch it under Settings → Network & internet → Wi-Fi (or Ethernet) → Private network.

## 2. Check it before touching the router

From another device:

```bash
dig @192.168.1.5 example.com +short     # an address
dig @192.168.1.5 router.numa +short     # 192.168.1.5, the Numa host
curl -sI http://router.numa --resolve router.numa:80:192.168.1.5 | head -1
```

If the first command times out, a firewall on the Numa host is dropping port 53. If only `curl` times out, it is dropping port 80.

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

The default `allow_from` admits ULA and link-local sources, not global ones. If clients reach Numa from a global IPv6 address, add your prefix as shown in [Exposed to the internet?](#exposed-to-the-internet), and update it when your ISP changes the prefix.

## 4. Confirm

Open the dashboard from any device (`http://192.168.1.5:5380`, or `http://numa.numa` once DNS points at Numa). Other devices ask for the API token: any username, and the password from `sudo numa token` on the Numa host. Their queries should appear in the query log with their own IPs.

## When the Numa host is down

Every device loses DNS until it comes back, the same as with any single resolver. Numa restarts itself under launchd, systemd and the Windows service manager, but a powered-off host is still an outage. Options, from least to most effort:

- Run Numa on something that stays on (a Pi, a NAS, a mini PC), not a laptop.
- Run a second Numa instance and set it as the router's secondary DNS. The two do not sync, so copy `numa.toml` and `services.json` between them when you change either.

## HTTPS on other devices

`http://router.numa` works everywhere. `https://` also needs Numa's local CA trusted on each device; on iPhone, `numa setup-phone` walks through it. Without it, browsers show a certificate warning.

## Exposed to the internet?

By default, Numa answers only loopback and private addresses: RFC 1918, link-local, `fc00::/7` and `100.64.0.0/10` (Tailscale). A public address or a port forward does not make it an open resolver, as long as Numa sees the real client address. A forwarder on the same host, such as Docker Desktop's port mapping, can replace that address. To serve a client with a public address, add its network to `allow_from`. A list replaces the default, so keep your LAN in it:

```toml
[server]
allow_from = ["192.168.0.0/16", "198.51.100.0/24"]
```

With `0.0.0.0/0` or `::/0` in the list, Numa answers the whole internet and becomes an open resolver.
