---
title: "Setting Numa as your tailnet resolver"
description: "Point your tailnet's global nameserver at a Numa node and every device on the tailnet resolves through it over WireGuard - laptops, servers, and phones alike, with nothing installed on the clients and no changes to Numa. This is the exact setup: three steps, the one toggle that gates the whole thing, how to lock the node down with allow_from, and how to confirm from the query log that traffic is really flowing over the tailnet."
date: 2026-05-29
---

If you run [Tailscale](https://tailscale.com/), you can make a Numa node the resolver for your entire tailnet. Every device - including phones, which have no good on-device DNS story - sends its queries to Numa over WireGuard. Clients install nothing. Numa needs no code changes and no special config: its default `0.0.0.0:53` bind is already reachable on the node's tailnet IP the moment it joins.

This guide walks through the setup on a small node (a Pi Zero W running Numa under systemd) but nothing here is hardware-specific - any machine on your tailnet running Numa works the same way.

<div class="hero-metrics">
<div class="metric-card">
<div class="metric-vs">Installed on clients</div>
<div class="metric-value">nothing</div>
<div class="metric-label">phones and laptops route DNS through Numa without an app or profile</div>
</div>
<div class="metric-card">
<div class="metric-vs">Numa config changes</div>
<div class="metric-value">none</div>
<div class="metric-label">the default <code>0.0.0.0:53</code> bind answers on the node's tailnet IP</div>
</div>
<div class="metric-card">
<div class="metric-vs">Transport</div>
<div class="metric-value">WireGuard</div>
<div class="metric-label">queries are encrypted end to end by the tailnet - no DoT/DoH profile needed</div>
</div>
</div>

---

## Before you start

You need Numa running on a machine that is (or will be) joined to your tailnet and admin access to the Tailscale console. Confirm Numa is up and listening on all interfaces - the default `bind_addr = "0.0.0.0:53"` is what makes it reachable on the tailnet IP. If you've pinned it to `127.0.0.1` change that first; a loopback-only resolver can't serve other devices.

## Step 1 - Join the node, but opt it out of tailnet DNS

Bring the Numa node onto the tailnet with tailnet DNS disabled *for that node*:

```bash
tailscale up --accept-dns=false
```

`--accept-dns=false` is required, not cosmetic. In the next step you point the tailnet's nameserver at this node. If the node also *accepts* that nameserver, it tries to resolve through itself and loops. Opt the resolver out; every other device opts in.

After it joins, note the node's tailnet IP (the `100.x.y.z` address in `tailscale status` or the admin console). The rest of this guide uses `100.65.127.63` as the example.

## Step 2 - Set the global nameserver

In the Tailscale admin console, go to **DNS → Global nameservers** ([Tailscale's DNS docs](https://tailscale.com/kb/1054/dns)) and add the node's tailnet IP:

```
100.65.127.63 # our pi-0's ip
```

## Step 3 - Turn on "Override DNS servers"

Directly beneath the nameserver list is an **Override DNS servers** toggle. Turn it **on**.

This is the step that catches everyone. With it **off** Tailscale treats your nameserver as a *fallback* - and any device that already has working DNS (a phone on WiFi, a laptop with a DHCP-assigned resolver) never falls back to it. The admin console shows your nameserver configured, yet clients keep using local DNS and may report "no resolvers configured." With it **on**, Tailscale forces every tailnet device through your nameserver. This single toggle is the difference between "nothing happens" and "it just works."

That completes the setup. Tailnet devices now resolve through Numa over WireGuard with nothing installed on them.

## Confirm it from the query log

The admin console only shows intent. The proof is on the node. With a client active on the tailnet, Numa's query log records that client's tailnet IP as the source:

```
100.81.95.112  A      example.com          NOERROR  cache  1ms
100.81.95.112  AAAA   gateway.example.net  NOERROR  fwd    34ms
100.81.95.112  A      news.ycombinator.com NOERROR  fwd    28ms
```

`100.81.95.112` is a tailnet address - the query reached Numa over WireGuard, not over the local network. If you see tailnet IPs as client sources, the path is working end to end.

## Lock the node down

A fresh Numa install has an empty `allow_from`, which means allow-all. That's fine on a closed bench, but a node serving a shared tailnet should be scoped to the networks you actually serve:

```toml
[server]
allow_from = ["192.168.1.0/24", "100.64.0.0/10"]
```

`100.64.0.0/10` is Tailscale's CGNAT range - it covers every device on your tailnet and nothing outside it. Add your LAN CIDR (shown here as `192.168.1.0/24`) if the node also answers local clients. With this in place Numa serves tailnet peers and your LAN and drops everything else.

## A note on what this is

This makes Numa your resolver *via Tailscale* - a centralized coordination service and an account sit in the path. It's the fastest way to get Numa in front of every device you own today, and for most setups that trade is worth it. Numa's longer-term direction is account-free, self-sovereign resolution that doesn't depend on a third party to broker connectivity; the [Iroh](https://www.iroh.computer/) work is the path there. Until then, "Numa as your tailnet resolver" is a clean, working answer that takes about five minutes.
