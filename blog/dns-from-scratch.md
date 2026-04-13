---
title: I Built a DNS Resolver from Scratch in Rust
description: How DNS actually works at the wire level — label compression, TTL tricks, DoH, and what surprised me building a resolver with zero DNS libraries.
date: 2026-03-20
---

I wanted to understand how DNS actually works. Not the "it translates domain names to IP addresses" explanation — the actual bytes on the wire. What does a DNS packet look like? How does label compression work? Why is everything crammed into 512 bytes?

So I built one from scratch in Rust. No `hickory-dns`, no `trust-dns`, no `simple-dns`. The entire RFC 1035 wire protocol — headers, labels, compression pointers, record types — parsed and serialized by hand. It started as a weekend learning project, became a side project I kept coming back to over 6 years, and eventually turned into [Numa](https://github.com/razvandimescu/numa) — which I now use as my actual system DNS.

A note on terminology: Numa supports two resolution modes. *Forward* mode relays queries to an upstream (Quad9, Cloudflare, or any DoH provider). *Recursive* mode walks the delegation chain from root servers itself — iterative queries to root, TLD, and authoritative nameservers, with full DNSSEC validation. In both modes, Numa does useful things with your DNS traffic locally (caching, ad blocking, overrides, local service domains) before resolving what it can't answer. This post covers the wire protocol and forwarding path; [the next post](/blog/posts/dnssec-from-scratch.html) covers recursive resolution and DNSSEC.

Here's what surprised me along the way.

## What does a DNS packet actually look like?

You can see a real one yourself. Run this:

```bash
dig @127.0.0.1 example.com A +noedns
```

```
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15242
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;example.com.                   IN      A

;; ANSWER SECTION:
example.com.            53      IN      A       104.18.27.120
example.com.            53      IN      A       104.18.26.120
```

That's the human-readable version. But what's actually on the wire? A DNS query for `example.com A` is just 29 bytes:

```
         ID    Flags  QCount ACount NSCount ARCount
        ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐
Header: AB CD  01 00  00 01  00 00  00 00  00 00
        └────┘ └────┘ └────┘ └────┘ └────┘ └────┘
         ↑      ↑      ↑
         │      │      └─ 1 question, 0 answers, 0 authority, 0 additional
         │      └─ Standard query, recursion desired
         └─ Random ID (we'll match this in the response)

Question: 07 65 78 61 6D 70 6C 65  03 63 6F 6D  00  00 01  00 01
          ── ─────────────────────  ── ─────────  ──  ─────  ─────
          7  e  x  a  m  p  l  e   3  c  o  m   end  A      IN
          ↑                        ↑             ↑
          └─ length prefix         └─ length     └─ root label (end of name)
```

12 bytes of header + 17 bytes of question = 29 bytes to ask "what's the IP for example.com?" Compare that to an HTTP request for the same information — you'd need hundreds of bytes just for headers.

We can send exactly those bytes and capture what comes back:

```python
python3 -c "
import socket
# Hand-craft a DNS query: header (12 bytes) + question (17 bytes)
q  = b'\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'  # header
q += b'\x07example\x03com\x00\x00\x01\x00\x01'              # question
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(q, ('127.0.0.1', 53))
resp = s.recv(512)
for i in range(0, len(resp), 16):
    h = ' '.join(f'{b:02x}' for b in resp[i:i+16])
    a = ''.join(chr(b) if 32<=b<127 else '.' for b in resp[i:i+16])
    print(f'{i:08x}  {h:<48s}  {a}')
"
```

```
00000000  ab cd 81 80 00 01 00 02 00 00 00 00 07 65 78 61   .............exa
00000010  6d 70 6c 65 03 63 6f 6d 00 00 01 00 01 07 65 78   mple.com......ex
00000020  61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01 00 00   ample.com.......
00000030  00 19 00 04 68 12 1b 78 07 65 78 61 6d 70 6c 65   ....h..x.example
00000040  03 63 6f 6d 00 00 01 00 01 00 00 00 19 00 04 68   .com...........h
00000050  12 1a 78                                          ..x
```

83 bytes back. Let's annotate the response:

```
         ID    Flags  QCount ACount NSCount ARCount
        ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐
Header: AB CD  81 80  00 01  00 02  00 00  00 00
        └────┘ └────┘ └────┘ └────┘ └────┘ └────┘
         ↑      ↑      ↑      ↑
         │      │      │      └─ 2 answers
         │      │      └─ 1 question (echoed back)
         │      └─ Response flag set, recursion available
         └─ Same ID as our query

Question: 07 65 78 61 6D 70 6C 65  03 63 6F 6D  00  00 01  00 01
          (same as our query — echoed back)

Answer 1: 07 65 78 61 6D 70 6C 65  03 63 6F 6D  00  00 01  00 01
          ─────────────────────────────────────  ──  ─────  ─────
          e  x  a  m  p  l  e  .  c  o  m       end  A      IN

          00 00 00 19  00 04  68 12 1B 78
          ───────────  ─────  ───────────
          TTL: 25s     len:4  104.18.27.120

Answer 2: (same domain repeated)  00 01  00 01  00 00 00 19  00 04  68 12 1A 78
                                                                    ───────────
                                                                    104.18.26.120
```

Notice something wasteful? The domain `example.com` appears *three times* — once in the question, twice in the answers. That's 39 bytes of repeated names in an 83-byte packet. DNS has a solution for this — but first, the overall structure.

The whole thing fits in a single UDP datagram. The structure is:

```
+--+--+--+--+--+--+--+--+
|         Header         |  12 bytes: ID, flags, counts
+--+--+--+--+--+--+--+--+
|        Questions       |  What you're asking
+--+--+--+--+--+--+--+--+
|         Answers        |  The response records
+--+--+--+--+--+--+--+--+
|       Authorities      |  NS records for the zone
+--+--+--+--+--+--+--+--+
|       Additional       |  Extra helpful records
+--+--+--+--+--+--+--+--+
```

In Rust, parsing the header is just reading 12 bytes and unpacking the flags:

```rust
pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsHeader> {
    let id = buffer.read_u16()?;
    let flags = buffer.read_u16()?;
    // Flags pack 9 fields into 16 bits
    let recursion_desired = (flags & (1 << 8)) > 0;
    let truncated_message = (flags & (1 << 9)) > 0;
    let authoritative_answer = (flags & (1 << 10)) > 0;
    let opcode = (flags >> 11) & 0x0F;
    let response = (flags & (1 << 15)) > 0;
    // ... and so on
}
```

No padding, no alignment, no JSON overhead. DNS was designed in 1987 when every byte counted, and honestly? The wire format is kind of beautiful in its efficiency.

## Label compression is the clever part

Remember how `example.com` appeared three times in that 83-byte response? Domain names in DNS are stored as a sequence of **labels** — length-prefixed segments:

```
example.com → [7]example[3]com[0]
```

The `[7]` means "the next 7 bytes are a label." The `[0]` is the root label (end of name). That's 13 bytes per occurrence, 39 bytes for three repetitions. In a response with authority and additional records, domain names can account for half the packet.

DNS solves this with **compression pointers** — if the top two bits of a length byte are `11`, the remaining 14 bits are an offset back into the packet where the rest of the name can be found. A well-compressed version of our response would replace the answer names with `C0 0C` — a 2-byte pointer to offset 12 where `example.com` first appears in the question section. That turns 39 bytes of names into 15 (13 + 2 + 2). Our upstream didn't bother compressing, but many do — especially when related domains appear:

```
Offset 0x20: [6]google[3]com[0]        ← full name
Offset 0x40: [4]mail[0xC0][0x20]       ← "mail" + pointer to offset 0x20
Offset 0x50: [3]www[0xC0][0x20]        ← "www" + pointer to offset 0x20
```

Pointers can chain — a pointer can point to another pointer. Parsing this correctly requires tracking your position in the buffer and handling jumps:

```rust
pub fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
    let mut pos = self.pos();
    let mut jumped = false;
    let mut delim = "";

    loop {
        let len = self.get(pos)?;

        // Top two bits set = compression pointer
        if (len & 0xC0) == 0xC0 {
            if !jumped {
                self.seek(pos + 2)?; // advance past the pointer
            }
            let offset = (((len as u16) ^ 0xC0) << 8) | self.get(pos + 1)? as u16;
            pos = offset as usize;
            jumped = true;
            continue;
        }

        pos += 1;
        if len == 0 { break; } // root label

        outstr.push_str(delim);
        outstr.push_str(&self.get_range(pos, len as usize)?
            .iter().map(|&b| b as char).collect::<String>());
        delim = ".";
        pos += len as usize;
    }

    if !jumped {
        self.seek(pos)?;
    }
    Ok(())
}
```

This one bit me: when you follow a pointer, you must *not* advance the buffer's read position past where you jumped from. The pointer is 2 bytes, so you advance by 2, but the actual label data lives elsewhere in the packet. If you follow the pointer and also advance past it, you'll skip over the next record entirely. I spent a fun evening debugging that one.

## TTL adjustment on read, not write

This is my favorite trick in the whole codebase. I initially stored the remaining TTL and decremented it, which meant I needed a background thread to sweep expired entries. It worked, but it felt wrong — too much machinery for something simple.

The cleaner approach: store the original TTL and the timestamp when the record was cached. On read, compute `remaining = original_ttl - elapsed`. If it's zero or negative, the entry is stale — evict it lazily.

```rust
pub fn lookup(&mut self, domain: &str, qtype: QueryType) -> Option<DnsPacket> {
    let key = (domain.to_lowercase(), qtype);
    let entry = self.entries.get(&key)?;
    let elapsed = entry.cached_at.elapsed().as_secs() as u32;

    if elapsed >= entry.original_ttl {
        self.entries.remove(&key);
        return None;
    }

    // Adjust TTLs in the response to reflect remaining time
    let mut packet = entry.packet.clone();
    for answer in &mut packet.answers {
        answer.set_ttl(entry.original_ttl.saturating_sub(elapsed));
    }
    Some(packet)
}
```

No background thread. No timer. Entries expire lazily. The cache stays consistent because every consumer sees the adjusted TTL.

## The resolution pipeline

Each incoming UDP packet spawns a tokio task. Each task walks a deterministic pipeline — every step either answers or passes to the next:

```
                     ┌─────────────────────────────────────────────────────┐
                     │              Numa Resolution Pipeline               │
                     └─────────────────────────────────────────────────────┘

  Query ──→ Overrides ──→ .numa TLD ──→ Blocklist ──→ Zones ──→ Cache ──→ DoH
    │        │              │             │             │         │         │
    │        │ match?       │ match?      │ blocked?    │ match?  │ hit?    │
    │        ↓              ↓             ↓             ↓         ↓         ↓
    │      respond        respond       0.0.0.0      respond   respond   forward
    │      (auto-reverts  (reverse      (ad gone)    (static   (TTL      to upstream
    │       after N min)   proxy+TLS)                 records)  adjusted) (encrypted)
    │
    └──→ Each step either answers or passes to the next.
```

This is where "from scratch" pays off. Want conditional forwarding for Tailscale? Insert a step before the upstream. Want to override `api.example.com` for 5 minutes while debugging? Add an entry in the overrides step — it auto-expires. A DNS library would have hidden this pipeline behind an opaque `resolve()` call.

## DNS-over-HTTPS: the "wait, that's it?" moment

The most recent addition, and honestly the one that surprised me with how little code it needed. DoH (RFC 8484) is conceptually simple: take the exact same DNS wire-format packet you'd send over UDP, POST it to an HTTPS endpoint with `Content-Type: application/dns-message`, and parse the response the same way. Same bytes, different transport.

```rust
async fn forward_doh(
    query: &DnsPacket,
    url: &str,
    client: &reqwest::Client,
    timeout_duration: Duration,
) -> Result<DnsPacket> {
    let mut send_buffer = BytePacketBuffer::new();
    query.write(&mut send_buffer)?;

    let resp = timeout(timeout_duration, client
        .post(url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(send_buffer.filled().to_vec())
        .send())
    .await??.error_for_status()?;

    let bytes = resp.bytes().await?;
    let mut recv_buffer = BytePacketBuffer::from_bytes(&bytes);
    DnsPacket::from_buffer(&mut recv_buffer)
}
```

The one gotcha that cost me an hour: Quad9 and other DoH providers require HTTP/2. My first attempt used HTTP/1.1 and got a cryptic 400 Bad Request. Adding the `http2` feature to reqwest fixed it. The upside of HTTP/2? Connection multiplexing means subsequent queries reuse the TLS session — ~16ms vs ~50ms for the first query. Free performance.

The `Upstream` enum dispatches between UDP and DoH based on the URL scheme:

```rust
pub enum Upstream {
    Udp(SocketAddr),
    Doh { url: String, client: reqwest::Client },
}
```

If the configured address starts with `https://`, it's DoH. Otherwise, plain UDP. Simple, no toggles.

## "Why not just use dnsmasq + nginx + mkcert?"

You absolutely can — those are mature, battle-tested tools. The difference is integration: with dnsmasq + nginx + mkcert, you're configuring three tools with three config formats. Numa puts the DNS record, reverse proxy, and TLS cert behind one API call:

```bash
curl -X POST localhost:5380/services -d '{"name":"frontend","target_port":5173}'
```

That creates the DNS entry, generates a TLS certificate, and starts proxying — including WebSocket upgrade for Vite HMR. One command, no config files. Having full control over the resolution pipeline is what makes auto-revert overrides and LAN discovery possible.

## What I learned

**DNS is a 40-year-old protocol that works remarkably well.** The wire format is tight, the caching model is elegant, and the hierarchical delegation system has scaled to billions of queries per day. The things people complain about (DNSSEC complexity, lack of encryption) are extensions bolted on decades later, not flaws in the original design.

**The hard parts aren't where you'd expect.** Parsing the wire protocol was straightforward (RFC 1035 is well-written). The hard parts were: browsers rejecting wildcard certs under single-label TLDs, macOS resolver quirks (`scutil` vs `/etc/resolv.conf`), and getting multiple processes to bind the same multicast port (`SO_REUSEPORT` on macOS, `SO_REUSEADDR` on Linux).

**Learn the vocabulary before you show up.** I initially called Numa a "DNS resolver" and got corrected — it's a forwarding resolver. The distinction matters to people who work with DNS professionally, and being sloppy about it cost me credibility in my first community posts.

## What's next

**Update (March 2026):** Recursive resolution and DNSSEC validation are now shipped. Numa resolves from root nameservers with full chain-of-trust verification (RSA/SHA-256, ECDSA P-256, Ed25519) and NSEC/NSEC3 authenticated denial of existence.

**[Read the follow-up: Implementing DNSSEC from Scratch in Rust →](/blog/posts/dnssec-from-scratch.html)**

Still on the roadmap:

- **DoT (DNS-over-TLS)** — DoH was first because it passes through captive portals and corporate firewalls (port 443 vs 853). DoT has less framing overhead, so it's faster. Both will be available.
- **[pkarr](https://github.com/pubky/pkarr) integration** — self-sovereign DNS via the Mainline BitTorrent DHT. Publish DNS records signed with your Ed25519 key, no registrar needed.

[github.com/razvandimescu/numa](https://github.com/razvandimescu/numa)
