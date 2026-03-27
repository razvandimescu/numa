---
title: Implementing DNSSEC from Scratch in Rust
description: Recursive resolution from root hints, chain-of-trust validation, NSEC/NSEC3 denial proofs, and what I learned implementing DNSSEC with zero DNS libraries.
date: March 2026
---

In the [previous post](/blog/dns-from-scratch.html) I covered how DNS works at the wire level — packet format, label compression, TTL caching, DoH. Numa was a forwarding resolver: it parsed packets, did useful things locally, and relayed the rest to Cloudflare or Quad9.

That post ended with "recursive resolution and DNSSEC are on the roadmap." This post is about building both.

The short version: Numa now resolves from root nameservers with iterative queries, validates the full DNSSEC chain of trust, and cryptographically proves that non-existent domains don't exist. No upstream dependency. No DNS libraries. Just `ring` for the crypto primitives and a lot of RFC reading.

## Why recursive?

A forwarding resolver trusts its upstream. When you ask Quad9 for `cloudflare.com`, you trust that Quad9 returns the real answer. If Quad9 lies, gets compromised, or is legally compelled to redirect you — you have no way to know.

A recursive resolver doesn't trust anyone. It starts at the root nameservers (operated by 12 independent organizations) and follows the delegation chain: root → `.com` TLD → `cloudflare.com` authoritative servers. Each server only answers for its own zone. No single entity sees your full query pattern.

DNSSEC adds cryptographic proof to each step. The root signs `.com`'s key. `.com` signs `cloudflare.com`'s key. `cloudflare.com` signs its own records. If any step is tampered with, the chain breaks and Numa rejects the response.

## The iterative resolution loop

Recursive resolution is a misnomer — the resolver actually uses *iterative* queries. It asks root "where is `cloudflare.com`?", root says "I don't know, but here are the `.com` nameservers." It asks `.com`, which says "here are cloudflare's nameservers." It asks those, and gets the answer.

```
resolve("cloudflare.com", A)
  → ask 198.41.0.4 (a.root-servers.net)
    ← "try .com: ns1.gtld-servers.net (192.5.6.30)"  [referral + glue]
  → ask 192.5.6.30 (ns1.gtld-servers.net)
    ← "try cloudflare: ns1.cloudflare.com (173.245.58.51)"  [referral + glue]
  → ask 173.245.58.51 (ns1.cloudflare.com)
    ← "104.16.132.229"  [answer]
```

The implementation (`src/recursive.rs`) is a loop with three possible outcomes per query:

1. **Answer** — the server knows the record. Cache it, return it.
2. **Referral** — the server delegates to another zone. Extract NS records and glue (A/AAAA records for the nameservers, included in the additional section to avoid a chicken-and-egg problem), then query the next server.
3. **NXDOMAIN/REFUSED** — the name doesn't exist or the server refuses. Cache the negative result.

CNAME chasing adds complexity: if you ask for `www.cloudflare.com` and get a CNAME to `cloudflare.com`, you need to restart resolution for the new name. I cap this at 8 levels.

### TLD priming

Cold-cache resolution is slow. Every query needs root → TLD → authoritative, each with its own network round-trip. For the first query to `example.com`, that's three serial UDP round-trips before you get an answer.

TLD priming solves this. On startup, Numa queries root for NS records of 34 common TLDs (`.com`, `.org`, `.net`, `.io`, `.dev`, plus EU ccTLDs), caching NS records, glue addresses, DS records, and DNSKEY records. After priming, the first query to any `.com` domain skips root entirely — it already knows where `.com`'s nameservers are, and already has the DNSSEC keys needed to validate the response.

## DNSSEC chain of trust

DNSSEC doesn't encrypt DNS traffic. It *signs* it. Every DNS record can have an accompanying RRSIG (signature) record. The resolver verifies the signature against the zone's DNSKEY, then verifies that DNSKEY against the parent zone's DS (delegation signer) record, walking up until it reaches the root trust anchor — a hardcoded public key that IANA publishes and the entire internet agrees on.

```
cloudflare.com A 104.16.132.229
  signed by → RRSIG (key_tag=34505, algo=13, signer=cloudflare.com)
  verified with → DNSKEY (cloudflare.com, key_tag=34505, ECDSA P-256)
  vouched for by → DS (at .com, key_tag=2371, digest=SHA-256 of cloudflare's DNSKEY)
  signed by → RRSIG (key_tag=19718, signer=com)
  verified with → DNSKEY (com, key_tag=19718)
  vouched for by → DS (at root, key_tag=30909)
  signed by → RRSIG (signer=.)
  verified with → DNSKEY (., key_tag=20326)  ← root trust anchor (hardcoded)
```

### How keys get there

The domain owner generates the DNSKEY keypair — typically their DNS provider (Cloudflare, etc.) does this. The owner then submits the DS record (a hash of their DNSKEY) to their registrar (Namecheap, GoDaddy), who passes it to the registry (Verisign for `.com`). The registry signs it into the TLD zone, and IANA signs the TLD's DS into the root. Trust flows up; keys flow down.

The irony: you "own" your DNSSEC keys, but your registrar controls whether the DS record gets published. If they remove it — by mistake, by policy, or by court order — your DNSSEC chain breaks silently.

### The trust anchor

IANA's root KSK (Key Signing Key) has key tag 20326, algorithm 8 (RSA/SHA-256), and a 256-byte public key. It was last rolled in 2018. I hardcode it as a `const` array — this is the one thing in the entire system that requires out-of-band trust.

```rust
const ROOT_KSK_PUBLIC_KEY: &[u8] = &[
    0x03, 0x01, 0x00, 0x01, 0xac, 0xff, 0xb4, 0x09,
    // ... 256 bytes total
];
```

When IANA rolls this key (rare — the previous key lasted from 2010 to 2018), every DNSSEC validator on the internet needs updating. For Numa, that means a binary update. Something to watch. Every DNSKEY also has a key tag — a 16-bit checksum over its RDATA. The first test I wrote: compute the root KSK's key tag and assert it equals 20326. Instant confidence that the encoding is correct.

## The crypto

Numa uses `ring` for all cryptographic operations. Three algorithms cover the vast majority of signed zones:

| Algorithm | ID | Usage | Verify time |
|---|---|---|---|
| RSA/SHA-256 | 8 | Root, most TLDs | 10.9 µs |
| ECDSA P-256 | 13 | Cloudflare, many modern zones | 174 ns |
| Ed25519 | 15 | Newer zones | ~200 ns |

### RSA key format conversion

DNS stores RSA public keys in RFC 3110 format (exponent length, exponent, modulus). `ring` expects PKCS#1 DER (ASN.1 encoded). Converting between them means writing a minimal ASN.1 encoder with leading-zero stripping and sign-bit padding. Getting this wrong produces keys that `ring` silently rejects — one of the harder bugs to track down.

### ECDSA is simpler

ECDSA P-256 keys in DNS are 64 bytes (x + y coordinates). `ring` expects uncompressed point format: `0x04` prefix + 64 bytes. One line:

```rust
let mut uncompressed = Vec::with_capacity(65);
uncompressed.push(0x04);
uncompressed.extend_from_slice(public_key);  // 64 bytes from DNS
```

Signatures are also 64 bytes (r + s), used directly. No format conversion needed.

### Building the signed data

RRSIG verification doesn't sign the DNS packet — it signs a canonical form of the records. Building this correctly is the most detail-sensitive part of DNSSEC. The signed data is:

1. RRSIG RDATA fields (type covered, algorithm, labels, original TTL, expiration, inception, key tag, signer name) — *without* the signature itself
2. For each record in the RRset: owner name (lowercased, uncompressed) + type + class + original TTL (from the RRSIG, not the record's current TTL) + RDATA length + canonical RDATA

The records must be sorted by their canonical wire-format representation. Owner names must be lowercased. The TTL must be the *original* TTL from the RRSIG, not the decremented TTL from caching.

Getting any of these details wrong — wrong TTL, wrong case, wrong sort order, wrong RDATA encoding — produces a valid-looking but incorrect signed data blob, and `ring` returns a signature mismatch with no diagnostic information. I spent more time debugging signed data construction than any other part of DNSSEC.

## Proving a name doesn't exist

Verifying that `cloudflare.com` has a valid A record is one thing. Proving that `doesnotexist.cloudflare.com` *doesn't* exist — cryptographically, in a way that can't be forged — is harder.

### NSEC

NSEC records form a chain. Each NSEC says "the next name in this zone after me is X, and at my name these record types exist." If you query `beta.example.com` and the zone has `alpha.example.com → NSEC → gamma.example.com`, the gap proves `beta` doesn't exist — there's nothing between `alpha` and `gamma`.

For NXDOMAIN proofs, RFC 4035 §5.4 requires two things:
1. An NSEC record whose gap covers the queried name
2. An NSEC record proving no wildcard exists at the closest encloser

The canonical DNS name ordering (RFC 4034 §6.1) compares labels right-to-left, case-insensitive. `a.example.com` < `b.example.com` because at the `example.com` level they're equal, then `a` < `b`. But `z.example.com` < `a.example.org` because `.com` < `.org` at the TLD level.

### NSEC3

NSEC3 solves NSEC's zone enumeration problem — with NSEC, you can walk the chain and discover every name in the zone. NSEC3 hashes the names first (iterated SHA-1 with a salt), so the NSEC3 chain reveals hashes, not names.

The proof is a 3-part closest encloser proof (RFC 5155 §8.4): find an ancestor whose hash matches an NSEC3 owner, prove the next-closer name falls within a hash range gap, and prove the wildcard at the closest encloser also falls within a gap. All three must hold, or the denial is rejected.

I cap NSEC3 iterations at 500 (RFC 9276 recommends 0). Higher iteration counts are a DoS vector — each verification requires `iterations + 1` SHA-1 hashes.

## Making it fast

Cold-cache DNSSEC validation initially required ~5 network fetches per query (DNSKEY for each zone in the chain, plus DS records). Three optimizations brought this down to ~1:

**TLD priming** (startup) — fetch root DNSKEY + each TLD's NS/DS/DNSKEY. After priming, the trust chain from root to any `.com` zone is fully cached.

**Referral DS piggybacking** — when a TLD server refers you to `cloudflare.com`'s nameservers, the authority section often includes DS records for the child zone. Cache them during resolution instead of fetching separately during validation.

**DNSKEY prefetch** — before the validation loop, scan all RRSIGs for signer zones and batch-fetch any missing DNSKEYs. This avoids serial DNSKEY fetches inside the per-RRset verification loop.

Result: a cold-cache query for `cloudflare.com` with full DNSSEC validation takes ~90ms. The TLD chain is already warm; only one DNSKEY fetch is needed (for `cloudflare.com` itself).

| Operation | Time |
|---|---|
| ECDSA P-256 verify | 174 ns |
| Ed25519 verify | ~200 ns |
| RSA/SHA-256 verify | 10.9 µs |
| DS digest (SHA-256) | 257 ns |
| Key tag computation | 20–63 ns |
| Cold-cache validation (1 fetch) | ~90 ms |

The network fetch dominates. The crypto is noise.

## Surviving hostile networks

I deployed Numa as my system DNS and switched to a different network. Everything broke. Every query: SERVFAIL, 3-second timeout.

The network probe told the story: the ISP blocks outbound UDP port 53 to all servers except a handful of whitelisted public resolvers (Google, Cloudflare). Root servers, TLD servers, authoritative servers — all unreachable over UDP. The ISP forces you onto their DNS or a blessed upstream. Recursive resolution is impossible.

Except TCP port 53 worked fine. And every DNS server is required to support TCP (RFC 1035 section 4.2.2). The ISP apparently only filters UDP.

The fix has three parts:

**TCP fallback.** Every outbound query tries UDP first (800ms timeout). If UDP fails or the response is truncated, retry immediately over TCP. TCP uses a 2-byte length prefix before the DNS message — trivial to implement, and it handles DNSSEC responses that exceed the UDP payload limit.

**UDP auto-disable.** After 3 consecutive UDP failures, flip a global `AtomicBool` and skip UDP entirely — go TCP-first for all queries. This avoids burning 800ms per hop on a network where UDP will never work. The flag resets when the network changes (detected via LAN IP monitoring).

**Query minimization (RFC 7816).** When querying root servers, send only the TLD — `com` instead of `secret-project.example.com`. Root servers handle trillions of queries and are operated by 12 organizations. Minimization reduces what they learn from yours.

The result: on a network that blocks UDP:53, Numa detects the block within the first 3 queries, switches to TCP, and resolves normally at 300-500ms per cold query. Cached queries remain 0ms. No manual config change needed — switch networks and it adapts.

I wouldn't have found this without dogfooding. The code worked perfectly on my home network. It took a real hostile network to expose the assumption that UDP always works.

## What I learned

**DNSSEC is a verification system, not an encryption system.** It proves authenticity — this record was signed by the zone owner. It doesn't hide what you're querying. For privacy, you still need encrypted transport (DoH/DoT) or recursive resolution (no single upstream).

**The hardest bugs are in data serialization, not crypto.** `ring` either verifies or it doesn't — a binary answer. But getting the signed data blob exactly right (correct TTL, correct case, correct sort, correct RDATA encoding for each record type) requires extreme precision. A single wrong byte means verification fails with no hint about what's wrong.

**Negative proofs are harder than positive proofs.** Verifying a record exists: verify one RRSIG. Proving a record doesn't exist: find the right NSEC/NSEC3 records, verify their RRSIGs, check gap coverage, check wildcard denial, compute hashes. The NSEC3 closest encloser proof alone has three sub-proofs, each requiring hash computation and range checking.

**Performance optimization is about avoiding network, not avoiding CPU.** The crypto takes nanoseconds to microseconds. The network fetch takes tens of milliseconds. Every optimization that matters — TLD priming, DS piggybacking, DNSKEY prefetch — is about eliminating a round trip, not speeding up a hash.

## What's next

- **[pkarr](https://github.com/pubky/pkarr) integration** — self-sovereign DNS via the Mainline BitTorrent DHT. Your Ed25519 key is your domain. No registrar, no ICANN.
- **DoT (DNS-over-TLS)** — the last encrypted transport we don't support

The code is at [github.com/razvandimescu/numa](https://github.com/razvandimescu/numa) — the DNSSEC validation is in [`src/dnssec.rs`](https://github.com/razvandimescu/numa/blob/main/src/dnssec.rs) and the recursive resolver in [`src/recursive.rs`](https://github.com/razvandimescu/numa/blob/main/src/recursive.rs). MIT license.
