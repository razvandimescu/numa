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

### The trust anchor

IANA's root KSK (Key Signing Key) has key tag 20326, algorithm 8 (RSA/SHA-256), and a 256-byte public key. It was last rolled in 2018. I hardcode it as a `const` array — this is the one thing in the entire system that requires out-of-band trust.

```rust
const ROOT_KSK_PUBLIC_KEY: &[u8] = &[
    0x03, 0x01, 0x00, 0x01, 0xac, 0xff, 0xb4, 0x09,
    // ... 256 bytes total
];
```

When IANA rolls this key (rare — the previous key lasted from 2010 to 2018), every DNSSEC validator on the internet needs updating. For Numa, that means a binary update. Something to watch.

### Key tag computation

Every DNSKEY has a key tag — a 16-bit identifier computed per RFC 4034 Appendix B. It's a simple checksum over the DNSKEY RDATA (flags + protocol + algorithm + public key), summing 16-bit words with carry:

```rust
pub fn compute_key_tag(flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> u16 {
    let mut rdata = Vec::with_capacity(4 + public_key.len());
    rdata.push((flags >> 8) as u8);
    rdata.push((flags & 0xFF) as u8);
    rdata.push(protocol);
    rdata.push(algorithm);
    rdata.extend_from_slice(public_key);

    let mut ac: u32 = 0;
    for (i, &byte) in rdata.iter().enumerate() {
        if i % 2 == 0 { ac += (byte as u32) << 8; }
        else { ac += byte as u32; }
    }
    ac += (ac >> 16) & 0xFFFF;
    (ac & 0xFFFF) as u16
}
```

The first test I wrote: compute the root KSK's key tag and assert it equals 20326. Instant confidence that the RDATA encoding is correct.

## The crypto

Numa uses `ring` for all cryptographic operations. Three algorithms cover the vast majority of signed zones:

| Algorithm | ID | Usage | Verify time |
|---|---|---|---|
| RSA/SHA-256 | 8 | Root, most TLDs | 10.9 µs |
| ECDSA P-256 | 13 | Cloudflare, many modern zones | 174 ns |
| Ed25519 | 15 | Newer zones | ~200 ns |

### RSA key format conversion

DNS stores RSA public keys in RFC 3110 format: exponent length (1 or 3 bytes), exponent, modulus. `ring` expects PKCS#1 DER (ASN.1 encoded). Converting between them means writing a minimal ASN.1 encoder:

```rust
fn rsa_dnskey_to_der(public_key: &[u8]) -> Option<Vec<u8>> {
    // Parse RFC 3110: [exp_len] [exponent] [modulus]
    let (exp_len, exp_start) = if public_key[0] == 0 {
        let len = u16::from_be_bytes([public_key[1], public_key[2]]) as usize;
        (len, 3)
    } else {
        (public_key[0] as usize, 1)
    };
    let exponent = &public_key[exp_start..exp_start + exp_len];
    let modulus = &public_key[exp_start + exp_len..];

    // Build ASN.1 DER: SEQUENCE { INTEGER modulus, INTEGER exponent }
    let mod_der = asn1_integer(modulus);
    let exp_der = asn1_integer(exponent);
    // ... wrap in SEQUENCE tag + length
}
```

The `asn1_integer` function handles leading-zero stripping (DER integers must be minimal) and sign-bit padding (high bit set means negative in ASN.1, so positive numbers need a `0x00` prefix). Getting this wrong produces keys that `ring` silently rejects — one of the harder bugs to track down.

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

The proof is a 3-part closest encloser proof (RFC 5155 §8.4):
1. **Closest encloser** — find an ancestor of the queried name whose hash exactly matches an NSEC3 owner
2. **Next closer** — the name one label longer than the closest encloser must fall within an NSEC3 hash range (proving it doesn't exist)
3. **Wildcard denial** — the wildcard at the closest encloser (`*.closest_encloser`) must also fall within an NSEC3 hash range

```rust
// Pre-compute hashes for all ancestors
for i in 0..labels.len() {
    let name: String = labels[i..].join(".");
    ancestor_hashes.push(nsec3_hash(&name, algorithm, iterations, salt));
}

// Walk from longest candidate: is this the closest encloser?
for i in 1..labels.len() {
    let ce_hash = &ancestor_hashes[i];
    if !decoded.iter().any(|(oh, _)| oh == ce_hash) { continue; }  // (1)
    let nc_hash = &ancestor_hashes[i - 1];
    if !nsec3_any_covers(&decoded, nc_hash) { continue; }          // (2)
    let wc = format!("*.{}", labels[i..].join("."));
    let wc_hash = nsec3_hash(&wc, algorithm, iterations, salt)?;
    if nsec3_any_covers(&decoded, &wc_hash) { proven = true; break; }  // (3)
}
```

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

## What I learned

**DNSSEC is a verification system, not an encryption system.** It proves authenticity — this record was signed by the zone owner. It doesn't hide what you're querying. For privacy, you still need encrypted transport (DoH/DoT) or recursive resolution (no single upstream).

**The hardest bugs are in data serialization, not crypto.** `ring` either verifies or it doesn't — a binary answer. But getting the signed data blob exactly right (correct TTL, correct case, correct sort, correct RDATA encoding for each record type) requires extreme precision. A single wrong byte means verification fails with no hint about what's wrong.

**Negative proofs are harder than positive proofs.** Verifying a record exists: verify one RRSIG. Proving a record doesn't exist: find the right NSEC/NSEC3 records, verify their RRSIGs, check gap coverage, check wildcard denial, compute hashes. The NSEC3 closest encloser proof alone has three sub-proofs, each requiring hash computation and range checking.

**Performance optimization is about avoiding network, not avoiding CPU.** The crypto takes nanoseconds to microseconds. The network fetch takes tens of milliseconds. Every optimization that matters — TLD priming, DS piggybacking, DNSKEY prefetch — is about eliminating a round trip, not speeding up a hash.

## What's next

Numa now has 13 feature layers, from basic DNS forwarding through full recursive DNSSEC resolution. The immediate roadmap:

- **DoT (DNS-over-TLS)** — the last encrypted transport we don't support
- **[pkarr](https://github.com/pubky/pkarr) integration** — self-sovereign DNS via the Mainline BitTorrent DHT. Ed25519-signed DNS records published without a registrar.
- **Global `.numa` names** — human-readable names backed by DHT, not ICANN

The code is at [github.com/razvandimescu/numa](https://github.com/razvandimescu/numa). MIT license. The entire DNSSEC implementation is in [`src/dnssec.rs`](https://github.com/razvandimescu/numa/blob/main/src/dnssec.rs) (~1,600 lines) and [`src/recursive.rs`](https://github.com/razvandimescu/numa/blob/main/src/recursive.rs) (~600 lines).
