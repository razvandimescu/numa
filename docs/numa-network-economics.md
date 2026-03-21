# Numa Network Economics

*March 2026*

## Overview

Numa starts as a portable DNS resolver (ad blocking, developer overrides, local service proxy). The network economics layer transforms it into a decentralized naming system where `.numa` domains are globally resolvable, cryptographically owned, and economically sustained by the nodes that serve them.

The key insight: **every other decentralized naming system asked people to install infrastructure for names. Numa IS the infrastructure — names are a bonus.**

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  Numa Chain                      │
│  (lightweight — ownership only, no DNS records)  │
│                                                  │
│  Block: { name_claims, renewals, transfers,      │
│           audit_results, rewards, slashing }     │
└──────────────────────┬──────────────────────────┘
                       │ name → owner_pubkey
                       ▼
┌─────────────────────────────────────────────────┐
│              Mainline DHT (15M nodes)            │
│                                                  │
│  pkarr SignedPacket(owner_pubkey) →              │
│    { A: 1.2.3.4, AAAA: ::1, TXT: "...", ... }  │
└──────────────────────┬──────────────────────────┘
                       │ DNS records
                       ▼
┌─────────────────────────────────────────────────┐
│              Numa Resolver Nodes                 │
│                                                  │
│  DNS :53 ──▶ resolve .numa via chain+DHT        │
│  HTTP :80 / HTTPS :443 ──▶ proxy .numa domains  │
│  Ad blocking, caching, overrides (local value)   │
└─────────────────────────────────────────────────┘
```

**Separation of concerns:**
- **Chain** stores ownership (who owns `myblog.numa`) — changes rarely
- **DHT** stores DNS records (what IP does `myblog.numa` point to) — changes frequently, free to update
- **Nodes** resolve queries, republish records, earn rewards

## Why Not Blockchain for DNS Records?

| | Records on-chain | Records on DHT, ownership on-chain |
|---|---|---|
| IP update speed | Block time (seconds-minutes) | Instant (~100ms) |
| Chain size | Grows fast (every DNS change) | Tiny (only ownership events) |
| Cost per update | Transaction fee every time | Free (DHT put) |
| Historical records | Stored forever (bloat) | Ephemeral (bounded storage) |

Handshake (HNS) validated this design — chain for names, off-chain for records. Namecoin put everything on-chain and the chain bloated. ENS puts everything on Ethereum and every update costs gas.

## The NUMA Token

```
Earned by:   Running a node, serving queries, republishing names, passing audits
Spent on:    Registering .numa names, renewing names, premium features
Staked by:   Node operators (skin in the game)
Slashed for: Failed audits, NXDOMAIN hijacking, downtime, serving wrong records
```

### Token Flow

```
Name registrant pays $1/month for "myblog.numa"
  ├─ 10% → protocol treasury (funds development)
  ├─ 10% → auditor rewards
  └─ 80% → split among nodes that republish the record
           (proportional to verified service contribution)
```

## Proof-of-Service (not Proof-of-Work)

Traditional mining burns electricity computing useless hashes. Numa nodes earn by performing useful work:

| Traditional Mining | Numa Mining |
|---|---|
| SHA-256 hash computation | DNS resolution for real users |
| Electricity wasted | Ad blocking, caching, privacy |
| Miners don't use the network | Operators ARE the network |
| Specialized hardware (ASICs) | Any machine running Numa |

### Service Score

A node's block production eligibility and reward share is proportional to its verifiable service:

```
Score = (queries_resolved × w1)
      + (names_republished × w2)
      + (audit_challenges_passed × w3)
      + (uptime_hours × w4)
      + (geographic_diversity_bonus × w5)
```

### Audit Protocol

Independent auditor nodes verify that resolver nodes are honest:

1. Auditor sends a challenge query to a random node from a random location
2. Node must respond correctly and within latency threshold
3. Auditor submits result to chain (passed/failed, latency)
4. Nodes that consistently fail get slashed
5. Auditors earn rewards for performing audits

**What gets audited:**
- Correct DNS resolution (no NXDOMAIN hijacking)
- Ad blocking is active (blocked domains return 0.0.0.0)
- Name records match DHT-published data (no tampering)
- Latency is within acceptable bounds
- Uptime (periodic liveness checks)

## Chain Design

The Numa chain is lightweight — it only stores ownership and audit events, not DNS records.

### Block Contents

```rust
Block {
    // Name operations
    name_claims:   Vec<NameClaim>,    // { name, owner_pubkey, payment_proof }
    renewals:      Vec<Renewal>,      // { name, payment_proof }
    transfers:     Vec<Transfer>,     // { name, from_pubkey, to_pubkey, signature }

    // Network health
    audit_results: Vec<AuditResult>,  // { node_id, passed, latency_ms, auditor_id }
    slashing:      Vec<SlashEvent>,   // { node_id, reason, amount }

    // Economics
    rewards:       Vec<Reward>,       // { node_id, amount, reason }

    // Consensus
    producer:      NodeId,            // selected by service score
    prev_hash:     [u8; 32],
    timestamp:     u64,
    signature:     [u8; 64],
}
```

### Block Size Estimate

Assuming 1000 names registered per day, 10,000 audits per day:
- ~50 name operations per block (1 block/minute)
- ~170 audit results per block
- Block size: ~10-50 KB
- Chain growth: ~15-70 MB/year

Compare: Bitcoin grows ~50 GB/year, Ethereum ~200 GB/year. Numa's chain is three orders of magnitude smaller.

## Name Registration Flow

```
1. User runs: numa register myblog
2. Numa generates Ed25519 keypair (stored locally)
3. Numa publishes DNS records to DHT (signed with keypair)
4. Numa submits name_claim transaction to chain:
   { name: "myblog", owner: pubkey, payment: tx_proof }
5. Block producer validates:
   - Name is not already claimed
   - Payment is valid
   - Pubkey matches DHT-published records
6. Name is confirmed in next block (~1 minute)
7. Background task republishes to DHT every hour
```

### Name Collision Resolution

The chain provides global ordering — first confirmed transaction wins. Unlike pure DHT (where two publishers race with timestamps), the chain's consensus determines the canonical owner.

If a name expires (owner stops paying or stops republishing for >7 days), it enters a grace period (30 days), then becomes available for re-registration.

## Pricing Model

```
Free tier:
  - Self-published names (DHT only, no chain, no guarantees)
  - Expires if you stop republishing (~2 hours)
  - No collision protection
  - Good for: local dev, experiments, ephemeral services

Registered tier ($1-5/month):
  - On-chain name claim (collision protection)
  - Network republishing (nodes keep your name alive)
  - Survives your machine being offline
  - Good for: personal sites, projects, small businesses

Premium tier ($10-50/month):
  - Priority resolution (cached on more nodes)
  - Custom audit frequency
  - SLA guarantees (99.9% resolution uptime)
  - Good for: businesses, high-traffic services
```

## Competitive Landscape

| | Namecoin | ENS | Handshake | Numa |
|---|---|---|---|---|
| Launched | 2011 | 2017 | 2018 | 2026 |
| Chain | Bitcoin fork | Ethereum | Own chain | Own lightweight chain |
| TLD | .bit | .eth | Any TLD | .numa |
| Records on-chain | Yes (bloated) | Yes (gas fees) | No (correct) | No (DHT) |
| Resolution requires | NMC node | ETH node/gateway | HNS node | Numa resolver (has independent value) |
| Standalone utility | None | None | None | Ad blocking + privacy + dev tools |
| Registration cost | Mining fees | $5-600+/yr gas | Auction | $1-5/month |
| Mining model | SHA-256 (wasteful) | ETH PoS | PoW (Blake2b) | Proof-of-Service (useful work) |
| Cold-start problem | Fatal | Mitigated by ETH ecosystem | Fatal | Solved (resolver has independent utility) |
| Status | Dead | Active (crypto-native) | Low adoption | Building |

### Why Each Predecessor Failed or Stalled

**Namecoin:** Infrastructure existed only for names. No reason to run a node unless you needed .bit domains. Nobody used .bit domains because nobody ran nodes.

**ENS:** Succeeded within crypto (Ethereum users) but cannot break out. Requires a wallet, pays gas, resolves to ETH addresses not IPs. It's naming for crypto, not naming for the internet.

**Handshake:** Correct architecture (chain for names, off-chain for records) but same cold-start problem as Namecoin. $10M VC funding couldn't solve the fundamental issue: nobody runs HNS nodes because nobody uses HNS names.

**Numa's structural advantage:** People install Numa for ad blocking. They're already running the infrastructure. Names are a feature, not the product.

## The Flywheel

```
Users install Numa for ad blocking (free, immediate value)
  → They're now running a resolver node
  → Node can participate in name resolution network
  → Node earns tokens passively (proof-of-service)
  → Tokens fund .numa name registrations
  → More names → more value in the network
  → More value → more users install Numa
  → More nodes → more resilient → more trust
  → More trust → businesses register names
  → Revenue flows to node operators
  → More operators → better coverage → better service
```

The critical insight: the flywheel starts spinning WITHOUT the token or the chain. Ad blocking alone drives installation. Everything else layers on top.

## .onion Bridge

Numa can serve as a human-readable naming layer for Tor hidden services:

```
protonmail.numa  → protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion
nytimes.numa     → nytimesn7cgmftshazwhfgzm37qxb44r64ytbb2dj3x62d2lnez7pyd.onion
```

56-character .onion addresses become 1-word .numa names. The proxy routes through Tor's SOCKS proxy. Combined with Numa's auto-generated TLS, users get `https://protonmail.numa` with a green lock — something .onion addresses can't easily provide.

This creates unique value: Numa becomes the UX layer for the dark web without requiring users to understand Tor, .onion addresses, or certificate management.

## Implementation Phases

```
Phase 5 (next):     Pkarr integration — DHT resolution for z-base32 keys
Phase 6:            .numa self-publishing — your node claims names on DHT
Phase 7:            Audit protocol — challenge queries, reputation scores
Phase 8:            NUMA token + lightweight chain (only if Phase 6-7 validate demand)
Phase 9:            Staking, slashing, full decentralized marketplace
Phase 10:           .onion bridge — human-readable Tor naming
```

**Critical rule:** Each phase must validate demand before proceeding to the next. Premature tokenization kills projects. The chain launches only when there are enough nodes and enough name registrations to sustain the economics.

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| ICANN assigns .numa to someone | Low | Use fallback TLD, community will follow the resolver not the TLD |
| Token attracts speculators, not users | High | Launch token AFTER product-market fit, not before |
| Regulatory scrutiny on token | Medium | Structure as utility token (payment for service), not security |
| Chain governance becomes political | Medium | Minimal governance — chain rules are simple and stable |
| 51% attack on lightweight chain | Medium | Proof-of-service makes attacks expensive (need real infrastructure) |
| DHT record expiry causes downtime | Low | Network republishing with redundancy, stale-while-revalidate |
| Key loss = name loss | Medium | Optional key escrow, social recovery, hierarchical key derivation |
| Nobody registers paid names | High | Free tier works without chain. Paid tier only launches with proven demand |

## Open Questions

1. **Block time:** 1 minute? 10 seconds? Faster = better UX but more chain growth.
2. **Minimum stake:** How much must a node stake to participate? Too high = centralization, too low = Sybil attacks.
3. **Auditor selection:** Random? Stake-weighted? How to prevent auditor collusion?
4. **Name pricing:** Flat fee? Length-based (shorter = more expensive)? Auction for premium names?
5. **Cross-chain bridges:** Should NUMA tokens be bridgeable to Ethereum/Solana for liquidity?
6. **Privacy:** Should the chain record who owns each name, or can ownership be zero-knowledge?
7. **Light clients:** Can a Numa node validate the chain without storing all of it?

## Success Metrics

| Milestone | Target | Prerequisite |
|---|---|---|
| Pkarr resolution working | 100 z-base32 domains resolvable | Phase 5 |
| .numa self-publishing | 1,000 self-published names | Phase 6 |
| Audit protocol live | 100 nodes passing audits | Phase 7 |
| Token launch | 10,000 Numa installations, 5,000 names | Phase 8 |
| Paid registrations | 1,000 paid .numa names | Phase 8 |
| Break-even for node operators | $10+/month per node | Phase 9 |
| .onion bridge | 100 mapped .onion services | Phase 10 |
