//! Pkarr Phase 1: relay resolution + petnames.
//!
//! Resolve Ed25519 public keys as domain names. Signed DNS records are fetched
//! from an HTTP relay (default `relay.pkarr.org`), verified with `ring`, then
//! parsed via Numa's own `DnsPacket::from_buffer()`. No new dependencies.
//!
//! Petnames live under `.key` (not `.numa`) — see `docs/implementation/pkarr-integration.md`
//! for the trust-model rationale.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use log::{debug, warn};

use crate::buffer::BytePacketBuffer;
use crate::config::PkarrConfig;
use crate::header::ResultCode;
use crate::packet::DnsPacket;
use crate::question::QueryType;
use crate::record::DnsRecord;

const Z32_ALPHABET: &[u8] = b"ybndrfg8ejkmcpqxot1uwisza345h769";
const Z32_KEY_LEN: usize = 52;
const MAX_SIGNED_PACKET_BYTES: usize = 1072;
const RELAY_TIMEOUT: Duration = Duration::from_secs(3);
/// Pkarr signed packets carry no DNS TTL of their own; this is the resolver-side
/// cache freshness window. 5 min matches typical short-TTL DNS without spamming
/// the relay.
const CACHE_TTL: Duration = Duration::from_secs(300);
/// Cap on distinct cached keys. The relay is open, so an attacker can publish
/// arbitrarily many keys and induce a lookup for each; bound the cache and evict
/// the oldest-fetched entry past this point.
const MAX_CACHED_PACKETS: usize = 4096;

#[derive(Clone, Debug)]
struct CachedPacket {
    dns_bytes: Vec<u8>,
    fetched_at: Instant,
    /// Signed BEP44 `seq`; `store_packet` uses it to reject rollback replays.
    timestamp: u64,
}

impl CachedPacket {
    fn new(dns_bytes: Vec<u8>, timestamp: u64) -> Self {
        CachedPacket {
            dns_bytes,
            fetched_at: Instant::now(),
            timestamp,
        }
    }
}

pub struct PkarrStore {
    packets: HashMap<[u8; 32], CachedPacket>,
    petnames: HashMap<String, [u8; 32]>,
    relay_url: String,
    client: reqwest::Client,
}

impl PkarrStore {
    pub fn new(
        config: &PkarrConfig,
        resolver: Option<Arc<crate::bootstrap_resolver::NumaResolver>>,
    ) -> Self {
        let mut petnames = HashMap::new();
        for (name, key_str) in &config.petnames {
            match decode_key(key_str) {
                Some(key) => {
                    petnames.insert(name.clone(), key);
                }
                None => warn!("pkarr: invalid key for petname '{}': {}", name, key_str),
            }
        }
        PkarrStore {
            packets: HashMap::new(),
            petnames,
            relay_url: config.relay.trim_end_matches('/').to_string(),
            client: crate::forward::build_https_client_with_resolver(1, resolver),
        }
    }

    pub fn resolve_petname(&self, name: &str) -> Option<[u8; 32]> {
        self.petnames.get(name).copied()
    }

    /// Reject rollback replays — the relay is untrusted, so a valid signature
    /// alone can't stop an old packet pinning an abandoned IP. `seq` is monotonic.
    fn store_packet(&mut self, pubkey: [u8; 32], packet: CachedPacket) {
        match self.packets.get(&pubkey).map(|c| c.timestamp) {
            Some(cached_ts) if packet.timestamp <= cached_ts => return, // rollback replay
            Some(_) => {}                                               // overwrite, no growth
            None if self.packets.len() >= MAX_CACHED_PACKETS => self.evict_oldest(),
            None => {}
        }
        self.packets.insert(pubkey, packet);
    }

    fn evict_oldest(&mut self) {
        if let Some(oldest) = self
            .packets
            .iter()
            .min_by_key(|(_, p)| p.fetched_at)
            .map(|(k, _)| *k)
        {
            self.packets.remove(&oldest);
        }
    }

    /// Seed the cache with an already-verified inner packet so integration tests
    /// can drive `resolve` down the cache-hit path without a live relay.
    #[cfg(test)]
    pub(crate) fn seed_packet(&mut self, pubkey: [u8; 32], dns_bytes: Vec<u8>) {
        self.packets.insert(pubkey, CachedPacket::new(dns_bytes, 1));
    }
}

pub(crate) fn z32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buf: u64 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        buf = (buf << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buf >> bits) & 0x1f) as usize;
            out.push(Z32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buf << (5 - bits)) & 0x1f) as usize;
        out.push(Z32_ALPHABET[idx] as char);
    }
    out
}

fn z32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut buf: u64 = 0;
    let mut bits = 0u32;
    for c in s.chars() {
        let idx = Z32_ALPHABET.iter().position(|&a| a == c as u8)?;
        buf = (buf << 5) | idx as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// Returns the 32-byte key iff `s` is a valid z-base32 string decoding to 32
/// bytes — the 32-byte check is the real gate (only a 52-char z32 string can
/// reach it). `classify` pre-checks `Z32_KEY_LEN` purely to skip the decode on
/// ordinary labels, not for correctness.
pub fn decode_key(s: &str) -> Option<[u8; 32]> {
    let bytes = z32_decode(s)?;
    (bytes.len() == 32).then(|| {
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        key
    })
}

/// Build the bencoded signable payload: `3:seqi{ts}e1:v{len}:{dns}`.
/// Fixed template per BEP44 / pkarr — not a general bencode encoder.
fn build_signable(timestamp: u64, dns_bytes: &[u8]) -> Vec<u8> {
    let ts = timestamp.to_string();
    let len = dns_bytes.len().to_string();
    let mut buf = Vec::with_capacity(8 + ts.len() + 4 + len.len() + 1 + dns_bytes.len());
    buf.extend_from_slice(b"3:seqi");
    buf.extend_from_slice(ts.as_bytes());
    buf.extend_from_slice(b"e1:v");
    buf.extend_from_slice(len.as_bytes());
    buf.push(b':');
    buf.extend_from_slice(dns_bytes);
    buf
}

#[derive(Debug, PartialEq, Eq)]
pub enum PkarrTarget {
    Key {
        pubkey: [u8; 32],
        subdomain: Option<String>,
    },
    Petname {
        name: String,
        subdomain: Option<String>,
    },
}

/// Classify a qname for pkarr routing. The key is the effective root: it must be
/// the rightmost label (an optional trailing `.key` aside), so a real domain can
/// never be shadowed by an embedded key (`<z32>.example.com` → `None`, not Key).
/// Returns:
///   - `Key` when the root label is a 52-char z-base32 pubkey
///   - `Petname` when qname ends in `.key` and the root label isn't a z32 key
///   - `None` otherwise (not a pkarr query)
///
/// `classify_routes_by_root_label` enumerates the accepted forms.
pub fn classify(qname: &str) -> Option<PkarrTarget> {
    // qname arrives lower-cased from the wire parser (read_qname), like every
    // other local stage relies on — no re-normalization here.
    let q = qname.strip_suffix('.').unwrap_or(qname);
    let (core, has_key_tld) = match q.strip_suffix(".key") {
        Some(rest) => (rest, true),
        None => (q, false),
    };
    if core.is_empty() {
        return None;
    }
    let (subdomain, root) = match core.rsplit_once('.') {
        Some((sub, root)) => (Some(sub.to_string()), root),
        None => (None, core),
    };
    if root.len() == Z32_KEY_LEN {
        if let Some(pubkey) = decode_key(root) {
            return Some(PkarrTarget::Key { pubkey, subdomain });
        }
    }
    // A non-key root label is a petname only under the `.key` TLD.
    has_key_tld.then(|| PkarrTarget::Petname {
        name: root.to_string(),
        subdomain,
    })
}

/// Resolve a pkarr domain. Returns `Some` on success, `None` on fetch/verify
/// failure (caller decides SERVFAIL vs NXDOMAIN). Records are rewritten to
/// `qname` so the client sees the name it queried. Sync fetch on cache miss
/// or stale; SWR + dedup are Phase 2.
pub async fn resolve(
    query: &DnsPacket,
    qname: &str,
    qtype: QueryType,
    pubkey: &[u8; 32],
    subdomain: Option<&str>,
    store: &Arc<RwLock<PkarrStore>>,
) -> Option<DnsPacket> {
    let z32 = z32_encode(pubkey);

    let cached = {
        let s = store.read().ok()?;
        s.packets
            .get(pubkey)
            .filter(|p| p.fetched_at.elapsed() < CACHE_TTL)
            .cloned()
    };

    let packet = match cached {
        Some(p) => p,
        None => {
            // Cache hits never reach here, so the clones stay off that path.
            let (relay_url, client) = {
                let s = store.read().ok()?;
                (s.relay_url.clone(), s.client.clone())
            };
            match fetch_from_relay(&client, &relay_url, &z32, pubkey).await {
                Ok(fresh) => {
                    if let Ok(mut w) = store.write() {
                        w.store_packet(*pubkey, fresh.clone());
                    }
                    fresh
                }
                Err(e) => {
                    debug!("pkarr: relay fetch failed for {}: {}", z32, e);
                    return None;
                }
            }
        }
    };

    let mut buf = BytePacketBuffer::from_bytes(&packet.dns_bytes);
    let inner = match DnsPacket::from_buffer(&mut buf) {
        Ok(p) => p,
        Err(e) => {
            warn!("pkarr: malformed inner DNS packet: {}", e);
            return None;
        }
    };

    let answers = filter_matching_records(&inner.answers, &z32, subdomain, qtype, qname);
    let mut resp = DnsPacket::response_from(query, ResultCode::NOERROR);
    resp.answers = answers;
    Some(resp)
}

/// pkarr surfaces only what `strip_private` can vet: address literals and TXT.
/// Name-target records (CNAME/NS/SRV/MX, SVCB/HTTPS `TargetName`) are dropped —
/// fail-closed, since the IP-only scrub can't catch a target into private space.
fn is_vettable(r: &DnsRecord) -> bool {
    match r {
        DnsRecord::A { .. } | DnsRecord::AAAA { .. } => true,
        DnsRecord::UNKNOWN { qtype, .. } => *qtype == QueryType::TXT.to_num(),
        _ => false,
    }
}

/// Filter pkarr records matching the requested subdomain + qtype, rewriting
/// the domain to `qname` so clients see their own query name.
///
/// Owner-name forms accepted in published packets:
///   - `<z32key>` or `<z32key>.`        → apex (absolute form, observed live)
///   - `<sub>.<z32key>`                 → subdomain (absolute)
///   - `@` or empty                     → apex (publisher convention)
///   - `<sub>`                          → subdomain (relative to origin)
fn filter_matching_records(
    records: &[DnsRecord],
    z32: &str,
    subdomain: Option<&str>,
    qtype: QueryType,
    qname: &str,
) -> Vec<DnsRecord> {
    let want_num = qtype.to_num();
    let abs = subdomain.map(|sub| format!("{}.{}", sub, z32));
    records
        .iter()
        .filter(|r| is_vettable(r))
        .filter(|r| r.query_type().to_num() == want_num)
        .filter(|r| {
            let dom = r.domain();
            let dom = dom.trim_end_matches('.');
            match subdomain {
                None => dom.is_empty() || dom == "@" || dom.eq_ignore_ascii_case(z32),
                Some(sub) => {
                    dom.eq_ignore_ascii_case(sub)
                        || dom.eq_ignore_ascii_case(abs.as_deref().unwrap())
                }
            }
        })
        .map(|r| {
            let mut cloned = r.clone();
            cloned.set_domain(qname.to_string());
            cloned
        })
        .collect()
}

async fn fetch_from_relay(
    client: &reqwest::Client,
    relay_url: &str,
    z32: &str,
    pubkey: &[u8; 32],
) -> crate::Result<CachedPacket> {
    let url = format!("{}/{}", relay_url, z32);
    let resp = client.get(&url).timeout(RELAY_TIMEOUT).send().await?;
    if !resp.status().is_success() {
        return Err(format!("relay returned HTTP {}", resp.status()).into());
    }
    parse_signed_packet(&resp.bytes().await?, pubkey)
}

/// Parse and Ed25519-verify a signed packet: `<64B sig><8B ts-BE><=1000B dns>`.
/// The transport is untrusted; this is the only trust gate, so it runs on every
/// relay/DHT response before the bytes reach the cache.
fn parse_signed_packet(body: &[u8], pubkey: &[u8; 32]) -> crate::Result<CachedPacket> {
    if body.len() < 72 {
        return Err(format!("signed packet too short: {} bytes", body.len()).into());
    }
    if body.len() > MAX_SIGNED_PACKET_BYTES {
        return Err(format!("signed packet too large: {} bytes", body.len()).into());
    }
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&body[64..72]);
    let timestamp = u64::from_be_bytes(ts_bytes);
    let dns_bytes = body[72..].to_vec();

    let signable = build_signable(timestamp, &dns_bytes);
    if !crate::dnssec::verify_ed25519(pubkey, &signable, &body[..64]) {
        return Err("signature verification failed".into());
    }

    Ok(CachedPacket::new(dns_bytes, timestamp))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_for(b: u8) -> String {
        z32_encode(&[b; 32])
    }

    /// A fresh Ed25519 keypair + its 32-byte public key, for signing test packets.
    fn test_keypair() -> (ring::signature::Ed25519KeyPair, [u8; 32]) {
        use ring::signature::KeyPair;
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(kp.public_key().as_ref());
        (kp, pubkey)
    }

    /// `<64B sig><8B ts-BE><dns>` signed by `kp` — a well-formed relay body.
    fn signed_body(kp: &ring::signature::Ed25519KeyPair, ts: u64, dns: &[u8]) -> Vec<u8> {
        let sig = kp.sign(&build_signable(ts, dns));
        let mut body = Vec::with_capacity(72 + dns.len());
        body.extend_from_slice(sig.as_ref());
        body.extend_from_slice(&ts.to_be_bytes());
        body.extend_from_slice(dns);
        body
    }

    #[test]
    fn z32_roundtrip_32_bytes() {
        let bytes: [u8; 32] = [
            0x1c, 0x3f, 0xab, 0xd0, 0x45, 0x19, 0x27, 0x84, 0xe2, 0x9d, 0x11, 0x88, 0x66, 0xc3,
            0xf5, 0xee, 0x09, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77,
        ];
        let encoded = z32_encode(&bytes);
        assert_eq!(encoded.len(), Z32_KEY_LEN);
        assert_eq!(z32_decode(&encoded).unwrap(), bytes);
    }

    #[test]
    fn z32_decode_rejects_invalid_chars() {
        assert!(z32_decode("this has spaces").is_none());
        assert!(z32_decode("AAAA").is_none()); // uppercase not in alphabet
    }

    #[test]
    fn signable_matches_bencode_template() {
        assert_eq!(
            build_signable(1234567, b"hello"),
            b"3:seqi1234567e1:v5:hello"
        );
    }

    #[test]
    fn verify_rejects_bad_signature() {
        // Random sig over a non-zero key must not verify (avoids Ed25519
        // neutral-element edge cases that could spuriously succeed).
        let signable = build_signable(0, b"anything");
        assert!(!crate::dnssec::verify_ed25519(
            &[1u8; 32],
            &signable,
            &[0x42u8; 64]
        ));
    }

    #[test]
    fn parse_signed_packet_accepts_valid_rejects_tampering() {
        let (kp, pubkey) = test_keypair();
        let ts = 0x0102_0304_0506_0708u64;
        let dns = b"\x12\x34 inner dns bytes, not parsed here";
        let body = signed_body(&kp, ts, dns);

        let ok = parse_signed_packet(&body, &pubkey).unwrap();
        assert_eq!(ok.timestamp, ts);
        assert_eq!(ok.dns_bytes, dns);

        // Size bounds (no valid sig needed — checked before verify).
        assert!(parse_signed_packet(&body[..71], &pubkey).is_err());
        assert!(parse_signed_packet(&vec![0u8; MAX_SIGNED_PACKET_BYTES + 1], &pubkey).is_err());

        // Tampered DNS body, tampered timestamp, and cross-key all fail verify.
        let mut tampered_dns = body.clone();
        *tampered_dns.last_mut().unwrap() ^= 0xff;
        assert!(parse_signed_packet(&tampered_dns, &pubkey).is_err());

        let mut tampered_ts = body.clone();
        tampered_ts[64] ^= 0xff;
        assert!(parse_signed_packet(&tampered_ts, &pubkey).is_err());

        let (_, other_pubkey) = test_keypair();
        assert!(parse_signed_packet(&body, &other_pubkey).is_err());
    }

    #[test]
    fn cache_is_bounded() {
        let mut store = PkarrStore::new(&PkarrConfig::default(), None);
        for i in 0..(MAX_CACHED_PACKETS as u32 + 10) {
            let mut pubkey = [0u8; 32];
            pubkey[..4].copy_from_slice(&i.to_be_bytes());
            store.store_packet(pubkey, CachedPacket::new(vec![0], i as u64));
        }
        assert!(store.packets.len() <= MAX_CACHED_PACKETS);
    }

    fn key_target(subdomain: Option<&str>) -> Option<PkarrTarget> {
        Some(PkarrTarget::Key {
            pubkey: [0u8; 32],
            subdomain: subdomain.map(String::from),
        })
    }

    fn petname(name: &str, subdomain: Option<&str>) -> Option<PkarrTarget> {
        Some(PkarrTarget::Petname {
            name: name.into(),
            subdomain: subdomain.map(String::from),
        })
    }

    #[test]
    fn classify_routes_by_root_label() {
        let k = key_for(0);
        let cases: &[(String, Option<PkarrTarget>)] = &[
            // Key as root, with/without subdomain and `.key` aside.
            (k.clone(), key_target(None)),
            (format!("git.{k}"), key_target(Some("git"))),
            (format!("{k}.key"), key_target(None)),
            (format!("git.{k}.key"), key_target(Some("git"))),
            (format!("{k}."), key_target(None)), // trailing dot normalized
            // Petname: non-key root under `.key` only.
            ("alice.key".into(), petname("alice", None)),
            ("git.alice.key".into(), petname("alice", Some("git"))),
            (
                "deep.nested.alice.key".into(),
                petname("alice", Some("deep.nested")),
            ),
            ("alice.key.".into(), petname("alice", None)), // trailing dot normalized
            // Key not the rightmost label → real DNS wins, never shadowed.
            (format!("{k}.example.com"), None),
            (format!("login.{k}.paypal.com"), None),
            (format!("{k}.com"), None),
            // Not pkarr-shaped at all.
            ("example.com".into(), None),
            ("".into(), None),
            ("alice.numa".into(), None),
            ("key".into(), None), // bare `.key` TLD isn't a routable petname
        ];
        for (qname, expected) in cases {
            assert_eq!(classify(qname), *expected, "classify({qname:?})");
        }
    }

    #[test]
    fn filter_drops_name_target_records() {
        // A surfaced name-target into private space would bypass the IP scrub.
        let z32 = z32_encode(&[0u8; 32]);
        let records = vec![DnsRecord::CNAME {
            domain: z32.clone(),
            host: "metadata.google.internal.".into(),
            ttl: 60,
        }];
        let out = filter_matching_records(&records, &z32, None, QueryType::CNAME, "alice.key");
        assert!(
            out.is_empty(),
            "pkarr must not surface CNAME/name-target records (rebind bypass)"
        );
    }

    #[test]
    fn store_rejects_rollback_to_older_packet() {
        // An older replayed packet must not roll the cache back (untrusted relay).
        let mut store = PkarrStore::new(&PkarrConfig::default(), None);
        let pubkey = [7u8; 32];
        let newer = CachedPacket::new(vec![1], 200);
        let older = CachedPacket::new(vec![2], 100);
        store.store_packet(pubkey, newer);
        store.store_packet(pubkey, older); // replayed older — must be ignored
        assert_eq!(
            store.packets.get(&pubkey).unwrap().timestamp,
            200,
            "older replayed packet must not replace newer cached one"
        );
    }

    #[test]
    fn decode_key_strictness() {
        assert!(decode_key(&key_for(0)).is_some());
        assert!(decode_key("alice").is_none());
        assert!(decode_key("").is_none());
        // Right length but invalid char:
        let mut bad = key_for(0);
        bad.replace_range(0..1, "A");
        assert!(decode_key(&bad).is_none());
    }
}
