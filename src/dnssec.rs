use std::sync::{LazyLock, Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use log::{debug, trace};
use ring::digest;
use ring::signature;

use crate::buffer::BytePacketBuffer;
use crate::cache::{DnsCache, DnssecStatus};
use crate::packet::DnsPacket;
use crate::question::QueryType;
use crate::record::DnsRecord;
use crate::srtt::SrttCache;

#[derive(Debug, Default)]
pub struct ValidationStats {
    pub dnskey_cache_hits: u16,
    pub dnskey_fetches: u16,
    pub ds_cache_hits: u16,
    pub ds_fetches: u16,
    pub elapsed_ms: u64,
}

const MAX_CHAIN_DEPTH: u8 = 10;

// IANA root zone KSK (key tag 20326, algorithm 8, flags 257)
// Source: https://data.iana.org/root-anchors/root-anchors.xml
#[cfg(test)]
const ROOT_KSK_KEY_TAG: u16 = 20326;
const ROOT_KSK_ALGORITHM: u8 = 8;
const ROOT_KSK_FLAGS: u16 = 257;
// Decoded from base64: AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbz...
const ROOT_KSK_PUBLIC_KEY: &[u8] = &[
    0x03, 0x01, 0x00, 0x01, 0xac, 0xff, 0xb4, 0x09, 0xbc, 0xc9, 0x39, 0xf8, 0x31, 0xf7, 0xa1, 0xe5,
    0xec, 0x88, 0xf7, 0xa5, 0x92, 0x55, 0xec, 0x53, 0x04, 0x0b, 0xe4, 0x32, 0x02, 0x73, 0x90, 0xa4,
    0xce, 0x89, 0x6d, 0x6f, 0x90, 0x86, 0xf3, 0xc5, 0xe1, 0x77, 0xfb, 0xfe, 0x11, 0x81, 0x63, 0xaa,
    0xec, 0x7a, 0xf1, 0x46, 0x2c, 0x47, 0x94, 0x59, 0x44, 0xc4, 0xe2, 0xc0, 0x26, 0xbe, 0x5e, 0x98,
    0xbb, 0xcd, 0xed, 0x25, 0x97, 0x82, 0x72, 0xe1, 0xe3, 0xe0, 0x79, 0xc5, 0x09, 0x4d, 0x57, 0x3f,
    0x0e, 0x83, 0xc9, 0x2f, 0x02, 0xb3, 0x2d, 0x35, 0x13, 0xb1, 0x55, 0x0b, 0x82, 0x69, 0x29, 0xc8,
    0x0d, 0xd0, 0xf9, 0x2c, 0xac, 0x96, 0x6d, 0x17, 0x76, 0x9f, 0xd5, 0x86, 0x7b, 0x64, 0x7c, 0x3f,
    0x38, 0x02, 0x9a, 0xbd, 0xc4, 0x81, 0x52, 0xeb, 0x8f, 0x20, 0x71, 0x59, 0xec, 0xc5, 0xd2, 0x32,
    0xc7, 0xc1, 0x53, 0x7c, 0x79, 0xf4, 0xb7, 0xac, 0x28, 0xff, 0x11, 0x68, 0x2f, 0x21, 0x68, 0x1b,
    0xf6, 0xd6, 0xab, 0xa5, 0x55, 0x03, 0x2b, 0xf6, 0xf9, 0xf0, 0x36, 0xbe, 0xb2, 0xaa, 0xa5, 0xb3,
    0x77, 0x8d, 0x6e, 0xeb, 0xfb, 0xa6, 0xbf, 0x9e, 0xa1, 0x91, 0xbe, 0x4a, 0xb0, 0xca, 0xea, 0x75,
    0x9e, 0x2f, 0x77, 0x3a, 0x1f, 0x90, 0x29, 0xc7, 0x3e, 0xcb, 0x8d, 0x57, 0x35, 0xb9, 0x32, 0x1d,
    0xb0, 0x85, 0xf1, 0xb8, 0xe2, 0xd8, 0x03, 0x8f, 0xe2, 0x94, 0x19, 0x92, 0x54, 0x8c, 0xee, 0x0d,
    0x67, 0xdd, 0x45, 0x47, 0xe1, 0x1d, 0xd6, 0x3a, 0xf9, 0xc9, 0xfc, 0x1c, 0x54, 0x66, 0xfb, 0x68,
    0x4c, 0xf0, 0x09, 0xd7, 0x19, 0x7c, 0x2c, 0xf7, 0x9e, 0x79, 0x2a, 0xb5, 0x01, 0xe6, 0xa8, 0xa1,
    0xca, 0x51, 0x9a, 0xf2, 0xcb, 0x9b, 0x5f, 0x63, 0x67, 0xe9, 0x4c, 0x0d, 0x47, 0x50, 0x24, 0x51,
    0x35, 0x7b, 0xe1, 0xb5,
];

static TRUST_ANCHORS: LazyLock<Vec<DnsRecord>> = LazyLock::new(|| {
    vec![DnsRecord::DNSKEY {
        domain: ".".into(),
        flags: ROOT_KSK_FLAGS,
        protocol: 3,
        algorithm: ROOT_KSK_ALGORITHM,
        public_key: ROOT_KSK_PUBLIC_KEY.to_vec(),
        ttl: 172800,
    }]
});

/// Top-level validation: verify the DNSSEC chain of trust for a response.
pub async fn validate_response(
    response: &DnsPacket,
    cache: &RwLock<DnsCache>,
    root_hints: &[std::net::SocketAddr],
    srtt: &RwLock<SrttCache>,
) -> (DnssecStatus, ValidationStats) {
    let start = Instant::now();
    let stats = Mutex::new(ValidationStats::default());
    let trust_anchors = &*TRUST_ANCHORS;

    // Extract RRSIGs from all sections
    let all_rrsigs: Vec<&DnsRecord> = response
        .answers
        .iter()
        .chain(response.authorities.iter())
        .chain(response.resources.iter())
        .filter(|r| matches!(r, DnsRecord::RRSIG { .. }))
        .collect();

    if all_rrsigs.is_empty() {
        let mut s = stats.into_inner().unwrap_or_else(|e| e.into_inner());
        s.elapsed_ms = start.elapsed().as_millis() as u64;
        return (DnssecStatus::Insecure, s);
    }

    // Prefetch DNSKEYs for all signer zones
    let mut signer_zones: Vec<String> = Vec::new();
    for r in &all_rrsigs {
        if let DnsRecord::RRSIG { signer_name, .. } = r {
            let lower = signer_name.to_lowercase();
            if !signer_zones.contains(&lower) {
                signer_zones.push(lower);
            }
        }
    }
    for zone in &signer_zones {
        fetch_dnskeys(zone, cache, root_hints, srtt, &stats).await;
    }

    // Group answer records into RRsets (by domain + type, excluding RRSIGs)
    let rrsets = group_rrsets(&response.answers);

    for (name, qtype, rrset) in &rrsets {
        let matching_rrsigs: Vec<&&DnsRecord> = all_rrsigs
            .iter()
            .filter(|r| {
                if let DnsRecord::RRSIG {
                    domain,
                    type_covered,
                    ..
                } = r
                {
                    domain.eq_ignore_ascii_case(name)
                        && QueryType::from_num(*type_covered) == *qtype
                } else {
                    false
                }
            })
            .collect();

        if matching_rrsigs.is_empty() {
            continue; // No RRSIG for this RRset — might be Insecure
        }

        let mut any_verified = false;
        for rrsig in &matching_rrsigs {
            if let DnsRecord::RRSIG {
                signer_name,
                key_tag,
                algorithm,
                ..
            } = rrsig
            {
                let dnskey_response =
                    fetch_dnskeys(signer_name, cache, root_hints, srtt, &stats).await;
                let dnskeys: Vec<&DnsRecord> = dnskey_response
                    .iter()
                    .filter(|r| matches!(r, DnsRecord::DNSKEY { .. }))
                    .collect();
                if dnskeys.is_empty() {
                    trace!("dnssec: no DNSKEY found for signer '{}'", signer_name);
                    continue;
                }

                trace!(
                    "dnssec: verifying {} {:?} | signer={} key_tag={} algo={} | {} DNSKEYs available",
                    name, qtype, signer_name, key_tag, algorithm, dnskeys.len()
                );

                for dk in &dnskeys {
                    if let DnsRecord::DNSKEY {
                        flags,
                        protocol,
                        algorithm: dk_algo,
                        public_key,
                        ..
                    } = dk
                    {
                        let tag = compute_key_tag(*flags, *protocol, *dk_algo, public_key);
                        if *dk_algo != *algorithm {
                            trace!(
                                "dnssec:   DNSKEY tag={} algo={} — algo mismatch (want {})",
                                tag,
                                dk_algo,
                                algorithm
                            );
                            continue;
                        }
                        if tag != *key_tag {
                            trace!(
                                "dnssec:   DNSKEY tag={} — tag mismatch (want {})",
                                tag,
                                key_tag
                            );
                            continue;
                        }

                        // Check RRSIG time validity (RFC 4035 §5.3.1)
                        if let DnsRecord::RRSIG {
                            expiration,
                            inception,
                            ..
                        } = rrsig
                        {
                            if !is_rrsig_time_valid(*expiration, *inception) {
                                trace!("dnssec:   RRSIG expired or not yet valid (inception={} expiration={})", inception, expiration);
                                continue;
                            }
                        }

                        trace!("dnssec:   DNSKEY tag={} algo={} flags={} — matched, verifying signature ({} bytes)", tag, dk_algo, flags, public_key.len());
                        let signed_data = build_signed_data(rrsig, rrset);
                        if let DnsRecord::RRSIG { signature, .. } = rrsig {
                            let ok =
                                verify_signature(*algorithm, public_key, &signed_data, signature);
                            trace!(
                                "dnssec:   verify result: {} (signed_data={} bytes, sig={} bytes)",
                                ok,
                                signed_data.len(),
                                signature.len()
                            );
                            if ok {
                                // Validate the DNSKEY itself via chain of trust
                                let chain_status = validate_chain(
                                    signer_name,
                                    &dnskey_response,
                                    cache,
                                    root_hints,
                                    srtt,
                                    trust_anchors,
                                    0,
                                    &stats,
                                )
                                .await;

                                trace!(
                                    "dnssec:   chain_status for '{}': {:?}",
                                    signer_name,
                                    chain_status
                                );
                                match chain_status {
                                    DnssecStatus::Secure => {
                                        any_verified = true;
                                        break;
                                    }
                                    DnssecStatus::Bogus => {
                                        let mut s =
                                            stats.into_inner().unwrap_or_else(|e| e.into_inner());
                                        s.elapsed_ms = start.elapsed().as_millis() as u64;
                                        return (DnssecStatus::Bogus, s);
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }

            if any_verified {
                break;
            }
        }

        if !any_verified && !matching_rrsigs.is_empty() {
            debug!("dnssec: no valid signature for {} {:?}", name, qtype);
            let mut s = stats.into_inner().unwrap_or_else(|e| e.into_inner());
            s.elapsed_ms = start.elapsed().as_millis() as u64;
            return (DnssecStatus::Bogus, s);
        }
    }

    let mut s = stats.into_inner().unwrap_or_else(|e| e.into_inner());
    s.elapsed_ms = start.elapsed().as_millis() as u64;
    if rrsets.is_empty() {
        // NXDOMAIN or NODATA — check authority section for NSEC/NSEC3 proofs
        let (qname, qtype_num) = response
            .questions
            .first()
            .map(|q| (q.name.as_str(), q.qtype.to_num()))
            .unwrap_or(("", 0));
        let is_nxdomain = response.header.rescode == crate::header::ResultCode::NXDOMAIN;

        let denial = validate_denial(
            &response.authorities,
            &all_rrsigs,
            qname,
            qtype_num,
            is_nxdomain,
            cache,
        );
        return (denial, s);
    }

    (DnssecStatus::Secure, s)
}

/// Walk the chain of trust from zone DNSKEY up to root trust anchor.
/// `zone_records` contains both DNSKEY and RRSIG records from the DNSKEY response.
#[allow(clippy::too_many_arguments)]
fn validate_chain<'a>(
    zone: &'a str,
    zone_records: &'a [DnsRecord],
    cache: &'a RwLock<DnsCache>,
    root_hints: &'a [std::net::SocketAddr],
    srtt: &'a RwLock<SrttCache>,
    trust_anchors: &'a [DnsRecord],
    depth: u8,
    stats: &'a Mutex<ValidationStats>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = DnssecStatus> + Send + 'a>> {
    Box::pin(async move {
        let zone_dnskeys: Vec<&DnsRecord> = zone_records
            .iter()
            .filter(|r| matches!(r, DnsRecord::DNSKEY { .. }))
            .collect();

        trace!(
            "dnssec: validate_chain zone='{}' depth={} dnskeys={}",
            zone,
            depth,
            zone_dnskeys.len()
        );
        if depth > MAX_CHAIN_DEPTH {
            return DnssecStatus::Indeterminate;
        }

        // Check if any zone DNSKEY matches a trust anchor
        for dk in &zone_dnskeys {
            if let DnsRecord::DNSKEY {
                flags,
                protocol,
                algorithm,
                public_key,
                ..
            } = dk
            {
                if *flags & 0x0101 != 0x0101 {
                    continue;
                }
                let tag = compute_key_tag(*flags, *protocol, *algorithm, public_key);
                for ta in trust_anchors {
                    if let DnsRecord::DNSKEY {
                        algorithm: ta_algo,
                        public_key: ta_key,
                        flags: ta_flags,
                        protocol: ta_proto,
                        ..
                    } = ta
                    {
                        let ta_tag = compute_key_tag(*ta_flags, *ta_proto, *ta_algo, ta_key);
                        if tag == ta_tag && algorithm == ta_algo && public_key == ta_key {
                            debug!("dnssec: trust anchor match for zone '{}'", zone);
                            return DnssecStatus::Secure;
                        }
                    }
                }
            }
        }

        // Not a trust anchor — need to verify via parent DS
        if zone == "." || zone.is_empty() {
            log::warn!(
                "dnssec: root zone DNSKEY does not match trust anchor — possible KSK rollover. \
                 Update Numa to get the new root trust anchor."
            );
            return DnssecStatus::Indeterminate;
        }
        let parent = parent_zone(zone);
        let ds_records = fetch_ds(zone, cache, root_hints, srtt, stats).await;

        if ds_records.is_empty() {
            debug!("dnssec: no DS for zone '{}' at parent '{}'", zone, parent);
            return DnssecStatus::Insecure;
        }

        // Verify DS matches a zone DNSKEY
        let mut ds_matched = false;
        for ds in &ds_records {
            for dk in &zone_dnskeys {
                if verify_ds(ds, dk, zone) {
                    ds_matched = true;
                    break;
                }
            }
            if ds_matched {
                break;
            }
        }

        if !ds_matched {
            debug!("dnssec: DS digest mismatch for zone '{}'", zone);
            return DnssecStatus::Bogus;
        }

        // Verify the DNSKEY RRset is self-signed by a KSK
        if !verify_dnskey_self_signed(zone_records) {
            debug!("dnssec: DNSKEY RRset not self-signed for zone '{}'", zone);
            return DnssecStatus::Bogus;
        }

        // Walk up: validate the parent's DNSKEY
        trace!("dnssec: fetching parent DNSKEY for '{}'", parent);
        let parent_records = fetch_dnskeys(&parent, cache, root_hints, srtt, stats).await;
        if parent_records.is_empty() {
            debug!("dnssec: no parent DNSKEY for '{}' — Indeterminate", parent);
            return DnssecStatus::Indeterminate;
        }

        validate_chain(
            &parent,
            &parent_records,
            cache,
            root_hints,
            srtt,
            trust_anchors,
            depth + 1,
            stats,
        )
        .await
    })
}

/// Verify that the DNSKEY RRset is signed by a KSK within the set.
fn verify_dnskey_self_signed(records: &[DnsRecord]) -> bool {
    let dnskeys: Vec<&DnsRecord> = records
        .iter()
        .filter(|r| matches!(r, DnsRecord::DNSKEY { .. }))
        .collect();

    // Find RRSIG covering DNSKEY type
    for r in records {
        if let DnsRecord::RRSIG {
            type_covered,
            algorithm,
            key_tag,
            signature,
            ..
        } = r
        {
            if QueryType::from_num(*type_covered) != QueryType::DNSKEY {
                continue;
            }

            // Find the KSK that made this signature
            for dk in &dnskeys {
                if let DnsRecord::DNSKEY {
                    flags,
                    protocol,
                    algorithm: dk_algo,
                    public_key,
                    ..
                } = dk
                {
                    if *flags & 0x0101 != 0x0101 {
                        continue; // Not a KSK
                    }
                    if dk_algo != algorithm {
                        continue;
                    }
                    let tag = compute_key_tag(*flags, *protocol, *dk_algo, public_key);
                    if tag != *key_tag {
                        continue;
                    }

                    // Verify: RRSIG(DNSKEY) signed by this KSK
                    let signed_data = build_signed_data(r, &dnskeys);
                    if verify_signature(*algorithm, public_key, &signed_data, signature) {
                        trace!("dnssec: DNSKEY RRset self-signed by KSK tag={}", tag);
                        return true;
                    }
                }
            }
        }
    }

    false
}

// -- Fetching helpers --

/// Fetch DNSKEY response for a zone. Returns all answer records (DNSKEY + RRSIG)
/// so the caller can verify the DNSKEY RRset is self-signed.
async fn fetch_dnskeys(
    zone: &str,
    cache: &RwLock<DnsCache>,
    root_hints: &[std::net::SocketAddr],
    srtt: &RwLock<SrttCache>,
    stats: &Mutex<ValidationStats>,
) -> Vec<DnsRecord> {
    if let Some(pkt) = cache.read().unwrap().lookup(zone, QueryType::DNSKEY) {
        stats.lock().unwrap().dnskey_cache_hits += 1;
        trace!(
            "dnssec: fetch_dnskeys('{}') cache hit — {} records",
            zone,
            pkt.answers.len()
        );
        return pkt.answers;
    }

    trace!("dnssec: fetch_dnskeys('{}') cache miss — resolving", zone);
    stats.lock().unwrap().dnskey_fetches += 1;
    if let Ok(pkt) =
        crate::recursive::resolve_iterative(zone, QueryType::DNSKEY, cache, root_hints, srtt, 0, 0)
            .await
    {
        cache.write().unwrap().insert(zone, QueryType::DNSKEY, &pkt);
        return pkt.answers;
    }

    Vec::new()
}

async fn fetch_ds(
    child: &str,
    cache: &RwLock<DnsCache>,
    root_hints: &[std::net::SocketAddr],
    srtt: &RwLock<SrttCache>,
    stats: &Mutex<ValidationStats>,
) -> Vec<DnsRecord> {
    if let Some(pkt) = cache.read().unwrap().lookup(child, QueryType::DS) {
        stats.lock().unwrap().ds_cache_hits += 1;
        return pkt
            .answers
            .into_iter()
            .filter(|r| matches!(r, DnsRecord::DS { .. }))
            .collect();
    }

    stats.lock().unwrap().ds_fetches += 1;
    if let Ok(pkt) =
        crate::recursive::resolve_iterative(child, QueryType::DS, cache, root_hints, srtt, 0, 0)
            .await
    {
        cache.write().unwrap().insert(child, QueryType::DS, &pkt);
        return pkt
            .answers
            .into_iter()
            .filter(|r| matches!(r, DnsRecord::DS { .. }))
            .collect();
    }

    Vec::new()
}

// -- Crypto primitives --

pub fn compute_key_tag(flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> u16 {
    // RFC 4034 Appendix B: sum all 16-bit words of DNSKEY RDATA
    let mut rdata = Vec::with_capacity(4 + public_key.len());
    rdata.push((flags >> 8) as u8);
    rdata.push((flags & 0xFF) as u8);
    rdata.push(protocol);
    rdata.push(algorithm);
    rdata.extend_from_slice(public_key);

    let mut ac: u32 = 0;
    for (i, &byte) in rdata.iter().enumerate() {
        if i % 2 == 0 {
            ac += (byte as u32) << 8;
        } else {
            ac += byte as u32;
        }
    }
    ac += (ac >> 16) & 0xFFFF;
    (ac & 0xFFFF) as u16
}

pub fn verify_signature(algorithm: u8, public_key: &[u8], signed_data: &[u8], sig: &[u8]) -> bool {
    match algorithm {
        8 => verify_rsa_sha256(public_key, signed_data, sig),
        13 => verify_ecdsa_p256(public_key, signed_data, sig),
        15 => verify_ed25519(public_key, signed_data, sig),
        _ => {
            debug!("dnssec: unsupported algorithm {}", algorithm);
            false
        }
    }
}

fn verify_rsa_sha256(public_key: &[u8], signed_data: &[u8], sig: &[u8]) -> bool {
    let der = match rsa_dnskey_to_der(public_key) {
        Some(d) => d,
        None => return false,
    };
    let key = signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, &der);
    key.verify(signed_data, sig).is_ok()
}

fn verify_ecdsa_p256(public_key: &[u8], signed_data: &[u8], sig: &[u8]) -> bool {
    if public_key.len() != 64 || sig.len() != 64 {
        return false;
    }
    // Ring expects uncompressed point: 0x04 + x(32) + y(32)
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(public_key);

    let key = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &uncompressed);
    key.verify(signed_data, sig).is_ok()
}

fn verify_ed25519(public_key: &[u8], signed_data: &[u8], sig: &[u8]) -> bool {
    if public_key.len() != 32 || sig.len() != 64 {
        return false;
    }
    let key = signature::UnparsedPublicKey::new(&signature::ED25519, public_key);
    key.verify(signed_data, sig).is_ok()
}

/// Convert RFC 3110 RSA public key to DER-encoded RSAPublicKey (PKCS#1)
fn rsa_dnskey_to_der(public_key: &[u8]) -> Option<Vec<u8>> {
    if public_key.is_empty() {
        return None;
    }

    // RFC 3110: first byte is exponent length (if non-zero) or 0 followed by 2-byte length
    let (exp_len, exp_start) = if public_key[0] == 0 {
        if public_key.len() < 3 {
            return None;
        }
        let len = u16::from_be_bytes([public_key[1], public_key[2]]) as usize;
        (len, 3)
    } else {
        (public_key[0] as usize, 1)
    };

    if public_key.len() < exp_start + exp_len {
        return None;
    }

    let exponent = &public_key[exp_start..exp_start + exp_len];
    let modulus = &public_key[exp_start + exp_len..];

    if modulus.is_empty() {
        return None;
    }

    // Build ASN.1 DER: SEQUENCE { INTEGER modulus, INTEGER exponent }
    let mod_der = asn1_integer(modulus);
    let exp_der = asn1_integer(exponent);

    let seq_content_len = mod_der.len() + exp_der.len();
    let mut der = Vec::with_capacity(4 + seq_content_len);
    der.push(0x30); // SEQUENCE tag
    der.extend(asn1_length(seq_content_len));
    der.extend(&mod_der);
    der.extend(&exp_der);

    Some(der)
}

fn asn1_integer(bytes: &[u8]) -> Vec<u8> {
    // Strip leading zeros but keep at least one byte
    let stripped = match bytes.iter().position(|&b| b != 0) {
        Some(pos) => &bytes[pos..],
        None => &[0],
    };

    // Add leading zero if high bit set (to keep it positive)
    let needs_pad = stripped[0] & 0x80 != 0;
    let len = stripped.len() + if needs_pad { 1 } else { 0 };

    let mut result = Vec::with_capacity(2 + len);
    result.push(0x02); // INTEGER tag
    result.extend(asn1_length(len));
    if needs_pad {
        result.push(0x00);
    }
    result.extend(stripped);
    result
}

fn asn1_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    }
}

pub fn verify_ds(ds: &DnsRecord, dnskey: &DnsRecord, owner: &str) -> bool {
    if let (
        DnsRecord::DS {
            key_tag: ds_tag,
            algorithm: ds_algo,
            digest_type,
            digest,
            ..
        },
        DnsRecord::DNSKEY {
            flags,
            protocol,
            algorithm: dk_algo,
            public_key,
            ..
        },
    ) = (ds, dnskey)
    {
        // Key tag and algorithm must match
        let computed_tag = compute_key_tag(*flags, *protocol, *dk_algo, public_key);
        if computed_tag != *ds_tag || dk_algo != ds_algo {
            return false;
        }

        // Compute digest: SHA-256(owner_wire + DNSKEY_RDATA)
        let owner_wire = name_to_wire(owner);
        let mut dnskey_rdata = Vec::with_capacity(4 + public_key.len());
        dnskey_rdata.push((*flags >> 8) as u8);
        dnskey_rdata.push((*flags & 0xFF) as u8);
        dnskey_rdata.push(*protocol);
        dnskey_rdata.push(*dk_algo);
        dnskey_rdata.extend_from_slice(public_key);

        let mut input = Vec::with_capacity(owner_wire.len() + dnskey_rdata.len());
        input.extend(&owner_wire);
        input.extend(&dnskey_rdata);

        match *digest_type {
            2 => {
                // SHA-256
                let computed = digest::digest(&digest::SHA256, &input);
                computed.as_ref() == digest.as_slice()
            }
            4 => {
                // SHA-384
                let computed = digest::digest(&digest::SHA384, &input);
                computed.as_ref() == digest.as_slice()
            }
            _ => false,
        }
    } else {
        false
    }
}

// -- Canonical wire format --

/// Encode a DNS name in canonical wire form per RFC 4034 §6.2:
/// uncompressed, with ASCII letters lowercased.
///
/// Lowercasing happens *after* escape resolution because `\065` yields
/// `'A'`, which canonical form must convert to `'a'`.
pub fn name_to_wire(name: &str) -> Vec<u8> {
    let mut buf = BytePacketBuffer::new();
    buf.write_qname(name)
        .expect("name_to_wire: input must parse as a valid DNS name");
    let mut wire = buf.filled().to_vec();

    let mut i = 0;
    while i < wire.len() {
        let label_len = wire[i] as usize;
        if label_len == 0 {
            break;
        }
        i += 1;
        let end = i + label_len;
        wire[i..end].make_ascii_lowercase();
        i = end;
    }

    wire
}

pub fn build_signed_data(rrsig: &DnsRecord, rrset: &[&DnsRecord]) -> Vec<u8> {
    let mut data = Vec::with_capacity(256);

    if let DnsRecord::RRSIG {
        type_covered,
        algorithm,
        labels,
        original_ttl,
        expiration,
        inception,
        key_tag,
        signer_name,
        ..
    } = rrsig
    {
        // RRSIG RDATA (without signature)
        data.extend(&type_covered.to_be_bytes());
        data.push(*algorithm);
        data.push(*labels);
        data.extend(&original_ttl.to_be_bytes());
        data.extend(&expiration.to_be_bytes());
        data.extend(&inception.to_be_bytes());
        data.extend(&key_tag.to_be_bytes());
        data.extend(name_to_wire(signer_name));

        // Sort RRset records by canonical wire form
        let mut canonical_records: Vec<Vec<u8>> = rrset
            .iter()
            .map(|r| record_to_canonical_wire(r, *original_ttl))
            .collect();
        canonical_records.sort();

        for rec_wire in &canonical_records {
            data.extend(rec_wire);
        }
    }

    data
}

fn record_to_canonical_wire(record: &DnsRecord, original_ttl: u32) -> Vec<u8> {
    let mut wire = Vec::with_capacity(128);

    // Owner name (lowercased, uncompressed)
    wire.extend(name_to_wire(record.domain()));

    // Type
    wire.extend(&record.query_type().to_num().to_be_bytes());

    // Class IN
    wire.extend(&1u16.to_be_bytes());

    // Original TTL (from RRSIG, not the record's current TTL)
    wire.extend(&original_ttl.to_be_bytes());

    // RDATA — write the record to a temporary buffer to get the canonical RDATA
    let rdata = record_rdata_canonical(record);
    wire.extend(&(rdata.len() as u16).to_be_bytes());
    wire.extend(&rdata);

    wire
}

fn record_rdata_canonical(record: &DnsRecord) -> Vec<u8> {
    match record {
        DnsRecord::A { addr, .. } => addr.octets().to_vec(),
        DnsRecord::AAAA { addr, .. } => addr.octets().to_vec(),
        DnsRecord::NS { host, .. } => name_to_wire(host),
        DnsRecord::CNAME { host, .. } => name_to_wire(host),
        DnsRecord::MX { priority, host, .. } => {
            let mut rdata = Vec::with_capacity(2 + host.len() + 2);
            rdata.extend(&priority.to_be_bytes());
            rdata.extend(name_to_wire(host));
            rdata
        }
        DnsRecord::DNSKEY {
            flags,
            protocol,
            algorithm,
            public_key,
            ..
        } => {
            let mut rdata = Vec::with_capacity(4 + public_key.len());
            rdata.extend(&flags.to_be_bytes());
            rdata.push(*protocol);
            rdata.push(*algorithm);
            rdata.extend(public_key);
            rdata
        }
        DnsRecord::DS {
            key_tag,
            algorithm,
            digest_type,
            digest,
            ..
        } => {
            let mut rdata = Vec::with_capacity(4 + digest.len());
            rdata.extend(&key_tag.to_be_bytes());
            rdata.push(*algorithm);
            rdata.push(*digest_type);
            rdata.extend(digest);
            rdata
        }
        DnsRecord::NSEC {
            next_domain,
            type_bitmap,
            ..
        } => {
            let wire = name_to_wire(next_domain);
            let mut rdata = Vec::with_capacity(wire.len() + type_bitmap.len());
            rdata.extend(&wire);
            rdata.extend(type_bitmap);
            rdata
        }
        DnsRecord::NSEC3 {
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hashed_owner,
            type_bitmap,
            ..
        } => {
            let mut rdata =
                Vec::with_capacity(6 + salt.len() + next_hashed_owner.len() + type_bitmap.len());
            rdata.push(*hash_algorithm);
            rdata.push(*flags);
            rdata.extend(&iterations.to_be_bytes());
            rdata.push(salt.len() as u8);
            rdata.extend(salt);
            rdata.push(next_hashed_owner.len() as u8);
            rdata.extend(next_hashed_owner);
            rdata.extend(type_bitmap);
            rdata
        }
        DnsRecord::UNKNOWN { data, .. } => data.clone(),
        DnsRecord::RRSIG { .. } => Vec::new(),
    }
}

fn group_rrsets(records: &[DnsRecord]) -> Vec<(String, QueryType, Vec<&DnsRecord>)> {
    let mut groups: Vec<(String, QueryType, Vec<&DnsRecord>)> = Vec::new();
    for record in records {
        if matches!(record, DnsRecord::RRSIG { .. }) {
            continue;
        }
        let domain = record.domain().to_lowercase();
        let qtype = record.query_type();
        if let Some(group) = groups
            .iter_mut()
            .find(|(d, t, _)| *d == domain && *t == qtype)
        {
            group.2.push(record);
        } else {
            groups.push((domain, qtype, vec![record]));
        }
    }
    groups
}

fn is_rrsig_time_valid(expiration: u32, inception: u32) -> bool {
    const FUDGE: u32 = 300; // 5-minute clock skew tolerance (BIND uses 300s)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    // RFC 4034 §3.1.5: use serial number arithmetic for wrap-safe comparison
    let inception_ok = now.wrapping_sub(inception) < (1u32 << 31);
    let expiration_ok = expiration.wrapping_sub(now) < (1u32 << 31);
    (inception_ok || now.wrapping_add(FUDGE) >= inception) && expiration_ok
}

// -- NSEC/NSEC3 denial of existence --

pub fn type_bitmap_contains(bitmap: &[u8], qtype: u16) -> bool {
    let target_window = (qtype / 256) as u8;
    let target_bit = (qtype % 256) as u8;
    let byte_offset = (target_bit / 8) as usize;
    let bit_mask = 0x80 >> (target_bit % 8);

    let mut pos = 0;
    while pos + 2 <= bitmap.len() {
        let window = bitmap[pos];
        let bmap_len = bitmap[pos + 1] as usize;
        if pos + 2 + bmap_len > bitmap.len() {
            break;
        }
        if window == target_window && byte_offset < bmap_len {
            return bitmap[pos + 2 + byte_offset] & bit_mask != 0;
        }
        pos += 2 + bmap_len;
    }
    false
}

fn canonical_dns_name_order(a: &str, b: &str) -> std::cmp::Ordering {
    // RFC 4034 §6.1: compare labels right-to-left, case-insensitive.
    // Two-phase: zip compares common labels from the root, then label count
    // breaks ties (shorter name sorts first, e.g., "com" < "a.com").
    let a_iter = a.rsplit('.').filter(|l| !l.is_empty());
    let b_iter = b.rsplit('.').filter(|l| !l.is_empty());

    for (la, lb) in a_iter.zip(b_iter) {
        match la
            .as_bytes()
            .iter()
            .map(|b| b.to_ascii_lowercase())
            .cmp(lb.as_bytes().iter().map(|b| b.to_ascii_lowercase()))
        {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }

    let a_count = a.split('.').filter(|l| !l.is_empty()).count();
    let b_count = b.split('.').filter(|l| !l.is_empty()).count();
    a_count.cmp(&b_count)
}

fn nsec_covers_name(owner: &str, next: &str, qname: &str) -> bool {
    use std::cmp::Ordering;

    let on = canonical_dns_name_order(owner, next);
    let qo = canonical_dns_name_order(qname, owner);
    let qn = canonical_dns_name_order(qname, next);
    if matches!(on, Ordering::Greater | Ordering::Equal) {
        qo == Ordering::Greater || qn == Ordering::Less
    } else {
        qo == Ordering::Greater && qn == Ordering::Less
    }
}

/// RFC 4035 §5.4: compute the closest encloser, then derive the wildcard name.
fn closest_encloser(qname: &str, zone_nsecs: &[&DnsRecord]) -> Option<String> {
    let labels: Vec<&str> = qname.split('.').filter(|l| !l.is_empty()).collect();
    // Walk from longest candidate down: qname itself, then parent, then grandparent...
    for i in 0..labels.len() {
        let candidate: String = labels[i..].join(".");
        // Closest encloser must match an NSEC owner exactly
        let is_owner = zone_nsecs.iter().any(|r| {
            if let DnsRecord::NSEC { domain, .. } = r {
                domain.eq_ignore_ascii_case(&candidate)
            } else {
                false
            }
        });
        if is_owner {
            return Some(candidate);
        }
    }
    None
}

fn nsec_proves_nodata(owner: &str, qname: &str, bitmap: &[u8], qtype: u16) -> bool {
    owner.eq_ignore_ascii_case(qname)
        && !type_bitmap_contains(bitmap, qtype)
        && !type_bitmap_contains(bitmap, QueryType::CNAME.to_num())
}

/// RFC 9276 recommends 0 iterations; we reject anything above this as a DoS vector.
const MAX_NSEC3_ITERATIONS: u16 = 500;

fn nsec3_hash(name: &str, algorithm: u8, iterations: u16, salt: &[u8]) -> Option<Vec<u8>> {
    if algorithm != 1 {
        return None; // Only SHA-1 (algorithm 1) defined
    }
    if iterations > MAX_NSEC3_ITERATIONS {
        return None;
    }

    let wire_name = name_to_wire(name);
    let mut buf = Vec::with_capacity(wire_name.len() + salt.len());
    buf.extend(&wire_name);
    buf.extend(salt);

    let mut hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &buf);

    for _ in 0..iterations {
        buf.clear();
        buf.extend(hash.as_ref());
        buf.extend(salt);
        hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &buf);
    }

    Some(hash.as_ref().to_vec())
}

fn base32hex_decode(input: &str) -> Option<Vec<u8>> {
    // Lookup table: ASCII byte -> base32hex value (0xFF = invalid)
    const LUT: [u8; 128] = {
        let mut t = [0xFFu8; 128];
        // 0-9 -> 0-9
        t[b'0' as usize] = 0;
        t[b'1' as usize] = 1;
        t[b'2' as usize] = 2;
        t[b'3' as usize] = 3;
        t[b'4' as usize] = 4;
        t[b'5' as usize] = 5;
        t[b'6' as usize] = 6;
        t[b'7' as usize] = 7;
        t[b'8' as usize] = 8;
        t[b'9' as usize] = 9;
        // A-V -> 10-31 (uppercase)
        t[b'A' as usize] = 10;
        t[b'B' as usize] = 11;
        t[b'C' as usize] = 12;
        t[b'D' as usize] = 13;
        t[b'E' as usize] = 14;
        t[b'F' as usize] = 15;
        t[b'G' as usize] = 16;
        t[b'H' as usize] = 17;
        t[b'I' as usize] = 18;
        t[b'J' as usize] = 19;
        t[b'K' as usize] = 20;
        t[b'L' as usize] = 21;
        t[b'M' as usize] = 22;
        t[b'N' as usize] = 23;
        t[b'O' as usize] = 24;
        t[b'P' as usize] = 25;
        t[b'Q' as usize] = 26;
        t[b'R' as usize] = 27;
        t[b'S' as usize] = 28;
        t[b'T' as usize] = 29;
        t[b'U' as usize] = 30;
        t[b'V' as usize] = 31;
        // a-v -> 10-31 (lowercase)
        t[b'a' as usize] = 10;
        t[b'b' as usize] = 11;
        t[b'c' as usize] = 12;
        t[b'd' as usize] = 13;
        t[b'e' as usize] = 14;
        t[b'f' as usize] = 15;
        t[b'g' as usize] = 16;
        t[b'h' as usize] = 17;
        t[b'i' as usize] = 18;
        t[b'j' as usize] = 19;
        t[b'k' as usize] = 20;
        t[b'l' as usize] = 21;
        t[b'm' as usize] = 22;
        t[b'n' as usize] = 23;
        t[b'o' as usize] = 24;
        t[b'p' as usize] = 25;
        t[b'q' as usize] = 26;
        t[b'r' as usize] = 27;
        t[b's' as usize] = 28;
        t[b't' as usize] = 29;
        t[b'u' as usize] = 30;
        t[b'v' as usize] = 31;
        t
    };

    let mut bits = 0u64;
    let mut bit_count = 0u8;
    let mut output = Vec::with_capacity(input.len() * 5 / 8);

    for &ch in input.as_bytes() {
        if ch == b'=' {
            break;
        }
        if ch >= 128 {
            return None;
        }
        let val = LUT[ch as usize];
        if val == 0xFF {
            return None;
        }
        bits = (bits << 5) | val as u64;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            output.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }
    Some(output)
}

fn nsec3_owner_hash(domain: &str) -> Option<Vec<u8>> {
    let first_label = domain.split('.').next()?;
    base32hex_decode(first_label)
}

fn nsec3_hash_in_range(owner_hash: &[u8], next_hash: &[u8], target_hash: &[u8]) -> bool {
    if owner_hash < next_hash {
        target_hash > owner_hash && target_hash < next_hash
    } else {
        // Wrap-around
        target_hash > owner_hash || target_hash < next_hash
    }
}

/// Check if any pre-decoded NSEC3 record's range covers the target hash.
fn nsec3_any_covers(decoded: &[(Vec<u8>, &DnsRecord)], target: &[u8]) -> bool {
    decoded.iter().any(|(oh, r)| {
        if let DnsRecord::NSEC3 {
            next_hashed_owner, ..
        } = r
        {
            nsec3_hash_in_range(oh, next_hashed_owner, target)
        } else {
            false
        }
    })
}

/// Verify that authority-section NSEC/NSEC3 RRSIGs are cryptographically valid.
fn verify_authority_rrsigs(
    authorities: &[DnsRecord],
    all_rrsigs: &[&DnsRecord],
    denial_type: QueryType,
    cache: &RwLock<DnsCache>,
) -> bool {
    // Group authority denial records into RRsets
    let denial_records: Vec<DnsRecord> = authorities
        .iter()
        .filter(|r| r.query_type() == denial_type)
        .cloned()
        .collect();
    let denial_rrsets = group_rrsets(&denial_records);

    for (name, qtype, rrset) in &denial_rrsets {
        let covering_rrsig = all_rrsigs.iter().find(|r| {
            if let DnsRecord::RRSIG {
                domain,
                type_covered,
                ..
            } = r
            {
                domain.eq_ignore_ascii_case(name) && QueryType::from_num(*type_covered) == *qtype
            } else {
                false
            }
        });

        let rrsig = match covering_rrsig {
            Some(r) => r,
            None => return false,
        };

        if let DnsRecord::RRSIG {
            signer_name,
            key_tag,
            algorithm,
            signature,
            expiration,
            inception,
            ..
        } = rrsig
        {
            if !is_rrsig_time_valid(*expiration, *inception) {
                return false;
            }

            // Look up signer DNSKEY in cache
            let dnskeys = match cache.read().unwrap().lookup(signer_name, QueryType::DNSKEY) {
                Some(pkt) => pkt.answers,
                None => return false,
            };

            let signed_data = build_signed_data(rrsig, rrset);
            let verified = dnskeys.iter().any(|dk| {
                if let DnsRecord::DNSKEY {
                    flags,
                    protocol,
                    algorithm: dk_algo,
                    public_key,
                    ..
                } = dk
                {
                    if dk_algo != algorithm {
                        return false;
                    }
                    let tag = compute_key_tag(*flags, *protocol, *dk_algo, public_key);
                    if tag != *key_tag {
                        return false;
                    }
                    verify_signature(*algorithm, public_key, &signed_data, signature)
                } else {
                    false
                }
            });

            if !verified {
                return false;
            }
        }
    }

    !denial_rrsets.is_empty()
}

/// Validate denial of existence using NSEC or NSEC3 records from authority section.
fn validate_denial(
    authorities: &[DnsRecord],
    all_rrsigs: &[&DnsRecord],
    qname: &str,
    qtype: u16,
    is_nxdomain: bool,
    cache: &RwLock<DnsCache>,
) -> DnssecStatus {
    // Try NSEC first
    let nsecs: Vec<&DnsRecord> = authorities
        .iter()
        .filter(|r| matches!(r, DnsRecord::NSEC { .. }))
        .collect();

    if !nsecs.is_empty() {
        if !verify_authority_rrsigs(authorities, all_rrsigs, QueryType::NSEC, cache) {
            debug!("dnssec: NSEC authority RRSIGs failed verification");
            return DnssecStatus::Indeterminate;
        }

        if is_nxdomain {
            // RFC 4035 §5.4: need (1) NSEC covering the name gap AND (2) NSEC proving
            // no wildcard at *.closest_encloser
            let name_covered = nsecs.iter().any(|r| {
                if let DnsRecord::NSEC {
                    domain,
                    next_domain,
                    ..
                } = r
                {
                    nsec_covers_name(domain, next_domain, qname)
                } else {
                    false
                }
            });

            let wildcard_denied = if let Some(ce) = closest_encloser(qname, &nsecs) {
                let wildcard = format!("*.{}", ce);
                // Wildcard must either be covered by a gap or matched with the type absent
                nsecs.iter().any(|r| {
                    if let DnsRecord::NSEC {
                        domain,
                        next_domain,
                        ..
                    } = r
                    {
                        nsec_covers_name(domain, next_domain, &wildcard)
                            || domain.eq_ignore_ascii_case(&wildcard)
                    } else {
                        false
                    }
                })
            } else {
                // No closest encloser found — can't prove wildcard absence,
                // but some zones don't use wildcards; accept name coverage alone
                true
            };

            if name_covered && wildcard_denied {
                debug!("dnssec: NSEC proves NXDOMAIN for '{}'", qname);
                return DnssecStatus::Secure;
            }
        } else {
            // NODATA — name exists but type doesn't
            let nodata_proven = nsecs.iter().any(|r| {
                if let DnsRecord::NSEC {
                    domain,
                    type_bitmap,
                    ..
                } = r
                {
                    nsec_proves_nodata(domain, qname, type_bitmap, qtype)
                } else {
                    false
                }
            });
            if nodata_proven {
                debug!("dnssec: NSEC proves NODATA for '{}' type {}", qname, qtype);
                return DnssecStatus::Secure;
            }
        }

        return DnssecStatus::Bogus;
    }

    // Try NSEC3
    let nsec3s: Vec<&DnsRecord> = authorities
        .iter()
        .filter(|r| matches!(r, DnsRecord::NSEC3 { .. }))
        .collect();

    if !nsec3s.is_empty() {
        if !verify_authority_rrsigs(authorities, all_rrsigs, QueryType::NSEC3, cache) {
            debug!("dnssec: NSEC3 authority RRSIGs failed verification");
            return DnssecStatus::Indeterminate;
        }

        // Get hash params from first NSEC3
        if let Some(DnsRecord::NSEC3 {
            hash_algorithm,
            iterations,
            salt,
            ..
        }) = nsec3s.first().copied()
        {
            let qname_hash = match nsec3_hash(qname, *hash_algorithm, *iterations, salt) {
                Some(h) => h,
                None => return DnssecStatus::Indeterminate,
            };

            // Pre-decode all NSEC3 owner hashes once
            let decoded: Vec<(Vec<u8>, &DnsRecord)> = nsec3s
                .iter()
                .filter_map(|r| {
                    if let DnsRecord::NSEC3 { domain, .. } = r {
                        match nsec3_owner_hash(domain) {
                            Some(h) => Some((h, *r)),
                            None => {
                                trace!("dnssec: malformed NSEC3 owner '{}' — skipping", domain);
                                None
                            }
                        }
                    } else {
                        None
                    }
                })
                .collect();

            if is_nxdomain {
                // RFC 5155 §8.4: need (1) closest encloser match, (2) next closer covered,
                // (3) wildcard at closest encloser denied
                let labels: Vec<&str> = qname.split('.').filter(|l| !l.is_empty()).collect();

                // Pre-compute hashes for all ancestor names + wildcards
                let mut ancestor_hashes: Vec<Option<Vec<u8>>> = Vec::with_capacity(labels.len());
                for i in 0..labels.len() {
                    let name: String = labels[i..].join(".");
                    ancestor_hashes.push(nsec3_hash(&name, *hash_algorithm, *iterations, salt));
                }

                let mut proven = false;
                for i in 1..labels.len() {
                    let ce_hash = match &ancestor_hashes[i] {
                        Some(h) => h,
                        None => continue,
                    };

                    // (1) Closest encloser: exact hash match
                    if !decoded.iter().any(|(oh, _)| oh == ce_hash) {
                        continue;
                    }

                    // (2) Next closer name covered by range
                    // ancestor_hashes[i-1] is the hash of labels[i-1..] (one label prepended to CE)
                    let nc_hash = match &ancestor_hashes[i - 1] {
                        Some(h) => h,
                        None => continue,
                    };
                    if !nsec3_any_covers(&decoded, nc_hash) {
                        continue;
                    }

                    // (3) Wildcard at closest encloser denied
                    let wildcard = format!("*.{}", labels[i..].join("."));
                    let wc_hash = match nsec3_hash(&wildcard, *hash_algorithm, *iterations, salt) {
                        Some(h) => h,
                        None => continue,
                    };
                    if nsec3_any_covers(&decoded, &wc_hash) {
                        proven = true;
                        break;
                    }
                }

                if proven {
                    debug!("dnssec: NSEC3 proves NXDOMAIN for '{}'", qname);
                    return DnssecStatus::Secure;
                }
            } else {
                // NODATA — exact hash match with type not in bitmap
                let nodata = decoded.iter().any(|(oh, r)| {
                    if let DnsRecord::NSEC3 { type_bitmap, .. } = r {
                        oh == &qname_hash
                            && !type_bitmap_contains(type_bitmap, qtype)
                            && !type_bitmap_contains(type_bitmap, QueryType::CNAME.to_num())
                    } else {
                        false
                    }
                });
                if nodata {
                    debug!("dnssec: NSEC3 proves NODATA for '{}' type {}", qname, qtype);
                    return DnssecStatus::Secure;
                }
            }

            return DnssecStatus::Bogus;
        }
    }

    DnssecStatus::Indeterminate
}

fn parent_zone(zone: &str) -> String {
    if zone == "." || zone.is_empty() {
        return ".".into();
    }
    match zone.find('.') {
        Some(pos) => {
            let parent = &zone[pos + 1..];
            if parent.is_empty() {
                ".".into()
            } else {
                parent.into()
            }
        }
        None => ".".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_tag_root_ksk() {
        let tag = compute_key_tag(ROOT_KSK_FLAGS, 3, ROOT_KSK_ALGORITHM, ROOT_KSK_PUBLIC_KEY);
        assert_eq!(tag, ROOT_KSK_KEY_TAG);
    }

    #[test]
    fn name_to_wire_root() {
        assert_eq!(name_to_wire("."), vec![0]);
        assert_eq!(name_to_wire(""), vec![0]);
    }

    #[test]
    fn name_to_wire_domain() {
        let wire = name_to_wire("Example.COM");
        assert_eq!(
            wire,
            vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]
        );
    }

    #[test]
    fn name_to_wire_escaped_dot_in_label_is_not_a_separator() {
        // `exa\.mple.com` is two labels: `exa.mple` (8 bytes including the 0x2E) and `com`.
        let wire = name_to_wire("exa\\.mple.com");
        assert_eq!(
            wire,
            vec![8, b'e', b'x', b'a', b'.', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]
        );
    }

    #[test]
    fn name_to_wire_decimal_escape_is_lowercased() {
        // \065 = 'A', must become 'a' in canonical form.
        let wire = name_to_wire("\\065bc.com");
        assert_eq!(wire, vec![3, b'a', b'b', b'c', 3, b'c', b'o', b'm', 0]);
    }

    #[test]
    fn parent_zone_cases() {
        assert_eq!(parent_zone("example.com"), "com");
        assert_eq!(parent_zone("com"), ".");
        assert_eq!(parent_zone("."), ".");
        assert_eq!(parent_zone("sub.example.com"), "example.com");
    }

    #[test]
    fn ds_verification() {
        // Verify DS digest: SHA-256(owner_wire + DNSKEY_RDATA) must match DS.digest
        let dk = DnsRecord::DNSKEY {
            domain: "test.example".into(),
            flags: 257,
            protocol: 3,
            algorithm: 8,
            public_key: vec![1, 2, 3, 4],
            ttl: 3600,
        };

        // Compute expected digest
        let owner_wire = name_to_wire("test.example");
        let mut dnskey_rdata = vec![1u8, 1, 3, 8]; // flags=257, proto=3, algo=8
        dnskey_rdata.extend(&[1, 2, 3, 4]);

        let mut input = Vec::new();
        input.extend(&owner_wire);
        input.extend(&dnskey_rdata);
        let expected = ring::digest::digest(&ring::digest::SHA256, &input);

        let ds = DnsRecord::DS {
            domain: "test.example".into(),
            key_tag: compute_key_tag(257, 3, 8, &[1, 2, 3, 4]),
            algorithm: 8,
            digest_type: 2,
            digest: expected.as_ref().to_vec(),
            ttl: 3600,
        };

        assert!(verify_ds(&ds, &dk, "test.example"));
    }

    #[test]
    fn rsa_der_conversion() {
        // Minimal RSA key: 3-byte exponent (65537 = 0x010001), 4-byte modulus
        let mut key = vec![3u8]; // exp_len = 3
        key.extend(&[0x01, 0x00, 0x01]); // exponent = 65537
        key.extend(&[0xFF, 0xAA, 0xBB, 0xCC]); // modulus

        let der = rsa_dnskey_to_der(&key).unwrap();
        // Should be a valid ASN.1 SEQUENCE containing two INTEGERs
        assert_eq!(der[0], 0x30); // SEQUENCE
    }

    #[test]
    fn group_rrsets_basic() {
        let records = vec![
            DnsRecord::A {
                domain: "example.com".into(),
                addr: "1.2.3.4".parse().unwrap(),
                ttl: 300,
            },
            DnsRecord::A {
                domain: "example.com".into(),
                addr: "5.6.7.8".parse().unwrap(),
                ttl: 300,
            },
        ];
        let groups = group_rrsets(&records);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].2.len(), 2);
    }

    #[test]
    fn type_bitmap_contains_a() {
        // Window 0, bitmap: A(1) + NS(2) + SOA(6) + MX(15) + AAAA(28)
        // Byte 0: bits 1,2 set = 0x60; byte 0 also has SOA(6) = 0x02 → 0x62
        // Actually: bit N means type N. Byte 0 covers types 0-7, byte 1 covers 8-15, etc.
        // Type 1 (A) = byte 0, bit 6 (0x40); Type 2 (NS) = byte 0, bit 5 (0x20)
        // Window 0, length 4, bitmap covers types 0-31
        let bitmap = vec![
            0u8, 4,    // window 0, 4 bytes
            0x62, // byte 0: types 1(A), 2(NS), 6(SOA) → bits 6,5,1 → 0x40|0x20|0x02
            0x01, // byte 1: type 15(MX) → bit 0 → 0x01
            0x00, // byte 2: nothing
            0x08, // byte 3: type 28(AAAA) → bit 3 → 0x08
        ];
        assert!(type_bitmap_contains(&bitmap, 1)); // A
        assert!(type_bitmap_contains(&bitmap, 2)); // NS
        assert!(type_bitmap_contains(&bitmap, 6)); // SOA
        assert!(type_bitmap_contains(&bitmap, 15)); // MX
        assert!(type_bitmap_contains(&bitmap, 28)); // AAAA
        assert!(!type_bitmap_contains(&bitmap, 5)); // CNAME — not set
        assert!(!type_bitmap_contains(&bitmap, 16)); // TXT — not set
    }

    #[test]
    fn canonical_name_ordering() {
        use std::cmp::Ordering;
        assert_eq!(
            canonical_dns_name_order("a.example.com", "b.example.com"),
            Ordering::Less
        );
        assert_eq!(
            canonical_dns_name_order("z.example.com", "a.example.org"),
            Ordering::Less // .com < .org
        );
        assert_eq!(
            canonical_dns_name_order("example.com", "a.example.com"),
            Ordering::Less // shorter sorts first
        );
        assert_eq!(
            canonical_dns_name_order("example.com", "example.com"),
            Ordering::Equal
        );
    }

    #[test]
    fn nsec_covers_name_basic() {
        // gap: alpha.example.com -> gamma.example.com
        assert!(nsec_covers_name(
            "alpha.example.com",
            "gamma.example.com",
            "beta.example.com"
        ));
        assert!(nsec_covers_name(
            "alpha.example.com",
            "gamma.example.com",
            "delta.example.com"
        ));
        assert!(!nsec_covers_name(
            "alpha.example.com",
            "gamma.example.com",
            "zebra.example.com"
        ));
    }

    #[test]
    fn nsec3_hash_rejects_high_iterations() {
        assert!(nsec3_hash("example.com", 1, 500, &[]).is_some());
        assert!(nsec3_hash("example.com", 1, 501, &[]).is_none());
    }

    #[test]
    fn closest_encloser_finds_parent() {
        let nsec1 = DnsRecord::NSEC {
            domain: "example.com".into(),
            next_domain: "z.example.com".into(),
            type_bitmap: vec![],
            ttl: 300,
        };
        let nsecs: Vec<&DnsRecord> = vec![&nsec1];
        // foo.example.com doesn't exist; closest encloser is example.com (the NSEC owner)
        assert_eq!(
            closest_encloser("foo.example.com", &nsecs),
            Some("example.com".into())
        );
        // example.com is itself an NSEC owner, so it IS a closest encloser
        assert_eq!(
            closest_encloser("example.com", &nsecs),
            Some("example.com".into())
        );
        // nothing.org has no matching owner
        assert_eq!(closest_encloser("nothing.org", &nsecs), None);
    }

    #[test]
    fn nsec_nodata_proof() {
        // NSEC at example.com with A and NS in bitmap, but not AAAA
        let bitmap = vec![0u8, 1, 0x62]; // A(1), NS(2), SOA(6)
        assert!(nsec_proves_nodata(
            "example.com",
            "example.com",
            &bitmap,
            28
        )); // AAAA not in bitmap
        assert!(!nsec_proves_nodata(
            "example.com",
            "example.com",
            &bitmap,
            1
        )); // A IS in bitmap
    }

    #[test]
    fn nsec3_hash_basic() {
        // Hash with 0 iterations, empty salt
        let hash = nsec3_hash("example.com", 1, 0, &[]).unwrap();
        assert_eq!(hash.len(), 20); // SHA-1 output
    }

    #[test]
    fn nsec3_range_check() {
        assert!(nsec3_hash_in_range(&[1], &[3], &[2])); // 1 < 2 < 3
        assert!(!nsec3_hash_in_range(&[1], &[3], &[4])); // 4 not in range
                                                         // Wrap-around: [250] -> [10] covers [255] and [5]
        assert!(nsec3_hash_in_range(&[250], &[10], &[255]));
        assert!(nsec3_hash_in_range(&[250], &[10], &[5]));
        assert!(!nsec3_hash_in_range(&[250], &[10], &[100])); // not in wrapped range
    }

    #[test]
    fn base32hex_decode_known_values() {
        // "00000000" in base32hex = all zeros
        assert_eq!(base32hex_decode("00000000").unwrap(), vec![0, 0, 0, 0, 0]);
        // "10" = 0x08 (1 << 3)
        assert_eq!(base32hex_decode("10").unwrap(), vec![0x08]);
        // case-insensitive: "vv" = "VV" = [0xFF, 0x80..] -> 31<<5|31 = 0x03FF -> bytes [0xFF]
        assert_eq!(base32hex_decode("VV"), base32hex_decode("vv"));
        // invalid char
        assert!(base32hex_decode("!!").is_none());
    }
}
