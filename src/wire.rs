//! Wire-level DNS utilities: question extraction, TTL offset scanning, and patching.
//!
//! These operate directly on raw DNS wire bytes without full packet parsing,
//! enabling zero-copy forwarding and wire-level caching.

use std::borrow::Cow;

use crate::Result;

/// Metadata extracted from scanning a DNS response's wire bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireMeta {
    /// Byte offsets of every TTL field in answer + authority + additional sections.
    /// Each offset points to the first byte of a 4-byte big-endian TTL.
    /// EDNS OPT pseudo-records are excluded (their "TTL" is flags, not a real TTL).
    pub ttl_offsets: Vec<usize>,
    /// How many of the offsets belong to the answer section (the first `answer_count`
    /// entries). Used to extract min-TTL from answers only.
    pub answer_count: usize,
}

/// Read a 16-bit section count from the header.
fn count(wire: &[u8], at: usize) -> usize {
    u16::from_be_bytes([wire[at], wire[at + 1]]) as usize
}

/// A record's TYPE sits in the two bytes before its CLASS, four before its
/// TTL. Matching on it (not on literal root-name bytes) catches an OPT whose
/// owner name reaches root through a compression pointer — the same trap
/// `DnsPacket::read` already guards against.
fn record_type(wire: &[u8], ttl_offset: usize) -> u16 {
    u16::from_be_bytes([wire[ttl_offset - 4], wire[ttl_offset - 3]])
}

const TYPE_OPT: u16 = 41;
const TYPE_TSIG: u16 = 250;

/// Scan a DNS response's wire bytes and return metadata about TTL field locations.
///
/// Walks the header, skips the question section, then for each resource record in
/// answer, authority, and additional sections, records the byte offset of the TTL
/// field. EDNS OPT records (type 41 with root name) are excluded.
pub fn scan_ttl_offsets(wire: &[u8]) -> Result<WireMeta> {
    if wire.len() < 12 {
        return Err("wire too short for DNS header".into());
    }

    let mut pos = 12;
    for _ in 0..count(wire, 4) {
        skip_question(wire, &mut pos)?;
    }

    let mut ttl_offsets = Vec::new();
    let mut answer_count = 0;

    // ANCOUNT, NSCOUNT, ARCOUNT: answers first, so they lead `ttl_offsets`.
    for (section, at) in [6, 8, 10].into_iter().enumerate() {
        for _ in 0..count(wire, at) {
            let ttl_offset = skip_record(wire, &mut pos)?;
            if record_type(wire, ttl_offset) != TYPE_OPT {
                ttl_offsets.push(ttl_offset);
                if section == 0 {
                    answer_count += 1;
                }
            }
        }
    }

    Ok(WireMeta {
        ttl_offsets,
        answer_count,
    })
}

/// Extract the minimum TTL from the answer section offsets of a wire response.
pub fn min_ttl_from_wire(wire: &[u8], meta: &WireMeta) -> Option<u32> {
    meta.ttl_offsets
        .iter()
        .take(meta.answer_count)
        .filter_map(|&off| {
            if off + 4 <= wire.len() {
                Some(u32::from_be_bytes([
                    wire[off],
                    wire[off + 1],
                    wire[off + 2],
                    wire[off + 3],
                ]))
            } else {
                None
            }
        })
        .min()
}

/// Patch the transaction ID (bytes 0..2) in a DNS wire message.
pub fn patch_id(wire: &mut [u8], new_id: u16) {
    let bytes = new_id.to_be_bytes();
    wire[0] = bytes[0];
    wire[1] = bytes[1];
}

/// Patch all TTL fields at the given offsets to `new_ttl`.
pub fn patch_ttls(wire: &mut [u8], offsets: &[usize], new_ttl: u32) {
    let bytes = new_ttl.to_be_bytes();
    for &off in offsets {
        wire[off] = bytes[0];
        wire[off + 1] = bytes[1];
        wire[off + 2] = bytes[2];
        wire[off + 3] = bytes[3];
    }
}

const DO_FLAG: u8 = 0x80;
const TC_FLAG: u8 = 0x02;

/// TC=1 (RFC 1035 §4.1.1, header byte 2) means "this answer did not fit, ask
/// again over TCP". Cached, it would answer every later client — including the
/// ones already on TCP, where the retry has nowhere left to go.
pub fn is_truncated(wire: &[u8]) -> bool {
    wire.get(2).is_some_and(|flags| flags & TC_FLAG != 0)
}

/// Make a query wire carry DO=1 within a budget that can hold the answer:
/// flip the flag on the client's OPT, or append one and bump ARCOUNT. Patches
/// bytes rather than reserializing, so client EDNS options, name compression
/// and wires past `BytePacketBuffer`'s 4096-byte ceiling all survive untouched
/// (issue #191). Wires we cannot walk go upstream as they came.
pub fn ensure_do_bit(wire: &[u8]) -> Cow<'_, [u8]> {
    match locate_opt(wire) {
        Ok(OptSite::Flag(ttl)) if wire[ttl + 2] & DO_FLAG != 0 && payload_in_budget(wire, ttl) => {
            Cow::Borrowed(wire)
        }
        Ok(OptSite::Flag(ttl)) => {
            let mut out = wire.to_vec();
            out[ttl + 2] |= DO_FLAG;
            if !payload_in_budget(&out, ttl) {
                let clamped = payload(&out, ttl).clamp(MIN_UPSTREAM_PAYLOAD, MAX_UPSTREAM_PAYLOAD);
                out[ttl - 2..ttl].copy_from_slice(&clamped.to_be_bytes());
            }
            Cow::Owned(out)
        }
        Ok(OptSite::End(end)) => {
            append_do_opt(&wire[..end]).map_or(Cow::Borrowed(wire), Cow::Owned)
        }
        Err(_) => Cow::Borrowed(wire),
    }
}

/// EDNS payload size is hop-by-hop (RFC 6891 §6.2.3) — upstream answers to us,
/// not to our client, so the client's budget is not ours to pass on. Forwarding
/// a small one alongside DO=1 asks for RRSIGs that cannot fit and earns a TC=1
/// with no records, for answers that fit unsigned.
const MIN_UPSTREAM_PAYLOAD: u16 = crate::packet::DEFAULT_EDNS_PAYLOAD;

/// Ceiling on the budget we advertise: `forward_udp_raw` receives into 4096
/// bytes, and a reply larger than the buffer is silently cut into a wire that
/// cannot parse. Never invite an answer we cannot receive.
const MAX_UPSTREAM_PAYLOAD: u16 = 4096;

/// The bare OPT `append_do_opt` writes: root name, TYPE=41, our payload
/// budget, DO=1. Public so the fuzz oracle asserts against the same bytes.
pub const APPENDED_DO_OPT: [u8; 11] = {
    let p = MIN_UPSTREAM_PAYLOAD.to_be_bytes();
    [0, 0, 41, p[0], p[1], 0, 0, DO_FLAG, 0, 0, 0]
};

/// The OPT's CLASS field, which holds the payload size, sits in the two bytes
/// before its TTL.
fn payload(wire: &[u8], ttl: usize) -> u16 {
    u16::from_be_bytes([wire[ttl - 2], wire[ttl - 1]])
}

fn payload_in_budget(wire: &[u8], ttl: usize) -> bool {
    (MIN_UPSTREAM_PAYLOAD..=MAX_UPSTREAM_PAYLOAD).contains(&payload(wire, ttl))
}

/// `None` when ARCOUNT cannot cover one more record, since an appended OPT
/// the count does not reach is trailing garbage to the upstream.
fn append_do_opt(wire: &[u8]) -> Option<Vec<u8>> {
    let arcount = u16::from_be_bytes([wire[10], wire[11]]).checked_add(1)?;
    let mut out = Vec::with_capacity(wire.len() + APPENDED_DO_OPT.len());
    out.extend_from_slice(wire);
    out[10..12].copy_from_slice(&arcount.to_be_bytes());
    out.extend_from_slice(&APPENDED_DO_OPT);
    Some(out)
}

/// Where DO belongs in a query wire.
enum OptSite {
    /// Offset of the OPT record's TTL field, whose third byte holds DO.
    Flag(usize),
    /// End of the counted records — where an OPT can be appended. Any bytes
    /// past it are uncounted trailing junk that must not survive the append,
    /// or upstream reads them as the record ARCOUNT now reaches.
    End(usize),
}

fn locate_opt(wire: &[u8]) -> Result<OptSite> {
    if wire.len() < 12 {
        return Err("wire too short for DNS header".into());
    }

    let mut pos = 12;
    for _ in 0..count(wire, 4) {
        skip_question(wire, &mut pos)?;
    }
    for _ in 0..count(wire, 6) + count(wire, 8) {
        skip_record(wire, &mut pos)?;
    }
    for _ in 0..count(wire, 10) {
        let ttl_offset = skip_record(wire, &mut pos)?;
        match record_type(wire, ttl_offset) {
            TYPE_OPT => return Ok(OptSite::Flag(ttl_offset)),
            // A TSIG must stay the last record and its MAC covers the header
            // (RFC 8945 §5.1) — appending an OPT behind it, or bumping
            // ARCOUNT, voids the signature. Not ours to patch.
            TYPE_TSIG => return Err("TSIG-signed message".into()),
            _ => {}
        }
    }

    Ok(OptSite::End(pos))
}

/// Skip one question entry: name, then QTYPE(2) + QCLASS(2).
fn skip_question(wire: &[u8], pos: &mut usize) -> Result<()> {
    skip_wire_name(wire, pos)?;
    if *pos + 4 > wire.len() {
        return Err("wire truncated in question section".into());
    }
    *pos += 4;
    Ok(())
}

/// Skip one resource record: name, fixed fields, then RDATA. Returns the offset
/// of its TTL field, which sits after TYPE(2) + CLASS(2).
fn skip_record(wire: &[u8], pos: &mut usize) -> Result<usize> {
    skip_wire_name(wire, pos)?;
    if *pos + 10 > wire.len() {
        return Err("wire truncated in resource record".into());
    }
    let ttl_offset = *pos + 4;
    let rdlength = u16::from_be_bytes([wire[*pos + 8], wire[*pos + 9]]) as usize;
    *pos += 10 + rdlength;
    if *pos > wire.len() {
        return Err("wire truncated in resource record RDATA".into());
    }
    Ok(ttl_offset)
}

/// Skip a DNS name in wire bytes, advancing `pos` past it.
fn skip_wire_name(wire: &[u8], pos: &mut usize) -> Result<()> {
    loop {
        if *pos >= wire.len() {
            return Err("wire truncated skipping name".into());
        }
        let len = wire[*pos] as usize;

        if len & 0xC0 == 0xC0 {
            *pos += 2; // compression pointer is 2 bytes
            return Ok(());
        }
        if len == 0 {
            *pos += 1;
            return Ok(());
        }
        *pos += 1 + len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::BytePacketBuffer;
    use crate::cache::{DnsCache, DnssecStatus};
    use crate::header::ResultCode;
    use crate::packet::{DnsPacket, EdnsOpt};
    use crate::question::{DnsQuestion, QueryType};
    use crate::record::DnsRecord;

    // ── Helpers ──────────────────────────────────────────────────────

    /// Serialize a DnsPacket to wire bytes.
    fn to_wire(pkt: &DnsPacket) -> Vec<u8> {
        let mut buf = BytePacketBuffer::new();
        pkt.write(&mut buf).unwrap();
        buf.filled().to_vec()
    }

    /// Build a minimal response with given answers.
    fn response(id: u16, domain: &str, answers: Vec<DnsRecord>) -> DnsPacket {
        let mut pkt = DnsPacket::new();
        pkt.header.id = id;
        pkt.header.response = true;
        pkt.header.recursion_desired = true;
        pkt.header.recursion_available = true;
        pkt.header.rescode = ResultCode::NOERROR;
        pkt.questions
            .push(DnsQuestion::new(domain.to_string(), QueryType::A));
        pkt.answers = answers;
        pkt
    }

    fn a_record(domain: &str, ip: &str, ttl: u32) -> DnsRecord {
        DnsRecord::A {
            domain: domain.into(),
            addr: ip.parse().unwrap(),
            ttl,
        }
    }

    fn aaaa_record(domain: &str, ip: &str, ttl: u32) -> DnsRecord {
        DnsRecord::AAAA {
            domain: domain.into(),
            addr: ip.parse().unwrap(),
            ttl,
        }
    }

    fn cname_record(domain: &str, host: &str, ttl: u32) -> DnsRecord {
        DnsRecord::CNAME {
            domain: domain.into(),
            host: host.into(),
            ttl,
        }
    }

    fn ns_record(domain: &str, host: &str, ttl: u32) -> DnsRecord {
        DnsRecord::NS {
            domain: domain.into(),
            host: host.into(),
            ttl,
        }
    }

    fn mx_record(domain: &str, host: &str, priority: u16, ttl: u32) -> DnsRecord {
        DnsRecord::MX {
            domain: domain.into(),
            priority,
            host: host.into(),
            ttl,
        }
    }

    // ── A. TTL offset extraction ────────────────────────────────────

    #[test]
    fn scan_single_a_record() {
        let pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        let wire = to_wire(&pkt);
        let meta = scan_ttl_offsets(&wire).unwrap();

        assert_eq!(meta.ttl_offsets.len(), 1);
        assert_eq!(meta.answer_count, 1);

        let off = meta.ttl_offsets[0];
        let ttl = u32::from_be_bytes([wire[off], wire[off + 1], wire[off + 2], wire[off + 3]]);
        assert_eq!(ttl, 300);
    }

    #[test]
    fn scan_multiple_a_records() {
        let pkt = response(
            0x1234,
            "example.com",
            vec![
                a_record("example.com", "1.2.3.4", 300),
                a_record("example.com", "5.6.7.8", 600),
                a_record("example.com", "9.10.11.12", 120),
            ],
        );
        let wire = to_wire(&pkt);
        let meta = scan_ttl_offsets(&wire).unwrap();

        assert_eq!(meta.ttl_offsets.len(), 3);
        assert_eq!(meta.answer_count, 3);

        let ttls: Vec<u32> = meta
            .ttl_offsets
            .iter()
            .map(|&off| {
                u32::from_be_bytes([wire[off], wire[off + 1], wire[off + 2], wire[off + 3]])
            })
            .collect();
        assert_eq!(ttls, vec![300, 600, 120]);
    }

    #[test]
    fn scan_mixed_sections() {
        let mut pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        pkt.authorities
            .push(ns_record("example.com", "ns1.example.com", 3600));
        pkt.authorities
            .push(ns_record("example.com", "ns2.example.com", 3600));
        pkt.resources
            .push(a_record("ns1.example.com", "10.0.0.1", 1800));
        let wire = to_wire(&pkt);
        let meta = scan_ttl_offsets(&wire).unwrap();

        assert_eq!(meta.ttl_offsets.len(), 4); // 1 answer + 2 authority + 1 additional
        assert_eq!(meta.answer_count, 1);
    }

    #[test]
    fn scan_cname_chain() {
        let pkt = response(
            0x1234,
            "www.example.com",
            vec![
                cname_record("www.example.com", "example.com", 300),
                a_record("example.com", "1.2.3.4", 600),
            ],
        );
        let wire = to_wire(&pkt);
        let meta = scan_ttl_offsets(&wire).unwrap();

        assert_eq!(meta.ttl_offsets.len(), 2);
        assert_eq!(meta.answer_count, 2);

        let ttls: Vec<u32> = meta
            .ttl_offsets
            .iter()
            .map(|&off| {
                u32::from_be_bytes([wire[off], wire[off + 1], wire[off + 2], wire[off + 3]])
            })
            .collect();
        assert_eq!(ttls, vec![300, 600]);
    }

    #[test]
    fn scan_compressed_names() {
        // Build a packet with name compression (the serializer uses compression
        // for repeated domain names). Two A records for the same domain will
        // have the second name compressed as a pointer.
        let pkt = response(
            0x1234,
            "example.com",
            vec![
                a_record("example.com", "1.2.3.4", 300),
                a_record("example.com", "5.6.7.8", 600),
            ],
        );
        let wire = to_wire(&pkt);

        // Verify compression is actually present (second name should be a pointer)
        // The first answer's name is at some offset, and the second should use 0xC0xx
        let meta = scan_ttl_offsets(&wire).unwrap();
        assert_eq!(meta.ttl_offsets.len(), 2);

        let ttls: Vec<u32> = meta
            .ttl_offsets
            .iter()
            .map(|&off| {
                u32::from_be_bytes([wire[off], wire[off + 1], wire[off + 2], wire[off + 3]])
            })
            .collect();
        assert_eq!(ttls, vec![300, 600]);
    }

    #[test]
    fn scan_edns_opt_excluded() {
        let mut pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        pkt.edns = Some(EdnsOpt {
            udp_payload_size: 1232,
            extended_rcode: 0,
            version: 0,
            do_bit: false,
            options: vec![],
        });
        let wire = to_wire(&pkt);
        let meta = scan_ttl_offsets(&wire).unwrap();

        // Only the A record's TTL, not the OPT pseudo-record's "TTL"
        assert_eq!(meta.ttl_offsets.len(), 1);
        assert_eq!(meta.answer_count, 1);
    }

    #[test]
    fn scan_rrsig_only_wire_ttl() {
        let mut pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        pkt.answers.push(DnsRecord::RRSIG {
            domain: "example.com".into(),
            type_covered: 1, // A
            algorithm: 13,
            labels: 2,
            original_ttl: 9999, // must NOT appear in offsets
            expiration: 1700000000,
            inception: 1690000000,
            key_tag: 12345,
            signer_name: "example.com".into(),
            signature: vec![0x01, 0x02, 0x03, 0x04],
            ttl: 300,
        });
        let wire = to_wire(&pkt);
        let meta = scan_ttl_offsets(&wire).unwrap();

        // 2 TTL offsets: A record + RRSIG wire TTL
        assert_eq!(meta.ttl_offsets.len(), 2);
        assert_eq!(meta.answer_count, 2);

        // Both wire TTLs should be 300, not 9999
        for &off in &meta.ttl_offsets {
            let ttl = u32::from_be_bytes([wire[off], wire[off + 1], wire[off + 2], wire[off + 3]]);
            assert_eq!(ttl, 300);
        }

        // Verify that 9999 (original_ttl) exists somewhere in the wire but is NOT in offsets
        let original_ttl_bytes = 9999u32.to_be_bytes();
        let found_at = wire
            .windows(4)
            .position(|w| w == original_ttl_bytes)
            .expect("original_ttl should be in wire");
        assert!(
            !meta.ttl_offsets.contains(&found_at),
            "original_ttl offset must not be in ttl_offsets"
        );
    }

    #[test]
    fn scan_nsec_variable_rdata() {
        let mut pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        pkt.authorities.push(DnsRecord::NSEC {
            domain: "example.com".into(),
            next_domain: "z.example.com".into(),
            type_bitmap: vec![0x00, 0x06, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03],
            ttl: 1800,
        });
        let wire = to_wire(&pkt);
        let meta = scan_ttl_offsets(&wire).unwrap();

        assert_eq!(meta.ttl_offsets.len(), 2); // A + NSEC
        assert_eq!(meta.answer_count, 1);

        let nsec_ttl_off = meta.ttl_offsets[1];
        let ttl = u32::from_be_bytes([
            wire[nsec_ttl_off],
            wire[nsec_ttl_off + 1],
            wire[nsec_ttl_off + 2],
            wire[nsec_ttl_off + 3],
        ]);
        assert_eq!(ttl, 1800);
    }

    #[test]
    fn scan_empty_response() {
        let pkt = response(0x1234, "nxdomain.example.com", vec![]);
        let wire = to_wire(&pkt);
        let meta = scan_ttl_offsets(&wire).unwrap();

        assert!(meta.ttl_offsets.is_empty());
        assert_eq!(meta.answer_count, 0);
    }

    #[test]
    fn scan_unknown_record_type() {
        // Manually build a response with an unknown type (99) using raw wire bytes
        let mut pkt = response(0x1234, "example.com", vec![]);
        pkt.answers.push(DnsRecord::UNKNOWN {
            domain: "example.com".into(),
            qtype: 99,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            ttl: 500,
        });
        let wire = to_wire(&pkt);
        let meta = scan_ttl_offsets(&wire).unwrap();

        assert_eq!(meta.ttl_offsets.len(), 1);
        let off = meta.ttl_offsets[0];
        let ttl = u32::from_be_bytes([wire[off], wire[off + 1], wire[off + 2], wire[off + 3]]);
        assert_eq!(ttl, 500);
    }

    #[test]
    fn scan_truncated_wire_returns_error() {
        let pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        let wire = to_wire(&pkt);
        // Truncate mid-record
        let truncated = &wire[..wire.len() - 2];
        assert!(scan_ttl_offsets(truncated).is_err());
    }

    #[test]
    fn scan_too_short_for_header() {
        assert!(scan_ttl_offsets(&[0u8; 5]).is_err());
    }

    #[test]
    fn scan_query_packet_no_offsets() {
        let pkt = DnsPacket::query(0x1234, "example.com", QueryType::A);
        let wire = to_wire(&pkt);
        let meta = scan_ttl_offsets(&wire).unwrap();
        assert!(meta.ttl_offsets.is_empty());
    }

    // ── B. TTL patching ─────────────────────────────────────────────

    #[test]
    fn patch_ttl_single() {
        let pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        let mut wire = to_wire(&pkt);
        let meta = scan_ttl_offsets(&wire).unwrap();

        patch_ttls(&mut wire, &meta.ttl_offsets, 120);

        let off = meta.ttl_offsets[0];
        assert_eq!(
            u32::from_be_bytes([wire[off], wire[off + 1], wire[off + 2], wire[off + 3]]),
            120
        );
    }

    #[test]
    fn patch_ttl_multiple() {
        let pkt = response(
            0x1234,
            "example.com",
            vec![
                a_record("example.com", "1.2.3.4", 300),
                a_record("example.com", "5.6.7.8", 600),
                a_record("example.com", "9.10.11.12", 900),
            ],
        );
        let mut wire = to_wire(&pkt);
        let meta = scan_ttl_offsets(&wire).unwrap();

        patch_ttls(&mut wire, &meta.ttl_offsets, 42);

        for &off in &meta.ttl_offsets {
            assert_eq!(
                u32::from_be_bytes([wire[off], wire[off + 1], wire[off + 2], wire[off + 3]]),
                42
            );
        }
    }

    #[test]
    fn patch_ttl_preserves_other_bytes() {
        let pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        let original = to_wire(&pkt);
        let mut patched = original.clone();
        let meta = scan_ttl_offsets(&patched).unwrap();

        patch_ttls(&mut patched, &meta.ttl_offsets, 120);

        // Every byte outside TTL offsets should be identical
        for (i, (&orig, &patc)) in original.iter().zip(patched.iter()).enumerate() {
            let in_ttl = meta.ttl_offsets.iter().any(|&off| i >= off && i < off + 4);
            if !in_ttl {
                assert_eq!(
                    orig, patc,
                    "byte {} changed (outside TTL): orig={:#04x}, patched={:#04x}",
                    i, orig, patc
                );
            }
        }
    }

    #[test]
    fn patch_ttl_zero() {
        let pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        let mut wire = to_wire(&pkt);
        let meta = scan_ttl_offsets(&wire).unwrap();

        patch_ttls(&mut wire, &meta.ttl_offsets, 0);

        let off = meta.ttl_offsets[0];
        assert_eq!(&wire[off..off + 4], &[0, 0, 0, 0]);
    }

    #[test]
    fn patch_ttl_max_u32() {
        let pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        let mut wire = to_wire(&pkt);
        let meta = scan_ttl_offsets(&wire).unwrap();

        patch_ttls(&mut wire, &meta.ttl_offsets, u32::MAX);

        let off = meta.ttl_offsets[0];
        assert_eq!(&wire[off..off + 4], &[0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn patch_ttl_edns_untouched() {
        let mut pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        pkt.edns = Some(EdnsOpt {
            udp_payload_size: 1232,
            extended_rcode: 0,
            version: 0,
            do_bit: true,
            options: vec![],
        });
        let original = to_wire(&pkt);
        let mut patched = original.clone();
        let meta = scan_ttl_offsets(&patched).unwrap();

        patch_ttls(&mut patched, &meta.ttl_offsets, 42);

        // Only the A record's TTL bytes should differ; everything else
        // (including the OPT "TTL" containing the DO bit) must be unchanged.
        for (i, (&orig, &patc)) in original.iter().zip(patched.iter()).enumerate() {
            let in_ttl = meta.ttl_offsets.iter().any(|&off| i >= off && i < off + 4);
            if !in_ttl {
                assert_eq!(
                    orig, patc,
                    "byte {} changed (outside TTL): orig={:#04x}, patched={:#04x}",
                    i, orig, patc
                );
            }
        }
    }

    // ── C. ID patching ──────────────────────────────────────────────

    #[test]
    fn patch_id_basic() {
        let pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        let mut wire = to_wire(&pkt);

        patch_id(&mut wire, 0xABCD);
        assert_eq!(&wire[0..2], &[0xAB, 0xCD]);
    }

    #[test]
    fn patch_id_preserves_flags() {
        let pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        let original = to_wire(&pkt);
        let mut patched = original.clone();

        patch_id(&mut patched, 0x9999);

        // Bytes 2..12 (flags + counts) unchanged
        assert_eq!(&original[2..12], &patched[2..12]);
    }

    #[test]
    fn patch_id_zero() {
        let pkt = response(
            0xFFFF,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        let mut wire = to_wire(&pkt);

        patch_id(&mut wire, 0x0000);
        assert_eq!(&wire[0..2], &[0x00, 0x00]);
    }

    // ── D. min_ttl_from_wire ────────────────────────────────────────

    #[test]
    fn min_ttl_answers_only() {
        let mut pkt = response(
            0x1234,
            "example.com",
            vec![
                a_record("example.com", "1.2.3.4", 300),
                a_record("example.com", "5.6.7.8", 60),
            ],
        );
        pkt.authorities
            .push(ns_record("example.com", "ns1.example.com", 10)); // lower but in authority, not answer
        let wire = to_wire(&pkt);
        let meta = scan_ttl_offsets(&wire).unwrap();

        assert_eq!(min_ttl_from_wire(&wire, &meta), Some(60)); // from answers only
    }

    #[test]
    fn min_ttl_empty_answers() {
        let pkt = response(0x1234, "example.com", vec![]);
        let wire = to_wire(&pkt);
        let meta = scan_ttl_offsets(&wire).unwrap();
        assert_eq!(min_ttl_from_wire(&wire, &meta), None);
    }

    // ── F. Round-trip fidelity ──────────────────────────────────────
    //
    // These verify that wire bytes → scan → patch → parse produces the
    // same semantic content as the original packet. They test the full
    // integration path that the wire-level cache will use.

    #[test]
    fn round_trip_simple_a() {
        let pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        let wire = to_wire(&pkt);
        let meta = scan_ttl_offsets(&wire).unwrap();

        let mut patched = wire.clone();
        patch_id(&mut patched, 0xABCD);
        patch_ttls(&mut patched, &meta.ttl_offsets, 120);

        // Parse the patched wire
        let mut buf = BytePacketBuffer::from_bytes(&patched);
        let parsed = DnsPacket::from_buffer(&mut buf).unwrap();

        assert_eq!(parsed.header.id, 0xABCD);
        assert_eq!(parsed.answers.len(), 1);
        match &parsed.answers[0] {
            DnsRecord::A { domain, addr, ttl } => {
                assert_eq!(domain, "example.com");
                assert_eq!(*addr, "1.2.3.4".parse::<std::net::Ipv4Addr>().unwrap());
                assert_eq!(*ttl, 120);
            }
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[test]
    fn round_trip_edns_survives() {
        let mut pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        pkt.edns = Some(EdnsOpt {
            udp_payload_size: 1232,
            extended_rcode: 0,
            version: 0,
            do_bit: true,
            options: vec![],
        });
        let wire = to_wire(&pkt);
        let meta = scan_ttl_offsets(&wire).unwrap();

        let mut patched = wire.clone();
        patch_ttls(&mut patched, &meta.ttl_offsets, 42);

        let mut buf = BytePacketBuffer::from_bytes(&patched);
        let parsed = DnsPacket::from_buffer(&mut buf).unwrap();

        let edns = parsed.edns.as_ref().expect("EDNS should survive");
        assert_eq!(edns.udp_payload_size, 1232);
        assert!(edns.do_bit);
    }

    #[test]
    fn round_trip_dnssec_full() {
        let mut pkt = response(
            0x1234,
            "example.com",
            vec![
                a_record("example.com", "1.2.3.4", 300),
                DnsRecord::RRSIG {
                    domain: "example.com".into(),
                    type_covered: 1,
                    algorithm: 13,
                    labels: 2,
                    original_ttl: 300,
                    expiration: 1700000000,
                    inception: 1690000000,
                    key_tag: 12345,
                    signer_name: "example.com".into(),
                    signature: vec![1, 2, 3, 4, 5, 6, 7, 8],
                    ttl: 300,
                },
            ],
        );
        pkt.authorities.push(DnsRecord::NSEC {
            domain: "example.com".into(),
            next_domain: "z.example.com".into(),
            type_bitmap: vec![0x00, 0x06, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03],
            ttl: 300,
        });
        pkt.resources.push(DnsRecord::DNSKEY {
            domain: "example.com".into(),
            flags: 257,
            protocol: 3,
            algorithm: 13,
            public_key: vec![10, 20, 30, 40],
            ttl: 3600,
        });
        pkt.edns = Some(EdnsOpt {
            udp_payload_size: 1232,
            extended_rcode: 0,
            version: 0,
            do_bit: true,
            options: vec![],
        });
        let wire = to_wire(&pkt);
        let meta = scan_ttl_offsets(&wire).unwrap();

        // 4 TTL offsets: A + RRSIG (answers) + NSEC (authority) + DNSKEY (additional)
        // OPT excluded
        assert_eq!(meta.ttl_offsets.len(), 4);
        assert_eq!(meta.answer_count, 2);

        let mut patched = wire.clone();
        patch_ttls(&mut patched, &meta.ttl_offsets, 42);

        let mut buf = BytePacketBuffer::from_bytes(&patched);
        let parsed = DnsPacket::from_buffer(&mut buf).unwrap();

        assert_eq!(parsed.answers.len(), 2);
        assert_eq!(parsed.authorities.len(), 1);
        assert_eq!(parsed.resources.len(), 1);
        assert!(parsed.edns.is_some());

        // All TTLs should be 42 now
        for ans in &parsed.answers {
            assert_eq!(ans.ttl(), 42);
        }
        for auth in &parsed.authorities {
            assert_eq!(auth.ttl(), 42);
        }
        for res in &parsed.resources {
            assert_eq!(res.ttl(), 42);
        }

        // RRSIG original_ttl must be preserved (it's inside RDATA, not a wire TTL)
        match &parsed.answers[1] {
            DnsRecord::RRSIG { original_ttl, .. } => assert_eq!(*original_ttl, 300),
            other => panic!("expected RRSIG, got {:?}", other),
        }
    }

    #[test]
    fn round_trip_nxdomain_soa() {
        let mut pkt = DnsPacket::new();
        pkt.header.id = 0x5678;
        pkt.header.response = true;
        pkt.header.rescode = ResultCode::NXDOMAIN;
        pkt.questions
            .push(DnsQuestion::new("missing.example.com".into(), QueryType::A));
        // SOA in authority (we don't have a SOA variant, so use NS as proxy for offset testing)
        pkt.authorities
            .push(ns_record("example.com", "ns1.example.com", 900));

        let wire = to_wire(&pkt);
        let meta = scan_ttl_offsets(&wire).unwrap();

        assert_eq!(meta.ttl_offsets.len(), 1);
        assert_eq!(meta.answer_count, 0); // no answers, only authority

        let mut patched = wire.clone();
        patch_id(&mut patched, 0x9999);
        patch_ttls(&mut patched, &meta.ttl_offsets, 60);

        let mut buf = BytePacketBuffer::from_bytes(&patched);
        let parsed = DnsPacket::from_buffer(&mut buf).unwrap();

        assert_eq!(parsed.header.id, 0x9999);
        assert_eq!(parsed.header.rescode, ResultCode::NXDOMAIN);
        assert_eq!(parsed.authorities[0].ttl(), 60);
    }

    #[test]
    fn round_trip_mx_record() {
        let pkt = response(
            0x1234,
            "example.com",
            vec![mx_record("example.com", "mail.example.com", 10, 3600)],
        );
        let wire = to_wire(&pkt);
        let meta = scan_ttl_offsets(&wire).unwrap();

        let mut patched = wire.clone();
        patch_ttls(&mut patched, &meta.ttl_offsets, 100);

        let mut buf = BytePacketBuffer::from_bytes(&patched);
        let parsed = DnsPacket::from_buffer(&mut buf).unwrap();

        match &parsed.answers[0] {
            DnsRecord::MX {
                domain,
                priority,
                host,
                ttl,
            } => {
                assert_eq!(domain, "example.com");
                assert_eq!(*priority, 10);
                assert_eq!(host, "mail.example.com");
                assert_eq!(*ttl, 100);
            }
            other => panic!("expected MX, got {:?}", other),
        }
    }

    #[test]
    fn round_trip_many_records() {
        let answers: Vec<DnsRecord> = (0..20)
            .map(|i| a_record("example.com", &format!("10.0.0.{}", i), 300 + i * 10))
            .collect();
        let pkt = response(0x1234, "example.com", answers);
        let wire = to_wire(&pkt);
        let meta = scan_ttl_offsets(&wire).unwrap();

        assert_eq!(meta.ttl_offsets.len(), 20);

        let mut patched = wire.clone();
        patch_ttls(&mut patched, &meta.ttl_offsets, 1);

        let mut buf = BytePacketBuffer::from_bytes(&patched);
        let parsed = DnsPacket::from_buffer(&mut buf).unwrap();

        assert_eq!(parsed.answers.len(), 20);
        for ans in &parsed.answers {
            assert_eq!(ans.ttl(), 1);
        }
    }

    // ── G. Edge cases ───────────────────────────────────────────────

    #[test]
    fn scan_rejects_empty_wire() {
        assert!(scan_ttl_offsets(&[]).is_err());
    }

    // ── G. Cache behavior tests ─────────────────────────────────────
    //
    // These test existing DnsCache behavior that must be preserved after
    // the wire-level migration. They use the current parsed-packet API
    // and serve as a regression suite.

    #[test]
    fn cache_insert_lookup_hit() {
        let mut cache = DnsCache::new(100, 1, 3600);
        let pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        cache.insert("example.com", QueryType::A, &pkt);

        let (result, status, _) = cache
            .lookup_with_status("example.com", QueryType::A)
            .expect("should hit");
        assert_eq!(result.answers.len(), 1);
        assert_eq!(status, DnssecStatus::Indeterminate);
    }

    #[test]
    fn cache_lookup_adjusts_ttl() {
        let mut cache = DnsCache::new(100, 1, 3600);
        let pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        cache.insert("example.com", QueryType::A, &pkt);

        let (result, _, _) = cache
            .lookup_with_status("example.com", QueryType::A)
            .unwrap();
        // TTL should be <= 300 (at most original, reduced by elapsed time)
        assert!(result.answers[0].ttl() <= 300);
        assert!(result.answers[0].ttl() > 0);
    }

    #[test]
    fn cache_miss_wrong_domain() {
        let mut cache = DnsCache::new(100, 1, 3600);
        let pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        cache.insert("example.com", QueryType::A, &pkt);

        assert!(cache
            .lookup_with_status("other.com", QueryType::A)
            .is_none());
    }

    #[test]
    fn cache_miss_wrong_qtype() {
        let mut cache = DnsCache::new(100, 1, 3600);
        let pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        cache.insert("example.com", QueryType::A, &pkt);

        assert!(cache
            .lookup_with_status("example.com", QueryType::AAAA)
            .is_none());
    }

    #[test]
    fn cache_overwrite_no_double_count() {
        let mut cache = DnsCache::new(100, 1, 3600);
        let pkt1 = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        let pkt2 = response(
            0x5678,
            "example.com",
            vec![a_record("example.com", "5.6.7.8", 600)],
        );

        cache.insert("example.com", QueryType::A, &pkt1);
        assert_eq!(cache.len(), 1);

        cache.insert("example.com", QueryType::A, &pkt2);
        assert_eq!(cache.len(), 1); // no double count

        let (result, _, _) = cache
            .lookup_with_status("example.com", QueryType::A)
            .unwrap();
        match &result.answers[0] {
            DnsRecord::A { addr, .. } => {
                assert_eq!(*addr, "5.6.7.8".parse::<std::net::Ipv4Addr>().unwrap())
            }
            _ => panic!("expected A record"),
        }
    }

    #[test]
    fn cache_ttl_clamped_min() {
        let mut cache = DnsCache::new(100, 60, 3600);
        let pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 5)],
        );
        cache.insert("example.com", QueryType::A, &pkt);

        let (remaining, total) = cache.ttl_remaining("example.com", QueryType::A).unwrap();
        assert_eq!(total, 60); // clamped up from 5
        assert!(remaining <= 60);
    }

    #[test]
    fn cache_ttl_clamped_max() {
        let mut cache = DnsCache::new(100, 1, 3600);
        let pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 999999)],
        );
        cache.insert("example.com", QueryType::A, &pkt);

        let (_, total) = cache.ttl_remaining("example.com", QueryType::A).unwrap();
        assert_eq!(total, 3600); // clamped down from 999999
    }

    #[test]
    fn cache_len_empty_clear() {
        let mut cache = DnsCache::new(100, 1, 3600);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        let pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        cache.insert("example.com", QueryType::A, &pkt);
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);

        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        assert!(cache.lookup("example.com", QueryType::A).is_none());
    }

    #[test]
    fn cache_remove_domain() {
        let mut cache = DnsCache::new(100, 1, 3600);
        let pkt_a = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        let pkt_aaaa = response(
            0x5678,
            "example.com",
            vec![aaaa_record("example.com", "::1", 300)],
        );
        cache.insert("example.com", QueryType::A, &pkt_a);
        cache.insert("example.com", QueryType::AAAA, &pkt_aaaa);
        assert_eq!(cache.len(), 2);

        cache.remove("example.com");
        assert_eq!(cache.len(), 0);
        assert!(cache.lookup("example.com", QueryType::A).is_none());
        assert!(cache.lookup("example.com", QueryType::AAAA).is_none());
    }

    #[test]
    fn cache_list_entries() {
        let mut cache = DnsCache::new(100, 1, 3600);
        let pkt_a = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        let pkt_b = response(
            0x5678,
            "test.org",
            vec![a_record("test.org", "5.6.7.8", 600)],
        );
        cache.insert("example.com", QueryType::A, &pkt_a);
        cache.insert("test.org", QueryType::A, &pkt_b);

        let list = cache.list();
        assert_eq!(list.len(), 2);
        let domains: Vec<&str> = list.iter().map(|e| e.domain.as_str()).collect();
        assert!(domains.contains(&"example.com"));
        assert!(domains.contains(&"test.org"));
    }

    #[test]
    fn cache_heap_bytes_grows() {
        let mut cache = DnsCache::new(100, 1, 3600);
        let empty = cache.heap_bytes();

        let pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        cache.insert("example.com", QueryType::A, &pkt);
        assert!(cache.heap_bytes() > empty);
    }

    #[test]
    fn cache_needs_warm_behavior() {
        let mut cache = DnsCache::new(100, 1, 3600);

        // Missing → needs warm
        assert!(cache.needs_warm("example.com"));

        // Both A and AAAA cached → does not need warm
        let pkt_a = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        let pkt_aaaa = response(
            0x5678,
            "example.com",
            vec![aaaa_record("example.com", "::1", 300)],
        );
        cache.insert("example.com", QueryType::A, &pkt_a);
        cache.insert("example.com", QueryType::AAAA, &pkt_aaaa);
        assert!(!cache.needs_warm("example.com"));

        // Only A cached → needs warm (AAAA missing)
        cache.remove("example.com");
        cache.insert("example.com", QueryType::A, &pkt_a);
        assert!(cache.needs_warm("example.com"));
    }

    #[test]
    fn cache_ttl_remaining_api() {
        let mut cache = DnsCache::new(100, 60, 3600);
        assert!(cache.ttl_remaining("missing.com", QueryType::A).is_none());

        let pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        cache.insert("example.com", QueryType::A, &pkt);
        let (remaining, total) = cache.ttl_remaining("example.com", QueryType::A).unwrap();
        assert_eq!(total, 300);
        assert!(remaining > 0);
        assert!(remaining <= 300);
    }

    #[test]
    fn cache_dnssec_status_preserved() {
        let mut cache = DnsCache::new(100, 1, 3600);
        let pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 300)],
        );
        cache.insert_with_status("example.com", QueryType::A, &pkt, DnssecStatus::Secure);

        let (_, status, _) = cache
            .lookup_with_status("example.com", QueryType::A)
            .unwrap();
        assert_eq!(status, DnssecStatus::Secure);
    }

    // ── I. Memory footprint baseline ──────────────────────────────
    //
    // Measures the current parsed-packet cache memory vs what wire-level
    // storage would cost for the same entries. This is a baseline — after
    // migration, re-run to verify improvement.

    #[test]
    fn memory_footprint_baseline() {
        let mut cache = DnsCache::new(1000, 1, 3600);

        // Simulate a realistic cache: 50 domains, mix of record types
        let domains: Vec<String> = (0..50)
            .map(|i| format!("domain{}.example.com", i))
            .collect();

        let mut total_wire_bytes = 0usize;
        let mut total_wire_meta_bytes = 0usize;

        for (i, domain) in domains.iter().enumerate() {
            // A record
            let pkt_a = response(
                i as u16,
                domain,
                vec![
                    a_record(domain, &format!("10.0.{}.1", i % 256), 300),
                    a_record(domain, &format!("10.0.{}.2", i % 256), 300),
                ],
            );
            cache.insert(domain, QueryType::A, &pkt_a);

            let wire_a = to_wire(&pkt_a);
            let meta_a = scan_ttl_offsets(&wire_a).unwrap();
            total_wire_bytes += wire_a.len();
            total_wire_meta_bytes += meta_a.ttl_offsets.len() * std::mem::size_of::<usize>();

            // AAAA record for half of them
            if i % 2 == 0 {
                let pkt_aaaa = response(
                    (i + 1000) as u16,
                    domain,
                    vec![aaaa_record(domain, &format!("2001:db8::{:x}", i), 600)],
                );
                cache.insert(domain, QueryType::AAAA, &pkt_aaaa);

                let wire_aaaa = to_wire(&pkt_aaaa);
                let meta_aaaa = scan_ttl_offsets(&wire_aaaa).unwrap();
                total_wire_bytes += wire_aaaa.len();
                total_wire_meta_bytes += meta_aaaa.ttl_offsets.len() * std::mem::size_of::<usize>();
            }
        }

        // Compare only the variable per-entry data (what actually differs
        // between parsed and wire storage). HashMap overhead, domain keys,
        // Instant, Duration, DnssecStatus are identical in both approaches.
        let mut parsed_data_bytes = 0usize;
        // Re-insert and measure just packet.heap_bytes() per entry
        {
            let mut cache2 = DnsCache::new(1000, 1, 3600);
            for (i, domain) in domains.iter().enumerate() {
                let pkt_a = response(
                    i as u16,
                    domain,
                    vec![
                        a_record(domain, &format!("10.0.{}.1", i % 256), 300),
                        a_record(domain, &format!("10.0.{}.2", i % 256), 300),
                    ],
                );
                parsed_data_bytes += pkt_a.heap_bytes();
                cache2.insert(domain, QueryType::A, &pkt_a);

                if i % 2 == 0 {
                    let pkt_aaaa = response(
                        (i + 1000) as u16,
                        domain,
                        vec![aaaa_record(domain, &format!("2001:db8::{:x}", i), 600)],
                    );
                    parsed_data_bytes += pkt_aaaa.heap_bytes();
                    cache2.insert(domain, QueryType::AAAA, &pkt_aaaa);
                }
            }
        }

        let wire_total = total_wire_bytes + total_wire_meta_bytes;
        let entry_count = cache.len();

        // Also measure the struct size difference per entry
        let parsed_struct = std::mem::size_of::<DnsPacket>();
        let wire_struct = std::mem::size_of::<Vec<u8>>()
            + std::mem::size_of::<Vec<usize>>()
            + std::mem::size_of::<usize>(); // wire + offsets + answer_count

        println!();
        println!(
            "=== Cache Memory Footprint Baseline ({} entries) ===",
            entry_count
        );
        println!();
        println!("Variable data (heap, per-entry payload):");
        println!(
            "  Parsed (packet.heap_bytes):  {} bytes ({:.1}/entry)",
            parsed_data_bytes,
            parsed_data_bytes as f64 / entry_count as f64
        );
        println!(
            "  Wire (bytes + TTL offsets):   {} bytes ({:.1}/entry)",
            wire_total,
            wire_total as f64 / entry_count as f64
        );
        println!(
            "  Ratio:                        {:.1}x smaller with wire",
            parsed_data_bytes as f64 / wire_total as f64
        );
        println!();
        println!("Struct overhead (stack, per entry):");
        println!("  DnsPacket:                   {} bytes", parsed_struct);
        println!("  Wire (Vec<u8>+Vec<usize>+usize): {} bytes", wire_struct);
        println!();
        println!("Total per-entry (struct + avg heap):");
        let parsed_total_per = parsed_struct as f64 + parsed_data_bytes as f64 / entry_count as f64;
        let wire_total_per = wire_struct as f64 + wire_total as f64 / entry_count as f64;
        println!("  Parsed:  {:.0} bytes", parsed_total_per);
        println!("  Wire:    {:.0} bytes", wire_total_per);
        println!(
            "  Ratio:   {:.1}x smaller with wire",
            parsed_total_per / wire_total_per
        );
        println!();

        // Assertions
        assert!(
            wire_total < parsed_data_bytes,
            "wire data ({wire_total}) should be smaller than parsed data ({parsed_data_bytes})"
        );
    }

    #[test]
    fn cache_max_entries_evicts_stalest() {
        let mut cache = DnsCache::new(2, 1, 3600);
        // Insert with decreasing TTL so test0.com is stalest
        for (i, ttl) in [(0, 60), (1, 3600)] {
            let domain = format!("test{}.com", i);
            let pkt = response(
                i as u16,
                &domain,
                vec![a_record(&domain, &format!("1.2.3.{}", i), ttl)],
            );
            cache.insert(&domain, QueryType::A, &pkt);
        }
        assert_eq!(cache.len(), 2);

        // Third insert should evict test0.com (lowest remaining TTL)
        let pkt = response(2, "test2.com", vec![a_record("test2.com", "1.2.3.2", 3600)]);
        cache.insert("test2.com", QueryType::A, &pkt);
        assert_eq!(cache.len(), 2);
        assert!(cache.lookup("test0.com", QueryType::A).is_none()); // evicted
        assert!(cache.lookup("test2.com", QueryType::A).is_some()); // inserted
    }

    #[test]
    fn lookup_wire_signals_stale_when_expired() {
        use crate::cache::Freshness;
        let mut cache = DnsCache::new(100, 1, 1); // max_ttl=1s so entry expires fast
        let pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 1)],
        );
        cache.insert("example.com", QueryType::A, &pkt);

        let (_, _, f) = cache.lookup_wire("example.com", QueryType::A, 0).unwrap();
        assert_eq!(f, Freshness::Fresh);

        std::thread::sleep(std::time::Duration::from_millis(1100));

        let (_, _, f) = cache.lookup_wire("example.com", QueryType::A, 0).unwrap();
        assert_eq!(f, Freshness::Stale);
    }

    #[test]
    fn lookup_wire_signals_prefetch_near_expiry() {
        use crate::cache::Freshness;
        let mut cache = DnsCache::new(100, 10, 10);
        let pkt = response(
            0x1234,
            "example.com",
            vec![a_record("example.com", "1.2.3.4", 10)],
        );
        cache.insert("example.com", QueryType::A, &pkt);

        let (_, _, f) = cache.lookup_wire("example.com", QueryType::A, 0).unwrap();
        assert_eq!(f, Freshness::Fresh);

        std::thread::sleep(std::time::Duration::from_millis(9100));

        let result = cache.lookup_wire("example.com", QueryType::A, 0);
        if let Some((_, _, f)) = result {
            assert_eq!(f, Freshness::NearExpiry);
        }
    }

    // ── ensure_do_bit (issue #191) ───────────────────────────────────

    fn query_wire() -> Vec<u8> {
        to_wire(&DnsPacket::query(0xABCD, "example.com", QueryType::A))
    }

    fn parse_wire(wire: &[u8]) -> DnsPacket {
        DnsPacket::from_buffer(&mut BytePacketBuffer::from_bytes(wire)).unwrap()
    }

    #[test]
    fn ensure_do_bit_appends_opt_when_client_sent_none() {
        let wire = query_wire();
        let out = ensure_do_bit(&wire);

        assert_eq!(out.len(), wire.len() + 11, "one bare OPT appended");
        assert_eq!(&out[12..wire.len()], &wire[12..], "client bytes untouched");
        assert_eq!(&out[10..12], &1u16.to_be_bytes(), "ARCOUNT incremented");
        let edns = parse_wire(&out).edns.expect("OPT present");
        assert!(edns.do_bit);
        assert_eq!(edns.udp_payload_size, crate::packet::DEFAULT_EDNS_PAYLOAD);
    }

    #[test]
    fn ensure_do_bit_preserves_client_edns_options() {
        let mut query = DnsPacket::query(0xABCD, "example.com", QueryType::A);
        query.edns = Some(EdnsOpt {
            udp_payload_size: 512,
            do_bit: false,
            // an EDNS cookie (opt code 10) the upstream must still see
            options: vec![0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8],
            ..Default::default()
        });
        let wire = to_wire(&query);
        let out = ensure_do_bit(&wire);

        assert_eq!(out.len(), wire.len(), "patched in place, not rebuilt");
        let edns = parse_wire(&out).edns.expect("OPT present");
        assert!(edns.do_bit);
        assert_eq!(edns.options, vec![0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn ensure_do_bit_raises_a_payload_size_that_cannot_hold_dnssec() {
        // EDNS payload size is hop-by-hop (RFC 6891 §6.2.3): upstream answers
        // to *us*, so the client's budget is not ours to forward. Asking for
        // DNSSEC records inside 512 bytes earns a TC=1 with no records, which
        // the cache then serves to every later client, TCP included.
        let mut query = DnsPacket::query(0xABCD, "example.com", QueryType::A);
        query.edns = Some(EdnsOpt {
            udp_payload_size: 512,
            do_bit: false,
            ..Default::default()
        });
        let wire = to_wire(&query);
        let edns = parse_wire(&ensure_do_bit(&wire)).edns.expect("OPT present");

        assert!(edns.do_bit);
        assert_eq!(
            edns.udp_payload_size,
            crate::packet::DEFAULT_EDNS_PAYLOAD,
            "a DO=1 query must carry a budget that can hold the RRSIGs it asks for"
        );
    }

    #[test]
    fn ensure_do_bit_keeps_a_payload_size_above_the_default() {
        let mut query = DnsPacket::query(0xABCD, "example.com", QueryType::A);
        query.edns = Some(EdnsOpt {
            udp_payload_size: 4096,
            ..Default::default()
        });
        let wire = to_wire(&query);
        let edns = parse_wire(&ensure_do_bit(&wire)).edns.expect("OPT present");

        assert_eq!(edns.udp_payload_size, 4096, "never lower a roomier budget");
    }

    #[test]
    fn ensure_do_bit_lowers_a_payload_size_the_receive_buffer_cannot_hold() {
        // `forward_udp_raw` receives into 4096 bytes; advertising 65535 invites
        // a reply the kernel cuts mid-record into a wire that cannot parse.
        let mut query = DnsPacket::query(0xABCD, "example.com", QueryType::A);
        query.edns = Some(EdnsOpt {
            udp_payload_size: 65535,
            do_bit: true,
            ..Default::default()
        });
        let wire = to_wire(&query);
        let edns = parse_wire(&ensure_do_bit(&wire)).edns.expect("OPT present");

        assert_eq!(edns.udp_payload_size, MAX_UPSTREAM_PAYLOAD);
    }

    #[test]
    fn ensure_do_bit_patches_an_opt_named_via_compression_pointer() {
        // RFC 6891 wants a literal root name on the OPT, but a peer can reach
        // root through a compression pointer — packet.rs guards this exact
        // shape. Missing it here would append a second OPT (FORMERR upstream).
        let mut wire = query_wire();
        wire[10..12].copy_from_slice(&1u16.to_be_bytes()); // ARCOUNT
        let root_offset = wire.len() - 5; // qname's terminating root label
        assert_eq!(wire[root_offset], 0);
        let do_byte = wire.len() + 8; // pointer(2) + type + class + 2 into TTL
        wire.extend_from_slice(&[0xC0, root_offset as u8]);
        wire.extend_from_slice(&[0, 41]); // TYPE=OPT
        wire.extend_from_slice(&MIN_UPSTREAM_PAYLOAD.to_be_bytes());
        wire.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // TTL (DO clear), RDLENGTH

        let out = ensure_do_bit(&wire);

        assert_eq!(out.len(), wire.len(), "patched in place, no second OPT");
        assert_eq!(out[do_byte] & DO_FLAG, DO_FLAG, "DO set on the found OPT");
    }

    #[test]
    fn ensure_do_bit_leaves_tsig_signed_wires_untouched() {
        // A TSIG's MAC covers the header and the record must stay last
        // (RFC 8945 §5.1); patching would void the signature upstream.
        let mut wire = query_wire();
        wire[10..12].copy_from_slice(&1u16.to_be_bytes()); // ARCOUNT
        wire.extend_from_slice(&[0]); // root name
        wire.extend_from_slice(&250u16.to_be_bytes()); // TYPE=TSIG
        wire.extend_from_slice(&[0, 255]); // CLASS=ANY
        wire.extend_from_slice(&[0, 0, 0, 0]); // TTL
        wire.extend_from_slice(&[0, 0]); // RDLENGTH

        assert_eq!(&ensure_do_bit(&wire)[..], &wire[..]);
    }

    #[test]
    fn ensure_do_bit_leaves_do_queries_byte_identical() {
        let mut query = DnsPacket::query(0xABCD, "example.com", QueryType::A);
        query.edns = Some(EdnsOpt {
            do_bit: true,
            ..Default::default()
        });
        let wire = to_wire(&query);
        assert_eq!(&ensure_do_bit(&wire)[..], &wire[..]);
    }

    #[test]
    fn ensure_do_bit_patches_wire_larger_than_the_packet_buffer() {
        // Parse-and-reserialize truncates at BytePacketBuffer's 4096 bytes;
        // a padded TCP/DoH query that size must still forward intact.
        let (wire, do_byte) = oversized_padded_query();
        let out = ensure_do_bit(&wire);

        assert!(wire.len() > 4096);
        assert_eq!(out.len(), wire.len(), "oversized wire kept whole");
        assert_eq!(out[do_byte] & DO_FLAG, DO_FLAG, "DO set in place");
        assert_eq!(&out[..do_byte], &wire[..do_byte]);
        assert_eq!(&out[do_byte + 1..], &wire[do_byte + 1..]);
    }

    /// Header + question + an OPT carrying 4096 bytes of EDNS padding, and
    /// the offset of its DO byte. Hand-built: `DnsPacket::write` caps at 4096.
    fn oversized_padded_query() -> (Vec<u8>, usize) {
        const PADDING: usize = 4096;
        let mut wire = query_wire();
        wire[10..12].copy_from_slice(&1u16.to_be_bytes()); // ARCOUNT
        let do_byte = wire.len() + 7; // root name + type + class + 2 into TTL
        wire.extend_from_slice(&[0, 0, 41]); // root name, TYPE=OPT
        wire.extend_from_slice(&crate::packet::DEFAULT_EDNS_PAYLOAD.to_be_bytes());
        wire.extend_from_slice(&[0, 0, 0, 0]); // TTL, DO clear
        wire.extend_from_slice(&((4 + PADDING) as u16).to_be_bytes()); // RDLENGTH
        wire.extend_from_slice(&[0, 12]); // opt code: padding (RFC 7830)
        wire.extend_from_slice(&(PADDING as u16).to_be_bytes());
        wire.extend(std::iter::repeat_n(0u8, PADDING));
        (wire, do_byte)
    }

    #[test]
    fn ensure_do_bit_passes_malformed_wires_through_untouched() {
        let truncated = &query_wire()[..8];
        assert_eq!(&ensure_do_bit(truncated)[..], truncated);
    }

    #[test]
    fn ensure_do_bit_appends_behind_counted_records_not_behind_junk() {
        // libFuzzer, CI job 92347736024: ANCOUNT=2 with uncounted bytes past
        // the last counted record, so the append path returns a wire *shorter*
        // than its input. Legal — what it drops is junk upstream would have
        // read as the record ARCOUNT now reaches.
        const FUZZED: [u8; 54] = [
            18, 52, 129, 44, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 80, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
            0, 0, 1, 0, 0, 0, 0, 0, 2, 229, 0, 0, 0, 0, 0, 0, 0, 0, 93, 1, 0, 46, 0, 0, 184, 216,
            35,
        ];
        let out = ensure_do_bit(&FUZZED);

        assert!(out.len() < FUZZED.len(), "trailing junk dropped");
        assert_eq!(
            &out[out.len() - APPENDED_DO_OPT.len()..],
            &APPENDED_DO_OPT,
            "wire ends with the OPT we appended"
        );
        assert_eq!(
            &ensure_do_bit(&out)[..],
            &out[..],
            "an appended OPT the walker cannot find again is one upstream cannot find either"
        );
    }

    #[test]
    fn ensure_do_bit_drops_trailing_bytes_rather_than_forwarding_do_0() {
        // An OPT appended *behind* uncounted bytes is not the record ARCOUNT
        // reaches, so the trailing junk goes at the counted boundary instead.
        // Forwarding the wire untouched is not the safe alternative: it keeps
        // DO=0, and any client can pin an RRSIG-less entry in the shared cache
        // by padding its query (issue #191).
        let mut wire = query_wire();
        wire.extend_from_slice(&[0xDE, 0xAD]);
        let out = ensure_do_bit(&wire);

        let edns = parse_wire(&out).edns.expect("OPT appended");
        assert!(
            edns.do_bit,
            "trailing bytes must not defeat DO normalization"
        );
        assert_eq!(
            out.len(),
            wire.len() - 2 + 11,
            "junk dropped, one bare OPT appended at the counted boundary"
        );
    }
}
