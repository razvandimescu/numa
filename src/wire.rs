//! Wire-level DNS utilities: question extraction, TTL offset scanning, and patching.
//!
//! These operate directly on raw DNS wire bytes without full packet parsing,
//! enabling zero-copy forwarding and wire-level caching.

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

/// Scan a DNS response's wire bytes and return metadata about TTL field locations.
///
/// Walks the header, skips the question section, then for each resource record in
/// answer, authority, and additional sections, records the byte offset of the TTL
/// field. EDNS OPT records (type 41 with root name) are excluded.
pub fn scan_ttl_offsets(wire: &[u8]) -> Result<WireMeta> {
    if wire.len() < 12 {
        return Err("wire too short for DNS header".into());
    }

    let qdcount = u16::from_be_bytes([wire[4], wire[5]]) as usize;
    let ancount = u16::from_be_bytes([wire[6], wire[7]]) as usize;
    let nscount = u16::from_be_bytes([wire[8], wire[9]]) as usize;
    let arcount = u16::from_be_bytes([wire[10], wire[11]]) as usize;

    let mut pos = 12;

    // Skip question section
    for _ in 0..qdcount {
        skip_wire_name(wire, &mut pos)?;
        if pos + 4 > wire.len() {
            return Err("wire truncated in question section".into());
        }
        pos += 4; // QTYPE(2) + QCLASS(2)
    }

    let mut ttl_offsets = Vec::new();

    // Process answer + authority + additional sections
    let section_counts = [ancount, nscount, arcount];
    let mut answer_offset_count = 0;

    for (section_idx, &count) in section_counts.iter().enumerate() {
        for _ in 0..count {
            // Check if this is an OPT record: root name (0x00) + type 41
            let is_opt = pos < wire.len()
                && wire[pos] == 0x00
                && pos + 3 <= wire.len()
                && u16::from_be_bytes([wire[pos + 1], wire[pos + 2]]) == 41;

            // Skip name
            skip_wire_name(wire, &mut pos)?;

            if pos + 10 > wire.len() {
                return Err("wire truncated in resource record".into());
            }

            // TYPE(2) + CLASS(2) = 4 bytes before TTL
            let ttl_offset = pos + 4;

            if !is_opt {
                ttl_offsets.push(ttl_offset);
                if section_idx == 0 {
                    answer_offset_count += 1;
                }
            }

            // Skip TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes
            let rdlength = u16::from_be_bytes([wire[pos + 8], wire[pos + 9]]) as usize;
            pos += 10 + rdlength;

            if pos > wire.len() {
                return Err("wire truncated in resource record RDATA".into());
            }
        }
    }

    Ok(WireMeta {
        ttl_offsets,
        answer_count: answer_offset_count,
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
}
