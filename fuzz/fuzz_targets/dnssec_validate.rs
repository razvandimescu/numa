#![no_main]
//! The DNSSEC validator runs over fully attacker-controlled records: every
//! DNSKEY, DS, RRSIG, and NSEC bitmap in a signed response comes off the wire.
//! `validate_response` itself does network I/O (it fetches signer DNSKEYs), so
//! this target exercises the pure, CPU-bound primitives it calls — canonical
//! wire reconstruction, key-tag, DS digest, signature verification, and NSEC
//! bitmap walking. These are the KeyTrap-class hot paths: a panic, overflow, or
//! hang here is a remote DoS reachable through any signed name.
use libfuzzer_sys::fuzz_target;
use numa::buffer::BytePacketBuffer;
use numa::dnssec::{
    build_signed_data, compute_key_tag, type_bitmap_contains, verify_ds, verify_signature,
};
use numa::packet::DnsPacket;
use numa::record::DnsRecord;

// Cap combinatorial work so a legitimately large signed packet doesn't look
// like a hang to libfuzzer. The bug classes we care about reproduce well within
// these bounds.
const MAX_RECORDS: usize = 64;
const MAX_PAIRS: usize = 256;

fuzz_target!(|data: &[u8]| {
    let mut buf = BytePacketBuffer::from_bytes(data);
    let Ok(packet) = DnsPacket::from_buffer(&mut buf) else {
        return;
    };

    let records: Vec<&DnsRecord> = packet
        .answers
        .iter()
        .chain(packet.authorities.iter())
        .chain(packet.resources.iter())
        .take(MAX_RECORDS)
        .collect();

    for r in &records {
        match r {
            DnsRecord::DNSKEY {
                flags,
                protocol,
                algorithm,
                public_key,
                ..
            } => {
                let _ = compute_key_tag(*flags, *protocol, *algorithm, public_key);
            }
            DnsRecord::NSEC { type_bitmap, .. } | DnsRecord::NSEC3 { type_bitmap, .. } => {
                // Walk the bitmap for a few query types, including the boundary
                // ones, to exercise window/length arithmetic.
                for qtype in [0u16, 1, 46, 47, 50, 255, 65535] {
                    let _ = type_bitmap_contains(type_bitmap, qtype);
                }
            }
            _ => {}
        }
    }

    let dnskeys: Vec<&DnsRecord> = records
        .iter()
        .copied()
        .filter(|r| matches!(r, DnsRecord::DNSKEY { .. }))
        .collect();
    let dss: Vec<&DnsRecord> = records
        .iter()
        .copied()
        .filter(|r| matches!(r, DnsRecord::DS { .. }))
        .collect();
    let rrsigs: Vec<&DnsRecord> = records
        .iter()
        .copied()
        .filter(|r| matches!(r, DnsRecord::RRSIG { .. }))
        .collect();

    // DS digest matching: hashes the DNSKEY's canonical RDATA.
    let mut pairs = 0;
    for ds in &dss {
        for dk in &dnskeys {
            if pairs >= MAX_PAIRS {
                break;
            }
            pairs += 1;
            let _ = verify_ds(ds, dk, ds.domain());
        }
    }

    // Canonical signed-data reconstruction + raw signature verification. Pairing
    // every RRSIG against every record set is the path that walks attacker RDATA
    // back into wire form, then hands attacker key/sig material to the crypto.
    let signed = build_signed_data_safe(&rrsigs, &records);
    pairs = 0;
    for (rrsig, signed_data) in &signed {
        if let DnsRecord::RRSIG {
            algorithm,
            signature,
            ..
        } = rrsig
        {
            for dk in &dnskeys {
                if pairs >= MAX_PAIRS {
                    break;
                }
                pairs += 1;
                if let DnsRecord::DNSKEY { public_key, .. } = dk {
                    let _ = verify_signature(*algorithm, public_key, signed_data, signature);
                }
            }
        }
    }
});

fn build_signed_data_safe<'a>(
    rrsigs: &[&'a DnsRecord],
    records: &[&'a DnsRecord],
) -> Vec<(&'a DnsRecord, Vec<u8>)> {
    rrsigs
        .iter()
        .filter_map(|rrsig| {
            let DnsRecord::RRSIG { type_covered, .. } = rrsig else {
                return None;
            };
            let rrset: Vec<&DnsRecord> = records
                .iter()
                .copied()
                .filter(|r| r.query_type().to_num() == *type_covered)
                .take(MAX_RECORDS)
                .collect();
            if rrset.is_empty() {
                return None;
            }
            Some((*rrsig, build_signed_data(rrsig, &rrset)))
        })
        .collect()
}
