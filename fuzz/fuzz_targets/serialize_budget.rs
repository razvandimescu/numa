#![no_main]
//! `serialize_with_fallback` is the last gate before a reply leaves on the
//! wire, and its response side is adversarial: forward mode caches whatever an
//! upstream sent, up to 3-4KB once DO=1 rides every query (#347). For UDP it
//! must honor the client's advertised payload budget with a 512 floor
//! (RFC 6891 §6.2.3 / RFC 1035 §4.2.1) — an oversized answer becomes TC=1 with
//! empty sections, never an oversized datagram, which is the ~85x reflection
//! surface #348 closed.
//!
//! Input layout: [ctl byte][2-byte advertised size BE][response wire].
use libfuzzer_sys::fuzz_target;
use numa::buffer::BytePacketBuffer;
use numa::ctx::serialize_with_fallback;
use numa::packet::{DnsPacket, EdnsOpt};
use numa::question::QueryType;
use numa::stats::Transport;

fuzz_target!(|data: &[u8]| {
    let [ctl, size_hi, size_lo, wire @ ..] = data else {
        return;
    };
    let mut resp_buf = BytePacketBuffer::from_bytes(wire);
    let Ok(mut response) = DnsPacket::from_buffer(&mut resp_buf) else {
        return;
    };
    // A response that already carries TC=1 passes through as-is; the TC-shape
    // asserts below only hold for truncations we performed.
    let was_truncated = response.header.truncated_message;

    let has_edns = ctl & 1 != 0;
    let advertised = u16::from_be_bytes([*size_hi, *size_lo]);
    let transport = if ctl & 2 != 0 {
        Transport::Tcp
    } else {
        Transport::Udp
    };
    let mut query = DnsPacket::query(0x1234, "example.com", QueryType::A);
    if has_edns {
        query.edns = Some(EdnsOpt {
            udp_payload_size: advertised,
            do_bit: ctl & 4 != 0,
            ..Default::default()
        });
    }

    let buf = serialize_with_fallback(
        &mut response,
        &query,
        "example.com",
        ctl & 8 != 0,
        transport,
    )
    .expect("the fallback path must always produce a reply");
    let out = buf.filled();

    if matches!(transport, Transport::Udp) {
        let budget = if has_edns {
            usize::from(advertised).max(512)
        } else {
            512
        };
        assert!(
            out.len() <= budget,
            "UDP reply of {} bytes exceeds the client's budget of {}",
            out.len(),
            budget
        );
    }

    let mut reparse = BytePacketBuffer::from_bytes(out);
    let parsed =
        DnsPacket::from_buffer(&mut reparse).expect("numa emitted a reply it cannot parse back");
    if parsed.header.truncated_message && !was_truncated {
        assert!(
            parsed.answers.is_empty() && parsed.authorities.is_empty(),
            "our TC=1 reply must carry empty sections"
        );
        assert_eq!(
            parsed.edns.is_some(),
            has_edns,
            "our TC=1 reply must mirror the client's OPT exactly when present"
        );
    }
});
