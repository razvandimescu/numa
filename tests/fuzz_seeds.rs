//! The fuzz seed corpus is only useful if it still parses. A parser change that
//! silently invalidates every seed degrades CI fuzzing to random-bytes coverage
//! with no visible failure, so assert the seeds stay live.
use numa::buffer::BytePacketBuffer;
use numa::packet::DnsPacket;
use numa::svcb::strip_private_hints;
use std::net::IpAddr;

fn seeds(target: &str) -> Vec<(String, Vec<u8>)> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/seeds");
    let mut out: Vec<_> = std::fs::read_dir(format!("{dir}/{target}"))
        .unwrap_or_else(|e| panic!("missing seed dir for {target}: {e}"))
        .map(|e| {
            let path = e.expect("readable dir entry").path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            (name, std::fs::read(&path).expect("readable seed"))
        })
        .collect();
    assert!(!out.is_empty(), "no seeds for {target}");
    out.sort();
    out
}

#[test]
fn packet_seeds_parse() {
    for target in ["packet_parse", "packet_roundtrip", "dnssec_validate"] {
        for (name, bytes) in seeds(target) {
            let mut buf = BytePacketBuffer::from_bytes(&bytes);
            DnsPacket::from_buffer(&mut buf)
                .unwrap_or_else(|e| panic!("{target}/{name} no longer parses: {e}"));
        }
    }
}

#[test]
fn packet_seeds_round_trip() {
    for (name, bytes) in seeds("packet_roundtrip") {
        let mut buf = BytePacketBuffer::from_bytes(&bytes);
        let packet = DnsPacket::from_buffer(&mut buf).expect("seed parses");

        let mut out = BytePacketBuffer::new();
        packet.write(&mut out).expect("seed re-serializes");
        let written = out.filled().to_vec();

        let mut reparse = BytePacketBuffer::from_bytes(&written);
        let reparsed = DnsPacket::from_buffer(&mut reparse)
            .unwrap_or_else(|e| panic!("{name} serialized to something unparseable: {e}"));

        let mut second = BytePacketBuffer::new();
        reparsed.write(&mut second).expect("re-serialize");
        assert_eq!(second.filled(), written, "{name} write is not idempotent");
    }
}

#[test]
fn svcb_seeds_reach_the_scrubber() {
    let is_private = |ip: IpAddr| match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    };
    let rewritten = seeds("svcb_strip")
        .iter()
        .filter(|(_, rdata)| strip_private_hints(rdata, is_private).is_some())
        .count();
    assert!(rewritten > 0, "no svcb seed exercises the rewrite path");
}
