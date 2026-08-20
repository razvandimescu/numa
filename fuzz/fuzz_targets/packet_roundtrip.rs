#![no_main]
//! A packet the parser accepts must survive a write→re-parse cycle. Catches
//! serializer bugs (bad compression pointers, length fields that disagree with
//! the parser) where numa would emit a reply that nothing — including numa —
//! can read back.
//!
//! The invariant is idempotence of the second write, not equality with the
//! fuzzer's input: parsing normalises (labels containing `.` re-split, header
//! counts are recomputed), so comparing against the input would fire on
//! lossless rewrites.
use libfuzzer_sys::fuzz_target;
use numa::buffer::BytePacketBuffer;
use numa::packet::DnsPacket;

fuzz_target!(|data: &[u8]| {
    let mut buf = BytePacketBuffer::from_bytes(data);
    let Ok(packet) = DnsPacket::from_buffer(&mut buf) else {
        return; // unparseable input is the parser's job, not the serializer's
    };

    let mut out = BytePacketBuffer::new();
    if packet.write(&mut out).is_err() {
        return; // legitimate: a packet can parse yet exceed the 4096-byte buffer
    }

    let written = out.filled().to_vec();
    let mut reparse = BytePacketBuffer::from_bytes(&written);
    let reparsed =
        DnsPacket::from_buffer(&mut reparse).expect("numa serialized a packet it cannot parse");

    let mut second = BytePacketBuffer::new();
    reparsed
        .write(&mut second)
        .expect("re-serializing a packet numa just serialized must not fail");

    assert_eq!(
        second.filled(),
        written.as_slice(),
        "write→parse→write is not idempotent"
    );
});
