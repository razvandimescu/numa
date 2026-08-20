#![no_main]
//! Parse arbitrary bytes as a DNS message. The wire parser is hand-rolled and
//! handles fully attacker-controlled input (every query, every upstream reply,
//! every ODoH-relay payload). Any panic, overflow, or hang here is a remote DoS.
use libfuzzer_sys::fuzz_target;
use numa::buffer::BytePacketBuffer;
use numa::packet::DnsPacket;

fuzz_target!(|data: &[u8]| {
    let mut buf = BytePacketBuffer::from_bytes(data);
    let _ = DnsPacket::from_buffer(&mut buf);
});
