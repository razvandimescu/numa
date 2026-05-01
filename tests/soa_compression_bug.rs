//! Regression test for issue #128: SOA with compressed MNAME/RNAME must
//! survive Numa's round-trip — compression pointers reference the upstream
//! packet's byte layout, so we have to decompress on read and re-compress
//! on write.

use numa::buffer::BytePacketBuffer;
use numa::packet::DnsPacket;

const COMPRESSION_FLAG: u16 = 0xC000;

fn upstream_packet() -> Vec<u8> {
    let mut p = Vec::<u8>::new();

    p.extend_from_slice(&[
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00,
    ]);

    assert_eq!(p.len(), 12);
    write_name(&mut p, &["odin", "adobe", "com"]);
    p.extend_from_slice(&[0x00, 0x41, 0x00, 0x01]);

    p.extend_from_slice(&[0xC0, 0x0C]);
    p.extend_from_slice(&[0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x23, 0x7F]);
    let rdlen_pos_1 = p.len();
    p.extend_from_slice(&[0x00, 0x00]);
    let cname1_start = p.len();
    write_name(&mut p, &["cdn", "adobeaemcloud", "com"]);
    let rdlen_1 = (p.len() - cname1_start) as u16;
    p[rdlen_pos_1..rdlen_pos_1 + 2].copy_from_slice(&rdlen_1.to_be_bytes());

    p.extend_from_slice(&(COMPRESSION_FLAG | cname1_start as u16).to_be_bytes());
    p.extend_from_slice(&[0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x23, 0x7F]);
    let rdlen_pos_2 = p.len();
    p.extend_from_slice(&[0x00, 0x00]);
    let cname2_start = p.len();
    p.push(9);
    p.extend_from_slice(b"adobe-aem");
    let map_label_off = p.len();
    p.push(3);
    p.extend_from_slice(b"map");
    let fastly_label_off = p.len();
    p.push(6);
    p.extend_from_slice(b"fastly");
    p.push(3);
    p.extend_from_slice(b"net");
    p.push(0);
    let rdlen_2 = (p.len() - cname2_start) as u16;
    p[rdlen_pos_2..rdlen_pos_2 + 2].copy_from_slice(&rdlen_2.to_be_bytes());

    p.extend_from_slice(&(COMPRESSION_FLAG | fastly_label_off as u16).to_be_bytes());
    p.extend_from_slice(&[0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x07, 0x08]);
    let rdlen_pos_soa = p.len();
    p.extend_from_slice(&[0x00, 0x00]);
    let soa_rdata_start = p.len();
    p.extend_from_slice(&(COMPRESSION_FLAG | map_label_off as u16).to_be_bytes());
    p.extend_from_slice(&(COMPRESSION_FLAG | fastly_label_off as u16).to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes());
    p.extend_from_slice(&7200u32.to_be_bytes());
    p.extend_from_slice(&3600u32.to_be_bytes());
    p.extend_from_slice(&1209600u32.to_be_bytes());
    p.extend_from_slice(&1800u32.to_be_bytes());
    let rdlen_soa = (p.len() - soa_rdata_start) as u16;
    p[rdlen_pos_soa..rdlen_pos_soa + 2].copy_from_slice(&rdlen_soa.to_be_bytes());

    p
}

fn write_name(p: &mut Vec<u8>, labels: &[&str]) {
    for l in labels {
        p.push(l.len() as u8);
        p.extend_from_slice(l.as_bytes());
    }
    p.push(0);
}

#[test]
fn compressed_soa_survives_numa_round_trip() {
    let upstream = upstream_packet();

    let hickory_in = hickory_proto::op::Message::from_vec(&upstream)
        .expect("hand-crafted upstream must be valid");
    let hickory_proto::rr::RData::SOA(soa_in_rd) = hickory_in.authorities[0].data.clone() else {
        panic!("expected SOA rdata");
    };
    assert_eq!(soa_in_rd.mname.to_string(), "map.fastly.net.");
    assert_eq!(soa_in_rd.rname.to_string(), "fastly.net.");

    let mut in_buf = BytePacketBuffer::from_bytes(&upstream);
    let pkt = DnsPacket::from_buffer(&mut in_buf).expect("numa parses upstream");
    assert_eq!(pkt.answers.len(), 2);
    assert_eq!(pkt.authorities.len(), 1);

    let mut out_buf = BytePacketBuffer::new();
    pkt.write(&mut out_buf).expect("numa writes");
    let out = out_buf.filled().to_vec();

    let hickory_out =
        hickory_proto::op::Message::from_vec(&out).expect("numa re-emission must parse strictly");

    let hickory_proto::rr::RData::SOA(soa_out_rd) = hickory_out.authorities[0].data.clone() else {
        panic!("expected SOA rdata on output");
    };

    assert_eq!(soa_out_rd.mname.to_string(), "map.fastly.net.");
    assert_eq!(soa_out_rd.rname.to_string(), "fastly.net.");
    assert_eq!(soa_out_rd.serial, 1);
    assert_eq!(soa_out_rd.refresh, 7200);
    assert_eq!(soa_out_rd.retry, 3600);
    assert_eq!(soa_out_rd.expire, 1209600);
    assert_eq!(soa_out_rd.minimum, 1800);
}
