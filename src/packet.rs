use crate::buffer::BytePacketBuffer;
use crate::header::DnsHeader;
use crate::question::{DnsQuestion, QueryType};
use crate::record::DnsRecord;
use crate::Result;

/// Recommended EDNS0 UDP payload size (DNS Flag Day 2020) — avoids IP fragmentation.
pub const DEFAULT_EDNS_PAYLOAD: u16 = 1232;

/// EDNS0 OPT pseudo-record (RFC 6891)
#[derive(Clone, Debug)]
pub struct EdnsOpt {
    pub udp_payload_size: u16,
    pub extended_rcode: u8,
    pub version: u8,
    pub do_bit: bool,
    pub options: Vec<u8>,
}

impl Default for EdnsOpt {
    fn default() -> Self {
        EdnsOpt {
            udp_payload_size: DEFAULT_EDNS_PAYLOAD,
            extended_rcode: 0,
            version: 0,
            do_bit: false,
            options: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
    pub edns: Option<EdnsOpt>,
}

impl Default for DnsPacket {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
            edns: None,
        }
    }

    pub fn query(id: u16, domain: &str, qtype: crate::question::QueryType) -> DnsPacket {
        let mut pkt = DnsPacket::new();
        pkt.header.id = id;
        pkt.header.recursion_desired = true;
        pkt.questions
            .push(crate::question::DnsQuestion::new(domain.to_string(), qtype));
        pkt
    }

    pub fn heap_bytes(&self) -> usize {
        fn records_heap(records: &[DnsRecord]) -> usize {
            records
                .iter()
                .map(|r| std::mem::size_of::<DnsRecord>() + r.heap_bytes())
                .sum::<usize>()
        }
        let questions: usize = self
            .questions
            .iter()
            .map(|q| std::mem::size_of::<DnsQuestion>() + q.name.capacity())
            .sum();
        questions
            + records_heap(&self.answers)
            + records_heap(&self.authorities)
            + records_heap(&self.resources)
            + self.edns.as_ref().map_or(0, |e| e.options.capacity())
    }

    pub fn response_from(query: &DnsPacket, rescode: crate::header::ResultCode) -> DnsPacket {
        let mut resp = DnsPacket::new();
        resp.header.id = query.header.id;
        resp.header.response = true;
        resp.header.recursion_desired = query.header.recursion_desired;
        resp.header.recursion_available = true;
        resp.header.rescode = rescode;
        resp.questions = query.questions.clone();
        resp
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new(String::with_capacity(64), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }
        for _ in 0..result.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }
        for _ in 0..result.header.resource_entries {
            // Peek at type field to detect OPT pseudo-records.
            // OPT name is always root (0x00), so name byte + type field starts at pos+1.
            let peek_pos = buffer.pos();
            let name_byte = buffer.get(peek_pos)?;
            let is_opt = if name_byte == 0 {
                // Root name (single zero byte) — peek at type
                let type_hi = buffer.get(peek_pos + 1)?;
                let type_lo = buffer.get(peek_pos + 2)?;
                u16::from_be_bytes([type_hi, type_lo]) == 41
            } else {
                false
            };

            if is_opt {
                // Parse OPT manually to capture the class field (= UDP payload size)
                buffer.step(1)?; // skip root name (0x00)
                let _ = buffer.read_u16()?; // type (41)
                let udp_payload_size = buffer.read_u16()?; // class = UDP payload size
                let ttl_field = buffer.read_u32()?; // packed flags
                let rdlength = buffer.read_u16()?;
                let options = buffer.get_range(buffer.pos(), rdlength as usize)?.to_vec();
                buffer.step(rdlength as usize)?;

                result.edns = Some(EdnsOpt {
                    udp_payload_size,
                    extended_rcode: ((ttl_field >> 24) & 0xFF) as u8,
                    version: ((ttl_field >> 16) & 0xFF) as u8,
                    do_bit: (ttl_field >> 15) & 1 == 1,
                    options,
                });
            } else {
                let rec = DnsRecord::read(buffer)?;
                result.resources.push(rec);
            }
        }

        Ok(result)
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        let edns_count = if self.edns.is_some() { 1u16 } else { 0 };

        let mut header = self.header.clone();
        header.questions = self.questions.len() as u16;
        header.answers = self.answers.len() as u16;
        header.authoritative_entries = self.authorities.len() as u16;
        header.resource_entries = self.resources.len() as u16 + edns_count;

        header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }
        for rec in &self.answers {
            rec.write(buffer)?;
        }
        for rec in &self.authorities {
            rec.write(buffer)?;
        }
        for rec in &self.resources {
            rec.write(buffer)?;
        }

        // Write EDNS0 OPT pseudo-record
        if let Some(ref edns) = self.edns {
            buffer.write_u8(0)?; // root name
            buffer.write_u16(QueryType::OPT.to_num())?; // type 41
            buffer.write_u16(edns.udp_payload_size)?; // class = UDP payload size
                                                      // TTL = extended_rcode(8) | version(8) | DO(1) | Z(15)
            let ttl_field = ((edns.extended_rcode as u32) << 24)
                | ((edns.version as u32) << 16)
                | (if edns.do_bit { 1u32 << 15 } else { 0 });
            buffer.write_u32(ttl_field)?;
            buffer.write_u16(edns.options.len() as u16)?; // RDLENGTH
            buffer.write_bytes(&edns.options)?;
        }

        Ok(())
    }

    pub fn display(&self) {
        println!("{:#?}", self.header);

        for q in &self.questions {
            println!("{:#?}", q);
        }
        for rec in &self.answers {
            println!("{:#?}", rec);
        }
        for rec in &self.authorities {
            println!("{:#?}", rec);
        }
        for rec in &self.resources {
            println!("{:#?}", rec);
        }
        if let Some(ref edns) = self.edns {
            println!("EDNS: {:?}", edns);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::ResultCode;

    #[test]
    fn edns_round_trip() {
        let mut pkt = DnsPacket::new();
        pkt.header.id = 0x1234;
        pkt.header.response = true;
        pkt.header.rescode = ResultCode::NOERROR;
        pkt.edns = Some(EdnsOpt {
            do_bit: true,
            ..Default::default()
        });

        let mut buf = BytePacketBuffer::new();
        pkt.write(&mut buf).unwrap();
        buf.seek(0).unwrap();
        let parsed = DnsPacket::from_buffer(&mut buf).unwrap();

        let edns = parsed.edns.expect("EDNS should be present");
        assert_eq!(edns.udp_payload_size, DEFAULT_EDNS_PAYLOAD);
        assert!(edns.do_bit);
        assert_eq!(edns.version, 0);
    }

    #[test]
    fn edns_do_bit_false() {
        let mut pkt = DnsPacket::new();
        pkt.header.id = 0x5678;
        pkt.header.response = true;
        pkt.edns = Some(EdnsOpt {
            udp_payload_size: 1232,
            do_bit: false,
            ..Default::default()
        });

        let mut buf = BytePacketBuffer::new();
        pkt.write(&mut buf).unwrap();
        buf.seek(0).unwrap();
        let parsed = DnsPacket::from_buffer(&mut buf).unwrap();

        let edns = parsed.edns.expect("EDNS should be present");
        assert_eq!(edns.udp_payload_size, DEFAULT_EDNS_PAYLOAD);
        assert!(!edns.do_bit);
    }

    #[test]
    fn no_edns_by_default() {
        let pkt = DnsPacket::new();
        assert!(pkt.edns.is_none());
    }

    #[test]
    fn packet_without_edns_round_trips() {
        let mut pkt = DnsPacket::new();
        pkt.header.id = 0xABCD;
        pkt.header.response = true;
        pkt.header.rescode = ResultCode::NOERROR;
        pkt.answers.push(crate::record::DnsRecord::A {
            domain: "example.com".into(),
            addr: "1.2.3.4".parse().unwrap(),
            ttl: 300,
        });

        let parsed = packet_round_trip(&pkt);
        assert!(parsed.edns.is_none());
        assert_eq!(parsed.answers.len(), 1);
    }

    fn packet_round_trip(pkt: &DnsPacket) -> DnsPacket {
        let mut buf = BytePacketBuffer::new();
        pkt.write(&mut buf).unwrap();
        let wire_len = buf.pos();
        buf.seek(0).unwrap();
        let parsed = DnsPacket::from_buffer(&mut buf).unwrap();
        // Verify we consumed exactly what was written
        assert_eq!(
            buf.pos(),
            wire_len,
            "parse did not consume all written bytes"
        );
        parsed
    }

    #[test]
    fn nxdomain_with_nsec_authority_round_trips() {
        use crate::question::DnsQuestion;
        use crate::record::DnsRecord;

        let mut pkt = DnsPacket::new();
        pkt.header.id = 0x1111;
        pkt.header.response = true;
        pkt.header.rescode = ResultCode::NXDOMAIN;
        pkt.questions.push(DnsQuestion::new(
            "nonexistent.example.com".into(),
            QueryType::A,
        ));

        pkt.authorities.push(DnsRecord::NSEC {
            domain: "alpha.example.com".into(),
            next_domain: "gamma.example.com".into(),
            type_bitmap: vec![0, 2, 0x40, 0x01], // A + MX
            ttl: 3600,
        });
        pkt.authorities.push(DnsRecord::RRSIG {
            domain: "alpha.example.com".into(),
            type_covered: QueryType::NSEC.to_num(),
            algorithm: 13,
            labels: 3,
            original_ttl: 3600,
            expiration: 1700000000,
            inception: 1690000000,
            key_tag: 12345,
            signer_name: "example.com".into(),
            signature: vec![0xAA; 64],
            ttl: 3600,
        });

        // Wildcard denial NSEC
        pkt.authorities.push(DnsRecord::NSEC {
            domain: "example.com".into(),
            next_domain: "alpha.example.com".into(),
            type_bitmap: vec![0, 3, 0x62, 0x01, 0x80], // A, NS, SOA, MX, RRSIG
            ttl: 3600,
        });

        pkt.edns = Some(EdnsOpt {
            do_bit: true,
            ..Default::default()
        });

        let parsed = packet_round_trip(&pkt);

        assert_eq!(parsed.header.id, 0x1111);
        assert_eq!(parsed.header.rescode, ResultCode::NXDOMAIN);
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].name, "nonexistent.example.com");
        assert_eq!(parsed.authorities.len(), 3);

        // Verify NSEC records survived
        if let DnsRecord::NSEC {
            domain,
            next_domain,
            type_bitmap,
            ..
        } = &parsed.authorities[0]
        {
            assert_eq!(domain, "alpha.example.com");
            assert_eq!(next_domain, "gamma.example.com");
            assert_eq!(type_bitmap, &[0, 2, 0x40, 0x01]);
        } else {
            panic!("expected NSEC, got {:?}", parsed.authorities[0]);
        }

        // Verify RRSIG survived
        if let DnsRecord::RRSIG {
            type_covered,
            signer_name,
            signature,
            ..
        } = &parsed.authorities[1]
        {
            assert_eq!(*type_covered, QueryType::NSEC.to_num());
            assert_eq!(signer_name, "example.com");
            assert_eq!(signature.len(), 64);
        } else {
            panic!("expected RRSIG, got {:?}", parsed.authorities[1]);
        }

        // Verify EDNS survived
        assert!(parsed.edns.as_ref().unwrap().do_bit);
    }

    #[test]
    fn nxdomain_with_nsec3_authority_round_trips() {
        use crate::question::DnsQuestion;
        use crate::record::DnsRecord;

        let mut pkt = DnsPacket::new();
        pkt.header.id = 0x2222;
        pkt.header.response = true;
        pkt.header.rescode = ResultCode::NXDOMAIN;
        pkt.questions
            .push(DnsQuestion::new("no.example.com".into(), QueryType::AAAA));

        // Three NSEC3 records (closest encloser, next closer, wildcard)
        let salt = vec![0xAB, 0xCD];
        pkt.authorities.push(DnsRecord::NSEC3 {
            domain: "ABC123.example.com".into(),
            hash_algorithm: 1,
            flags: 0,
            iterations: 5,
            salt: salt.clone(),
            next_hashed_owner: vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
            ],
            type_bitmap: vec![0, 2, 0x60, 0x01], // NS, SOA, MX
            ttl: 300,
        });
        pkt.authorities.push(DnsRecord::NSEC3 {
            domain: "DEF456.example.com".into(),
            hash_algorithm: 1,
            flags: 0,
            iterations: 5,
            salt: salt.clone(),
            next_hashed_owner: vec![0x20; 20],
            type_bitmap: vec![0, 1, 0x40], // A
            ttl: 300,
        });
        pkt.authorities.push(DnsRecord::RRSIG {
            domain: "ABC123.example.com".into(),
            type_covered: QueryType::NSEC3.to_num(),
            algorithm: 8,
            labels: 3,
            original_ttl: 300,
            expiration: 2000000000,
            inception: 1600000000,
            key_tag: 54321,
            signer_name: "example.com".into(),
            signature: vec![0xBB; 128],
            ttl: 300,
        });

        pkt.edns = Some(EdnsOpt {
            do_bit: true,
            ..Default::default()
        });

        let parsed = packet_round_trip(&pkt);

        assert_eq!(parsed.header.rescode, ResultCode::NXDOMAIN);
        assert_eq!(parsed.authorities.len(), 3);

        // Verify first NSEC3 survived with all fields intact
        if let DnsRecord::NSEC3 {
            domain,
            hash_algorithm,
            flags,
            iterations,
            salt: parsed_salt,
            next_hashed_owner,
            type_bitmap,
            ..
        } = &parsed.authorities[0]
        {
            assert_eq!(domain, "abc123.example.com");
            assert_eq!(*hash_algorithm, 1);
            assert_eq!(*flags, 0);
            assert_eq!(*iterations, 5);
            assert_eq!(parsed_salt, &salt);
            assert_eq!(next_hashed_owner.len(), 20);
            assert_eq!(type_bitmap, &[0, 2, 0x60, 0x01]);
        } else {
            panic!("expected NSEC3, got {:?}", parsed.authorities[0]);
        }

        // Verify RRSIG covering NSEC3
        if let DnsRecord::RRSIG {
            type_covered,
            algorithm,
            signature,
            ..
        } = &parsed.authorities[2]
        {
            assert_eq!(*type_covered, QueryType::NSEC3.to_num());
            assert_eq!(*algorithm, 8);
            assert_eq!(signature.len(), 128);
        } else {
            panic!("expected RRSIG, got {:?}", parsed.authorities[2]);
        }
    }

    #[test]
    fn dnssec_answer_with_rrsig_round_trips() {
        use crate::question::DnsQuestion;
        use crate::record::DnsRecord;

        let mut pkt = DnsPacket::new();
        pkt.header.id = 0x3333;
        pkt.header.response = true;
        pkt.header.rescode = ResultCode::NOERROR;
        pkt.header.authed_data = true;
        pkt.questions
            .push(DnsQuestion::new("example.com".into(), QueryType::A));

        pkt.answers.push(DnsRecord::A {
            domain: "example.com".into(),
            addr: "93.184.216.34".parse().unwrap(),
            ttl: 300,
        });
        pkt.answers.push(DnsRecord::RRSIG {
            domain: "example.com".into(),
            type_covered: QueryType::A.to_num(),
            algorithm: 13,
            labels: 2,
            original_ttl: 300,
            expiration: 1700000000,
            inception: 1690000000,
            key_tag: 11111,
            signer_name: "example.com".into(),
            signature: vec![0xCC; 64],
            ttl: 300,
        });

        // Authority: NS + DS
        pkt.authorities.push(DnsRecord::NS {
            domain: "example.com".into(),
            host: "ns1.example.com".into(),
            ttl: 3600,
        });
        pkt.authorities.push(DnsRecord::DS {
            domain: "example.com".into(),
            key_tag: 22222,
            algorithm: 8,
            digest_type: 2,
            digest: vec![0xDD; 32],
            ttl: 86400,
        });

        // Additional: glue A + DNSKEY
        pkt.resources.push(DnsRecord::A {
            domain: "ns1.example.com".into(),
            addr: "198.51.100.1".parse().unwrap(),
            ttl: 3600,
        });
        pkt.resources.push(DnsRecord::DNSKEY {
            domain: "example.com".into(),
            flags: 257,
            protocol: 3,
            algorithm: 13,
            public_key: vec![0xEE; 64],
            ttl: 3600,
        });

        pkt.edns = Some(EdnsOpt {
            do_bit: true,
            ..Default::default()
        });

        let parsed = packet_round_trip(&pkt);

        assert_eq!(parsed.header.id, 0x3333);
        assert!(parsed.header.authed_data);
        assert_eq!(parsed.answers.len(), 2);
        assert_eq!(parsed.authorities.len(), 2);
        assert_eq!(parsed.resources.len(), 2);

        // Verify A record
        if let DnsRecord::A { addr, .. } = &parsed.answers[0] {
            assert_eq!(addr.to_string(), "93.184.216.34");
        } else {
            panic!("expected A");
        }

        // Verify RRSIG in answers
        if let DnsRecord::RRSIG {
            type_covered,
            key_tag,
            signer_name,
            ..
        } = &parsed.answers[1]
        {
            assert_eq!(*type_covered, 1); // A
            assert_eq!(*key_tag, 11111);
            assert_eq!(signer_name, "example.com");
        } else {
            panic!("expected RRSIG");
        }

        // Verify DS in authority
        if let DnsRecord::DS {
            key_tag, digest, ..
        } = &parsed.authorities[1]
        {
            assert_eq!(*key_tag, 22222);
            assert_eq!(digest.len(), 32);
        } else {
            panic!("expected DS");
        }

        // Verify DNSKEY in additional
        if let DnsRecord::DNSKEY {
            flags, public_key, ..
        } = &parsed.resources[1]
        {
            assert_eq!(*flags, 257);
            assert_eq!(public_key.len(), 64);
        } else {
            panic!("expected DNSKEY");
        }
    }
}
