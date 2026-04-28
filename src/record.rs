use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use crate::buffer::BytePacketBuffer;
use crate::question::QueryType;
use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data: Vec<u8>,
        ttl: u32,
    },
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    NS {
        domain: String,
        host: String,
        ttl: u32,
    },
    SOA {
        domain: String,
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
        ttl: u32,
    },
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    },
    PTR {
        domain: String,
        host: String,
        ttl: u32,
    },
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    },
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    },
    DNSKEY {
        domain: String,
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: Vec<u8>,
        ttl: u32,
    },
    DS {
        domain: String,
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
        ttl: u32,
    },
    RRSIG {
        domain: String,
        type_covered: u16,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        expiration: u32,
        inception: u32,
        key_tag: u16,
        signer_name: String,
        signature: Vec<u8>,
        ttl: u32,
    },
    NSEC {
        domain: String,
        next_domain: String,
        type_bitmap: Vec<u8>,
        ttl: u32,
    },
    NSEC3 {
        domain: String,
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: Vec<u8>,
        next_hashed_owner: Vec<u8>,
        type_bitmap: Vec<u8>,
        ttl: u32,
    },
}

impl DnsRecord {
    pub fn domain(&self) -> &str {
        match self {
            DnsRecord::A { domain, .. }
            | DnsRecord::NS { domain, .. }
            | DnsRecord::CNAME { domain, .. }
            | DnsRecord::PTR { domain, .. }
            | DnsRecord::MX { domain, .. }
            | DnsRecord::AAAA { domain, .. }
            | DnsRecord::DNSKEY { domain, .. }
            | DnsRecord::DS { domain, .. }
            | DnsRecord::RRSIG { domain, .. }
            | DnsRecord::NSEC { domain, .. }
            | DnsRecord::NSEC3 { domain, .. }
            | DnsRecord::SOA { domain, .. }
            | DnsRecord::UNKNOWN { domain, .. } => domain,
        }
    }

    pub fn query_type(&self) -> QueryType {
        match self {
            DnsRecord::A { .. } => QueryType::A,
            DnsRecord::AAAA { .. } => QueryType::AAAA,
            DnsRecord::NS { .. } => QueryType::NS,
            DnsRecord::CNAME { .. } => QueryType::CNAME,
            DnsRecord::PTR { .. } => QueryType::PTR,
            DnsRecord::MX { .. } => QueryType::MX,
            DnsRecord::SOA { .. } => QueryType::SOA,
            DnsRecord::DNSKEY { .. } => QueryType::DNSKEY,
            DnsRecord::DS { .. } => QueryType::DS,
            DnsRecord::RRSIG { .. } => QueryType::RRSIG,
            DnsRecord::NSEC { .. } => QueryType::NSEC,
            DnsRecord::NSEC3 { .. } => QueryType::NSEC3,
            DnsRecord::UNKNOWN { qtype, .. } => QueryType::UNKNOWN(*qtype),
        }
    }

    pub fn ttl(&self) -> u32 {
        match self {
            DnsRecord::A { ttl, .. }
            | DnsRecord::NS { ttl, .. }
            | DnsRecord::CNAME { ttl, .. }
            | DnsRecord::PTR { ttl, .. }
            | DnsRecord::MX { ttl, .. }
            | DnsRecord::AAAA { ttl, .. }
            | DnsRecord::DNSKEY { ttl, .. }
            | DnsRecord::DS { ttl, .. }
            | DnsRecord::RRSIG { ttl, .. }
            | DnsRecord::NSEC { ttl, .. }
            | DnsRecord::NSEC3 { ttl, .. }
            | DnsRecord::SOA { ttl, .. }
            | DnsRecord::UNKNOWN { ttl, .. } => *ttl,
        }
    }

    pub fn heap_bytes(&self) -> usize {
        match self {
            DnsRecord::A { domain, .. } => domain.capacity(),
            DnsRecord::NS { domain, host, .. }
            | DnsRecord::CNAME { domain, host, .. }
            | DnsRecord::PTR { domain, host, .. } => domain.capacity() + host.capacity(),
            DnsRecord::MX { domain, host, .. } => domain.capacity() + host.capacity(),
            DnsRecord::AAAA { domain, .. } => domain.capacity(),
            DnsRecord::DNSKEY {
                domain, public_key, ..
            } => domain.capacity() + public_key.capacity(),
            DnsRecord::DS { domain, digest, .. } => domain.capacity() + digest.capacity(),
            DnsRecord::RRSIG {
                domain,
                signer_name,
                signature,
                ..
            } => domain.capacity() + signer_name.capacity() + signature.capacity(),
            DnsRecord::NSEC {
                domain,
                next_domain,
                type_bitmap,
                ..
            } => domain.capacity() + next_domain.capacity() + type_bitmap.capacity(),
            DnsRecord::NSEC3 {
                domain,
                salt,
                next_hashed_owner,
                type_bitmap,
                ..
            } => {
                domain.capacity()
                    + salt.capacity()
                    + next_hashed_owner.capacity()
                    + type_bitmap.capacity()
            }
            DnsRecord::SOA {
                domain,
                mname,
                rname,
                ..
            } => domain.capacity() + mname.capacity() + rname.capacity(),
            DnsRecord::UNKNOWN { domain, data, .. } => domain.capacity() + data.capacity(),
        }
    }

    pub fn set_ttl(&mut self, new_ttl: u32) {
        match self {
            DnsRecord::A { ttl, .. }
            | DnsRecord::NS { ttl, .. }
            | DnsRecord::CNAME { ttl, .. }
            | DnsRecord::PTR { ttl, .. }
            | DnsRecord::MX { ttl, .. }
            | DnsRecord::AAAA { ttl, .. }
            | DnsRecord::DNSKEY { ttl, .. }
            | DnsRecord::DS { ttl, .. }
            | DnsRecord::RRSIG { ttl, .. }
            | DnsRecord::NSEC { ttl, .. }
            | DnsRecord::NSEC3 { ttl, .. }
            | DnsRecord::SOA { ttl, .. }
            | DnsRecord::UNKNOWN { ttl, .. } => *ttl = new_ttl,
        }
    }

    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord> {
        let mut domain = String::with_capacity(64);
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?; // class
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;
        let rdata_start = buffer.pos();

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    (raw_addr & 0xFF) as u8,
                );
                Ok(DnsRecord::A { domain, addr, ttl })
            }
            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    (raw_addr1 & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    (raw_addr2 & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    (raw_addr3 & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    (raw_addr4 & 0xFFFF) as u16,
                );
                Ok(DnsRecord::AAAA { domain, addr, ttl })
            }
            QueryType::NS => {
                let mut ns = String::with_capacity(64);
                buffer.read_qname(&mut ns)?;
                Ok(DnsRecord::NS {
                    domain,
                    host: ns,
                    ttl,
                })
            }
            QueryType::CNAME => {
                let mut cname = String::with_capacity(64);
                buffer.read_qname(&mut cname)?;
                Ok(DnsRecord::CNAME {
                    domain,
                    host: cname,
                    ttl,
                })
            }
            QueryType::PTR => {
                let mut ptr = String::with_capacity(64);
                buffer.read_qname(&mut ptr)?;
                Ok(DnsRecord::PTR {
                    domain,
                    host: ptr,
                    ttl,
                })
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut mx = String::with_capacity(64);
                buffer.read_qname(&mut mx)?;
                Ok(DnsRecord::MX {
                    domain,
                    priority,
                    host: mx,
                    ttl,
                })
            }
            QueryType::DNSKEY => {
                let flags = buffer.read_u16()?;
                let protocol = buffer.read()?;
                let algorithm = buffer.read()?;
                let key_len = data_len as usize - 4; // flags(2) + protocol(1) + algorithm(1)
                let public_key = buffer.get_range(buffer.pos(), key_len)?.to_vec();
                buffer.step(key_len)?;
                Ok(DnsRecord::DNSKEY {
                    domain,
                    flags,
                    protocol,
                    algorithm,
                    public_key,
                    ttl,
                })
            }
            QueryType::DS => {
                let key_tag = buffer.read_u16()?;
                let algorithm = buffer.read()?;
                let digest_type = buffer.read()?;
                let digest_len = data_len as usize - 4; // key_tag(2) + algorithm(1) + digest_type(1)
                let digest = buffer.get_range(buffer.pos(), digest_len)?.to_vec();
                buffer.step(digest_len)?;
                Ok(DnsRecord::DS {
                    domain,
                    key_tag,
                    algorithm,
                    digest_type,
                    digest,
                    ttl,
                })
            }
            QueryType::RRSIG => {
                let type_covered = buffer.read_u16()?;
                let algorithm = buffer.read()?;
                let labels = buffer.read()?;
                let original_ttl = buffer.read_u32()?;
                let expiration = buffer.read_u32()?;
                let inception = buffer.read_u32()?;
                let key_tag = buffer.read_u16()?;
                let mut signer_name = String::with_capacity(64);
                buffer.read_qname(&mut signer_name)?;
                let rdata_end = rdata_start + data_len as usize;
                let sig_len = rdata_end
                    .checked_sub(buffer.pos())
                    .ok_or("RRSIG data_len too short for fixed fields + signer_name")?;
                let signature = buffer.get_range(buffer.pos(), sig_len)?.to_vec();
                buffer.step(sig_len)?;
                Ok(DnsRecord::RRSIG {
                    domain,
                    type_covered,
                    algorithm,
                    labels,
                    original_ttl,
                    expiration,
                    inception,
                    key_tag,
                    signer_name,
                    signature,
                    ttl,
                })
            }
            QueryType::NSEC => {
                let rdata_end = rdata_start + data_len as usize;
                let mut next_domain = String::with_capacity(64);
                buffer.read_qname(&mut next_domain)?;
                let bitmap_len = rdata_end
                    .checked_sub(buffer.pos())
                    .ok_or("NSEC data_len too short for type bitmap")?;
                let type_bitmap = buffer.get_range(buffer.pos(), bitmap_len)?.to_vec();
                buffer.step(bitmap_len)?;
                Ok(DnsRecord::NSEC {
                    domain,
                    next_domain,
                    type_bitmap,
                    ttl,
                })
            }
            QueryType::NSEC3 => {
                let rdata_end = rdata_start + data_len as usize;
                let hash_algorithm = buffer.read()?;
                let flags = buffer.read()?;
                let iterations = buffer.read_u16()?;
                let salt_length = buffer.read()? as usize;
                let salt = buffer.get_range(buffer.pos(), salt_length)?.to_vec();
                buffer.step(salt_length)?;
                let hash_length = buffer.read()? as usize;
                let next_hashed_owner = buffer.get_range(buffer.pos(), hash_length)?.to_vec();
                buffer.step(hash_length)?;
                let bitmap_len = rdata_end
                    .checked_sub(buffer.pos())
                    .ok_or("NSEC3 data_len too short for type bitmap")?;
                let type_bitmap = buffer.get_range(buffer.pos(), bitmap_len)?.to_vec();
                buffer.step(bitmap_len)?;
                Ok(DnsRecord::NSEC3 {
                    domain,
                    hash_algorithm,
                    flags,
                    iterations,
                    salt,
                    next_hashed_owner,
                    type_bitmap,
                    ttl,
                })
            }
            QueryType::SOA => {
                // MNAME/RNAME compressible per RFC 1035 §3.3.13 — decompress to avoid stale pointers on re-emit.
                let mut mname = String::with_capacity(64);
                buffer.read_qname(&mut mname)?;
                let mut rname = String::with_capacity(64);
                buffer.read_qname(&mut rname)?;
                let serial = buffer.read_u32()?;
                let refresh = buffer.read_u32()?;
                let retry = buffer.read_u32()?;
                let expire = buffer.read_u32()?;
                let minimum = buffer.read_u32()?;
                Ok(DnsRecord::SOA {
                    domain,
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                    ttl,
                })
            }
            _ => {
                // TXT, SRV, HTTPS, SVCB, etc. — stored as opaque bytes until parsed natively
                let data = buffer.get_range(buffer.pos(), data_len as usize)?.to_vec();
                buffer.step(data_len as usize)?;
                Ok(DnsRecord::UNKNOWN {
                    domain,
                    qtype: qtype_num,
                    data,
                    ttl,
                })
            }
        }
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start_pos = buffer.pos();

        match *self {
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                write_header(buffer, domain, QueryType::A.to_num(), ttl)?;
                buffer.write_u16(4)?;
                buffer.write_bytes(&addr.octets())?;
            }
            DnsRecord::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                write_header(buffer, domain, QueryType::NS.to_num(), ttl)?;
                let pos = buffer.pos();
                buffer.write_u16(0)?;
                buffer.write_qname(host)?;
                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                write_header(buffer, domain, QueryType::CNAME.to_num(), ttl)?;
                let pos = buffer.pos();
                buffer.write_u16(0)?;
                buffer.write_qname(host)?;
                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::PTR {
                ref domain,
                ref host,
                ttl,
            } => {
                write_header(buffer, domain, QueryType::PTR.to_num(), ttl)?;
                let pos = buffer.pos();
                buffer.write_u16(0)?;
                buffer.write_qname(host)?;
                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                write_header(buffer, domain, QueryType::MX.to_num(), ttl)?;
                let pos = buffer.pos();
                buffer.write_u16(0)?;
                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;
                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::SOA {
                ref domain,
                ref mname,
                ref rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
                ttl,
            } => {
                write_header(buffer, domain, QueryType::SOA.to_num(), ttl)?;
                let rdlen_pos = buffer.pos();
                buffer.write_u16(0)?;
                buffer.write_qname(mname)?;
                buffer.write_qname(rname)?;
                buffer.write_u32(serial)?;
                buffer.write_u32(refresh)?;
                buffer.write_u32(retry)?;
                buffer.write_u32(expire)?;
                buffer.write_u32(minimum)?;
                let rdlen = buffer.pos() - (rdlen_pos + 2);
                buffer.set_u16(rdlen_pos, rdlen as u16)?;
            }
            DnsRecord::AAAA {
                ref domain,
                ref addr,
                ttl,
            } => {
                write_header(buffer, domain, QueryType::AAAA.to_num(), ttl)?;
                buffer.write_u16(16)?;
                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
            }
            DnsRecord::DNSKEY {
                ref domain,
                flags,
                protocol,
                algorithm,
                ref public_key,
                ttl,
            } => {
                write_header(buffer, domain, QueryType::DNSKEY.to_num(), ttl)?;
                buffer.write_u16((4 + public_key.len()) as u16)?;
                buffer.write_u16(flags)?;
                buffer.write_u8(protocol)?;
                buffer.write_u8(algorithm)?;
                buffer.write_bytes(public_key)?;
            }
            DnsRecord::DS {
                ref domain,
                key_tag,
                algorithm,
                digest_type,
                ref digest,
                ttl,
            } => {
                write_header(buffer, domain, QueryType::DS.to_num(), ttl)?;
                buffer.write_u16((4 + digest.len()) as u16)?;
                buffer.write_u16(key_tag)?;
                buffer.write_u8(algorithm)?;
                buffer.write_u8(digest_type)?;
                buffer.write_bytes(digest)?;
            }
            DnsRecord::RRSIG {
                ref domain,
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                ref signer_name,
                ref signature,
                ttl,
            } => {
                write_header(buffer, domain, QueryType::RRSIG.to_num(), ttl)?;
                let rdlen_pos = buffer.pos();
                buffer.write_u16(0)?; // RDLENGTH placeholder
                buffer.write_u16(type_covered)?;
                buffer.write_u8(algorithm)?;
                buffer.write_u8(labels)?;
                buffer.write_u32(original_ttl)?;
                buffer.write_u32(expiration)?;
                buffer.write_u32(inception)?;
                buffer.write_u16(key_tag)?;
                buffer.write_qname(signer_name)?;
                buffer.write_bytes(signature)?;
                let rdlen = buffer.pos() - (rdlen_pos + 2);
                buffer.set_u16(rdlen_pos, rdlen as u16)?;
            }
            DnsRecord::NSEC {
                ref domain,
                ref next_domain,
                ref type_bitmap,
                ttl,
            } => {
                write_header(buffer, domain, QueryType::NSEC.to_num(), ttl)?;
                let rdlen_pos = buffer.pos();
                buffer.write_u16(0)?;
                buffer.write_qname(next_domain)?;
                buffer.write_bytes(type_bitmap)?;
                let rdlen = buffer.pos() - (rdlen_pos + 2);
                buffer.set_u16(rdlen_pos, rdlen as u16)?;
            }
            DnsRecord::NSEC3 {
                ref domain,
                hash_algorithm,
                flags,
                iterations,
                ref salt,
                ref next_hashed_owner,
                ref type_bitmap,
                ttl,
            } => {
                write_header(buffer, domain, QueryType::NSEC3.to_num(), ttl)?;
                let rdlen =
                    1 + 1 + 2 + 1 + salt.len() + 1 + next_hashed_owner.len() + type_bitmap.len();
                buffer.write_u16(rdlen as u16)?;
                buffer.write_u8(hash_algorithm)?;
                buffer.write_u8(flags)?;
                buffer.write_u16(iterations)?;
                buffer.write_u8(salt.len() as u8)?;
                buffer.write_bytes(salt)?;
                buffer.write_u8(next_hashed_owner.len() as u8)?;
                buffer.write_bytes(next_hashed_owner)?;
                buffer.write_bytes(type_bitmap)?;
            }
            DnsRecord::UNKNOWN {
                ref domain,
                qtype,
                ref data,
                ttl,
            } => {
                write_header(buffer, domain, qtype, ttl)?;
                buffer.write_u16(data.len() as u16)?;
                buffer.write_bytes(data)?;
            }
        }

        Ok(buffer.pos() - start_pos)
    }
}

fn write_header(buffer: &mut BytePacketBuffer, domain: &str, qtype: u16, ttl: u32) -> Result<()> {
    buffer.write_qname(domain)?;
    buffer.write_u16(qtype)?;
    buffer.write_u16(1)?; // class IN
    buffer.write_u32(ttl)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(record: &DnsRecord) -> DnsRecord {
        let mut buf = BytePacketBuffer::new();
        record.write(&mut buf).unwrap();
        buf.seek(0).unwrap();
        DnsRecord::read(&mut buf).unwrap()
    }

    #[test]
    fn ptr_round_trip() {
        let rec = DnsRecord::PTR {
            domain: "9.9.9.9.in-addr.arpa".into(),
            host: "dns.quad9.net".into(),
            ttl: 3600,
        };
        let parsed = round_trip(&rec);
        assert_eq!(rec, parsed);
        assert_eq!(parsed.query_type(), QueryType::PTR);
    }

    #[test]
    fn unknown_preserves_raw_bytes() {
        let rec = DnsRecord::UNKNOWN {
            domain: "example.com".into(),
            qtype: 99,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            ttl: 300,
        };
        let parsed = round_trip(&rec);
        if let DnsRecord::UNKNOWN { data, .. } = &parsed {
            assert_eq!(data.len(), 4);
            assert_eq!(data, &[0xDE, 0xAD, 0xBE, 0xEF]);
        } else {
            panic!("expected UNKNOWN");
        }
    }

    #[test]
    fn dnskey_round_trip() {
        let rec = DnsRecord::DNSKEY {
            domain: "example.com".into(),
            flags: 257, // KSK
            protocol: 3,
            algorithm: 13, // ECDSAP256SHA256
            public_key: vec![1, 2, 3, 4, 5, 6, 7, 8],
            ttl: 3600,
        };
        let parsed = round_trip(&rec);
        assert_eq!(rec, parsed);
    }

    #[test]
    fn ds_round_trip() {
        let rec = DnsRecord::DS {
            domain: "example.com".into(),
            key_tag: 12345,
            algorithm: 8,
            digest_type: 2,
            digest: vec![0xAA, 0xBB, 0xCC, 0xDD],
            ttl: 86400,
        };
        let parsed = round_trip(&rec);
        assert_eq!(rec, parsed);
    }

    #[test]
    fn rrsig_round_trip() {
        let rec = DnsRecord::RRSIG {
            domain: "example.com".into(),
            type_covered: 1, // A
            algorithm: 13,
            labels: 2,
            original_ttl: 300,
            expiration: 1700000000,
            inception: 1690000000,
            key_tag: 54321,
            signer_name: "example.com".into(),
            signature: vec![0x01, 0x02, 0x03, 0x04, 0x05],
            ttl: 300,
        };
        let parsed = round_trip(&rec);
        assert_eq!(rec, parsed);
    }

    #[test]
    fn query_type_method() {
        assert_eq!(
            DnsRecord::DNSKEY {
                domain: String::new(),
                flags: 0,
                protocol: 3,
                algorithm: 8,
                public_key: vec![],
                ttl: 0,
            }
            .query_type(),
            QueryType::DNSKEY
        );
        assert_eq!(
            DnsRecord::DS {
                domain: String::new(),
                key_tag: 0,
                algorithm: 0,
                digest_type: 0,
                digest: vec![],
                ttl: 0,
            }
            .query_type(),
            QueryType::DS
        );
    }

    #[test]
    fn nsec_round_trip() {
        let rec = DnsRecord::NSEC {
            domain: "alpha.example.com".into(),
            next_domain: "gamma.example.com".into(),
            type_bitmap: vec![0, 2, 0x40, 0x01], // A(1), MX(15)
            ttl: 3600,
        };
        let parsed = round_trip(&rec);
        assert_eq!(rec, parsed);
    }

    #[test]
    fn nsec3_round_trip() {
        let rec = DnsRecord::NSEC3 {
            domain: "abc123.example.com".into(),
            hash_algorithm: 1,
            flags: 0,
            iterations: 10,
            salt: vec![0xAB, 0xCD],
            next_hashed_owner: vec![0x01, 0x02, 0x03, 0x04, 0x05],
            type_bitmap: vec![0, 1, 0x40], // A(1)
            ttl: 3600,
        };
        let parsed = round_trip(&rec);
        assert_eq!(rec, parsed);
    }

    #[test]
    fn heap_bytes_reflects_string_capacity() {
        let rec = DnsRecord::CNAME {
            domain: "a]".repeat(100),
            host: "b".repeat(200),
            ttl: 60,
        };
        assert!(rec.heap_bytes() >= 300);
    }
}
