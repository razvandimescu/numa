use crate::buffer::BytePacketBuffer;
use crate::Result;

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,      // 1
    NS,     // 2
    CNAME,  // 5
    SOA,    // 6
    PTR,    // 12
    MX,     // 15
    TXT,    // 16
    AAAA,   // 28
    SRV,    // 33
    DS,     // 43
    RRSIG,  // 46
    NSEC,   // 47
    DNSKEY, // 48
    NSEC3,  // 50
    OPT,    // 41 (EDNS0 pseudo-type)
    HTTPS,  // 65
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::SOA => 6,
            QueryType::PTR => 12,
            QueryType::MX => 15,
            QueryType::TXT => 16,
            QueryType::AAAA => 28,
            QueryType::SRV => 33,
            QueryType::OPT => 41,
            QueryType::DS => 43,
            QueryType::RRSIG => 46,
            QueryType::NSEC => 47,
            QueryType::DNSKEY => 48,
            QueryType::NSEC3 => 50,
            QueryType::HTTPS => 65,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            6 => QueryType::SOA,
            12 => QueryType::PTR,
            15 => QueryType::MX,
            16 => QueryType::TXT,
            28 => QueryType::AAAA,
            33 => QueryType::SRV,
            41 => QueryType::OPT,
            43 => QueryType::DS,
            46 => QueryType::RRSIG,
            47 => QueryType::NSEC,
            48 => QueryType::DNSKEY,
            50 => QueryType::NSEC3,
            65 => QueryType::HTTPS,
            _ => QueryType::UNKNOWN(num),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            QueryType::A => "A",
            QueryType::NS => "NS",
            QueryType::CNAME => "CNAME",
            QueryType::SOA => "SOA",
            QueryType::PTR => "PTR",
            QueryType::MX => "MX",
            QueryType::TXT => "TXT",
            QueryType::AAAA => "AAAA",
            QueryType::SRV => "SRV",
            QueryType::OPT => "OPT",
            QueryType::DS => "DS",
            QueryType::RRSIG => "RRSIG",
            QueryType::NSEC => "NSEC",
            QueryType::DNSKEY => "DNSKEY",
            QueryType::NSEC3 => "NSEC3",
            QueryType::HTTPS => "HTTPS",
            QueryType::UNKNOWN(_) => "UNKNOWN",
        }
    }

    pub fn parse_str(s: &str) -> Option<QueryType> {
        match s.to_ascii_uppercase().as_str() {
            "A" => Some(QueryType::A),
            "NS" => Some(QueryType::NS),
            "CNAME" => Some(QueryType::CNAME),
            "SOA" => Some(QueryType::SOA),
            "PTR" => Some(QueryType::PTR),
            "MX" => Some(QueryType::MX),
            "TXT" => Some(QueryType::TXT),
            "AAAA" => Some(QueryType::AAAA),
            "SRV" => Some(QueryType::SRV),
            "DS" => Some(QueryType::DS),
            "RRSIG" => Some(QueryType::RRSIG),
            "DNSKEY" => Some(QueryType::DNSKEY),
            "NSEC" => Some(QueryType::NSEC),
            "NSEC3" => Some(QueryType::NSEC3),
            "HTTPS" => Some(QueryType::HTTPS),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion { name, qtype }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        let _ = buffer.read_u16()?; // class

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_qname(&self.name)?;
        buffer.write_u16(self.qtype.to_num())?;
        buffer.write_u16(1)?;

        Ok(())
    }
}
