use crate::buffer::BytePacketBuffer;
use crate::Result;

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,     // 1
    NS,    // 2
    CNAME, // 5
    MX,    // 15
    AAAA,  // 28
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::UNKNOWN(num),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            QueryType::A => "A",
            QueryType::NS => "NS",
            QueryType::CNAME => "CNAME",
            QueryType::MX => "MX",
            QueryType::AAAA => "AAAA",
            QueryType::UNKNOWN(_) => "UNKNOWN",
        }
    }

    pub fn parse_str(s: &str) -> Option<QueryType> {
        if s.eq_ignore_ascii_case("A") {
            Some(QueryType::A)
        } else if s.eq_ignore_ascii_case("NS") {
            Some(QueryType::NS)
        } else if s.eq_ignore_ascii_case("CNAME") {
            Some(QueryType::CNAME)
        } else if s.eq_ignore_ascii_case("MX") {
            Some(QueryType::MX)
        } else if s.eq_ignore_ascii_case("AAAA") {
            Some(QueryType::AAAA)
        } else {
            None
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
