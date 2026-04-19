use crate::buffer::BytePacketBuffer;
use crate::Result;

macro_rules! define_qtypes {
    ( $( $variant:ident = $num:literal, $str:literal ),* $(,)? ) => {
        #[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
        pub enum QueryType {
            UNKNOWN(u16),
            $( $variant, )*
        }

        impl QueryType {
            pub fn to_num(&self) -> u16 {
                match *self {
                    QueryType::UNKNOWN(x) => x,
                    $( QueryType::$variant => $num, )*
                }
            }

            pub fn from_num(num: u16) -> QueryType {
                match num {
                    $( $num => QueryType::$variant, )*
                    _ => QueryType::UNKNOWN(num),
                }
            }

            pub fn as_str(&self) -> &'static str {
                match self {
                    QueryType::UNKNOWN(_) => "UNKNOWN",
                    $( QueryType::$variant => $str, )*
                }
            }

            pub fn parse_str(s: &str) -> Option<QueryType> {
                match s.to_ascii_uppercase().as_str() {
                    $( $str => Some(QueryType::$variant), )*
                    _ => None,
                }
            }
        }
    };
}

define_qtypes! {
    A      = 1,  "A",
    NS     = 2,  "NS",
    CNAME  = 5,  "CNAME",
    SOA    = 6,  "SOA",
    PTR    = 12, "PTR",
    MX     = 15, "MX",
    TXT    = 16, "TXT",
    AAAA   = 28, "AAAA",
    LOC    = 29, "LOC",
    SRV    = 33, "SRV",
    NAPTR  = 35, "NAPTR",
    OPT    = 41, "OPT",
    DS     = 43, "DS",
    RRSIG  = 46, "RRSIG",
    NSEC   = 47, "NSEC",
    DNSKEY = 48, "DNSKEY",
    NSEC3  = 50, "NSEC3",
    SVCB   = 64, "SVCB",
    HTTPS  = 65, "HTTPS",
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
