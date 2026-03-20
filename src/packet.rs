use crate::buffer::BytePacketBuffer;
use crate::header::DnsHeader;
use crate::question::{DnsQuestion, QueryType};
use crate::record::DnsRecord;
use crate::Result;

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
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
        }
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
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
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
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        // Filter out UNKNOWN records (e.g. EDNS OPT) that we can't re-serialize
        let answers: Vec<_> = self.answers.iter().filter(|r| !r.is_unknown()).collect();
        let authorities: Vec<_> = self
            .authorities
            .iter()
            .filter(|r| !r.is_unknown())
            .collect();
        let resources: Vec<_> = self.resources.iter().filter(|r| !r.is_unknown()).collect();

        let mut header = self.header.clone();
        header.questions = self.questions.len() as u16;
        header.answers = answers.len() as u16;
        header.authoritative_entries = authorities.len() as u16;
        header.resource_entries = resources.len() as u16;

        header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }
        for rec in answers {
            rec.write(buffer)?;
        }
        for rec in authorities {
            rec.write(buffer)?;
        }
        for rec in resources {
            rec.write(buffer)?;
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
    }
}
