use std::net::Ipv4Addr;

use crate::buffer::buffer::BytePacketBuffer;
use crate::utils::types::Result;

use super::dns_header::DnsHeader;
use super::dns_question::DnsQuestion;
use super::dns_record::DnsRecord;
use super::query_type::QueryType;

///DnsPacket wraps everything together
#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
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
    // read DNS packet from buffer
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
    // write DNS packet to buffer
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        // Write header
        self.header.write(buffer)?;
        // Write questions
        for question in &self.questions {
            question.write(buffer)?;
        }
        // Write answers
        for answer in &self.answers {
            answer.write(buffer)?;
        }
        // write authorities
        for auth in &self.authorities {
            auth.write(buffer)?;
        }
        // write resource entries
        for resource in &self.resources {
            resource.write(buffer)?;
        }
        Ok(())
    }

    /// It's useful to be able to pick a random A record from a packet. When we
    /// get multiple IP's for a single name, it doesn't matter which one we
    /// choose, so in those cases we can now pick one at random.
    pub fn get_random_a_record(&self) -> Option<Ipv4Addr> {
        self.answers
            .iter()
            .filter_map(|record| match record {
                DnsRecord::A { addr, .. } => Some(*addr),
                _ => None,
            })
            .next()
    }

    /// A helper function which returns an iterator over all name servers in
    /// the authorities section, represented as (domain, host) tuples
    fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities
            .iter()
            // In practice, these are always NS records in well formed packages.
            // Convert the NS records to a tuple which has only the data we need
            // to make it easy to work with.
            .filter_map(|record| match record {
                DnsRecord::NS { domain, host, .. } => Some((domain.as_str(), host.as_str())),
                _ => None,
            })
            // Discard servers which aren't authoritative to our query
            .filter(move |(domain, _)| qname.ends_with(*domain))
    }

    /// We'll use the fact that name servers often bundle the corresponding
    /// A records when replying to an NS query to implement a function that
    /// returns the actual IP for an NS record if possible.
    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        // Get an iterator over the nameservers in the authorities section
        self.get_ns(qname)
            // Now we need to look for a matching A record in the additional
            // section. Since we just want the first valid record, we can just
            // build a stream of matching records.
            .flat_map(|(_, host)| {
                self.resources
                    .iter()
                    // Filter for A records where the domain match the host
                    // of the NS record that we are currently processing
                    .filter_map(move |record| match record {
                        DnsRecord::A { domain, addr, .. } if domain == host => Some(addr),
                        _ => None,
                    })
            })
            .map(|addr| *addr)
            // Finally, pick the first valid entry
            .next()
    }

    /// However, not all name servers are as that nice. In certain cases there won't
    /// be any A records in the additional section, and we'll have to perform *another*
    /// lookup in the midst. For this, we introduce a method for returning the host
    /// name of an appropriate name server.
    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        // Get an iterator over the nameservers in the authorities section
        self.get_ns(qname)
            .map(|(_, host)| host)
            // Finally, pick the first valid entry
            .next()
    }
}
