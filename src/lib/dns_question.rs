use crate::types::Result;
use crate::buffer::buffer::BytePacketBuffer;
use crate::query_type::QueryType;


//DnsQuestion allows adding of more records later on
#[derive(PartialEq, Eq, Debug,Clone)]
pub struct DnsQuestion{
    pub name: String,
    pub question_type: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, question_type: QueryType) -> DnsQuestion{
        DnsQuestion {
            name,
            question_type
        }
    }
    // read DNS question from buffer
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.question_type = QueryType::from_num(buffer.read_u16()?);
        let _ = buffer.read_u16()?;
        Ok(())
    }
    // write DNS question to buffer
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        // Write name
        buffer.write_qname(&self.name)?;
        // Write question type
        buffer.write_u16(self.question_type.to_num())?;
        buffer.write_u16(1)?;

        Ok(())
    }
}
