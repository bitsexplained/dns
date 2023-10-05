use std::fmt::Error;

pub struct BytePacketBuffer{
    pub buf: [u8; 512],
    pub pos: usize,
}
/// BytePacketBuffer provides a convinient method of manipulating the packets

impl BytePacketBuffer {
    ///This gives us a fresh new BytePacketBuffer for holding the packet contents
    /// and a field for keeping track of where we are in the buffer
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer{
            buf: [0; 512],
            pos: 0,
        }
    }

    //current position in the buffer
    fn pos(&self) -> usize {
        self.pos
    }

    //step the buffer position forward a certain number of position
    fn step(&mut self, steps: usize) -> Result<(),()> {
        self.pos += steps;
        Ok(())
    }

    //change the buffer position
    fn seek(&mut self, pos: usize) -> Result<(),Error> {
        self.pos = pos;
        Ok(())
    }

    // read a single byte and move the position forward
    fn read(&mut self) -> Result<u8, Error> {
        if self.pos >= 512 {
            return Err(std::fmt::Error);
        }
        let res = self.buf[self.pos];
        self.pos += 1;
        Ok(res)
    }

    /// Get a single byte, without changing the buffer position
    fn get(&mut self, pos: usize) -> Result<u8, Error> {
        if pos >= 512 {
            return Err(std::fmt::Error);
        }
        Ok(self.buf[pos])
    }

    //get a range of bytes
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8], Error> {
        if start + len > 512 {
            return Err(std::fmt::Error);
        }
        Ok(&self.buf[start..start+len as usize])
    }

    //read two bytes stepping two bytes forward
    fn read_u16(&mut self) -> Result<u16, Error> {
        let res = (self.read()? as u16) << 8 | (self.read()? as u16);
        Ok(res as u16)
    }

    //read four bytes stepping four bytes forward
    fn read_u32(&mut self) -> Result<u32, Error> {
        let res = (self.read()? as u32) << 24
        | (self.read()? as u32) << 16
        | (self.read()? as u32) << 8
        | (self.read()? as u32) << 0;
        Ok(res)
    }

    ///read q name
    ///
    /// Read a domain name by reading the length bytes and concatenating them with dots in between
    ///  Will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
    fn read_qname(&mut self, outstr: &mut String) -> Result<(),Error> {
        // Since we might encounter jumps, we'll keep track of our position
        // locally as opposed to using the position within the struct. This
        // allows us to move the shared position to a point past our current
        // qname, while keeping track of our progress on the current qname
        // using this variable.
        let mut qname_pos = self.pos();


        // track wether we have jumped or not
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        //our delimiter which we append for each label
        //since we do not want a dot at the begining of the domain name we'll leave it empty for now
        //and set it to "." at the end of the first iteration
        let mut delimiter = " ";
        loop {
            //Dns packets are untrusted data so we need to have a guard against malicious packets
            // for instance one can craft a packet with a cycle in the jump instructions
            if jumps_performed > max_jumps{
                return  Err(std::fmt::Error);
            }

            // at this point we are at the begining of a label
            //NB: labels start with a length byte
            let len = self.get(qname_pos)?;

            // If len has the two most significant bit are set, it represents a
            // jump to some other offset in the packet:
            if (len & 0xC0) == 0xC0 {
                // Update the buffer position to a point past the current
                // label. We don't need to touch it any further.
                if !jumped {
                    self.seek(qname_pos + 2)?;
                }

                // read another byte, calculate the the offset and perform the jump
                // by updating our local position variable
                let b2 = self.get(qname_pos)? as u16;
                let offset = ((len as u16)^ 0xC0) << 8 | b2;
                qname_pos = offset as usize;

                //indicate that a jump was performed
                jumped = true;
                jumps_performed += 1;
                continue;
            }
            //base scenario when we are reading a single label and appending it to the output
            else {
                // move a single byte forward to move past the length byte
                qname_pos += 1;
                if len == 0 {
                    break;
                }
                //append the delimiter to our output first
                outstr.push_str(delimiter);

                //extract the actual ASCII bytes from this label and append them to the output buffer
                let str_buffer = self.get_range(qname_pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());
                delimiter = ".";

                // move forward the full length of the label
                qname_pos += len as usize;
            }
        }
        if !jumped {
            self.seek(qname_pos)?;
        }
        Ok(())
    }
}

// ResultCode
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR=0,
    FORMERR=1,
    SERVFAIL=2,
    NXDOMAIN=3,
    NOTIMP=4,
    REFUSED=5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR
        }
    }
}

//DnsHeader
pub struct  DnsHeader{
    pub id : u16, //16 bits
    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: ResultCode,       // 4 bits
    pub checking_disabled: bool,   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub z: bool,                   // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}

impl DnsHeader {
    pub fn new() -> DnsHeader{
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(),Error> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;

        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }
}

//QueryType to represent the record type being queried
#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A, //1
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1
        }
    }

    pub fn from_num(num: u16) -> QueryType{
        match num {
            1 => QueryType::A,
            _ => QueryType::UNKNOWN(num),
        }
    }
}


fn main() {
    println!("Hello, world!");
}
