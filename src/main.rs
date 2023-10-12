use std::net::{Ipv4Addr, UdpSocket, Ipv6Addr};


type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

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
    fn step(&mut self, steps: usize) -> Result<()>{
        self.pos += steps;
        Ok(())
    }

    //change the buffer position
    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;
        Ok(())
    }

    // read a single byte and move the position forward
    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err("End of buffer".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;
        Ok(res)
    }

    /// Get a single byte, without changing the buffer position
    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err("End of buffer".into());
        }
        Ok(self.buf[pos])
    }

    //get a range of bytes
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len > 512 {
            return Err("End of buffer".into());
        }
        Ok(&self.buf[start..start+len as usize])
    }

    //read two bytes stepping two bytes forward
    fn read_u16(&mut self) -> Result<u16> {
        let res = (self.read()? as u16) << 8 | (self.read()? as u16);
        Ok(res as u16)
    }

    //read four bytes stepping four bytes forward
    fn read_u32(&mut self) -> Result<u32> {
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
    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
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
        let mut delimiter = "";
        loop {
            //Dns packets are untrusted data so we need to have a guard against malicious packets
            // for instance one can craft a packet with a cycle in the jump instructions
            if jumps_performed > max_jumps{
                return  Err(format!("Limit of {} jumps exceeded", max_jumps).into());
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
                let b2 = self.get(qname_pos + 1)? as u16;
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

    // write a a helper function for writing a single byte and moving the position forward
    fn write(&mut self, byte: u8) -> Result<()> {
        if self.pos >= 512 {
            return Err("End of buffer".into());
        }
        self.buf[self.pos] = byte;
        self.pos += 1;
        Ok(())
    }
    // write_u8 a single byte
    fn write_u8(&mut self, byte: u8) -> Result<()> {
        self.write(byte)?;
        Ok(())
    }

    //write_u16 writes two bytes
    fn write_u16(&mut self, byte: u16) -> Result<()> {
        	self.write((byte >> 8) as u8)?;
            self.write((byte & 0xff) as u8)?;
            Ok(())
    }

    //write_u32 writes four bytes
    fn write_u32(&mut self, byte: u32) -> Result<()> {
        self.write((byte >> 24) as u8)?;
        self.write((byte >> 16) as u8)?;
        self.write((byte >> 8) as u8)?;
        self.write((byte >> 0) as u8)?;
        Ok(())
    }

    //write_qname write query names in labeled form
    fn write_qname(&mut self, q_name: &str) -> Result<()> {
        // Split the name on dots
        for label in q_name.split('.') {
            let len = label.len();
            if len > 0x3f {
                return Err("Label is too long and exceeds 63 characters".into());
            }
            self.write_u8(len as u8)?;
            // write the label
            for byte in label.as_bytes() {
                self.write(*byte)?;
            }
        }
        self.write_u8(0)?;
        Ok(())
    }

    fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        self.buf[pos] = val;

        Ok(())
    }

    fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;

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
#[derive(Debug, Clone)]
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
    // read DNS header from buffer
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
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
    // write DNS header to buffer
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        // Write id
        buffer.write_u16(self.id)?;
        // Write recursion_desired flag
        buffer.write_u8(
            (self.recursion_desired as u8)
            | ((self.truncated_message as u8) << 1)
            | ((self.authoritative_answer as u8) << 2)
            | ((self.opcode as u8) << 3)
            | ((self.response as u8) << 7)
        )?;
        // write rescode
        buffer.write_u8(
            (self.rescode as u8)
            | ((self.checking_disabled as u8) << 4)
            | ((self.authed_data as u8) << 5)
            | ((self.z as u8) << 6)
            | ((self.recursion_available as u8) << 7)
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}

//QueryType to represent the record type being queried
#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A, //1
    NS, //2
    CNAME, //5
    MX, //15
    AAAA, //28
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

    pub fn from_num(num: u16) -> QueryType{
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

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

//DnsRecord represents the actual dns record
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }, // 1
    NS {
        domain: String,
        host: String,
        ttl: u32,
    }, // 2
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    }, // 5
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    }, // 15
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    }, // 28
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8,
                );

                Ok(DnsRecord::A {
                    domain,
                    addr,
                    ttl,
                })
            }
            QueryType::NS => {
                let mut ns = String::new();
                buffer.read_qname(&mut ns)?;

                Ok(DnsRecord::NS {
                    domain: domain,
                    host: ns,
                    ttl: ttl,
                })
            }
            QueryType::CNAME => {
                let mut cname = String::new();
                buffer.read_qname(&mut cname)?;

                Ok(DnsRecord::CNAME {
                    domain,
                    host: cname,
                    ttl,
                })
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut mx = String::new();
                buffer.read_qname(&mut mx)?;

                Ok(DnsRecord::MX {
                    domain,
                    priority,
                    host: mx,
                    ttl,
                })
            }
            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    ((raw_addr1 >> 0) & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    ((raw_addr2 >> 0) & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    ((raw_addr3 >> 0) & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    ((raw_addr4 >> 0) & 0xFFFF) as u16,
                );

                Ok(DnsRecord::AAAA {
                    domain: domain,
                    addr: addr,
                    ttl: ttl,
                })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::UNKNOWN {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl,
                })
            }
        }
    }
    // write DNS record to buffer
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        // get start position
        let start_pos = buffer.pos();

        // match DNS record
        match *self {
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            },
            DnsRecord::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            },
            DnsRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            },
            DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::CNAME.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            },
            DnsRecord::AAAA {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?;

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
            },
            DnsRecord::UNKNOWN { .. } => {
                println!("skipping unknown record : {:?}", self);
            }
        }
        Ok(buffer.pos() - start_pos)
    }
}


///DnsPacket wraps everything together
#[derive(Clone, Debug)]
pub struct DnsPacket{
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>
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
            let mut question =
            DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
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
        for resource in &self.resources{
            resource.write(buffer)?;
        }
        Ok(())
    }
}

// Add lookup method to lookup DNS records
fn lookup(query_name: &str, query_type: QueryType) -> Result<DnsPacket> {
    //forward query to public dns
    let server = ("8.8.8.8", 53);

    // bind a UDP socket to arbitrary port
    let socket = UdpSocket::bind(("0.0.0.0", 42340))?;

    // Build our query packet. It's important that we remember to set the
    // `recursion_desired` flag. As noted earlier, the packet id is arbitrary.
    let mut packet = DnsPacket::new();
    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(query_name.to_string(), query_type));

    // Use our new write method to write the packet to a buffer...
    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;

    // ...and send it off to the server using our socket:
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

    // To prepare for receiving the response, we'll create a new `BytePacketBuffer`,
    // and ask the socket to write the response directly into our buffer.
    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf)?;

    //`DnsPacket::from_buffer()` is used to parse the response
    DnsPacket::from_buffer(&mut res_buffer)

}
/// Handle a single incoming packet
fn handle_query(socket: &UdpSocket) -> Result<()> {
    // With a socket ready, we can go ahead and read a packet. This will
    // block until one is received.
    let mut req_buffer = BytePacketBuffer::new();

    // The `recv_from` function will write the data into the provided buffer,
    // and return the length of the data read as well as the source address.
    // We're not interested in the length, but we need to keep track of the
    // source in order to send our reply later on.
    let (_, src) = socket.recv_from(&mut req_buffer.buf)?;

    // Next, `DnsPacket::from_buffer` is used to parse the raw bytes into
    // a `DnsPacket`.
    let mut request = DnsPacket::from_buffer(&mut req_buffer)?;

    // Create and initialize the response packet
    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_desired = true;
    packet.header.recursion_available = true;
    packet.header.response = true;

    // In the normal case, exactly one question is present
    if let Some(question) = request.questions.pop() {
        println!("Received query: {:?}", question);

        // Since all is set up and as expected, the query can be forwarded to the
        // target server. There's always the possibility that the query will
        // fail, in which case the `SERVFAIL` response code is set to indicate
        // as much to the client. If rather everything goes as planned, the
        // question and response records as copied into our response packet.
        if let Ok(result) = lookup(&question.name, question.question_type) {
            packet.questions.push(question);
            packet.header.rescode = result.header.rescode;

            for rec in result.answers {
                println!("Answer: {:?}", rec);
                packet.answers.push(rec);
            }
            for rec in result.authorities {
                println!("Authority: {:?}", rec);
                packet.authorities.push(rec);
            }
            for rec in result.resources {
                println!("Resource: {:?}", rec);
                packet.resources.push(rec);
            }
        } else {
            packet.header.rescode = ResultCode::SERVFAIL;
        }
    }
    // Being mindful of how unreliable input data from arbitrary senders can be, we
    // need make sure that a question is actually present. If not, we return `FORMERR`
    // to indicate that the sender made something wrong.
    else {
        packet.header.rescode = ResultCode::FORMERR;
    }

    // encode our response and send it back
    let mut res_buffer = BytePacketBuffer::new();
    packet.write(&mut res_buffer)?;

    let len = res_buffer.pos();
    let data = res_buffer.get_range(0, len)?;

    socket.send_to(data, src)?;

    Ok(())
}

fn main() -> Result<()> {
    // Bind an UDP socket on port 2053
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    // For now, queries are handled sequentially, so an infinite loop for servicing
    // requests is initiated.
    loop {
        match handle_query(&socket) {
            Ok(_) => {},
            Err(e) => eprintln!("An error occurred: {}", e),
        }
    }
}
