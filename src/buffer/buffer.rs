use crate::utils::types::Result;

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

/// BytePacketBuffer provides a convinient method of manipulating the packets

impl BytePacketBuffer {
    ///This gives us a fresh new BytePacketBuffer for holding the packet contents
    /// and a field for keeping track of where we are in the buffer
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    //current position in the buffer
    pub fn pos(&self) -> usize {
        self.pos
    }

    //step the buffer position forward a certain number of position
    pub fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;
        Ok(())
    }

    //change the buffer position
    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;
        Ok(())
    }

    // read a single byte and move the position forward
    pub fn read(&mut self) -> Result<u8> {
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
    pub fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len > 512 {
            return Err("End of buffer".into());
        }
        Ok(&self.buf[start..start + len as usize])
    }

    //read two bytes stepping two bytes forward
    pub fn read_u16(&mut self) -> Result<u16> {
        let res = (self.read()? as u16) << 8 | (self.read()? as u16);
        Ok(res as u16)
    }

    //read four bytes stepping four bytes forward
    pub fn read_u32(&mut self) -> Result<u32> {
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
    pub fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
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
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
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
                let offset = ((len as u16) ^ 0xC0) << 8 | b2;
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
    pub fn write_u8(&mut self, byte: u8) -> Result<()> {
        self.write(byte)?;
        Ok(())
    }

    //write_u16 writes two bytes
    pub fn write_u16(&mut self, byte: u16) -> Result<()> {
        self.write((byte >> 8) as u8)?;
        self.write((byte & 0xff) as u8)?;
        Ok(())
    }

    //write_u32 writes four bytes
    pub fn write_u32(&mut self, byte: u32) -> Result<()> {
        self.write((byte >> 24) as u8)?;
        self.write((byte >> 16) as u8)?;
        self.write((byte >> 8) as u8)?;
        self.write((byte >> 0) as u8)?;
        Ok(())
    }

    //write_qname write query names in labeled form
    pub fn write_qname(&mut self, q_name: &str) -> Result<()> {
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

    pub fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn create_byte_packet_buffer() -> BytePacketBuffer {
        BytePacketBuffer::new()
    }
    #[test]
    fn test_create_byte_packet_buffer() {
        let buffer = create_byte_packet_buffer();
        assert_eq!(buffer.pos(), 0);
    }
    #[test]
    fn test_get_range_from_buffer() {
        let mut buffer = create_byte_packet_buffer();
        let result = buffer.get_range(0, 10);
        assert!(result.is_ok());
        let right_val = result.unwrap();

        assert_eq!(right_val, vec![0; 10]);
    }
    #[test]
    fn test_write_single_byte() {
        let mut buffer = create_byte_packet_buffer();
        buffer.write_u8(0x12).unwrap();
        assert_eq!(buffer.pos(), 1);
    }
    #[test]
    fn test_write_two_bytes() {
        let mut buffer = create_byte_packet_buffer();
        buffer.write_u16(0x1234).unwrap();
        assert_eq!(buffer.pos(), 2);
    }
    #[test]
    fn test_write_four_bytes() {
        let mut buffer = create_byte_packet_buffer();
        buffer.write_u32(0x12345678).unwrap();
        assert_eq!(buffer.pos(), 4);
    }

    #[test]
    fn test_read_single_byte() {
        let mut buffer = create_byte_packet_buffer();
        buffer.write_u8(0x12).unwrap();
        let result = buffer.read();
        assert!(result.is_ok());
    }
    #[test]
    fn test_read_two_bytes() {
        let mut buffer = create_byte_packet_buffer();
        buffer.write_u16(0x1234).unwrap();
        let result = buffer.read_u16();
        assert!(result.is_ok());
    }
    #[test]
    fn test_read_four_bytes() {
        let mut buffer = create_byte_packet_buffer();
        buffer.write_u32(0x12345678).unwrap();
        let result = buffer.read_u32();
        assert!(result.is_ok());
    }
    #[test]
    fn test_write_qname() {
        let mut buffer = create_byte_packet_buffer();
        buffer.write_qname("www.example.com").unwrap();
        assert_eq!(buffer.pos(), 17);
    }
    #[test]
    fn test_read_qname() {
        let mut buffer = create_byte_packet_buffer();
        buffer.write_qname("www.example.com").unwrap();
        let result = buffer.read_qname(&mut "www.example.com".to_owned());
        assert!(result.is_ok());
    }
}
