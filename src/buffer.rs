use crate::Result;

const BUF_SIZE: usize = 4096;

pub struct BytePacketBuffer {
    pub buf: [u8; BUF_SIZE],
    pub pos: usize,
}

impl Default for BytePacketBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl BytePacketBuffer {
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; BUF_SIZE],
            pos: 0,
        }
    }

    pub fn from_bytes(data: &[u8]) -> Self {
        let mut buf = Self::new();
        let len = data.len().min(BUF_SIZE);
        buf.buf[..len].copy_from_slice(&data[..len]);
        buf
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn filled(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    pub fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;
        Ok(())
    }

    pub fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;
        Ok(())
    }

    pub fn read(&mut self) -> Result<u8> {
        if self.pos >= BUF_SIZE {
            return Err("End of buffer".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;
        Ok(res)
    }

    pub fn get(&self, pos: usize) -> Result<u8> {
        if pos >= BUF_SIZE {
            return Err("End of buffer".into());
        }
        Ok(self.buf[pos])
    }

    pub fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len > BUF_SIZE {
            return Err("End of buffer".into());
        }
        Ok(&self.buf[start..start + len])
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);
        Ok(res)
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | (self.read()? as u32);
        Ok(res)
    }

    /// Read a qname, handling label compression (pointer jumps).
    /// Converts wire format like [3]www[6]google[3]com[0] into "www.google.com".
    ///
    /// Label bytes are escaped per RFC 1035 §5.1:
    /// - literal `.` within a label → `\.`
    /// - literal `\` → `\\`
    /// - bytes outside `0x21..=0x7E` (excluding `.` and `\`) → `\DDD` (3-digit decimal)
    pub fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        let mut pos = self.pos();
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;
        let mut delim = "";

        loop {
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
            }

            let len = self.get(pos)?;

            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.seek(pos + 2)?;
                }

                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                jumped = true;
                jumps_performed += 1;
                continue;
            } else {
                pos += 1;

                if len == 0 {
                    break;
                }

                outstr.push_str(delim);

                let str_buffer = self.get_range(pos, len as usize)?;
                for &b in str_buffer {
                    let c = b.to_ascii_lowercase();
                    match c {
                        b'.' => outstr.push_str("\\."),
                        b'\\' => outstr.push_str("\\\\"),
                        0x21..=0x7E => outstr.push(c as char),
                        _ => outstr.push_str(&format!("\\{:03}", c)),
                    }
                }

                delim = ".";
                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }

    pub fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= BUF_SIZE {
            return Err("End of buffer".into());
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    pub fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)
    }

    pub fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;
        Ok(())
    }

    pub fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write((val & 0xFF) as u8)?;
        Ok(())
    }

    /// Write a qname in wire format, parsing RFC 1035 §5.1 text escapes.
    ///
    /// Dots are label separators unless escaped as `\.`. `\\` yields a literal
    /// backslash, and `\DDD` (three decimal digits) yields an arbitrary byte.
    pub fn write_qname(&mut self, qname: &str) -> Result<()> {
        if qname.is_empty() || qname == "." {
            self.write_u8(0)?;
            return Ok(());
        }

        let labels = parse_escaped_labels(qname)?;
        for label in &labels {
            if label.len() > 0x3f {
                return Err("Single label exceeds 63 characters of length".into());
            }
            self.write_u8(label.len() as u8)?;
            for b in label {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)?;
        Ok(())
    }

    pub fn write_bytes(&mut self, data: &[u8]) -> Result<()> {
        let end = self.pos + data.len();
        if end > BUF_SIZE {
            return Err("End of buffer".into());
        }
        self.buf[self.pos..end].copy_from_slice(data);
        self.pos = end;
        Ok(())
    }

    pub fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        if pos >= BUF_SIZE {
            return Err("End of buffer".into());
        }
        self.buf[pos] = val;
        Ok(())
    }

    pub fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;
        Ok(())
    }
}

fn parse_escaped_labels(qname: &str) -> Result<Vec<Vec<u8>>> {
    let mut labels: Vec<Vec<u8>> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let mut chars = qname.chars();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(d1) if d1.is_ascii_digit() => {
                    let d2 = chars
                        .next()
                        .and_then(|c| c.to_digit(10))
                        .ok_or("invalid \\DDD escape: expected 3 digits")?;
                    let d3 = chars
                        .next()
                        .and_then(|c| c.to_digit(10))
                        .ok_or("invalid \\DDD escape: expected 3 digits")?;
                    let val = d1.to_digit(10).unwrap() * 100 + d2 * 10 + d3;
                    if val > 255 {
                        return Err(format!("\\DDD escape out of range: {}", val).into());
                    }
                    current.push(val as u8);
                }
                Some(other) => {
                    let mut buf = [0u8; 4];
                    current.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
                }
                None => return Err("trailing backslash in qname".into()),
            }
        } else if c == '.' {
            if !current.is_empty() {
                labels.push(std::mem::take(&mut current));
            }
        } else {
            let mut buf = [0u8; 4];
            current.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    if !current.is_empty() {
        labels.push(current);
    }
    Ok(labels)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(wire: &[u8]) -> String {
        let mut buf = BytePacketBuffer::from_bytes(wire);
        let mut out = String::new();
        buf.read_qname(&mut out).unwrap();
        out
    }

    fn write_then_read(text: &str) -> String {
        let mut buf = BytePacketBuffer::new();
        buf.write_qname(text).unwrap();
        let wire_end = buf.pos();
        buf.seek(0).unwrap();
        let mut out = String::new();
        buf.read_qname(&mut out).unwrap();
        assert_eq!(
            buf.pos(),
            wire_end,
            "reader should consume exactly what writer wrote"
        );
        out
    }

    #[test]
    fn read_plain_domain() {
        // [3]www[6]google[3]com[0]
        let wire = b"\x03www\x06google\x03com\x00";
        assert_eq!(roundtrip(wire), "www.google.com");
    }

    #[test]
    fn read_label_with_literal_dot_is_escaped() {
        // fanf2's example: [8]exa.mple[3]com[0] — two labels, first contains 0x2E
        let wire = b"\x08exa.mple\x03com\x00";
        assert_eq!(roundtrip(wire), "exa\\.mple.com");
    }

    #[test]
    fn read_label_with_backslash_is_escaped() {
        // [4]a\bc[3]com[0]
        let wire = b"\x04a\\bc\x03com\x00";
        assert_eq!(roundtrip(wire), "a\\\\bc.com");
    }

    #[test]
    fn read_label_with_nonprintable_byte_uses_decimal_escape() {
        // [4]\x00foo[3]com[0] — null byte at label start
        let wire = b"\x04\x00foo\x03com\x00";
        assert_eq!(roundtrip(wire), "\\000foo.com");
    }

    #[test]
    fn read_label_with_space_uses_decimal_escape() {
        // Space (0x20) is outside 0x21..=0x7E, so it must be decimal-escaped.
        let wire = b"\x05a b c\x00";
        assert_eq!(roundtrip(wire), "a\\032b\\032c");
    }

    #[test]
    fn write_plain_domain() {
        let mut buf = BytePacketBuffer::new();
        buf.write_qname("www.google.com").unwrap();
        assert_eq!(&buf.buf[..buf.pos], b"\x03www\x06google\x03com\x00");
    }

    #[test]
    fn write_escaped_dot_does_not_split_label() {
        let mut buf = BytePacketBuffer::new();
        buf.write_qname("exa\\.mple.com").unwrap();
        assert_eq!(&buf.buf[..buf.pos], b"\x08exa.mple\x03com\x00");
    }

    #[test]
    fn write_escaped_backslash() {
        let mut buf = BytePacketBuffer::new();
        buf.write_qname("a\\\\bc.com").unwrap();
        assert_eq!(&buf.buf[..buf.pos], b"\x04a\\bc\x03com\x00");
    }

    #[test]
    fn write_decimal_escape_yields_raw_byte() {
        let mut buf = BytePacketBuffer::new();
        buf.write_qname("\\000foo.com").unwrap();
        assert_eq!(&buf.buf[..buf.pos], b"\x04\x00foo\x03com\x00");
    }

    #[test]
    fn write_rejects_out_of_range_decimal_escape() {
        let mut buf = BytePacketBuffer::new();
        assert!(buf.write_qname("\\999foo.com").is_err());
    }

    #[test]
    fn write_rejects_trailing_backslash() {
        let mut buf = BytePacketBuffer::new();
        assert!(buf.write_qname("foo\\").is_err());
    }

    #[test]
    fn write_rejects_short_decimal_escape() {
        let mut buf = BytePacketBuffer::new();
        assert!(buf.write_qname("\\1").is_err());
    }

    #[test]
    fn roundtrip_preserves_dot_in_label() {
        assert_eq!(write_then_read("exa\\.mple.com"), "exa\\.mple.com");
    }

    #[test]
    fn roundtrip_preserves_backslash_in_label() {
        assert_eq!(write_then_read("a\\\\b.com"), "a\\\\b.com");
    }

    #[test]
    fn roundtrip_preserves_nonprintable_byte() {
        assert_eq!(write_then_read("\\000foo.com"), "\\000foo.com");
    }

    #[test]
    fn root_name_empty_and_dot_both_produce_single_zero() {
        let mut a = BytePacketBuffer::new();
        a.write_qname("").unwrap();
        let mut b = BytePacketBuffer::new();
        b.write_qname(".").unwrap();
        assert_eq!(&a.buf[..a.pos], b"\x00");
        assert_eq!(&b.buf[..b.pos], b"\x00");
    }
}
