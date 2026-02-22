use std::str::from_utf8;

/// A simple, zero-copy cursor for parsing byte slices.
struct Parser<'a> {
    buffer: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, pos: 0 }
    }

    /// Returns the number of bytes remaining.
    fn remaining(&self) -> usize {
        self.buffer.len().saturating_sub(self.pos)
    }

    /// Reads a single u8.
    fn read_u8(&mut self) -> Option<u8> {
        if self.pos < self.buffer.len() {
            let b = self.buffer[self.pos];
            self.pos += 1;
            Some(b)
        } else {
            None
        }
    }

    /// Reads a u16 (Big Endian).
    fn read_u16(&mut self) -> Option<u16> {
        if self.remaining() >= 2 {
            let val = u16::from_be_bytes([self.buffer[self.pos], self.buffer[self.pos + 1]]);
            self.pos += 2;
            Some(val)
        } else {
            None
        }
    }

    /// Skips n bytes.
    fn skip(&mut self, n: usize) -> Option<()> {
        if self.remaining() >= n {
            self.pos += n;
            Some(())
        } else {
            None
        }
    }

    /// Returns a slice of n bytes.
    fn read_slice(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() >= n {
            let slice = &self.buffer[self.pos..self.pos + n];
            self.pos += n;
            Some(slice)
        } else {
            None
        }
    }
}

/// Attempts to parse the SNI (Server Name Indication) from a TLS ClientHello.
/// Returns None if the buffer is incomplete, invalid, or SNI is missing.
pub fn parse_sni(buffer: &[u8]) -> Option<String> {
    let mut p = Parser::new(buffer);

    // 1. TLS Record Header (5 bytes)
    // Type (1) | Version (2) | Length (2)
    let record_type = p.read_u8()?;
    if record_type != 0x16 {
        return None; // Not a Handshake record
    }
    p.skip(2)?; // Skip Version
    p.skip(2)?; // Skip Length

    // 2. Handshake Header (4 bytes)
    // Type (1) | Length (3)
    let handshake_type = p.read_u8()?;
    if handshake_type != 0x01 {
        return None; // Not a ClientHello
    }
    p.skip(3)?; // Skip Handshake Length (u24)

    // 3. ClientHello Body
    p.skip(2)?; // Legacy Version
    p.skip(32)?; // Random

    // Session ID
    let session_id_len = p.read_u8()? as usize;
    p.skip(session_id_len)?;

    // Cipher Suites
    let cipher_suites_len = p.read_u16()? as usize;
    p.skip(cipher_suites_len)?;

    // Compression Methods
    let compression_len = p.read_u8()? as usize;
    p.skip(compression_len)?;

    // 4. Extensions
    if p.remaining() < 2 {
        return None; // No extensions present
    }
    let extensions_len = p.read_u16()? as usize;

    // Create a sub-parser for extensions to avoid reading past the declared length
    let ext_bytes = p.read_slice(extensions_len)?;
    let mut ext_p = Parser::new(ext_bytes);

    while ext_p.remaining() >= 4 {
        let ext_type = ext_p.read_u16()?;
        let ext_len = ext_p.read_u16()? as usize;
        let ext_data = ext_p.read_slice(ext_len)?;

        // Extension Type 0x0000 is Server Name (SNI)
        if ext_type == 0x0000 {
            return parse_sni_extension(ext_data);
        }
    }

    None
}

/// Parses the body of the SNI extension.
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    let mut p = Parser::new(data);

    let list_len = p.read_u16()? as usize;
    if list_len != p.remaining() {
        return None; // Malformed list length
    }

    // Iterate over NameList
    while p.remaining() > 0 {
        let name_type = p.read_u8()?; // 0x00 = HostName
        let name_len = p.read_u16()? as usize;
        let name_bytes = p.read_slice(name_len)?;

        if name_type == 0x00 {
            return from_utf8(name_bytes).ok().map(|s| s.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sni_parsing_google() {
        // A captured real ClientHello header for "google.com"
        // Corrected lengths for consistency.
        let data: Vec<u8> = vec![
            0x16, // Record: Handshake
            0x03, 0x01, // Version: TLS 1.0
            0x00, 0xC2, // Length: 194 (Header + Body)
            0x01, // Handshake: ClientHello
            0x00, 0x00, 0xBE, // Length: 190 (Body)
            0x03, 0x03, // Version: TLS 1.2
            // Random (32 bytes)
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x00, // Session ID Len: 0
            0x00, 0x02, // Cipher Suites Len: 2
            0x13, 0x01, // Cipher: TLS_AES_128_GCM_SHA256
            0x01, // Compression Len: 1
            0x00, // Null
            0x00, 0x13, // Extensions Len: 19 (Total length of all extensions)
            // Extension: SNI (0x0000)
            0x00, 0x00, // Type
            0x00, 0x0F, // Length: 15 (Size of ListLen + Entry)
            // SNI Payload
            0x00, 0x0D, // List Length: 13 (Size of Entry)
            0x00, // Name Type: HostName
            0x00, 0x0A, // Name Length: 10
            // "google.com"
            0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        ];

        let sni = parse_sni(&data);
        assert_eq!(sni, Some("google.com".to_string()));
    }

    #[test]
    fn test_truncated_packet() {
        let data = vec![0x16, 0x03]; // Incomplete header
        assert_eq!(parse_sni(&data), None);
    }
}
