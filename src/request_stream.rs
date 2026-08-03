//! Request-side HTTP/1.1 stream framing for the MITM path.
//!
//! The proxy previously inspected only the first read of a connection, which
//! silently disabled request rewriting in three common cases:
//!
//! 1. HTTP/1.1 keep-alive — only the first request on a connection was seen.
//! 2. Binary request bodies — UTF-8 validation ran over head *and* body.
//! 3. Head split across reads — no complete `\r\n\r\n` in the first buffer.
//!
//! This module reassembles request heads across reads and re-arms inspection at
//! each request boundary, so rewriting applies per request rather than per
//! connection. It is deliberately conservative: whenever framing cannot be
//! determined with certainty, it degrades to raw passthrough for the remainder
//! of the connection rather than risk corrupting or stalling a body.

/// Maximum bytes buffered while waiting for a complete request head.
pub const MAX_REQUEST_HEAD_BYTES: usize = 64 * 1024;

const HEAD_TERMINATOR: &[u8] = b"\r\n\r\n";

/// What the caller should do with the bytes just read.
#[derive(Debug, PartialEq, Eq)]
pub enum Emit {
    /// Nothing to forward yet — an incomplete head is still buffering.
    Nothing,
    /// Forward these bytes; `head_len` leading bytes are an inspectable request
    /// head (0 when the payload is body or opaque passthrough).
    Forward { bytes: Vec<u8>, head_len: usize },
}

#[derive(Debug, PartialEq, Eq)]
enum State {
    /// Accumulating a request head.
    Head,
    /// Forwarding a body of known remaining length.
    Body { remaining: usize },
    /// Framing unknown (chunked, upgrade, oversized head) — forward verbatim
    /// and never inspect again on this connection.
    Passthrough,
}

/// Reassembles request heads and tracks request boundaries on one connection.
#[derive(Debug)]
pub struct RequestStream {
    state: State,
    pending: Vec<u8>,
}

impl Default for RequestStream {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestStream {
    pub fn new() -> Self {
        Self {
            state: State::Head,
            pending: Vec::new(),
        }
    }

    /// True once framing has been abandoned for this connection.
    ///
    /// Currently exercised by tests; kept public as the natural hook for
    /// metrics on how often framing degrades in the field.
    #[allow(dead_code)]
    pub fn is_passthrough(&self) -> bool {
        matches!(self.state, State::Passthrough)
    }

    /// Feed one read from the client.
    pub fn push(&mut self, chunk: &[u8]) -> Emit {
        match self.state {
            State::Passthrough => Emit::Forward {
                bytes: chunk.to_vec(),
                head_len: 0,
            },
            State::Body { remaining } => {
                let consumed = remaining.min(chunk.len());
                self.state = if remaining == consumed {
                    // Body complete — re-arm inspection for the next request.
                    State::Head
                } else {
                    State::Body {
                        remaining: remaining - consumed,
                    }
                };
                // Any bytes past the body belong to the next request; buffer
                // them so the following head is not missed.
                if consumed < chunk.len() {
                    let leftover = chunk[consumed..].to_vec();
                    let mut out = chunk[..consumed].to_vec();
                    match self.push(&leftover) {
                        Emit::Nothing => {}
                        Emit::Forward { bytes, .. } => out.extend_from_slice(&bytes),
                    }
                    // The head offset is no longer at position 0, so the caller
                    // must not treat this as inspectable.
                    return Emit::Forward {
                        bytes: out,
                        head_len: 0,
                    };
                }
                Emit::Forward {
                    bytes: chunk.to_vec(),
                    head_len: 0,
                }
            }
            State::Head => {
                self.pending.extend_from_slice(chunk);

                let Some(term) = find_subslice(&self.pending, HEAD_TERMINATOR) else {
                    if self.pending.len() > MAX_REQUEST_HEAD_BYTES {
                        // Refuse to buffer unbounded; forward what we have.
                        self.state = State::Passthrough;
                        let bytes = std::mem::take(&mut self.pending);
                        return Emit::Forward { bytes, head_len: 0 };
                    }
                    return Emit::Nothing;
                };

                let head_len = term + HEAD_TERMINATOR.len();
                let buf = std::mem::take(&mut self.pending);

                match body_framing(&buf[..head_len]) {
                    Framing::Length(len) => {
                        let carried = buf.len() - head_len;
                        self.state = if carried >= len {
                            State::Head
                        } else {
                            State::Body {
                                remaining: len - carried,
                            }
                        };
                        if carried > len {
                            // Pipelined: a following request is already here.
                            // Re-feed the surplus so its head is framed too.
                            let surplus = buf[head_len + len..].to_vec();
                            let mut out = buf[..head_len + len].to_vec();
                            if let Emit::Forward { bytes, .. } = self.push(&surplus) {
                                out.extend_from_slice(&bytes);
                            }
                            return Emit::Forward {
                                bytes: out,
                                head_len,
                            };
                        }
                        Emit::Forward {
                            bytes: buf,
                            head_len,
                        }
                    }
                    Framing::Unknown => {
                        self.state = State::Passthrough;
                        Emit::Forward {
                            bytes: buf,
                            head_len,
                        }
                    }
                }
            }
        }
    }

    /// Bytes still buffered in an incomplete head, to flush on shutdown so a
    /// partial request is never swallowed.
    pub fn take_pending(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending)
    }
}

enum Framing {
    Length(usize),
    Unknown,
}

/// Determine request body framing from a complete head.
///
/// Only `Content-Length` and bodiless requests are framed. Chunked encoding and
/// protocol upgrades return `Unknown` so the caller degrades to passthrough.
fn body_framing(head: &[u8]) -> Framing {
    let mut length: Option<usize> = None;

    for line in head.split(|&b| b == b'\n') {
        let line = trim_ascii(line);
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let name = &line[..colon];
        let value = trim_ascii(&line[colon + 1..]);

        if name.eq_ignore_ascii_case(b"transfer-encoding") || name.eq_ignore_ascii_case(b"upgrade")
        {
            return Framing::Unknown;
        }
        if name.eq_ignore_ascii_case(b"content-length") {
            let Ok(text) = std::str::from_utf8(value) else {
                return Framing::Unknown;
            };
            match text.trim().parse::<usize>() {
                Ok(parsed) => length = Some(parsed),
                Err(_) => return Framing::Unknown,
            }
        }
    }

    Framing::Length(length.unwrap_or(0))
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = bytes {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = bytes {
        if last.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forward(emit: Emit) -> (Vec<u8>, usize) {
        match emit {
            Emit::Forward { bytes, head_len } => (bytes, head_len),
            Emit::Nothing => panic!("expected Forward, got Nothing"),
        }
    }

    #[test]
    fn simple_get_is_inspectable() {
        let mut s = RequestStream::new();
        let req = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n";
        let (bytes, head_len) = forward(s.push(req));
        assert_eq!(bytes, req);
        assert_eq!(head_len, req.len());
    }

    #[test]
    fn head_split_across_reads_is_reassembled() {
        let mut s = RequestStream::new();
        assert_eq!(s.push(b"GET /a HTTP/1.1\r\nHo"), Emit::Nothing);
        let (bytes, head_len) = forward(s.push(b"st: x\r\n\r\n"));
        assert_eq!(bytes, b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(head_len, bytes.len());
    }

    #[test]
    fn second_request_on_keepalive_is_still_inspected() {
        let mut s = RequestStream::new();
        let (_, first) = forward(s.push(b"GET /1 HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert!(first > 0);
        let (_, second) = forward(s.push(b"GET /2 HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert!(second > 0, "second keep-alive request must be inspectable");
    }

    #[test]
    fn binary_body_does_not_block_head_inspection() {
        let mut s = RequestStream::new();
        let mut req = b"POST /u HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\n".to_vec();
        let head_len = req.len();
        req.extend_from_slice(&[0xff, 0xfe, 0x00, 0x80]); // invalid UTF-8
        let (bytes, got) = forward(s.push(&req));
        assert_eq!(
            got, head_len,
            "head must be inspectable despite binary body"
        );
        assert_eq!(bytes, req, "body bytes must survive untouched");
    }

    #[test]
    fn large_body_spanning_reads_re_arms_after_completion() {
        let mut s = RequestStream::new();
        let head = b"POST /u HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n";
        forward(s.push(head));
        forward(s.push(&[b'A'; 6]));
        assert!(!s.is_passthrough());
        forward(s.push(&[b'A'; 4])); // body now complete
        let (_, head_len) = forward(s.push(b"GET /next HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert!(head_len > 0, "next request after body must be inspectable");
    }

    #[test]
    fn body_bytes_are_never_mistaken_for_a_head() {
        let mut s = RequestStream::new();
        let head = b"POST /u HTTP/1.1\r\nHost: x\r\nContent-Length: 30\r\n\r\n";
        forward(s.push(head));
        // Body that itself looks like an HTTP request head.
        let (_, head_len) = forward(s.push(b"GET /evil HTTP/1.1\r\nHost: y\r\n\r\n"));
        assert_eq!(head_len, 0, "body must not be inspected as a head");
    }

    #[test]
    fn chunked_degrades_to_passthrough_not_corruption() {
        let mut s = RequestStream::new();
        let req = b"POST /u HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n";
        let (_, head_len) = forward(s.push(req));
        assert!(head_len > 0, "the chunked head itself is still inspectable");
        assert!(s.is_passthrough());
        let (bytes, later) = forward(s.push(b"5\r\nhello\r\n0\r\n\r\n"));
        assert_eq!(
            bytes, b"5\r\nhello\r\n0\r\n\r\n",
            "chunk bytes forwarded verbatim"
        );
        assert_eq!(later, 0);
    }

    #[test]
    fn websocket_upgrade_degrades_to_passthrough() {
        let mut s = RequestStream::new();
        let req = b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\r\n";
        forward(s.push(req));
        assert!(
            s.is_passthrough(),
            "upgraded connections must not be reframed"
        );
    }

    #[test]
    fn oversized_head_degrades_without_unbounded_buffering() {
        let mut s = RequestStream::new();
        let big = vec![b'x'; MAX_REQUEST_HEAD_BYTES + 1];
        let (bytes, head_len) = forward(s.push(&big));
        assert_eq!(head_len, 0);
        assert_eq!(bytes.len(), big.len(), "buffered bytes must not be dropped");
        assert!(s.is_passthrough());
    }

    #[test]
    fn no_bytes_are_lost_across_a_full_exchange() {
        let mut s = RequestStream::new();
        let mut seen = Vec::new();
        let reads: Vec<&[u8]> = vec![
            b"POST /u HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nab",
            b"cde",
            b"GET /after HTTP/1.1\r\nHost: x\r\n\r\n",
        ];
        for r in &reads {
            if let Emit::Forward { bytes, .. } = s.push(r) {
                seen.extend_from_slice(&bytes);
            }
        }
        let expected: Vec<u8> = reads.concat();
        assert_eq!(seen, expected, "byte stream must be preserved exactly");
    }
}
