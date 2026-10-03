//! Shared HTTP/2 transport tuning and response-prefix validation.

/// Initial receive window advertised by clients for the CONNECT-IP stream.
///
/// HTTP/2 defaults to 65,535 bytes, which is far below the bandwidth-delay
/// product of typical mobile links and throttles server-to-client traffic.
pub const CLIENT_INITIAL_STREAM_WINDOW_SIZE: u32 = 4 * 1024 * 1024;

/// Initial receive window advertised by clients for the entire connection.
///
/// CONNECT-IP currently uses one long-lived stream, so the connection window
/// must be at least as large as the stream window or it remains the bottleneck.
pub const CLIENT_INITIAL_CONNECTION_WINDOW_SIZE: u32 = CLIENT_INITIAL_STREAM_WINDOW_SIZE;

const _: () = assert!(CLIENT_INITIAL_STREAM_WINDOW_SIZE > 65_535);
const _: () = assert!(CLIENT_INITIAL_CONNECTION_WINDOW_SIZE >= CLIENT_INITIAL_STREAM_WINDOW_SIZE);

/// Probe only the beginning of a response, across DATA fragmentation. Once the
/// stream starts with capsule bytes, later payloads must never be sniffed as HTML.
#[derive(Default)]
pub struct ResponsePrefixProbe {
    prefix: [u8; 9],
    len: usize,
    finished: bool,
}

impl ResponsePrefixProbe {
    pub fn is_html(&mut self, chunk: &[u8]) -> bool {
        for &byte in chunk {
            if self.finished {
                return false;
            }
            if self.len == 0 && byte.is_ascii_whitespace() {
                continue;
            }
            self.prefix[self.len] = byte;
            self.len += 1;
            let prefix = &self.prefix[..self.len];
            if crate::looks_like_html_response(prefix) {
                self.finished = true;
                return true;
            }
            self.finished = ![b"<html".as_slice(), b"<!doctype".as_slice()]
                .iter()
                .any(|pattern| {
                    pattern.len() >= prefix.len()
                        && pattern[..prefix.len()].eq_ignore_ascii_case(prefix)
                });
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fragmented_html_and_capsule_payloads_are_distinguished() {
        let mut probe = ResponsePrefixProbe::default();
        assert!(!probe.is_html(b" \r\n<ht"));
        assert!(probe.is_html(b"ML><body>"));
        let mut probe = ResponsePrefixProbe::default();
        assert!(!probe.is_html(&[7, 5]));
        assert!(!probe.is_html(b"<html"));
        let mut probe = ResponsePrefixProbe::default();
        assert!(!probe.is_html(b"<!DOC"));
        assert!(probe.is_html(b"TYPE html>"));
    }
}
