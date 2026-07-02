/// Decode a lowercase or uppercase hexadecimal string into bytes.
/// Returns `None` if the string has an odd length or contains non-hex characters.
#[must_use]
pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
    // The byte-offset slicing below panics on non-char-boundaries, so reject
    // any non-ASCII input up front (it cannot be valid hex anyway).
    if !s.is_ascii() || !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Parses a `cert_pin` config value that may contain one or more
/// comma-separated SHA-256 hex fingerprints (64 hex chars each). Supports the
/// dual-pin rotation workflow: during a manual cert rotation window an admin
/// sets this to `"<old_pin>,<new_pin>"` so already-deployed clients keep
/// trusting the old cert while newly-configured clients pick up the new one;
/// the server itself only ever writes a single pin to `cert_pin.txt`.
///
/// Fails closed: an empty string, an empty segment (leading/trailing/double
/// comma), a segment of the wrong length, or invalid hex all return `None`
/// rather than silently accepting a partial or malformed pin list.
#[must_use]
pub fn decode_hex_pins(s: &str) -> Option<Vec<Vec<u8>>> {
    let pins: Option<Vec<Vec<u8>>> = s
        .split(',')
        .map(|segment| {
            let bytes = decode_hex(segment.trim())?;
            (bytes.len() == 32).then_some(bytes)
        })
        .collect();
    pins.filter(|p| !p.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_hex_valid() {
        assert_eq!(decode_hex("deadbeef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(decode_hex(""), Some(vec![]));
        assert_eq!(decode_hex("00ff"), Some(vec![0x00, 0xff]));
    }

    #[test]
    fn decode_hex_uppercase() {
        assert_eq!(decode_hex("DEADBEEF"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn decode_hex_odd_length() {
        assert_eq!(decode_hex("abc"), None);
    }

    #[test]
    fn decode_hex_invalid_chars() {
        assert_eq!(decode_hex("zz"), None);
    }

    #[test]
    fn decode_hex_non_ascii_returns_none_instead_of_panicking() {
        // Multi-byte UTF-8 with an even byte length used to panic on a
        // non-char-boundary slice (`&s[i..i+2]`).
        assert_eq!(decode_hex("€€"), None); // 6 bytes
        assert_eq!(decode_hex("aé"), None); // 3 bytes, odd
        assert_eq!(decode_hex("aaé"), None); // 4 bytes, boundary splits 'é'
        assert_eq!(decode_hex("ÿÿ"), None); // 4 bytes, all non-ASCII
    }

    #[test]
    fn decode_hex_mixed_case() {
        assert_eq!(decode_hex("dEaDbEeF"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    proptest::proptest! {
        #[test]
        fn hex_roundtrip_proptest(bytes in proptest::collection::vec(0u8..=255, 0..100)) {
            use std::fmt::Write;
            let mut hex_str = String::with_capacity(bytes.len() * 2);
            for b in &bytes {
                let _ = write!(hex_str, "{b:02x}");
            }
            let decoded = decode_hex(&hex_str).unwrap();
            assert_eq!(decoded, bytes);
        }
    }

    #[test]
    fn decode_hex_single_byte() {
        assert_eq!(decode_hex("ff"), Some(vec![0xff]));
        assert_eq!(decode_hex("00"), Some(vec![0x00]));
        assert_eq!(decode_hex("01"), Some(vec![0x01]));
    }

    fn pin(byte: u8) -> String {
        hex_of(&[byte; 32])
    }

    fn hex_of(bytes: &[u8]) -> String {
        use std::fmt::Write;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    #[test]
    fn decode_hex_pins_single_pin() {
        let pin_a = pin(0xaa);
        assert_eq!(decode_hex_pins(&pin_a), Some(vec![vec![0xaa; 32]]));
    }

    #[test]
    fn decode_hex_pins_two_pins_comma_separated() {
        let combined = format!("{},{}", pin(0xaa), pin(0xbb));
        assert_eq!(
            decode_hex_pins(&combined),
            Some(vec![vec![0xaa; 32], vec![0xbb; 32]])
        );
    }

    #[test]
    fn decode_hex_pins_trims_whitespace_around_commas() {
        let combined = format!("{} , {}", pin(0xaa), pin(0xbb));
        assert_eq!(
            decode_hex_pins(&combined),
            Some(vec![vec![0xaa; 32], vec![0xbb; 32]])
        );
    }

    #[test]
    fn decode_hex_pins_rejects_empty_string() {
        assert_eq!(decode_hex_pins(""), None);
    }

    #[test]
    fn decode_hex_pins_rejects_trailing_comma() {
        let s = format!("{},", pin(0xaa));
        assert_eq!(decode_hex_pins(&s), None);
    }

    #[test]
    fn decode_hex_pins_rejects_double_comma() {
        let s = format!("{},,{}", pin(0xaa), pin(0xbb));
        assert_eq!(decode_hex_pins(&s), None);
    }

    #[test]
    fn decode_hex_pins_rejects_wrong_length_segment() {
        assert_eq!(decode_hex_pins("aabbcc"), None);
    }

    #[test]
    fn decode_hex_pins_rejects_invalid_hex_segment() {
        let s = "z".repeat(64);
        assert_eq!(decode_hex_pins(&s), None);
    }

    proptest::proptest! {
        #[test]
        fn decode_hex_pins_roundtrip_proptest(
            pins in proptest::collection::vec(
                proptest::collection::vec(0u8..=255, 32..=32),
                1..=4,
            )
        ) {
            let joined = pins.iter().map(|p| hex_of(p)).collect::<Vec<_>>().join(",");
            assert_eq!(decode_hex_pins(&joined), Some(pins));
        }
    }
}
