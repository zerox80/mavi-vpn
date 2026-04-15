/// Decode a lowercase or uppercase hexadecimal string into bytes.
/// Returns `None` if the string has an odd length or contains non-hex characters.
pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
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
}
