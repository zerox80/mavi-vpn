//! Android-side ECHConfigList parser — public_name only.
//!
//! Android uses the `ring` crypto provider, which does NOT expose HPKE in
//! rustls 0.23. We therefore cannot offer ECH GREASE (it requires a real HPKE
//! suite instance). What we *can* do is read the `public_name` from the
//! admin-provided `ECHConfigList` and use it as the outer SNI on the wire.
//! Because the server authenticates via SHA-256 cert pinning and ignores the
//! SNI, spoofing it gives us the core censorship-resistance benefit even
//! without full ECH.

use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::internal::msgs::handshake::EchConfigPayload;

/// Decode a hex string into bytes. Returns `None` on any parse error.
pub use shared::hex::decode_hex;

/// Extract the first V18 entry's `public_name` from an `ECHConfigList`. Returns
/// `None` when no V18 entry is present or the list fails to decode.
pub fn outer_sni_from_hex(hex: &str) -> Option<String> {
    outer_sni_from_bytes(&decode_hex(hex)?)
}

pub fn outer_sni_from_bytes(bytes: &[u8]) -> Option<String> {
    let mut reader = Reader::init(bytes);
    let payloads: Vec<EchConfigPayload> = Vec::read(&mut reader).ok()?;
    for payload in payloads {
        if let EchConfigPayload::V18(contents) = payload {
            return Some(contents.public_name.as_ref().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outer_sni_from_bytes_empty() {
        assert!(outer_sni_from_bytes(&[]).is_none());
    }

    #[test]
    fn outer_sni_from_bytes_garbage() {
        assert!(outer_sni_from_bytes(&[0xDE, 0xAD]).is_none());
    }

    #[test]
    fn outer_sni_from_hex_invalid() {
        assert!(outer_sni_from_hex("zz").is_none());
    }

    #[test]
    fn outer_sni_from_hex_odd_length() {
        assert!(outer_sni_from_hex("abc").is_none());
    }
}
