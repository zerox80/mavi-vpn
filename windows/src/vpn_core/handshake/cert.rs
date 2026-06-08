use sha2::{Digest, Sha256};

pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
/// Custom certificate verifier that trusts only a specific SHA-256 fingerprint.
#[derive(Debug)]
pub(super) struct PinnedServerVerifier {
    expected_hash: Vec<u8>,
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PinnedServerVerifier {
    pub(super) fn new(expected_hash: Vec<u8>) -> Self {
        Self {
            expected_hash,
            supported: rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms,
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let cert_hash = Sha256::digest(end_entity.as_ref());
        if cert_hash.as_slice() == self.expected_hash.as_slice() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("Certificate PIN mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_hex_empty_string() {
        assert_eq!(decode_hex(""), Some(vec![]));
    }

    #[test]
    fn decode_hex_valid_lowercase() {
        assert_eq!(decode_hex("deadbeef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn decode_hex_valid_uppercase() {
        assert_eq!(decode_hex("DEADBEEF"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn decode_hex_valid_mixed_case() {
        assert_eq!(decode_hex("DeAdBeEf"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn decode_hex_odd_length_returns_none() {
        assert_eq!(decode_hex("abc"), None);
        assert_eq!(decode_hex("1"), None);
        assert_eq!(decode_hex("deadbee"), None);
    }

    #[test]
    fn decode_hex_invalid_chars_returns_none() {
        assert_eq!(decode_hex("gg"), None);
        assert_eq!(decode_hex("zzzz"), None);
        assert_eq!(decode_hex("12abXX"), None);
    }

    #[test]
    fn decode_hex_single_byte() {
        assert_eq!(decode_hex("ff"), Some(vec![0xff]));
        assert_eq!(decode_hex("00"), Some(vec![0x00]));
    }

    #[test]
    fn decode_hex_all_zeros() {
        assert_eq!(decode_hex("00000000"), Some(vec![0, 0, 0, 0]));
    }

    #[test]
    fn decode_hex_all_ff() {
        assert_eq!(decode_hex("ffffffff"), Some(vec![0xff, 0xff, 0xff, 0xff]));
    }
}
