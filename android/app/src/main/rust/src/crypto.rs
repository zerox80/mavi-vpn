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

#[derive(Debug)]
pub struct PinnedServerVerifier {
    pub expected_hash: Vec<u8>,
    pub supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PinnedServerVerifier {
    pub fn new(expected_hash: Vec<u8>) -> Self {
        Self {
            expected_hash,
            supported: rustls::crypto::ring::default_provider().signature_verification_algorithms,
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
            Err(rustls::Error::General("Pin mismatch".into()))
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
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    #[test]
    fn decode_hex_valid() {
        assert_eq!(decode_hex("deadbeef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(decode_hex(""), Some(vec![]));
        assert_eq!(decode_hex("00ff"), Some(vec![0x00, 0xff]));
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
    fn decode_hex_uppercase() {
        assert_eq!(decode_hex("DEADBEEF"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn pinned_verifier_new_stores_hash() {
        let hash = vec![0x01, 0x02, 0x03];
        let verifier = PinnedServerVerifier::new(hash.clone());
        assert_eq!(verifier.expected_hash, hash);
    }

    #[test]
    fn pinned_verifier_accepts_matching_certificate_hash() {
        let cert = CertificateDer::from(vec![0x42; 32]);
        let expected_hash = Sha256::digest(cert.as_ref()).to_vec();
        let verifier = PinnedServerVerifier::new(expected_hash);

        let result = verifier.verify_server_cert(
            &cert,
            &[],
            &ServerName::try_from("vpn.example.com").unwrap(),
            &[],
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(1)),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn pinned_verifier_rejects_mismatched_certificate_hash() {
        let verifier = PinnedServerVerifier::new(vec![0x00; 32]);
        let cert = CertificateDer::from(vec![0x42; 32]);

        let err = verifier
            .verify_server_cert(
                &cert,
                &[],
                &ServerName::try_from("vpn.example.com").unwrap(),
                &[],
                UnixTime::since_unix_epoch(std::time::Duration::from_secs(1)),
            )
            .unwrap_err();

        assert!(err.to_string().contains("Pin mismatch"));
    }

    #[test]
    fn pinned_verifier_exposes_supported_signature_schemes() {
        let verifier = PinnedServerVerifier::new(vec![0x00; 32]);

        assert!(!verifier.supported_verify_schemes().is_empty());
    }
}
