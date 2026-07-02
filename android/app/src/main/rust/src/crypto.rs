pub use shared::hex::decode_hex_pins;

#[derive(Debug)]
pub struct PinnedServerVerifier {
    pub expected_hashes: Vec<Vec<u8>>,
    pub supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PinnedServerVerifier {
    pub fn new(expected_hashes: Vec<Vec<u8>>) -> Self {
        Self {
            expected_hashes,
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
        if shared::cert_pin::matches_any_pin(end_entity.as_ref(), &self.expected_hashes) {
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
    use sha2::{Digest, Sha256};

    #[test]
    fn decode_hex_pins_valid() {
        let pin = "aa".repeat(32);
        assert_eq!(decode_hex_pins(&pin), Some(vec![vec![0xaa; 32]]));
    }

    #[test]
    fn decode_hex_pins_rejects_odd_length() {
        assert_eq!(decode_hex_pins("abc"), None);
    }

    #[test]
    fn decode_hex_pins_rejects_invalid_chars() {
        assert_eq!(decode_hex_pins(&"z".repeat(64)), None);
    }

    #[test]
    fn pinned_verifier_new_stores_hashes() {
        let hash = vec![vec![0x01; 32]];
        let verifier = PinnedServerVerifier::new(hash.clone());
        assert_eq!(verifier.expected_hashes, hash);
    }

    #[test]
    fn pinned_verifier_accepts_matching_certificate_hash() {
        let cert = CertificateDer::from(vec![0x42; 32]);
        let expected_hash = Sha256::digest(cert.as_ref()).to_vec();
        let verifier = PinnedServerVerifier::new(vec![expected_hash]);

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
        let verifier = PinnedServerVerifier::new(vec![vec![0x00; 32]]);
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
    fn pinned_verifier_accepts_second_of_two_pins() {
        let cert = CertificateDer::from(vec![0x42; 32]);
        let expected_hash = Sha256::digest(cert.as_ref()).to_vec();
        let verifier = PinnedServerVerifier::new(vec![vec![0x00; 32], expected_hash]);

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
    fn pinned_verifier_exposes_supported_signature_schemes() {
        let verifier = PinnedServerVerifier::new(vec![vec![0x00; 32]]);

        assert!(!verifier.supported_verify_schemes().is_empty());
    }
}
