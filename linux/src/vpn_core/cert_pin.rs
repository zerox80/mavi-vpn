pub(super) use shared::hex::decode_hex_pins;

/// Custom certificate verifier that trusts only a set of SHA-256 fingerprints
/// (usually one, or two during a manual cert-rotation window).
#[derive(Debug)]
pub(super) struct PinnedServerVerifier {
    expected_hashes: Vec<Vec<u8>>,
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PinnedServerVerifier {
    pub(super) fn new(expected_hashes: Vec<Vec<u8>>) -> Self {
        Self {
            expected_hashes,
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
        if shared::cert_pin::matches_any_pin(end_entity.as_ref(), &self.expected_hashes) {
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
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use sha2::{Digest, Sha256};

    #[test]
    fn test_pinned_server_verifier_matches() {
        let dummy_cert_bytes = b"dummy certificate";
        let hash = Sha256::digest(dummy_cert_bytes).to_vec();

        let verifier = PinnedServerVerifier::new(vec![hash]);

        let end_entity = CertificateDer::from(dummy_cert_bytes.as_slice());
        let server_name = ServerName::try_from("example.com").unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(0));

        let result = verifier.verify_server_cert(&end_entity, &[], &server_name, &[], now);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pinned_server_verifier_mismatches() {
        let expected_hash = vec![0; 32];
        let verifier = PinnedServerVerifier::new(vec![expected_hash]);

        let dummy_cert_bytes = b"wrong certificate";
        let end_entity = CertificateDer::from(dummy_cert_bytes.as_slice());
        let server_name = ServerName::try_from("example.com").unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(0));

        let result = verifier.verify_server_cert(&end_entity, &[], &server_name, &[], now);
        assert!(result.is_err());
        if let Err(rustls::Error::General(msg)) = result {
            assert_eq!(msg, "Certificate PIN mismatch");
        } else {
            panic!("Expected General error, got {:?}", result);
        }
    }

    #[test]
    fn test_pinned_server_verifier_matches_second_of_two_pins() {
        let dummy_cert_bytes = b"dummy certificate";
        let hash = Sha256::digest(dummy_cert_bytes).to_vec();
        let other_hash = vec![0; 32];

        let verifier = PinnedServerVerifier::new(vec![other_hash, hash]);

        let end_entity = CertificateDer::from(dummy_cert_bytes.as_slice());
        let server_name = ServerName::try_from("example.com").unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(0));

        let result = verifier.verify_server_cert(&end_entity, &[], &server_name, &[], now);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pinned_server_verifier_rejects_when_no_pin_matches() {
        let dummy_cert_bytes = b"dummy certificate";
        let verifier = PinnedServerVerifier::new(vec![vec![0; 32], vec![1; 32]]);

        let end_entity = CertificateDer::from(dummy_cert_bytes.as_slice());
        let server_name = ServerName::try_from("example.com").unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(0));

        let result = verifier.verify_server_cert(&end_entity, &[], &server_name, &[], now);
        assert!(result.is_err());
    }
}
