use sha2::{Sha256, Digest};

pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
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
        dss: &rustls::DigitallySignedStruct
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }
    
    fn verify_tls13_signature(
        &self, 
        message: &[u8], 
        cert: &rustls::pki_types::CertificateDer<'_>, 
        dss: &rustls::DigitallySignedStruct
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }
    
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported.supported_schemes()
    }
}
