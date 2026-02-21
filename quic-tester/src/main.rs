use quinn::{ClientConfig, Endpoint};
use std::sync::Arc;
use std::net::SocketAddr;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;
use quinn::crypto::rustls::QuicClientConfig;

// A dummy verifier that accepts all SSL certificates (simulating a real DPI scanner)
#[derive(Debug)]
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr: SocketAddr = "194.242.56.169:10443".parse()?;

    // 1. Create QUIC Endpoint
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    
    // 2. Allow all certificates (Skip Verification)
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
        
    crypto.alpn_protocols = vec![b"h3".to_vec()];
        
    let client_config = ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap()));
    endpoint.set_default_client_config(client_config);

    println!("Connecting to Mavi-VPN on {}", server_addr);
    
    // 3. Establish connection
    let connection = endpoint.connect(server_addr, "localhost")?.await?;
    println!("QUIC Handshake successful.");

    // 4. INTENTIONALLY do not send a token
    let (mut send, mut recv) = connection.open_bi().await?;
    
    let fake_request = b"GET / HTTP/3\r\n\r\n";
    send.write_all(fake_request).await?;
    send.finish()?; 
    
    println!("Fake HTTP/3 Request sent. Waiting for response...");
    
    // 5. Read response from server (read everything available before connection dies)
    let mut buf: Vec<u8> = Vec::new();
    let read_result = tokio::time::timeout(
        std::time::Duration::from_secs(5), 
        recv.read_to_end(1024)
    ).await;

    match read_result {
        Ok(Ok(response)) => {
            let n = response.len();
            println!("\nSERVER RESPONSE ({} Bytes):", n);
            println!("--------------------------------------------------");
            
            print!("Hex (Frames): ");
            for b in &response[..std::cmp::min(n, 20)] { print!("{:02X} ", b); }
            println!("...");
            
            let text = String::from_utf8_lossy(&response);
            println!("\nText Extract:");
            println!("{}", text);
            println!("--------------------------------------------------");
            
            if text.contains("nginx") {
                println!("\nSUCCESS: The server is pretending to be NGINX!");
            }
        },
        Ok(Err(e)) => match e {
            quinn::ReadToEndError::Read(quinn::ReadError::ConnectionLost(_)) |
            quinn::ReadToEndError::Read(quinn::ReadError::ClosedStream) => {
                // If the stream dropped but we didn't read to end, fallback to a smaller read
                println!("Stream Error (Connection dropped by server).");
            },
            _ => println!("Stream Error: {:?}", e),
        },
        Err(_) => println!("Timeout"),
    }

    Ok(())
}
