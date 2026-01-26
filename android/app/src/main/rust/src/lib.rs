use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jint};
use std::os::unix::io::{FromRawFd, RawFd};
use android_logger::Config;
use log::{info, error};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use bytes::Bytes;
use shared::ControlMessage;
use std::net::ToSocketAddrs;

#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_connect(
    mut env: JNIEnv,
    _class: JClass,
    fd: jint,
    token: JString,
    endpoint: JString,
) -> jint {
    android_logger::init_once(Config::default().with_tag("MaviVPN"));
    
    let token: String = env.get_string(&token).expect("Couldn't get java string!").into();
    let endpoint: String = env.get_string(&endpoint).expect("Couldn't get java string!").into();
    
    info!("Rust received connect request. FD: {}, Endpoint: {}", fd, endpoint);

    match std::thread::spawn(move || {
        start_runtime(fd as RawFd, token, endpoint)
    }).join() {
        Ok(res) => if res { 0 } else { 1 },
        Err(_) => 1,
    }
}

#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_stop(
    _env: JNIEnv,
    _class: JClass,
) {
    info!("Stop requested");
    // In a real implementation, we would signal a CancellationToken here.
    // implementation details omitted for brevity as we are replacing the process usually.
}

fn start_runtime(fd: RawFd, token: String, endpoint_addr: String) -> bool {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        if let Err(e) = run_vpn(fd, token, endpoint_addr).await {
            error!("VPN Error: {:?}", e);
            return false;
        }
        true
    })
}

struct SkipServerVerification;
impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

async fn run_vpn(fd: RawFd, token: String, endpoint_str: String) -> anyhow::Result<()> {
    // 1. Configure Client
    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth(); // No client certs
        
    // DANGEROUS: Skip verification for self-signed certs
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
        
    client_crypto.alpn_protocols = vec![b"mavivpn".to_vec()];

    let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
    let transport_config = Arc::get_mut(&mut client_config.transport).unwrap();
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));

    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config);

    // 2. Connect
    let addr = endpoint_str.to_socket_addrs()?.next().ok_or(anyhow::anyhow!("Invalid address"))?;
    info!("Connecting to {}...", addr);
    
    let connection = endpoint.connect(addr, "localhost")?.await?;
    info!("Connected!");

    // 3. Handshake
    let (mut send_stream, mut recv_stream) = connection.open_bi().await?;
    
    let auth_msg = ControlMessage::Auth { token };
    let bytes = bincode::serialize(&auth_msg)?;
    send_stream.write_u32_le(bytes.len() as u32).await?;
    send_stream.write_all(&bytes).await?;
    
    // Read Config
    let len = recv_stream.read_u32_le().await? as usize;
    let mut buf = vec![0u8; len];
    recv_stream.read_exact(&mut buf).await?;
    let config: ControlMessage = bincode::deserialize(&buf)?;
    
    match config {
        ControlMessage::Config { assigned_ip, gateway, dns_server, .. } => {
            info!("VPN Config Received: IP={}, GW={}, DNS={}", assigned_ip, gateway, dns_server);
        }
        ControlMessage::Error { message } => {
            return Err(anyhow::anyhow!("Server Error: {}", message));
        }
        _ => return Err(anyhow::anyhow!("Invalid response")),
    }

    // 4. Packet Loop
    // Create Tokio File from RawFd
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut tun_file = tokio::fs::File::from_std(file);
    let (mut tun_reader, mut tun_writer) = tokio::io::split(tun_file);

    let connection_arc = Arc::new(connection);
    
    // Task: TUN -> QUIC
    let conn_send = connection_arc.clone();
    let tun_to_quic = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            match tun_reader.read(&mut buf).await {
                Ok(n) if n > 0 => {
                    let packet = Bytes::copy_from_slice(&buf[0..n]);
                    let _ = conn_send.send_datagram(packet);
                },
                _ => break,
            }
        }
    });

    // Loop: QUIC -> TUN
    let res = loop {
        match connection_arc.read_datagram().await {
            Ok(data) => {
                if let Err(_) = tun_writer.write_all(&data).await {
                   break;
                }
            }
            Err(e) => {
                error!("Connection lost: {}", e);
                break;
            }
        }
    };
    
    tun_to_quic.abort();
    Ok(())
}
