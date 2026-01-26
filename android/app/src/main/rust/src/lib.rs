use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jint;
use std::os::unix::io::{FromRawFd, RawFd, AsRawFd};
use android_logger::Config;
use log::{info, error};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use bytes::{BytesMut};
use shared::ControlMessage;
use std::sync::atomic::{AtomicBool, Ordering};

// Global stop flag for graceful shutdown
static STOP_FLAG: AtomicBool = AtomicBool::new(false);

#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_connect(
    mut env: JNIEnv,
    service: jni::objects::JObject,
    fd: jint,
    token: JString,
    endpoint: JString,
) -> jint {
    android_logger::init_once(Config::default().with_tag("MaviVPN"));
    
    // Reset stop flag
    STOP_FLAG.store(false, Ordering::SeqCst);
    
    let token: String = env.get_string(&token).expect("Couldn't get java string!").into();
    let endpoint: String = env.get_string(&endpoint).expect("Couldn't get java string!").into();
    
    // Create UDP socket and protect it
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("Failed to bind UDP socket");
    let sock_fd = socket.as_raw_fd();
    
    // Call VpnService.protect(int) to exclude this socket from VPN
    let protected = env.call_method(
        &service, 
        "protect", 
        "(I)Z", 
        &[jni::objects::JValue::Int(sock_fd as jint)]
    ).and_then(|val| val.z()).unwrap_or(false);
    
    if !protected {
        error!("Failed to protect VPN socket! Connection will likely loop.");
    } else {
        info!("Protected VPN socket FD: {}", sock_fd);
    }
    
    // Enable non-blocking on the socket (Quinn needs this)
    socket.set_nonblocking(true).expect("Failed to set non-blocking");

    info!("Rust received connect request. FD: {}, Endpoint: {}", fd, endpoint);

    match std::thread::spawn(move || {
        start_runtime(fd as RawFd, token, endpoint, socket)
    }).join() {
        Ok(res) => if res { 0 } else { 1 },
        Err(_) => 1,
    }
}

#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_stop(
    _env: JNIEnv,
    _class: jni::objects::JClass,
) {
    info!("Stop requested");
    STOP_FLAG.store(true, Ordering::SeqCst);
}

fn start_runtime(fd: RawFd, token: String, endpoint_addr: String, socket: std::net::UdpSocket) -> bool {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        if let Err(e) = run_vpn(fd, token, endpoint_addr, socket).await {
            error!("VPN Error: {:?}", e);
            return false;
        }
        true
    })
}

#[derive(Debug)]
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
        ]
    }
}

async fn run_vpn(fd: RawFd, token: String, endpoint_str: String, socket: std::net::UdpSocket) -> anyhow::Result<()> {
    // 1. Configure Client
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"mavivpn".to_vec()];

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));

    let mut client_config = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?));
    client_config.transport_config(Arc::new(transport_config));

    // Create Quinn Endpoint from the protected socket
    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(client_config);

    // 2. Connect
    // Parse address manually or resolve?
    // tokio::net::lookup_host needs string host:port.
    // If we use the endpoint to connect, we pass SocketAddr.
    
    let addr = tokio::net::lookup_host(&endpoint_str).await?
        .next()
        .ok_or(anyhow::anyhow!("Invalid address"))?;
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

    // 4. Packet Loop with reusable buffer
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let tun_file = tokio::fs::File::from_std(file);
    let (mut tun_reader, mut tun_writer) = tokio::io::split(tun_file);

    let connection_arc = Arc::new(connection);
    let stop_flag = Arc::new(AtomicBool::new(false));
    
    // Task: TUN -> QUIC (with buffer reuse)
    let conn_send = connection_arc.clone();
    let _stop_clone = stop_flag.clone();
    let tun_to_quic = tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(1500);
        buf.resize(1500, 0);
        loop {
            if STOP_FLAG.load(Ordering::SeqCst) {
                break;
            }
            match tun_reader.read(&mut buf[..]).await {
                Ok(n) if n > 0 => {
                    let packet_data = &buf[0..n];
                    // Log first byte to check version (0x45 for IPv4)
                    if n >= 1 {
                        let version = packet_data[0] >> 4;
                        if version != 4 {
                            info!("Non-IPv4 packet read from TUN: len={}, version={}, bytes={:02X?}", n, version, &packet_data[0..std::cmp::min(n, 4)]);
                        }
                    } else {
                         info!("Read empty packet?");
                    }
                    let packet = packet_data.to_vec().into();
                    let _ = conn_send.send_datagram(packet);
                },
                Ok(_) => {
                    // 0 bytes read, usually EOF or spurious wakeup
                }
                Err(e) => {
                    error!("TUN read error: {}", e);
                    break;
                }
            }
        }
    });

    // Loop: QUIC -> TUN
    loop {
        if STOP_FLAG.load(Ordering::SeqCst) {
            info!("Stop flag detected, exiting main loop");
            break;
        }
        
        tokio::select! {
            result = connection_arc.read_datagram() => {
                match result {
                    Ok(data) => {
                        if let Err(e) = tun_writer.write_all(&data).await {
                            error!("TUN write error: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Connection lost: {}", e);
                        break;
                    }
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                // Check stop flag periodically
            }
        }
    }
    
    tun_to_quic.abort();
    info!("VPN session ended cleanly");
    Ok(())
}
