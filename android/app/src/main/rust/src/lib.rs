use jni::JNIEnv;
use jni::objects::{JClass, JString, JObject, JValue};
use jni::sys::{jint, jlong};
use std::os::unix::io::{FromRawFd, RawFd, AsRawFd};
use android_logger::Config;
use log::{info, error};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use bytes::BytesMut;
use shared::ControlMessage;
use std::sync::atomic::{AtomicBool, Ordering};
use ring::digest;
use rustls::RootCertStore;

// Global stop flag removed. We use per-session flags.

struct VpnSession {
    runtime: tokio::runtime::Runtime,
    connection: quinn::Connection,
    config: ControlMessage,
    stop_flag: Arc<AtomicBool>,
}

#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_init(
    mut env: JNIEnv,
    _class: JClass,
    service: JObject, // Needed to protect the socket
    token: JString,
    endpoint: JString,
    cert_pin: JString,
) -> jlong {
    android_logger::init_once(Config::default().with_tag("MaviVPN"));
    
    let token: String = env.get_string(&token).expect("Couldn't get java string!").into();
    let endpoint: String = env.get_string(&endpoint).expect("Couldn't get java string!").into();
    let cert_pin_str: String = env.get_string(&cert_pin).expect("Couldn't get java string!").into();

    info!("Initializing VPN Session. Endpoint: {}", endpoint);

    // 1. Create Socket and Protect it
    let socket = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to bind UDP socket: {}", e);
            return 0;
        }
    };
    let sock_fd = socket.as_raw_fd();
    
    let protected = env.call_method(
        &service, 
        "protect", 
        "(I)Z", 
        &[JValue::Int(sock_fd as jint)]
    ).and_then(|val| val.z()).unwrap_or(false);
    
    if !protected {
        error!("Failed to protect VPN socket!");
        return 0;
    }
    
    match socket.set_nonblocking(true) {
        Ok(_) => {},
        Err(e) => {
            error!("Failed to set non-blocking: {}", e);
            return 0;
        }
    }

    // 2. Create Runtime
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            error!("Failed to create runtime: {}", e);
            return 0;
        }
    };

    // 3. Connect and Handshake
    let result = rt.block_on(async {
        connect_and_handshake(socket, token, endpoint, cert_pin_str).await
    });

    match result {
        Ok((connection, config)) => {
            info!("Handshake successful. IP: {:?}", config);
            let session = VpnSession {
                runtime: rt,
                connection,
                config,
                stop_flag: Arc::new(AtomicBool::new(false)),
            };
            Box::into_raw(Box::new(session)) as jlong
        },
        Err(e) => {
            error!("Handshake failed: {}", e);
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_getConfig<'a>(
    env: JNIEnv<'a>,
    _class: JClass<'a>,
    handle: jlong,
) -> JString<'a> {
    if handle == 0 { return env.new_string("{}").unwrap(); }
    let session = unsafe { &mut *(handle as *mut VpnSession) };
    
    let json = serde_json::to_string(&session.config).unwrap_or("{}".to_string());
    env.new_string(json).expect("Failed to create string")
}

#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_startLoop(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    tun_fd: jint,
) {
    if handle == 0 { return; }
    // borrow session, do not consume
    let session = unsafe { &mut *(handle as *mut VpnSession) };
    
    info!("Starting VPN Loop with TUN FD: {}", tun_fd);
    
    let stop_flag = session.stop_flag.clone();
    let conn = session.connection.clone();

    session.runtime.block_on(async {
        run_vpn_loop(conn, tun_fd, stop_flag).await;
    });
    
    info!("VPN Loop terminated.");
}

#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_stop(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle == 0 { return; }
    let session = unsafe { &*(handle as *mut VpnSession) };
    
    info!("Stop requested for session");
    session.stop_flag.store(true, Ordering::SeqCst);
}

#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_free(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle == 0 { return; }
    info!("Freeing VPN Session memory");
    unsafe {
        let _ = Box::from_raw(handle as *mut VpnSession);
    }
}

// --- Internal Logic ---

async fn connect_and_handshake(
    socket: std::net::UdpSocket, 
    token: String, 
    endpoint_str: String, 
    cert_pin: String
) -> anyhow::Result<(quinn::Connection, ControlMessage)> {
    
    // Verifier Setup
    let verifier = if let Some(bytes) = decode_hex(&cert_pin) {
         Arc::new(PinnedServerVerifier::new(bytes))
    } else {
         return Err(anyhow::anyhow!("Invalid Certificate PIN"));
    };

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"mavivpn".to_vec()];

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    
    let mut client_config = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?));
    client_config.transport_config(Arc::new(transport_config));

    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(client_config);

    // Connect
    let addr = tokio::net::lookup_host(&endpoint_str).await?
        .next()
        .ok_or(anyhow::anyhow!("Invalid address"))?;
    
    let connection = endpoint.connect(addr, "localhost")?.await?;

    // Handshake
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
    
    if let ControlMessage::Error { message } = &config {
        return Err(anyhow::anyhow!("Server Error: {}", message));
    }
    
    Ok((connection, config))
}

use tokio::io::AsyncWriteExt;
use tokio::io::AsyncReadExt;

async fn run_vpn_loop(connection: quinn::Connection, fd: jint, stop_flag: Arc<AtomicBool>) {
    let raw_fd = fd as RawFd;
    let file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
    
    // Set non-blocking
    unsafe {
        let flags = libc::fcntl(raw_fd, libc::F_GETFL);
        libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    
    let tun_reader = match AsyncFd::new(file.try_clone().unwrap()) {
        Ok(t) => t,
        Err(e) => { error!("Failed to create AsyncFd: {}", e); return; }
    };
    let tun_writer = match AsyncFd::new(file) {
        Ok(t) => t,
        Err(e) => { error!("Failed to create AsyncFd: {}", e); return; }
    };

    let connection_arc = Arc::new(connection);
    
    // TUN -> QUIC
    let conn_send = connection_arc.clone();
    let stop_check = stop_flag.clone();
    let tun_to_quic = tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(1500);
        loop {
            if stop_check.load(Ordering::Relaxed) { break; }
            
            let mut guard = match tun_reader.readable().await {
                Ok(g) => g,
                Err(_) => break,
            };

            let result = guard.try_io(|_inner| {
                 if buf.capacity() < 1500 { buf.reserve(1500); }
                 let ptr = buf.as_mut_ptr();
                 let n = unsafe { libc::read(raw_fd, ptr as *mut libc::c_void, 1500) };
                 if n < 0 {
                     let err = std::io::Error::last_os_error();
                     if err.kind() == std::io::ErrorKind::WouldBlock {
                         return Err(err); 
                     }
                     return Ok(Err(err));
                 }
                 Ok(Ok(n as usize))
            });

            match result {
                Ok(inner_result) => {
                    match inner_result {
                        Ok(n) => {
                            if n == 0 { break; } // EOF
                            unsafe { buf.set_len(n); }
                            let _ = conn_send.send_datagram(buf.to_vec().into());
                            buf.clear();
                        }
                        Err(e) => { error!("TUN Read Error: {}", e); break; }
                    }
                },
                Err(_) => continue, // WouldBlock
            }
        }
    });

    // QUIC -> TUN
    loop {
        if stop_flag.load(Ordering::Relaxed) { break; }
        
        tokio::select! {
             result = connection_arc.read_datagram() => {
                match result {
                    Ok(data) => {
                        loop {
                             let mut guard = match tun_writer.writable().await {
                                 Ok(g) => g,
                                 Err(_) => break,
                             };
                             match guard.try_io(|_inner| {
                                 let n = unsafe { libc::write(raw_fd, data.as_ptr() as *const libc::c_void, data.len()) };
                                 if n < 0 {
                                     let err = std::io::Error::last_os_error();
                                     if err.kind() == std::io::ErrorKind::WouldBlock { return Err(err); }
                                     Ok(Err(err))
                                 } else { Ok(Ok(n as usize)) }
                             }) {
                                 Ok(Ok(_)) => break,
                                 Ok(Err(e)) => { error!("TUN Write Error: {}", e); break; }, 
                                 Err(_) => continue,
                             }
                        }
                    }
                    Err(e) => { error!("Connection lost: {}", e); break; }
                }
            }
        }
    }
    
    tun_to_quic.abort();
}

// Helpers
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[derive(Debug)]
struct PinnedServerVerifier {
    expected_hash: Vec<u8>,
    inner: std::sync::Arc<dyn rustls::client::danger::ServerCertVerifier>,
}

impl PinnedServerVerifier {
    fn new(expected_hash: Vec<u8>) -> Self {
        let roots = RootCertStore::empty();
        let inner = rustls::client::WebPkiServerVerifier::builder(std::sync::Arc::new(roots))
            .build()
            .expect("Failed to build verifier");
        Self { expected_hash, inner }
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
        let cert_hash = digest::digest(&digest::SHA256, end_entity.as_ref());
        if cert_hash.as_ref() == self.expected_hash.as_slice() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
             Err(rustls::Error::General("Pin mismatch".into()))
        }
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &rustls::pki_types::CertificateDer<'_>, dss: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &rustls::pki_types::CertificateDer<'_>, dss: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
