use jni::objects::{JClass, JString, JObject};
use jni::{JValue, Env, AttachGuard, EnvUnowned};
use jni::sys::{jint, jlong};
#[cfg(target_os = "android")]
use std::os::unix::io::{FromRawFd, RawFd, AsRawFd};
#[cfg(not(target_os = "android"))]
use std::os::raw::c_int as RawFd; // Dummy type for non-android
use android_logger::Config;
use log::{info, error, warn};
use std::sync::Arc;
#[cfg(target_os = "android")]
use tokio::io::unix::AsyncFd;
use bytes::{Bytes, BytesMut, BufMut};
use shared::ControlMessage;
use std::sync::atomic::{AtomicBool, Ordering};
use sha2::{Sha256, Digest};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use futures_util::FutureExt;
use wtransport::{ClientConfig, Endpoint};

use std::sync::Once;

// Global stop flag removed. We use per-session flags.

struct VpnSession {
    runtime: tokio::runtime::Runtime,
    connection: wtransport::Connection,
    config: ControlMessage,
    stop_flag: Arc<AtomicBool>,
}



#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_init<'local>(
    env_unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
    service: JObject<'local>, // Needed to protect the socket
    token: JString<'local>,
    endpoint: JString<'local>,
    cert_pin: JString<'local>,
    censorship_resistant: jni::sys::jboolean, // New Argument
) -> jlong {
    // EnvUnowned is #[repr(transparent)] and FFI-safe.
    // We must convert it to a usable Env via AttachGuard.
    let mut guard = unsafe { AttachGuard::from_unowned(env_unowned.as_raw()) };
    let mut env = guard.borrow_env_mut();
    // 0. Panic Guard
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        static LOGGER_INIT: Once = Once::new();
        LOGGER_INIT.call_once(|| {
            android_logger::init_once(
                Config::default()
                    .with_tag("MaviVPN")
                    // Configure log level to balance visibility and performance
                    .with_max_level(log::LevelFilter::Info)
            );
            // Install Ring as the default crypto provider for the whole process
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    
    info!("JNI init called. CR Mode: {}", censorship_resistant);
    
    // Helper to extract string safely
    #[allow(deprecated)]
    let get_string = |env: &mut Env, jstr: &JString| -> Option<String> {
         match env.get_string(jstr) {
             Ok(s) => Some(s.into()),
             Err(e) => {
                 error!("Failed to get string from JNI: {}", e);
                 None
             }
         }
    };

    let token = match get_string(&mut env, &token) { Some(s) => s, None => { error!("Token is null/invalid"); return 0; } };
    let endpoint = match get_string(&mut env, &endpoint) { Some(s) => s, None => { error!("Endpoint is null/invalid"); return 0; } };
    let cert_pin_str = match get_string(&mut env, &cert_pin) { Some(s) => s, None => { error!("CertPin is null/invalid"); return 0; } };

    if cert_pin_str.is_empty() {
        error!("Certificate PIN is empty. Connection aborted.");
        return 0;
    }

    info!("Initializing VPN Session. Endpoint: {}", endpoint);

        // 1. Create Socket and Protect it via Android VpnService
        // We bind to [::]:0 to allow both IPv4 and IPv6 (Dual Stack)
        let socket = match std::net::UdpSocket::bind("[::]:0") {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to bind UDP socket: {}", e);
                return 0;
            }
        };
        
        // Initialize socket buffers
        let socket2_sock = socket2::Socket::from(socket);
        
        // Ensure Dual Stack is enabled (IPV6_V6ONLY = 0)
        if let Err(e) = socket2_sock.set_only_v6(false) {
             warn!("Failed to set IPV6_V6ONLY=false: {}", e);
        }
        // Set larger socket buffers for high-throughput stability
        let buffer_candidates = [4 * 1024 * 1024, 2 * 1024 * 1024, 1024 * 1024];
        for size in buffer_candidates {
            if socket2_sock.set_recv_buffer_size(size).is_ok() {
                 info!("Socket receive buffer: {}", size);
                 break;
            }
        }
        for size in buffer_candidates {
             if socket2_sock.set_send_buffer_size(size).is_ok() {
                 info!("Socket send buffer: {}", size);
                 break;
             }
        }

        // Allow Fragmentation (OS-level)
        #[cfg(target_os = "android")]
        unsafe {
            let fd = socket2_sock.as_raw_fd();
            let val: libc::c_int = libc::IP_PMTUDISC_DONT;
            let _ = libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            );
        }
        
        let socket = std::net::UdpSocket::from(socket2_sock);

        // Protect the socket via Android VpnService so it doesn't route through our tunnel
        #[cfg(target_os = "android")]
        let sock_fd = socket.as_raw_fd();
        #[cfg(not(target_os = "android"))]
        let sock_fd = 0;
        
        let protected = env.call_method(
            &service, 
            jni::jni_str!("protect"), 
            jni::jni_sig!("(I)Z"), 
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

        // 2. Create Runtime (Multi-threaded for better encryption performance)
        let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                error!("Failed to create runtime: {}", e);
                return 0;
            }
        };

        // 3. Connect and Handshake via WebTransport (with protected socket)
        let result = rt.block_on(async {
            connect_and_handshake(socket, token, endpoint, cert_pin_str, censorship_resistant).await
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
    }));

    match result {
        Ok(handle) => handle,
        Err(e) => {
            error!("Rust Panic caught in init: {:?}", e);
            0
        }
    }
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_getConfig<'local>(
    env_unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jni::sys::jstring {
    let mut guard = unsafe { AttachGuard::from_unowned(env_unowned.as_raw()) };
    let env = guard.borrow_env_mut();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if handle == 0 { return env.new_string("{}").unwrap().into_raw(); }
        let session = unsafe { &mut *(handle as *mut VpnSession) };
        
        let json = serde_json::to_string(&session.config).unwrap_or("{}".to_string());
        env.new_string(json).unwrap().into_raw()
    }));
    
    match result {
        Ok(s) => s,
        Err(_) => {
            error!("Panic in getConfig");
            env.new_string("{}").unwrap().into_raw()
        }
    }
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_startLoop<'local>(
    mut _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    tun_fd: jint,
) {
    if handle == 0 { return; }
    
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // borrow session, do not consume
        let session = unsafe { &mut *(handle as *mut VpnSession) };
        
        info!("Starting VPN Loop with TUN FD: {}", tun_fd);
        
        let stop_flag = session.stop_flag.clone();
        let conn = session.connection.clone();

        let config = session.config.clone();
        session.runtime.block_on(async {
            run_vpn_loop(conn, tun_fd, stop_flag, config).await;
        });
        
        info!("VPN Loop terminated.");
    }));
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_stop<'local>(
    mut _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if handle == 0 { return; }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let session = unsafe { &*(handle as *mut VpnSession) };
        
        info!("Stop requested for session");
        session.stop_flag.store(true, Ordering::SeqCst);
        // Close the connection to unblock receive_datagram() immediately
        // wtransport doesn't have a close() with code, just drop or let it timeout.
        // Setting stop flag is enough since the loop checks it.
    }));
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_free<'local>(
    mut _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if handle == 0 { return; }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        info!("Freeing VPN Session memory");
        unsafe {
            let _ = Box::from_raw(handle as *mut VpnSession);
        }
    }));
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_networkChanged<'local>(
    mut _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if handle == 0 { return; }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let session = unsafe { &*(handle as *mut VpnSession) };
        info!("Network Event: Triggering Rebind/Migration Ping");
        
        let conn = session.connection.clone();
        
        // Spawn a task to send a burst of pings/datagrams to force migration
        session.runtime.spawn(async move {
            info!("Starting migration burst (5 packets)...");
            for i in 0..5 {
                match conn.send_datagram(Bytes::from_static(&[])) {
                     Ok(_) => info!("Migration datagram {}/5 sent", i+1),
                     Err(e) => error!("Failed to send migration datagram {}/5: {}", i+1, e),
                }
                // Small delay to ensure they are spaced out slightly but cover the network switch window
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            }
            info!("Migration burst completed.");
        });
    }));
}

// --- Internal Logic ---

async fn connect_and_handshake(
    socket: std::net::UdpSocket,
    token: String, 
    endpoint_str: String, 
    cert_pin: String,
    _censorship_resistant: bool,
) -> anyhow::Result<(wtransport::Connection, ControlMessage)> {
    
    info!("Connect and Handshake started. Pin: {}", cert_pin);

    // Verifier Setup
    let cert_pin_bytes = if let Some(bytes) = decode_hex(&cert_pin) {
         info!("Pin decoded successfully. Len: {}", bytes.len());
         bytes
    } else {
         return Err(anyhow::anyhow!("Invalid Certificate PIN hex string"));
    };

    // Transport config tuning (matches all other clients)
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    // MTU Pinning: 1400 to match server
    transport_config.mtu_discovery_config(None);
    transport_config.initial_mtu(1400);
    transport_config.min_mtu(1400);
    transport_config.enable_segmentation_offload(true);
    transport_config.congestion_controller_factory(Arc::new(
        quinn::congestion::BbrConfig::default(),
    ));
    // Datagram queue tuning
    transport_config.datagram_receive_buffer_size(Some(2 * 1024 * 1024)); // 2MB
    transport_config.datagram_send_buffer_size(2 * 1024 * 1024); // 2MB

    // Build wtransport client with pinned cert verifier
    let verifier = Arc::new(PinnedServerVerifier::new(cert_pin_bytes));
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_no_client_auth();

    // WebTransport ALPN for wtransport compatibility
    client_crypto.alpn_protocols = vec![wtransport::tls::WEBTRANSPORT_ALPN.to_vec()];

    // Use the pre-created, VPN-protected socket
    let bind_addr = socket.local_addr()?;
    let mut client_config = ClientConfig::builder()
        .with_bind_address(bind_addr)
        .with_custom_tls(client_crypto)
        .build();

    client_config.quic_config_mut().transport_config(Arc::new(transport_config));

    let endpoint = Endpoint::client(client_config)?;

    // Resolve endpoint (add default port if missing)
    let mut resolved_endpoint = endpoint_str.clone();
    if !resolved_endpoint.contains(':') {
        resolved_endpoint = format!("{}:10443", resolved_endpoint);
    }

    let connect_url = format!("https://{}/vpn", resolved_endpoint);
    info!("Connecting to WebTransport endpoint {}", connect_url);

    let connection = endpoint.connect(&connect_url).await
        .map_err(|e| anyhow::anyhow!("WebTransport handshake failed: {}", e))?;

    info!("WebTransport handshake OK, sending auth token");

    // Application-level handshake (Auth -> Config)
    let (mut send_stream, mut recv_stream) = connection.open_bi().await?.await?;
    let auth_msg = ControlMessage::Auth { token };
    let bytes = bincode::serde::encode_to_vec(&auth_msg, bincode::config::standard())
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    send_stream.write_u32_le(bytes.len() as u32).await?;
    send_stream.write_all(&bytes).await?;
    info!("Auth sent");
    
    // Read Config
    let len = recv_stream.read_u32_le().await? as usize;
    if len > 65536 {
        return Err(anyhow::anyhow!("Server response too large: {} bytes", len));
    }
    let mut buf = vec![0u8; len];
    recv_stream.read_exact(&mut buf).await?;
    let config: ControlMessage = bincode::serde::decode_from_slice(&buf, bincode::config::standard())
        .map(|(v, _)| v)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    
    if let ControlMessage::Error { message } = &config {
        return Err(anyhow::anyhow!("Server Error: {}", message));
    }
    
    Ok((connection, config))
}


#[cfg(target_os = "android")]
async fn run_vpn_loop(connection: wtransport::Connection, fd: jint, stop_flag: Arc<AtomicBool>, config: ControlMessage) {
    let raw_fd = fd as RawFd;

    // Extract Gateway IPs for ICMP signaling
    let (gateway_v4, gateway_v6_opt) = match &config {
        ControlMessage::Config { gateway, gateway_v6, .. } => (*gateway, *gateway_v6),
        _ => (std::net::Ipv4Addr::new(10, 0, 0, 1), None),
    };
    
    // Duplicate FD to manage its lifecycle independently from Java
    let dup_fd = unsafe { libc::dup(raw_fd) };
    if dup_fd < 0 {
        error!("Could not duplicate FD: {}", std::io::Error::last_os_error());
        return;
    }

    let file = unsafe { std::fs::File::from_raw_fd(dup_fd) };
    
    // Set non-blocking on the DUPLICATED FD
    unsafe {
        let flags = libc::fcntl(dup_fd, libc::F_GETFL);
        libc::fcntl(dup_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    
    let tun_reader = match file.try_clone() {
        Ok(f) => match AsyncFd::new(f) {
            Ok(t) => t,
            Err(e) => { error!("Failed to create AsyncFd for reader: {}", e); return; }
        },
        Err(e) => { error!("Failed to clone file descriptor: {}", e); return; }
    };
    let tun_writer = match AsyncFd::new(file) {
        Ok(t) => t,
        Err(e) => { error!("Failed to create AsyncFd: {}", e); return; }
    };

    let connection_arc = Arc::new(connection);
    
    // TUN -> QUIC (via WebTransport datagrams)
    let conn_send = connection_arc.clone();
    let stop_check = stop_flag.clone();
    let read_fd = dup_fd; // Use the duplicated FD for reads

    // Channel for ICMP loopback packets
    let (tx_tun, mut rx_tun) = tokio::sync::mpsc::channel::<Vec<u8>>(128);

    let tun_to_quic = tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(65536); 
        loop {
            if stop_check.load(Ordering::Relaxed) { break; }
            
            let mut guard = match tun_reader.readable().await {
                Ok(g) => g,
                Err(_) => break,
            };

            // Read ONE packet from TUN
            let packet = match guard.try_io(|_inner| {
                 if buf.capacity() < 2048 {
                     buf.reserve(2048);
                 }
                 let chunk = buf.chunk_mut();
                 let max_len = 2048.min(chunk.len());
                 
                 let n = unsafe { libc::read(read_fd, chunk.as_mut_ptr() as *mut libc::c_void, max_len) };
                 
                 if n < 0 {
                     let err = std::io::Error::last_os_error();
                     return Err(err);
                 }
                 let n = n as usize;
                 if n == 0 { return Ok(None); } 
                 
                 unsafe { buf.advance_mut(n); }
                 let packet = buf.split_to(n).freeze();
                 Ok(Some(packet))
            }) {
                Ok(Ok(Some(p))) => p,
                Ok(Ok(None)) => break,
                Ok(Err(e)) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        error!("TUN Read Error: {}", e);
                        break;
                    }
                    continue;
                },
                Err(_) => continue, // WouldBlock
            };

            let packet_len = packet.len();
            let packet_bytes = packet.clone(); 

            // Send to QUIC via WebTransport datagram
            match conn_send.send_datagram(packet) {
                Ok(_) => {},
                Err(e) => {
                    use wtransport::error::SendDatagramError;
                    match e {
                        SendDatagramError::NotConnected => {
                            error!("Connection lost during send");
                            stop_check.store(true, Ordering::SeqCst);
                            break;
                        }
                        SendDatagramError::TooLarge => {
                            let current_mtu = conn_send.max_datagram_size().unwrap_or(1200) as u16;
                            
                            // Determine correct gateway for the packet version
                            let version = (packet_bytes[0] >> 4) & 0xF;
                            let gw = if version == 4 { 
                                std::net::IpAddr::V4(gateway_v4) 
                            } else { 
                                std::net::IpAddr::V6(gateway_v6_opt.unwrap_or("2001:db8::1".parse().unwrap())) 
                            };

                            warn!("Packet too large ({} bytes). Exceeds QUIC Path MTU ({} bytes). Sending ICMP Signal from {}.", packet_len, current_mtu, gw);
                            
                            if let Some(icmp_packet) = shared::icmp::generate_packet_too_big(&packet_bytes, current_mtu, Some(gw)) {
                                // Feed back to TUN via channel
                                let _ = tx_tun.try_send(icmp_packet);
                            }
                        },
                    }
                }
            }
        }
    });

    // QUIC -> TUN (via WebTransport datagrams)
    loop {
        if stop_flag.load(Ordering::Relaxed) { break; }
        
        tokio::select! {
             Some(icmp_pkt) = rx_tun.recv() => {
                 let mut guard = match tun_writer.writable().await {
                     Ok(g) => g,
                     Err(_) => break,
                 };
                 let _ = guard.try_io(|_inner| {
                     unsafe { libc::write(dup_fd, icmp_pkt.as_ptr() as *const libc::c_void, icmp_pkt.len()) };
                     Ok(())
                 });
             }
             res = connection_arc.receive_datagram() => {
                 match res {
                     Ok(first_datagram) => {
                        let first_packet = first_datagram.payload();
                        let mut batch: Vec<Bytes> = Vec::with_capacity(64);
                        batch.push(first_packet.clone());

                        for _ in 0..63 {
                             match connection_arc.receive_datagram().now_or_never() {
                                 Some(Ok(dgram)) => batch.push(dgram.payload().clone()),
                                 _ => break,
                             }
                        }

                        let mut batch_idx = 0;
                        while batch_idx < batch.len() {
                            let mut guard = match tun_writer.writable().await {
                                 Ok(g) => g,
                                 Err(_) => break,
                            };
                            
                            let res = guard.try_io(|_inner| {
                                while batch_idx < batch.len() {
                                     let packet = &batch[batch_idx];
                                     let n = unsafe { libc::write(dup_fd, packet.as_ptr() as *const libc::c_void, packet.len()) };
                                     if n < 0 {
                                         let err = std::io::Error::last_os_error();
                                         if err.kind() == std::io::ErrorKind::WouldBlock {
                                             return Err(err); 
                                         }
                                         return Err(err);
                                     }
                                     batch_idx += 1;
                                }
                                Ok(())
                            });
                            
                            match res {
                                Ok(Ok(())) => {}, 
                                Ok(Err(e)) => {
                                     error!("TUN Write Error (Critical): {}", e);
                                     break; 
                                },
                                Err(_) => {}, // WouldBlock: wait for writable again
                            }
                        }
                     }
                     Err(e) => { error!("Connection lost: {}", e); break; }
                 }
             }
        }
    }
    
    // Cleanup
    stop_flag.store(true, Ordering::SeqCst);
    tun_to_quic.abort();

}

#[cfg(not(target_os = "android"))]
async fn run_vpn_loop(_connection: wtransport::Connection, _fd: jint, _stop_flag: Arc<AtomicBool>, _config: ControlMessage) {
    error!("VPN Loop not supported on this platform");
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
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PinnedServerVerifier {
    fn new(expected_hash: Vec<u8>) -> Self {
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
