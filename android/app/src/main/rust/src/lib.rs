use jni::JNIEnv;
use jni::objects::{JClass, JString, JObject, JValue};
use jni::sys::{jint, jlong};
use std::os::unix::io::{FromRawFd, RawFd, AsRawFd};
use android_logger::Config;
use log::{info, error};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use bytes::{Bytes, BytesMut, BufMut};
use shared::ControlMessage;
use std::sync::atomic::{AtomicBool, Ordering};
use ring::digest;

use std::sync::Once;

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
    // 0. Panic Guard
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        static LOGGER_INIT: Once = Once::new();
        LOGGER_INIT.call_once(|| {
            android_logger::init_once(
                Config::default()
                    .with_tag("MaviVPN")
                    .with_max_level(log::LevelFilter::Debug)
            );
        });
    
    info!("JNI init called"); // visible proof
    
    // Helper to extract string safely
    let get_string = |env: &mut JNIEnv, jstr: &JString| -> Option<String> {
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

        // 1. Create Socket and Protect it
        let socket = match std::net::UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to bind UDP socket: {}", e);
                return 0;
            }
        };
        
        // Increase socket buffers to 8MB for high throughput
        let socket2_sock = socket2::Socket::from(socket);
        let _ = socket2_sock.set_recv_buffer_size(8 * 1024 * 1024);
        let _ = socket2_sock.set_send_buffer_size(8 * 1024 * 1024);
        let socket = std::net::UdpSocket::from(socket2_sock);

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

        // 2. Create Runtime (Multi-threaded for better encryption performance)
        let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
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
    }));

    match result {
        Ok(handle) => handle,
        Err(e) => {
            error!("Rust Panic caught in init: {:?}", e);
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
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if handle == 0 { return env.new_string("{}").unwrap_or_else(|_| JString::default()); }
        let session = unsafe { &mut *(handle as *mut VpnSession) };
        
        let json = serde_json::to_string(&session.config).unwrap_or("{}".to_string());
        env.new_string(json).unwrap_or_else(|_| JString::default())
    }));
    
    match result {
        Ok(s) => s,
        Err(_) => {
            error!("Panic in getConfig");
            env.new_string("{}").unwrap_or_else(|_| JString::default())
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_startLoop(
    _env: JNIEnv,
    _class: JClass,
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

        session.runtime.block_on(async {
            run_vpn_loop(conn, tun_fd, stop_flag).await;
        });
        
        info!("VPN Loop terminated.");
    }));
}

#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_stop(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle == 0 { return; }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let session = unsafe { &*(handle as *mut VpnSession) };
        
        info!("Stop requested for session");
        session.stop_flag.store(true, Ordering::SeqCst);
    }));
}

#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_free(
    _env: JNIEnv,
    _class: JClass,
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

#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_networkChanged(
    _env: JNIEnv,
    _class: JClass,
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
    cert_pin: String
) -> anyhow::Result<(quinn::Connection, ControlMessage)> {
    
    info!("Connect and Handshake started. Pin: {}", cert_pin);

    // Verifier Setup
    let verifier = if let Some(bytes) = decode_hex(&cert_pin) {
         info!("Pin decoded successfully. Len: {}", bytes.len());
         Arc::new(PinnedServerVerifier::new(bytes))
    } else {
         return Err(anyhow::anyhow!("Invalid Certificate PIN hex string"));
    };

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"mavivpn".to_vec()];

    // Performance Optimizations
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(2)));
    transport_config.datagram_receive_buffer_size(Some(8 * 1024 * 1024)); // 8MB
    transport_config.datagram_send_buffer_size(8 * 1024 * 1024); // 8MB
    
    // Enable BBR Congestion Control
    transport_config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    
    // Increase receive window
    transport_config.receive_window(quinn::VarInt::from(16u32 * 1024 * 1024)); // 16MB
    transport_config.stream_receive_window(quinn::VarInt::from(8u32 * 1024 * 1024)); // 8MB per stream
    transport_config.send_window(16 * 1024 * 1024); // 16MB send window
    // Enable MTU discovery
    transport_config.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));

    // Enable Segmentation Offload (GSO) for higher throughput
    transport_config.enable_segmentation_offload(true);

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
    info!("Resolving host: {}", endpoint_str);
    let addr = tokio::net::lookup_host(&endpoint_str).await?
        .next()
        .ok_or(anyhow::anyhow!("Invalid address"))?;
    
    info!("Connecting to {}", addr);
    let connection = endpoint.connect(addr, "localhost")?.await?;
    info!("Connection established");

    // Handshake
    let (mut send_stream, mut recv_stream) = connection.open_bi().await?;
    info!("Stream opened");
    
    let auth_msg = ControlMessage::Auth { token };
    let bytes = bincode::serialize(&auth_msg)?;
    send_stream.write_u32_le(bytes.len() as u32).await?;
    send_stream.write_all(&bytes).await?;
    info!("Auth sent");
    
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
    
use futures_util::FutureExt; // Import for now_or_never()

    // Shared timestamp of last received packet (in milliseconds)
    let last_receive = Arc::new(std::sync::atomic::AtomicI64::new(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as i64
    ));

    // TUN -> QUIC (Optimized Loop with Watchdog)
    let conn_send = connection_arc.clone();
    let stop_check = stop_flag.clone();
    let last_receive_producer = last_receive.clone();
    
    let tun_to_quic = tokio::spawn(async move {
        // Larger staging buffer to minimize allocations, though we use split_to
        let mut buf = BytesMut::with_capacity(65536); 
        loop {
            if stop_check.load(Ordering::Relaxed) { break; }
            
            // WATCHDOG CHECK
            // If we are actively trying to send data, check if the server is responding.
            // If we haven't heard from the server in 5 seconds, FORCE RESTART.
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as i64;
            let last = last_receive_producer.load(Ordering::Relaxed);
            
            if (now - last) > 5000 {
                // Check if we have actually sent something recently? 
                // We are in the loop, about to read/send.
                // If we are here, we are alive.
                // But we only want to kill if we are TRYING to send.
                // Actually, if we are just sitting here waiting for TUN packets, we shouldn't kill.
                // The kill check should happen AFTER we read a packet from TUN but BEFORE we send.
            }

            let mut guard = match tun_reader.readable().await {
                Ok(g) => g,
                Err(_) => break,
            };

            let result = guard.try_io(|_inner| {
                 // Try to read multiple packets if possible in a loop without yielding
                 let mut packets_read = 0;
                 loop {
                     // Reserve space for MTU (e.g., 2048)
                     if buf.capacity() < 2048 {
                         buf.reserve(2048);
                     }
                     let chunk = buf.chunk_mut();
                     // Use specific max len to avoid reading partial next packet
                     let max_len = 2048.min(chunk.len());
                     
                     let n = unsafe { libc::read(raw_fd, chunk.as_mut_ptr() as *mut libc::c_void, max_len) };
                     
                     if n < 0 {
                         let err = std::io::Error::last_os_error();
                         if err.kind() == std::io::ErrorKind::WouldBlock {
                             if packets_read > 0 { return Ok(packets_read); }
                             return Err(err); 
                         }
                         return Err(err);
                     }
                     let n = n as usize;
                     if n == 0 { return Ok(packets_read); } 
                     
                     unsafe { buf.advance_mut(n); }
                     
                     // WATCHDOG CHECK (Active)
                     // We have a packet to send. Is the connection healthy?
                     let now_w = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as i64;
                     let last_w = last_receive_producer.load(Ordering::Relaxed);
                     if (now_w - last_w) > 5000 {
                         error!("WATCHDOG: No response from server for 5s while sending data. Forcing Reconnect!");
                         // Signal stop AND return error to break loop
                         stop_check.store(true, Ordering::SeqCst);
                         // Quinn might block on send if full? active abort.
                         conn_send.close(0u32.into(), b"Watchdog Timeout");
                         return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Watchdog"));
                     }

                     // Send immediately
                     let packet = buf.split_to(n).freeze();
                     let _ = conn_send.send_datagram(packet);
                     
                     packets_read += 1;
                     if packets_read >= 64 { 
                         break;
                     }
                 }
                 Ok(packets_read)
            });

            match result {
                Ok(Ok(n)) => {
                     if n == 0 { break; } 
                },
                Ok(Err(e)) => {
                    error!("TUN Read Error: {}", e);
                    break;
                },
                Err(_) => continue, 
            }
        }
    });

    // QUIC -> TUN (Optimized Batch Write)
    loop {
        if stop_flag.load(Ordering::Relaxed) { break; }
        
        match connection_arc.read_datagram().await {
            Ok(first_packet) => {
                // Update Watchdog Timestamp
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as i64;
                last_receive.store(now, Ordering::Relaxed);

                // We have at least one packet. Try to grab more.
                let mut batch = Vec::with_capacity(64);
                batch.push(first_packet);

                for _ in 0..63 {
                     match connection_arc.read_datagram().now_or_never() {
                         Some(Ok(pkt)) => batch.push(pkt),
                         _ => break,
                     }
                }

                // Write batch to TUN
                let mut guard = match tun_writer.writable().await {
                     Ok(g) => g,
                     Err(_) => break,
                };
                
                let res = guard.try_io(|_inner| {
                    for packet in &batch {
                         let n = unsafe { libc::write(raw_fd, packet.as_ptr() as *const libc::c_void, packet.len()) };
                         if n < 0 {
                             let err = std::io::Error::last_os_error();
                             if err.kind() == std::io::ErrorKind::WouldBlock {
                                 return Err(err); 
                             }
                             return Err(err);
                         }
                    }
                    Ok(())
                });
                
                match res {
                    Ok(Ok(())) => {},
                    Ok(Err(e)) => { error!("TUN Write Error: {}", e); },
                    Err(_) => {},
                }
            }
            Err(e) => { error!("Connection lost: {}", e); break; }
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
        let cert_hash = digest::digest(&digest::SHA256, end_entity.as_ref());
        if cert_hash.as_ref() == self.expected_hash.as_slice() {
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
