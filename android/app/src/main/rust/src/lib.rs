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
use bytes::{Bytes, BufMut};
use shared::ControlMessage;
use std::sync::atomic::{AtomicBool, Ordering};
use sha2::{Sha256, Digest};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use futures_util::FutureExt;

use std::sync::Once;

// Global stop flag removed. We use per-session flags.

struct VpnSession {
    runtime: tokio::runtime::Runtime,
    connection: quinn::Connection,
    config: ControlMessage,
    stop_flag: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}



#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_init<'local>(
    env_unowned: EnvUnowned<'local>,
    _this: JObject<'local>,
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

    info!("JNI init - token: [redacted], endpoint: {}, cert_pin: {}", endpoint, cert_pin_str);

    if cert_pin_str.is_empty() {
        error!("Certificate PIN is empty. Connection aborted.");
        return 0;
    }

    info!("Initializing VPN Session. Endpoint: {}", endpoint);

    // 1. Resolve Endpoint and Bind to Correct Family
    use std::net::ToSocketAddrs;
    let addr = match endpoint.to_socket_addrs() {
        Ok(mut addrs) => addrs.next(),
        Err(e) => {
            error!("Failed to resolve endpoint {}: {}", endpoint, e);
            return 0;
        }
    };
    
    let target_addr = match addr {
        Some(a) => a,
        None => {
            error!("No address found for endpoint {}", endpoint);
            return 0;
        }
    };

    // Bind to the correct family based on the target address
    let bind_addr = if target_addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = match std::net::UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to bind UDP socket to {}: {}", bind_addr, e);
            return 0;
        }
    };
    
    // Initialize socket
    let socket2_sock = socket2::Socket::from(socket);
    
    // Set larger socket buffers for high-throughput stability (4MB for GSO bursts)
    let buffer_candidates = [4 * 1024 * 1024, 2 * 1024 * 1024, 1024 * 1024];
    
    for size in buffer_candidates {
        if let Err(e) = socket2_sock.set_recv_buffer_size(size) {
                warn!("Could not set receive buffer to {}: {}", size, e);
        } else {
                info!("Socket receive buffer: {}", size);
                break;
        }
    }
    for size in buffer_candidates {
            if let Err(e) = socket2_sock.set_send_buffer_size(size) {
                warn!("Could not set send buffer to {}: {}", size, e);
            } else {
                info!("Socket send buffer: {}", size);
                break;
            }
    }

    // Allow Fragmentation (OS-level fragmentation)
    // If the cellular network has MTU 1280 or 1300, and we send 1360 (wire), the OS must fragment it.
    // We switch to IP_PMTUDISC_DONT (MTU_DISCOVER_DONT) to ensure connectivity on restricted networks.
    #[cfg(target_os = "android")]
    unsafe {
        use std::os::unix::io::AsRawFd;
        let fd = socket2_sock.as_raw_fd();
        let val: libc::c_int = 0; // 0 is DONT for both IPv4 and IPv6/Linux

        if target_addr.is_ipv4() {
            // IPv4: IP_MTU_DISCOVER = 10, IP_PMTUDISC_DONT = 0
            let _ = libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            );
        } else {
            // IPv6: IPV6_MTU_DISCOVER = 23, IPV6_PMTUDISC_DONT = 0
            let _ = libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                23, // IPV6_MTU_DISCOVER
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            );
        }
        
        info!("UDP Fragmentation enabled (PMTUDISC_DONT) for Android socket");
    }

        let socket = std::net::UdpSocket::from(socket2_sock);

        #[cfg(target_os = "android")]
        let sock_fd = socket.as_raw_fd();
        #[cfg(not(target_os = "android"))]
        let sock_fd = 0; // Type matching dummy
        
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

        // 3. Connect and Handshake
        let result = rt.block_on(async {
            connect_and_handshake(socket, token, endpoint, cert_pin_str, censorship_resistant).await
        });

        match result {
            Ok((connection, config)) => {
                info!("Handshake successful. IP: {:?}", config);
                let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
                let session = VpnSession {
                    runtime: rt,
                    connection,
                    config,
                    stop_flag: Arc::new(AtomicBool::new(false)),
                    shutdown_tx,
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
        
        // --- SAFETY: Cast and dereference carefully ---
        let session = unsafe { 
            let ptr = handle as *mut VpnSession;
            if ptr.is_null() { return env.new_string("{}").unwrap().into_raw(); }
            &*ptr 
        };
        
        let json = serde_json::to_string(&session.config).unwrap_or_else(|_| "{}".to_string());
        env.new_string(json).unwrap_or_else(|_| env.new_string("{}").unwrap()).into_raw()
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
        let shutdown_rx = session.shutdown_tx.subscribe();
        session.runtime.block_on(async {
            run_vpn_loop(conn, tun_fd, stop_flag, config, shutdown_rx).await;
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
        let _ = session.shutdown_tx.send(());
        // Close the QUIC connection to unblock read_datagram() immediately
        session.connection.close(0u32.into(), b"user_disconnect");
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
                info!("Migration datagram {}/5 sent", i+1);
                // Send a 1-byte dummy datagram to force NAT rebind/migration
                let _ = conn.send_datagram(bytes::Bytes::from_static(&[0]));
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
    censorship_resistant: bool,
) -> anyhow::Result<(quinn::Connection, ControlMessage)> {
    
    info!("Connect and Handshake started. Pin: {}", cert_pin);

    // Verifier Setup
    let verifier = if let Some(bytes) = decode_hex(&cert_pin) {
         info!("Pin decoded successfully. Len: {}", bytes.len());
         Arc::new(PinnedServerVerifier::new(bytes))
    } else {
         return Err(anyhow::anyhow!("Invalid Certificate PIN hex string"));
    };

    let mut client_crypto = rustls::ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    
    // STRICT MODE: If censorship_resistant is enabled, we ONLY send "h3".
    // We do NOT send "mavivpn" as a fallback, because the string "mavivpn" in the ClientHello 
    // is a cleartext fingerprint that censors can use to block us.
    if censorship_resistant {
        client_crypto.alpn_protocols = vec![b"h3".to_vec()];
        info!("Censorship Resistant Mode enabled. ALPN: h3 (Strict)");
    } else {
        client_crypto.alpn_protocols = vec![b"mavivpn".to_vec()];
        info!("Standard Mode enabled. ALPN: mavivpn");
    }

    // Connect & MTU Logic
    info!("Resolving host: {}", endpoint_str);
    let addr = tokio::net::lookup_host(&endpoint_str).await?
        .next()
        .ok_or(anyhow::anyhow!("Invalid address"))?;

    // Rule 2: Outgoing QUIC Payload (Initial MTU) MUST be 1360.
    // IPv4 Wire: 1360 + 20 (IP) + 8 (UDP) = 1388 bytes.
    // IPv6 Wire: 1360 + 40 (IP) + 8 (UDP) = 1408 bytes.
    let quic_mtu = 1360;
    info!("Hard-pinning QUIC MTU: {} (Target Wire: 1388-1408)", quic_mtu);

    // Performance Optimizations
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    
    // MTU Pinning
    transport_config.mtu_discovery_config(None);
    transport_config.initial_mtu(quic_mtu); 
    transport_config.min_mtu(quic_mtu);

    // Enable Segmentation Offload (GSO) for higher throughput
    transport_config.enable_segmentation_offload(true);

    // Congestion Control: Use BBR for higher bandwidth and resistance to loss/jitter
    transport_config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));

    // Datagram queue tuning for high-speed GSO traffic (Avoiding 'dropping stale datagram' errors)
    // Increased to 4MB to match Backend and prevent bottlenecks during bursts
    transport_config.datagram_receive_buffer_size(Some(4 * 1024 * 1024)); // 4MB
    transport_config.datagram_send_buffer_size(4 * 1024 * 1024); // 4MB

    let mut client_config = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?));
    client_config.transport_config(Arc::new(transport_config));

    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(client_config);

    info!("Connecting to {}", addr);
    let connection = endpoint.connect(addr, "localhost")?.await?;
    info!("Connection established");

    // Handshake
    let (mut send_stream, mut recv_stream) = connection.open_bi().await?;
    info!("Stream opened");
    
    let auth_msg = ControlMessage::Auth { token };
    let bytes = bincode::serde::encode_to_vec(&auth_msg, bincode::config::standard()).map_err(|e| anyhow::anyhow!("{}", e))?;
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
async fn run_vpn_loop(connection: quinn::Connection, fd: jint, stop_flag: Arc<AtomicBool>, config: ControlMessage, mut shutdown_rx: tokio::sync::broadcast::Receiver<()>) {
    let raw_fd = fd as RawFd;

    // Extract Gateway IPs for ICMP signaling
    let (gateway_v4, gateway_v6_opt) = match &config {
        ControlMessage::Config { gateway, gateway_v6, .. } => (*gateway, *gateway_v6),
        _ => (std::net::Ipv4Addr::new(10, 0, 0, 1), None),
    };
    
    // Duplicated FD to manage its lifecycle independently from Java
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
    
    let tun_async_fd = match AsyncFd::new(file) {
        Ok(t) => Arc::new(t),
        Err(e) => { error!("Failed to create AsyncFd: {}", e); return; }
    };

    let connection_arc = Arc::new(connection);
    let (tx_tun, mut rx_tun) = tokio::sync::mpsc::channel::<Vec<u8>>(256); // Increased capacity

    info!("Entering concurrent VPN Loop Hub");

    // --- TASK 1: TUN -> QUIC (Outgoing / Upload) ---
    // Optimised with BATCHED reads to reduce syscall/tokio overhead.
    let stop_upload = stop_flag.clone();
    let tun_upload = tun_async_fd.clone();
    let conn_upload = connection_arc.clone();
    let tx_feedback = tx_tun.clone();
    
    let upload_task = tokio::spawn(async move {
        let mut read_buf = bytes::BytesMut::with_capacity(65536);
        loop {
            if stop_upload.load(Ordering::Relaxed) { break; }
            
            let mut readable_guard = tokio::select! {
                res = tun_upload.readable() => match res {
                    Ok(g) => g,
                    Err(_) => break,
                },
                _ = shutdown_rx.recv() => break,
            };
            
            let res = readable_guard.try_io(|inner| {
                let mut packets = Vec::with_capacity(32);
                loop {
                    if read_buf.remaining_mut() < 2048 { read_buf.reserve(2048); }
                    let chunk = read_buf.chunk_mut();
                    let n = unsafe { libc::read(inner.as_raw_fd(), chunk.as_mut_ptr() as *mut libc::c_void, chunk.len()) };
                    
                    if n < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.kind() == std::io::ErrorKind::WouldBlock {
                            if packets.is_empty() {
                                return Err(err); 
                            } else {
                                break;
                            }
                        }
                        return Err(err);
                    }
                    if n == 0 { break; }
                    
                    unsafe { read_buf.advance_mut(n as usize); }
                    packets.push(read_buf.split_to(n as usize).freeze());
                    if packets.len() >= 32 { break; } // Moderate batch size for responsiveness
                }
                Ok(packets)
            });

            if let Ok(Ok(packets)) = res {
                for packet in packets {
                    if let Err(e) = conn_upload.send_datagram(packet.clone()) {
                        match e {
                            quinn::SendDatagramError::ConnectionLost(_) => {
                                stop_upload.store(true, Ordering::SeqCst);
                                break;
                            }
                            quinn::SendDatagramError::TooLarge => {
                                let current_limit = conn_upload.max_datagram_size().unwrap_or(1200);
                                let version = (packet[0] >> 4) & 0xF;
                                let gw = if version == 4 { 
                                    std::net::IpAddr::V4(gateway_v4) 
                                } else { 
                                     // Use the provided gateway or the destination IP as fallback for ICMP source
                                     std::net::IpAddr::V6(gateway_v6_opt.unwrap_or_else(|| "fd00::1".parse().unwrap())) 
                                };
                                    // RFC 8200: IPv6 Minimum MTU is 1280. 
                                    // If Quinn reports < 1280, we still report 1280 to the stack
                                    // and let the backend/OS handle the fragmentation if possible.
                                    let reported_mtu = if version == 6 {
                                        std::cmp::max(current_limit as u16, 1280)
                                    } else {
                                        current_limit as u16
                                    };

                                    if let Some(icmp_packet) = shared::icmp::generate_packet_too_big(&packet, reported_mtu, Some(gw)) {
                                        let _ = tx_feedback.try_send(icmp_packet);
                                    }
                            },
                            _ => {}
                        }
                    }
                }
            }
        }
        info!("Upload task exited.");
    });

    // --- TASK 2: QUIC -> TUN (Incoming / Download) ---
    // Already supports batching via read_datagram().now_or_never().
    let stop_download = stop_flag.clone();
    let tun_download = tun_async_fd.clone();
    let conn_download = connection_arc.clone();
    
    let download_task = tokio::spawn(async move {
        loop {
            if stop_download.load(Ordering::Relaxed) { break; }
            
            match conn_download.read_datagram().await {
                Ok(first_packet) => {
                    let mut batch = Vec::with_capacity(32);
                    batch.push(first_packet);

                    for _ in 0..31 {
                         if let Some(Ok(pkt)) = conn_download.read_datagram().now_or_never() {
                             batch.push(pkt);
                         } else { break; }
                    }

                    // --- FIX: Ensure the ENTIRE batch is written to TUN ---
                    // The previous version would drop packets if libc::write returned WouldBlock.
                    for packet in batch {
                        loop {
                            if stop_download.load(Ordering::Relaxed) { break; }
                            
                            let mut guard = match tun_download.writable().await {
                                Ok(g) => g,
                                Err(_) => break,
                            };

                            let res = guard.try_io(|inner| {
                                let n = unsafe { libc::write(inner.as_raw_fd(), packet.as_ptr() as *const libc::c_void, packet.len()) };
                                if n < 0 {
                                    let err = std::io::Error::last_os_error();
                                    if err.kind() == std::io::ErrorKind::WouldBlock {
                                        return Err(err); // Wait for readiness
                                    }
                                    return Err(err); // Fatal error
                                }
                                Ok(())
                            });

                            match res {
                                Ok(Ok(())) => break, // Packet written, move to next
                                Ok(Err(e)) => {
                                    error!("Fatal TUN Write error: {}", e);
                                    stop_download.store(true, Ordering::SeqCst);
                                    break;
                                }
                                Err(_would_block) => continue, // Retry on next readiness
                            }
                        }
                    }
                }
                Err(_) => {
                    stop_download.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
        info!("Download task exited.");
    });

    // --- TASK 3: ICMP Feedback -> TUN ---
    let stop_icmp = stop_flag.clone();
    let tun_icmp = tun_async_fd.clone();
    let icmp_task = tokio::spawn(async move {
        while let Some(icmp_pkt) = rx_tun.recv().await {
            if stop_icmp.load(Ordering::Relaxed) { break; }
            if let Ok(mut guard) = tun_icmp.writable().await {
                let _ = guard.try_io(|inner| {
                    let _ = unsafe { libc::write(inner.as_raw_fd(), icmp_pkt.as_ptr() as *const libc::c_void, icmp_pkt.len()) };
                    Ok(())
                });
            }
        }
    });

    // Wait for any task to terminate
    let res = tokio::select! {
        r = upload_task => { error!("Upload task terminated: {:?}", r); "Upload" },
        r = download_task => { error!("Download task terminated: {:?}", r); "Download" },
        r = icmp_task => { error!("ICMP task terminated: {:?}", r); "ICMP" },
    };
    
    // Ensure all tasks stop by signaling the atomic flag
    warn!("VPN Loop Hub shutting down. Trigger: {} task exit", res);
    stop_flag.store(true, Ordering::SeqCst);
    let _ = connection_arc.close(0u32.into(), b"loop_exit");
    
    info!("VPN Loop tasks terminated.");
}

#[cfg(not(target_os = "android"))]
async fn run_vpn_loop(_connection: quinn::Connection, _fd: jint, _stop_flag: Arc<AtomicBool>, _config: ControlMessage, _shutdown_rx: tokio::sync::broadcast::Receiver<()>) {
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
