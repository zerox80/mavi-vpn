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

use std::sync::Once;

// Global stop flag removed. We use per-session flags.

enum VpnTransport {
    Quic(quinn::Connection),
    Http3(wtransport::Connection),
    Http2 {
        to_server: tokio::sync::mpsc::Sender<Vec<u8>>,
        from_server: std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
    },
}

struct VpnSession {
    runtime: tokio::runtime::Runtime,
    transport: VpnTransport,
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
    transport_mode: jint, // 0=QUIC, 1=HTTP/3, 2=HTTP/2
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
    
    let transport = match transport_mode {
        1 => shared::TransportMode::Http3,
        2 => shared::TransportMode::Http2,
        _ => shared::TransportMode::Quic,
    };
    info!("JNI init called. Transport: {}", transport);
    
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

        // 1. Create Socket and Protect it
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
             // We continue, as some OS/kernels might have it disabled by default or fail if bound to IPv4 mapped
        }
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
        // If the cellular network has MTU 1300, and we send 1360, the OS must fragment it.
        // By default, many sockets have IP_PMTUDISC_DO (Don't Fragment). We switch to IP_PMTUDISC_DONT.
        // Explicitly set IP_MTU_DISCOVER via libc because socket2 API varies between versions/targets
#[cfg(target_os = "android")]
    unsafe {
        let fd = socket2_sock.as_raw_fd();
        let val: libc::c_int = libc::IP_PMTUDISC_DONT;
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        );
        if ret < 0 {
            warn!("Failed to disable PMTUD (IPv4): {}", std::io::Error::last_os_error());
        }
    }
        
        // Note: socket2::MtuDiscover::Dont applies to IP_MTU_DISCOVER (IPv4).
        // For IPv6, we might need separate handling, but often Dual Stack sockets handle it.
        // Let's try setting it. If it fails, we log a warning but continue.

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
            connect_and_handshake(socket, token, endpoint, cert_pin_str, transport.clone()).await
        });

        match result {
            Ok((transport, config)) => {
                info!("Handshake successful. IP: {:?}", config);
                let session = VpnSession {
                    runtime: rt,
                    transport,
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
        let config = session.config.clone();

        match &session.transport {
            VpnTransport::Quic(conn) => {
                let conn = conn.clone();
                session.runtime.block_on(async {
                    run_vpn_loop(conn, tun_fd, stop_flag, config).await;
                });
            }
            VpnTransport::Http3(conn) => {
                let conn = conn.clone();
                session.runtime.block_on(async {
                    run_vpn_loop_h3(conn, tun_fd, stop_flag, config).await;
                });
            }
            VpnTransport::Http2 { to_server, from_server } => {
                let tx = to_server.clone();
                let rx = from_server.lock().unwrap().take()
                    .expect("H2 receiver already consumed");
                session.runtime.block_on(async {
                    run_vpn_loop_h2(tx, rx, tun_fd, stop_flag, config).await;
                });
            }
        }
        
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
        match &session.transport {
            VpnTransport::Quic(conn) => {
                conn.close(0u32.into(), b"user_disconnect");
            }
            VpnTransport::Http3(_) => {
                // Connection will close when stop_flag is detected
            }
            VpnTransport::Http2 { .. } => {
                // Channels will close when stop_flag is detected
            }
        }
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

        match &session.transport {
            VpnTransport::Quic(conn) => {
                let conn = conn.clone();
                session.runtime.spawn(async move {
                    info!("Starting migration burst (5 packets)...");
                    for i in 0..5 {
                        match conn.send_datagram(Bytes::from_static(&[])) {
                            Ok(_) => info!("Migration datagram {}/5 sent", i+1),
                            Err(e) => error!("Failed to send migration datagram {}/5: {}", i+1, e),
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                    }
                    info!("Migration burst completed.");
                });
            }
            _ => {
                info!("Network migration not supported for this transport mode");
            }
        }
    }));
}

// --- Internal Logic ---

async fn connect_and_handshake(
    socket: std::net::UdpSocket,
    token: String,
    endpoint_str: String,
    cert_pin: String,
    transport: shared::TransportMode,
) -> anyhow::Result<(VpnTransport, ControlMessage)> {

    info!("Connect and Handshake started. Pin: {}", cert_pin);

    let cert_pin_bytes = decode_hex(&cert_pin)
        .ok_or_else(|| anyhow::anyhow!("Invalid Certificate PIN hex string"))?;
    info!("Pin decoded successfully. Len: {}", cert_pin_bytes.len());

    match transport {
        shared::TransportMode::Quic => {
            connect_quic(socket, token, endpoint_str, cert_pin_bytes).await
        }
        shared::TransportMode::Http3 => {
            connect_h3(token, endpoint_str, cert_pin_bytes).await
        }
        shared::TransportMode::Http2 => {
            connect_h2(token, endpoint_str, cert_pin_bytes).await
        }
    }
}

async fn connect_quic(
    socket: std::net::UdpSocket,
    token: String,
    endpoint_str: String,
    cert_pin_bytes: Vec<u8>,
) -> anyhow::Result<(VpnTransport, ControlMessage)> {
    let verifier = Arc::new(PinnedServerVerifier::new(cert_pin_bytes));

    let mut client_crypto = rustls::ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    client_crypto.alpn_protocols = vec![b"mavivpn".to_vec(), b"h3".to_vec()];
    info!("QUIC transport mode. ALPN: mavivpn, h3");

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    transport_config.mtu_discovery_config(None);
    transport_config.initial_mtu(1360);
    transport_config.min_mtu(1360);
    transport_config.enable_segmentation_offload(true);
    transport_config.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    transport_config.datagram_send_buffer_size(2 * 1024 * 1024);

    let mut client_config = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?));
    client_config.transport_config(Arc::new(transport_config));

    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(), None, socket, Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(client_config);

    info!("Resolving host: {}", endpoint_str);
    let addr = tokio::net::lookup_host(&endpoint_str).await?
        .next().ok_or(anyhow::anyhow!("Invalid address"))?;

    info!("Connecting to {}", addr);
    let connection = endpoint.connect(addr, "localhost")?.await?;
    info!("QUIC connection established");

    let (mut send_stream, mut recv_stream) = connection.open_bi().await?;
    let auth_msg = ControlMessage::Auth { token };
    let bytes = bincode::serde::encode_to_vec(&auth_msg, bincode::config::standard())
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    send_stream.write_u32_le(bytes.len() as u32).await?;
    send_stream.write_all(&bytes).await?;

    let len = recv_stream.read_u32_le().await? as usize;
    if len > 65536 { return Err(anyhow::anyhow!("Server response too large")); }
    let mut buf = vec![0u8; len];
    recv_stream.read_exact(&mut buf).await?;
    let config: ControlMessage = bincode::serde::decode_from_slice(&buf, bincode::config::standard())
        .map(|(v, _)| v).map_err(|e| anyhow::anyhow!("{}", e))?;

    if let ControlMessage::Error { message } = &config {
        return Err(anyhow::anyhow!("Server Error: {}", message));
    }

    Ok((VpnTransport::Quic(connection), config))
}

async fn connect_h3(
    token: String,
    endpoint_str: String,
    cert_pin_bytes: Vec<u8>,
) -> anyhow::Result<(VpnTransport, ControlMessage)> {
    let cert_hash: [u8; 32] = cert_pin_bytes.as_slice().try_into()
        .map_err(|_| anyhow::anyhow!("Certificate PIN must be 32 bytes (SHA-256)"))?;

    let wt_config = wtransport::ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes([wtransport::tls::Sha256Digest::new(cert_hash)])
        .keep_alive_interval(Some(std::time::Duration::from_secs(5)))
        .max_idle_timeout(Some(std::time::Duration::from_secs(60)))
        .expect("valid idle timeout")
        .build();

    let wt_endpoint = wtransport::Endpoint::client(wt_config)?;

    let url = format!("https://{}/vpn", endpoint_str);
    info!("[HTTP/3] Connecting to {}", url);
    let connection = wt_endpoint.connect(&url).await
        .map_err(|e| anyhow::anyhow!("WebTransport connection failed: {}", e))?;
    info!("[HTTP/3] Connected to {}", connection.remote_address());

    // Auth via bi-stream
    let (mut send_stream, mut recv_stream) = connection.open_bi().await
        .map_err(|e| anyhow::anyhow!("Failed to open bi-stream: {}", e))?;

    let auth_msg = ControlMessage::Auth { token };
    let bytes = bincode::serde::encode_to_vec(&auth_msg, bincode::config::standard())
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    send_stream.write_u32_le(bytes.len() as u32).await?;
    send_stream.write_all(&bytes).await?;

    let len = recv_stream.read_u32_le().await? as usize;
    if len > 65536 { return Err(anyhow::anyhow!("Server response too large")); }
    let mut buf = vec![0u8; len];
    recv_stream.read_exact(&mut buf).await?;
    let config: ControlMessage = bincode::serde::decode_from_slice(&buf, bincode::config::standard())
        .map(|(v, _)| v).map_err(|e| anyhow::anyhow!("{}", e))?;

    if let ControlMessage::Error { message } = &config {
        return Err(anyhow::anyhow!("Server Error: {}", message));
    }

    Ok((VpnTransport::Http3(connection), config))
}

async fn connect_h2(
    token: String,
    endpoint_str: String,
    cert_pin_bytes: Vec<u8>,
) -> anyhow::Result<(VpnTransport, ControlMessage)> {
    let verifier = Arc::new(PinnedServerVerifier::new(cert_pin_bytes));

    let mut tls_config = rustls::ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h2".to_vec()];

    let addr = tokio::net::lookup_host(&endpoint_str).await?
        .next().ok_or(anyhow::anyhow!("Failed to resolve endpoint"))?;
    let host = endpoint_str.split(':').next().unwrap_or(&endpoint_str);

    info!("[HTTP/2] Connecting to {} (resolved: {})", endpoint_str, addr);
    let tcp_stream = tokio::net::TcpStream::connect(addr).await?;

    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| anyhow::anyhow!("Invalid server name: {}", e))?;
    let tls_stream = connector.connect(server_name, tcp_stream).await
        .map_err(|e| anyhow::anyhow!("TLS handshake failed: {}", e))?;

    info!("[HTTP/2] TLS handshake complete");

    let (h2_send_req, h2_conn) = h2::client::Builder::new()
        .initial_window_size(4 * 1024 * 1024)
        .initial_connection_window_size(4 * 1024 * 1024)
        .handshake(tls_stream).await
        .map_err(|e| anyhow::anyhow!("H2 handshake failed: {}", e))?;

    // Drive H2 connection in background
    tokio::spawn(async move {
        if let Err(e) = h2_conn.await {
            error!("[HTTP/2] Connection driver error: {}", e);
        }
    });

    let mut h2_send_req = h2_send_req.ready().await
        .map_err(|e| anyhow::anyhow!("H2 not ready: {}", e))?;
    let request = http::Request::builder().method("POST").uri("/vpn").body(()).unwrap();
    let (response_future, mut send_stream) = h2_send_req.send_request(request, false)
        .map_err(|e| anyhow::anyhow!("H2 send_request failed: {}", e))?;

    // Auth: [u32 LE len][bincode]
    let auth_msg = ControlMessage::Auth { token };
    let encoded = bincode::serde::encode_to_vec(&auth_msg, bincode::config::standard())
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let mut auth_frame = Vec::with_capacity(4 + encoded.len());
    auth_frame.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
    auth_frame.extend_from_slice(&encoded);
    send_stream.send_data(Bytes::from(auth_frame), false)
        .map_err(|e| anyhow::anyhow!("H2 send auth failed: {}", e))?;

    let response = response_future.await
        .map_err(|e| anyhow::anyhow!("H2 response error: {}", e))?;
    if response.status() != 200 {
        return Err(anyhow::anyhow!("[HTTP/2] Server returned status {}", response.status()));
    }
    let mut recv_body = response.into_body();

    // Read config: [u32 LE len][bincode]
    let config_data = recv_body.data().await
        .ok_or(anyhow::anyhow!("No config data"))?
        .map_err(|e| anyhow::anyhow!("H2 config read error: {}", e))?;
    let _ = recv_body.flow_control().release_capacity(config_data.len());

    if config_data.len() < 4 { return Err(anyhow::anyhow!("[HTTP/2] Config too short")); }
    let len = u32::from_le_bytes([config_data[0], config_data[1], config_data[2], config_data[3]]) as usize;
    if 4 + len > config_data.len() { return Err(anyhow::anyhow!("[HTTP/2] Config length mismatch")); }

    let config: ControlMessage = bincode::serde::decode_from_slice(
        &config_data[4..4 + len], bincode::config::standard()
    ).map(|(v, _)| v).map_err(|e| anyhow::anyhow!("{}", e))?;

    if let ControlMessage::Error { message } = &config {
        return Err(anyhow::anyhow!("Server Error: {}", message));
    }

    info!("[HTTP/2] Authenticated successfully");

    // Bridge H2 streams via channels so they survive across JNI calls
    let (to_server_tx, mut to_server_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
    let (from_server_tx, from_server_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);

    // Task: Channel -> H2 SendStream
    tokio::spawn(async move {
        while let Some(packet) = to_server_rx.recv().await {
            let pkt_len = packet.len() as u16;
            let mut frame = Vec::with_capacity(2 + packet.len());
            frame.extend_from_slice(&pkt_len.to_be_bytes());
            frame.extend_from_slice(&packet);
            if send_stream.send_data(Bytes::from(frame), false).is_err() { break; }
        }
    });

    // Task: H2 RecvBody -> Channel
    tokio::spawn(async move {
        let mut partial = Vec::new();
        loop {
            match recv_body.data().await {
                Some(Ok(chunk)) => {
                    let _ = recv_body.flow_control().release_capacity(chunk.len());
                    partial.extend_from_slice(&chunk);
                    while partial.len() >= 2 {
                        let pkt_len = u16::from_be_bytes([partial[0], partial[1]]) as usize;
                        if partial.len() < 2 + pkt_len { break; }
                        let data = partial[2..2 + pkt_len].to_vec();
                        partial.drain(..2 + pkt_len);
                        if !data.is_empty() {
                            if from_server_tx.send(data).await.is_err() { return; }
                        }
                    }
                }
                _ => break,
            }
        }
    });

    Ok((VpnTransport::Http2 {
        to_server: to_server_tx,
        from_server: std::sync::Mutex::new(Some(from_server_rx)),
    }, config))
}


#[cfg(target_os = "android")]
async fn run_vpn_loop(connection: quinn::Connection, fd: jint, stop_flag: Arc<AtomicBool>, config: ControlMessage) {
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
    
    // TUN -> QUIC
    let conn_send = connection_arc.clone();
    let stop_check = stop_flag.clone();
    let read_fd = dup_fd; // Use the duplicated FD for reads

    // We need a writer for ICMP loopback
    // Solution: Create a channel to send packets to the TUN Writer task.
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

            // Send to QUIC (Non-blocking / Drop on congestion)
            match conn_send.send_datagram(packet) {
                Ok(_) => {},
                Err(e) => {
                    match e {
                        quinn::SendDatagramError::ConnectionLost(_) => {
                            error!("Connection lost during send");
                            stop_check.store(true, Ordering::SeqCst);
                            break;
                        }
                         quinn::SendDatagramError::TooLarge => {
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
                         quinn::SendDatagramError::UnsupportedByPeer => {
                            error!("Datagrams unsupported by peer. Closing.");
                            stop_check.store(true, Ordering::SeqCst);
                            break;
                         },
                         quinn::SendDatagramError::Disabled => {
                             error!("Datagrams disabled. Closing.");
                             stop_check.store(true, Ordering::SeqCst);
                             break;
                         }
                    }
                }
            }
        }
    });

    // QUIC -> TUN
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
             res = connection_arc.read_datagram() => {
                 match res {
                     Ok(first_packet) => {
                        let mut batch = Vec::with_capacity(64);
                        batch.push(first_packet);

                        for _ in 0..63 {
                             match connection_arc.read_datagram().now_or_never() {
                                 Some(Ok(pkt)) => batch.push(pkt),
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
async fn run_vpn_loop(_connection: quinn::Connection, _fd: jint, _stop_flag: Arc<AtomicBool>, _config: ControlMessage) {
    error!("VPN Loop not supported on this platform");
}

// =============================================================================
// HTTP/3 (WebTransport) VPN Loop
// =============================================================================

#[cfg(target_os = "android")]
async fn run_vpn_loop_h3(connection: wtransport::Connection, fd: jint, stop_flag: Arc<AtomicBool>, config: ControlMessage) {
    use std::os::unix::io::{FromRawFd, AsRawFd};

    let raw_fd = fd as RawFd;
    let (gateway_v4, _gateway_v6_opt) = match &config {
        ControlMessage::Config { gateway, gateway_v6, .. } => (*gateway, *gateway_v6),
        _ => (std::net::Ipv4Addr::new(10, 0, 0, 1), None),
    };

    let dup_fd = unsafe { libc::dup(raw_fd) };
    if dup_fd < 0 { error!("Could not duplicate FD"); return; }

    let file = unsafe { std::fs::File::from_raw_fd(dup_fd) };
    unsafe {
        let flags = libc::fcntl(dup_fd, libc::F_GETFL);
        libc::fcntl(dup_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let tun_reader = match file.try_clone() {
        Ok(f) => match AsyncFd::new(f) { Ok(t) => t, Err(e) => { error!("AsyncFd reader: {}", e); return; } },
        Err(e) => { error!("Clone FD: {}", e); return; }
    };
    let tun_writer = match AsyncFd::new(file) {
        Ok(t) => t, Err(e) => { error!("AsyncFd writer: {}", e); return; }
    };

    let conn_send = connection.clone();
    let stop_read = stop_flag.clone();
    let read_fd = dup_fd;

    let tun_to_h3 = tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(65536);
        loop {
            if stop_read.load(Ordering::Relaxed) { break; }
            let mut guard = match tun_reader.readable().await { Ok(g) => g, Err(_) => break };

            let packet = match guard.try_io(|_inner| {
                if buf.capacity() < 2048 { buf.reserve(2048); }
                let chunk = buf.chunk_mut();
                let max_len = 2048.min(chunk.len());
                let n = unsafe { libc::read(read_fd, chunk.as_mut_ptr() as *mut libc::c_void, max_len) };
                if n < 0 { return Err(std::io::Error::last_os_error()); }
                let n = n as usize;
                if n == 0 { return Ok(None); }
                unsafe { buf.advance_mut(n); }
                let packet = buf.split_to(n).freeze();
                Ok(Some(packet))
            }) {
                Ok(Ok(Some(p))) => p,
                Ok(Ok(None)) => break,
                Ok(Err(e)) => { if e.kind() != std::io::ErrorKind::WouldBlock { error!("TUN read: {}", e); break; } continue; }
                Err(_) => continue,
            };

            let data = packet.to_vec();
            if let Err(e) = conn_send.send_datagram(data) {
                if matches!(e, wtransport::error::SendDatagramError::TooLarge) {
                    let current_mtu = 1200u16;
                    let gw = std::net::IpAddr::V4(gateway_v4);
                    if let Some(icmp_pkt) = shared::icmp::generate_packet_too_big(&packet, current_mtu, Some(gw)) {
                        // Feed ICMP back to TUN (best-effort)
                        if let Ok(mut g) = tun_writer.writable().await {
                            let _ = g.try_io(|_| {
                                unsafe { libc::write(dup_fd, icmp_pkt.as_ptr() as *const libc::c_void, icmp_pkt.len()) };
                                Ok(())
                            });
                        }
                    }
                }
            }
        }
    });

    // WebTransport datagram -> TUN
    loop {
        if stop_flag.load(Ordering::Relaxed) { break; }
        match connection.receive_datagram().await {
            Ok(datagram) => {
                let data = datagram.payload();
                if data.is_empty() { continue; }

                let mut guard = match tun_writer.writable().await { Ok(g) => g, Err(_) => break };
                let _ = guard.try_io(|_inner| {
                    let n = unsafe { libc::write(dup_fd, data.as_ptr() as *const libc::c_void, data.len()) };
                    if n < 0 { return Err(std::io::Error::last_os_error()); }
                    Ok(())
                });
            }
            Err(e) => { error!("[HTTP/3] Connection lost: {}", e); break; }
        }
    }

    stop_flag.store(true, Ordering::SeqCst);
    tun_to_h3.abort();
}

#[cfg(not(target_os = "android"))]
async fn run_vpn_loop_h3(_connection: wtransport::Connection, _fd: jint, _stop_flag: Arc<AtomicBool>, _config: ControlMessage) {
    error!("VPN Loop not supported on this platform");
}

// =============================================================================
// HTTP/2 (TCP) VPN Loop
// =============================================================================

#[cfg(target_os = "android")]
async fn run_vpn_loop_h2(
    to_server: tokio::sync::mpsc::Sender<Vec<u8>>,
    mut from_server: tokio::sync::mpsc::Receiver<Vec<u8>>,
    fd: jint,
    stop_flag: Arc<AtomicBool>,
    _config: ControlMessage,
) {
    use std::os::unix::io::FromRawFd;

    let raw_fd = fd as RawFd;
    let dup_fd = unsafe { libc::dup(raw_fd) };
    if dup_fd < 0 { error!("Could not duplicate FD"); return; }

    let file = unsafe { std::fs::File::from_raw_fd(dup_fd) };
    unsafe {
        let flags = libc::fcntl(dup_fd, libc::F_GETFL);
        libc::fcntl(dup_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let tun_reader = match file.try_clone() {
        Ok(f) => match AsyncFd::new(f) { Ok(t) => t, Err(e) => { error!("AsyncFd reader: {}", e); return; } },
        Err(e) => { error!("Clone FD: {}", e); return; }
    };
    let tun_writer = match AsyncFd::new(file) {
        Ok(t) => t, Err(e) => { error!("AsyncFd writer: {}", e); return; }
    };

    let stop_read = stop_flag.clone();
    let read_fd = dup_fd;

    // TUN -> H2 (via channel)
    let tun_to_h2 = tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(65536);
        loop {
            if stop_read.load(Ordering::Relaxed) { break; }
            let mut guard = match tun_reader.readable().await { Ok(g) => g, Err(_) => break };

            let packet = match guard.try_io(|_inner| {
                if buf.capacity() < 2048 { buf.reserve(2048); }
                let chunk = buf.chunk_mut();
                let max_len = 2048.min(chunk.len());
                let n = unsafe { libc::read(read_fd, chunk.as_mut_ptr() as *mut libc::c_void, max_len) };
                if n < 0 { return Err(std::io::Error::last_os_error()); }
                let n = n as usize;
                if n == 0 { return Ok(None); }
                unsafe { buf.advance_mut(n); }
                Ok(Some(buf.split_to(n).freeze()))
            }) {
                Ok(Ok(Some(p))) => p,
                Ok(Ok(None)) => break,
                Ok(Err(e)) => { if e.kind() != std::io::ErrorKind::WouldBlock { break; } continue; }
                Err(_) => continue,
            };

            if to_server.send(packet.to_vec()).await.is_err() { break; }
        }
    });

    // H2 -> TUN (from channel)
    loop {
        if stop_flag.load(Ordering::Relaxed) { break; }
        match from_server.recv().await {
            Some(data) => {
                if data.is_empty() { continue; }
                let mut guard = match tun_writer.writable().await { Ok(g) => g, Err(_) => break };
                let _ = guard.try_io(|_inner| {
                    let n = unsafe { libc::write(dup_fd, data.as_ptr() as *const libc::c_void, data.len()) };
                    if n < 0 { return Err(std::io::Error::last_os_error()); }
                    Ok(())
                });
            }
            None => break,
        }
    }

    stop_flag.store(true, Ordering::SeqCst);
    tun_to_h2.abort();
}

#[cfg(not(target_os = "android"))]
async fn run_vpn_loop_h2(
    _to_server: tokio::sync::mpsc::Sender<Vec<u8>>,
    _from_server: tokio::sync::mpsc::Receiver<Vec<u8>>,
    _fd: jint,
    _stop_flag: Arc<AtomicBool>,
    _config: ControlMessage,
) {
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
