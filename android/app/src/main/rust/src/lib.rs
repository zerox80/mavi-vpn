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
#[cfg(target_os = "android")]
use futures_util::FutureExt;
use wtransport::{ClientConfig, Endpoint};
use anyhow::Context;

use std::sync::Once;

// Global stop flag removed. We use per-session flags.

pub enum ActiveConnection {
    Quic(wtransport::Connection),
    Tcp {
        send_stream: h2::SendStream<Bytes>,
        recv_stream: h2::RecvStream,
        leftover: bytes::BytesMut,
    },
    Consumed,
}

struct VpnSession {
    runtime: tokio::runtime::Runtime,
    connection: ActiveConnection,
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
    prefer_tcp: jni::sys::jboolean, // New Argument
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
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    
    info!("JNI init called. CR Mode: {}", censorship_resistant);
    let prefer_tcp_bool = prefer_tcp;
    
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
        info!("Certificate PIN is empty. Using system certificates.");
    }

    info!("Initializing VPN Session. Endpoint: {}", endpoint);

        // 1. Create Socket and Protect it via Android VpnService
        // Use socket2 to create the socket so we can set IPV6_V6ONLY=false
        // BEFORE bind() — the kernel rejects the option with EINVAL if set after binding.
        let socket2_sock = match socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        ) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to create UDP socket: {}", e);
                return 0;
            }
        };

        // Enable dual-stack (IPv4 + IPv6) before binding
        if let Err(e) = socket2_sock.set_only_v6(false) {
            warn!("Failed to set IPV6_V6ONLY=false: {}", e);
        }

        if let Err(e) = socket2_sock.bind(&"[::]:0".parse::<std::net::SocketAddr>().unwrap().into()) {
            error!("Failed to bind UDP socket: {}", e);
            return 0;
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

        // 3. Connect and Handshake via WebTransport or TCP (with protected socket)
        let result = rt.block_on(async {
            if prefer_tcp_bool {
                connect_and_handshake_tcp(socket, token, endpoint, cert_pin_str, censorship_resistant).await
            } else {
                connect_and_handshake_quic(&mut env, &service, socket, token, endpoint, cert_pin_str, censorship_resistant).await
            }
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
        
        // Fix for Roaming: We clone the connection instead of consuming it (ActiveConnection::Consumed).
        // This ensures the Java-triggered networkChanged() callback can still access the handle to send migration pings.
        let conn = match &session.connection {
             ActiveConnection::Quic(c) => ActiveConnection::Quic(c.clone()),
             ActiveConnection::Tcp { .. } => std::mem::replace(&mut session.connection, ActiveConnection::Consumed),
             ActiveConnection::Consumed => ActiveConnection::Consumed,
        };

        if matches!(conn, ActiveConnection::Consumed) {
            error!("VPN Session is already consumed or invalid.");
            return;
        }

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
        // We only migrate over QUIC
        if let ActiveConnection::Quic(ref conn) = session.connection {
            let conn_clone = conn.clone();
            // Spawn a task to send a burst of pings/datagrams to force migration
            session.runtime.spawn(async move {
                info!("Starting migration burst (5 packets)...");
                for i in 0..5 {
                    match conn_clone.send_datagram(Bytes::from_static(&[])) {
                         Ok(_) => info!("Migration datagram {}/5 sent", i+1),
                         Err(e) => error!("Failed to send migration datagram {}/5: {}", i+1, e),
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                }
                info!("Migration burst completed.");
            });
        }
    }));
}

// --- Internal Logic ---

async fn connect_and_handshake_quic(
    _env: &mut Env<'_>,
    _service: &JObject<'_>,
    socket: std::net::UdpSocket,
    token: String, 
    endpoint_str: String, 
    cert_pin: String,
    _censorship_resistant: bool,
) -> anyhow::Result<(ActiveConnection, ControlMessage)> {
    
    info!("Connect and Handshake started. Pin: {}", cert_pin);

    // Transport config tuning (matches all other clients)
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    transport_config.congestion_controller_factory(Arc::new(
        quinn::congestion::BbrConfig::default(),
    ));
    // MTU Pinning: Strictly enforce 1360 to match global rule.
    transport_config.initial_mtu(1360);
    transport_config.min_mtu(1360);
    transport_config.max_mtu(Some(1360));
    transport_config.mtu_discovery_config(None); // Disable discovery to strictly follow the rule.
    // Datagram queue tuning: Increased for high-speed stability
    transport_config.datagram_receive_buffer_size(Some(8 * 1024 * 1024)); // 8MB
    transport_config.datagram_send_buffer_size(8 * 1024 * 1024); // 8MB

    // Use the pre-created, VPN-protected socket.
    // Extract the bound address, then drop the socket immediately so the port is
    // free for wtransport/quinn to re-bind it via with_bind_address().
    // If we don't drop it first, Endpoint::client() fails with EADDRINUSE because
    // both sockets would be competing for the same port.
    let bind_addr = socket.local_addr()?;
    drop(socket);
    let client_config = if cert_pin.is_empty() {
        // with_native_certs() silently loads nothing on Android (CAs aren't at
        // standard Linux paths), causing UnknownIssuer on every connection.
        // Use Mozilla's bundled roots (webpki-roots) instead.
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut client_crypto = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        client_crypto.alpn_protocols = vec![wtransport::tls::WEBTRANSPORT_ALPN.to_vec()];
        ClientConfig::builder()
            .with_bind_address(bind_addr)
            .with_custom_tls(client_crypto)
            .build()
    } else {
        let cert_pin_bytes = decode_hex(&cert_pin)
            .ok_or_else(|| anyhow::anyhow!("Invalid Certificate PIN hex string"))?;
        info!("Pin decoded successfully. Len: {}", cert_pin_bytes.len());
        
        let verifier = Arc::new(PinnedServerVerifier::new(cert_pin_bytes));
        let mut client_crypto = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

        client_crypto.alpn_protocols = vec![wtransport::tls::WEBTRANSPORT_ALPN.to_vec()];
        ClientConfig::builder()
            .with_bind_address(bind_addr)
            .with_custom_tls(client_crypto)
            .build()
    };

    let mut client_config = client_config;
    client_config.quic_config_mut().transport_config(Arc::new(transport_config));

    let endpoint = Endpoint::client(client_config)?;

    // --- SOCKET OPTIMIZATION & PROTECTION ---
    // After endpoint creation, find the actual UDP socket FD used by quinn
    #[cfg(target_os = "android")]
    if let Some(fd) = find_fd_by_port(bind_addr.port()) {
        info!("Active QUIC socket found (FD: {}). Optimizing...", fd);
        
    // 1. Protect from VPN routing loop
        let protected = _env.call_method(
            _service, 
            jni::jni_str!("protect"), 
            jni::jni_sig!("(I)Z"), 
            &[JValue::Int(fd as jint)]
        ).and_then(|val| val.z()).unwrap_or(false);
        
        if protected {
            info!("QUIC socket protected successfully.");
        } else {
            warn!("Failed to protect QUIC socket! Speed may be limited.");
        }

        // 2. Set massive OS-level buffers (8MB)
        let buf_size: libc::c_int = 8 * 1024 * 1024;
        unsafe {
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &buf_size as *const _ as *const _, std::mem::size_of_val(&buf_size) as libc::socklen_t);
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, &buf_size as *const _ as *const _, std::mem::size_of_val(&buf_size) as libc::socklen_t);
            
            // 3. Allow OS-level Fragmentation (IP_PMTUDISC_DONT)
            // This ensures our 1360 MTU packets can be fragmented by the local OS if the path MTU is even smaller.
            let pmtu_dont: libc::c_int = libc::IP_PMTUDISC_DONT;
            libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, &pmtu_dont as *const _ as *const _, std::mem::size_of_val(&pmtu_dont) as libc::socklen_t);
            
            // IPv6 equivalent: IPV6_PMTUDISC_DONT
            #[cfg(target_os = "android")]
            {
               // IPV6_MTU_DISCOVER is 23 on Android/Linux
               // IPV6_PMTUDISC_DONT is 0
               let pmtu_v6: libc::c_int = 0; 
               libc::setsockopt(fd, libc::IPPROTO_IPV6, 23, &pmtu_v6 as *const _ as *const _, std::mem::size_of_val(&pmtu_v6) as libc::socklen_t);
            }
        }
    } else {
        warn!("Could not find active QUIC socket FD for protection!");
    }

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
    
    Ok((ActiveConnection::Quic(connection), config))
}

async fn connect_and_handshake_tcp(
    _socket: std::net::UdpSocket,
    token: String, 
    endpoint_str: String, 
    cert_pin: String,
    _censorship_resistant: bool,
) -> anyhow::Result<(ActiveConnection, ControlMessage)> {
    info!("Connect and Handshake TCP started. Pin: {}", cert_pin);

    // Convert UdpSocket to TcpStream by creating a new TCP connection
    let endpoint_str_resolved = if endpoint_str.contains(':') { endpoint_str.clone() } else { format!("{}:443", endpoint_str) };
    let addr = tokio::net::lookup_host(&endpoint_str_resolved).await?.next().context("Failed to resolve TCP endpoint")?;
    
    // We create a completely new TcpSocket so that Android VpnService protects it (since we can't reuse UDP socket for TCP)
    // Actually, on Android, VpnService protects Sockets via java side.
    // Wait! The passed UDP socket is already protected by Java, but TCP is a new socket. We must connect normally.
    // If the Java tunnel is not yet active (because we haven't read config), then `lookup_host` and `TcpSocket` connection
    // will just go through the normal network! VpnService only intercepts AFTER TUN is created. 
    // And Java `Builder().establish()` happens AFTER this returns.
    // So TCP does not need `protect()` call here explicitly!
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let _ = stream.set_nodelay(true);

    let server_name = endpoint_str_resolved.split(':').next().unwrap_or(&endpoint_str_resolved);

    let cert_pin_bytes = if let Some(bytes) = decode_hex(&cert_pin) { bytes } else { return Err(anyhow::anyhow!("Invalid PIN")); };

    let mut client_crypto = rustls::ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerVerifier::new(cert_pin_bytes)))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h2".to_vec()];

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_crypto));
    let domain = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|_| anyhow::anyhow!("Invalid server name"))?;
    
    let tls_stream = connector.connect(domain, stream).await?;

    let (mut h2_client, connection) = h2::client::Builder::new()
        .initial_window_size(4 * 1024 * 1024)
        .initial_connection_window_size(4 * 1024 * 1024)
        .handshake(tls_stream)
        .await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = http::Request::builder().uri("/vpn").method("POST").body(()).unwrap();
    let (response_future, mut send_stream) = h2_client.send_request(request, false)?;

    let auth_msg = ControlMessage::Auth { token: token };
    let bytes = bincode::serde::encode_to_vec(&auth_msg, bincode::config::standard())?;
    
    let mut auth_frame = Vec::with_capacity(4 + bytes.len());
    auth_frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    auth_frame.extend_from_slice(&bytes);
    send_stream.send_data(Bytes::from(auth_frame), false)?;

    let response = response_future.await?;
    if response.status() != http::StatusCode::OK {
        return Err(anyhow::anyhow!("Server rejected TCP connection"));
    }
    let mut recv_stream = response.into_body();

    let mut buffer = bytes::BytesMut::new();
    while buffer.len() < 4 {
        if let Some(Ok(chunk)) = recv_stream.data().await {
            buffer.extend_from_slice(&chunk);
            let _ = recv_stream.flow_control().release_capacity(chunk.len());
        } else {
            return Err(anyhow::anyhow!("Failed to read h2 payload"));
        }
    }
    
    let msg_len = u32::from_le_bytes(buffer[..4].try_into().unwrap()) as usize;
    let _ = buffer.split_to(4);
    if msg_len > 8192 * 4 { return Err(anyhow::anyhow!("Payload too large")); }
    
    while buffer.len() < msg_len {
        if let Some(Ok(chunk)) = recv_stream.data().await {
            buffer.extend_from_slice(&chunk);
            let _ = recv_stream.flow_control().release_capacity(chunk.len());
        } else {
            return Err(anyhow::anyhow!("Failed to read h2 payload"));
        }
    }

    let config: ControlMessage = bincode::serde::decode_from_slice(&buffer[..msg_len], bincode::config::standard()).map(|(v,_)| v)?;
    let _ = buffer.split_to(msg_len);

    Ok((ActiveConnection::Tcp { send_stream, recv_stream, leftover: buffer }, config))
}


#[cfg(target_os = "android")]
async fn run_vpn_loop(connection: ActiveConnection, fd: jint, stop_flag: Arc<AtomicBool>, config: ControlMessage) {
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
            Ok(t) => Arc::new(t),
            Err(e) => { error!("Failed to create AsyncFd for reader: {}", e); return; }
        },
        Err(e) => { error!("Failed to clone file descriptor: {}", e); return; }
    };
    let tun_writer = match AsyncFd::new(file) {
        Ok(t) => Arc::new(t),
        Err(e) => { error!("Failed to create AsyncFd: {}", e); return; }
    };

    // Channel for ICMP loopback packets
    let (tx_tun, rx_tun) = tokio::sync::mpsc::channel::<Vec<u8>>(128);

    match connection {
        ActiveConnection::Quic(quic_conn) => {
            let connection_arc = Arc::new(quic_conn);
            let conn_send = connection_arc.clone();
            let stop_check = stop_flag.clone();
            let stop_flag_outer = stop_flag.clone();
            let read_fd = dup_fd;

            let tun_to_quic = tokio::spawn(async move {
                let mut buf = BytesMut::with_capacity(65536);
                'outer: loop {
                    if stop_check.load(Ordering::Relaxed) { break; }

                    let mut guard = match tun_reader.readable().await {
                        Ok(g) => g,
                        Err(_) => break,
                    };

                    // Drain all available packets in one readable() wakeup instead of
                    // yielding back to the reactor after every single packet.
                    // This is the main reason Android was slower than Windows: the
                    // per-packet readable().await overhead killed throughput.
                    loop {
                        if buf.capacity() < 2048 {
                            buf.reserve(2048);
                        }
                        let chunk = buf.chunk_mut();
                        let max_len = 2048.min(chunk.len());

                        let read_result = guard.try_io(|_inner| {
                            let n = unsafe { libc::read(read_fd, chunk.as_mut_ptr() as *mut libc::c_void, max_len) };
                            if n < 0 {
                                return Err(std::io::Error::last_os_error());
                            }
                            Ok(n as usize)
                        });

                        let n = match read_result {
                            Ok(Ok(0)) => break 'outer, // EOF
                            Ok(Ok(n)) => n,
                            Ok(Err(e)) => {
                                if e.kind() != std::io::ErrorKind::WouldBlock {
                                    error!("TUN Read Error: {}", e);
                                    break 'outer;
                                }
                                break; // fd drained, wait for next readable()
                            }
                            Err(_) => break, // WouldBlock from try_io
                        };

                        unsafe { buf.advance_mut(n); }
                        let packet = buf.split_to(n).freeze();
                        let packet_len = packet.len();
                        let packet_bytes = packet.clone();

                        match conn_send.send_datagram(packet) {
                            Ok(_) => {},
                            Err(e) => {
                                use wtransport::error::SendDatagramError;
                                match e {
                                    SendDatagramError::NotConnected => {
                                        error!("Connection lost during send");
                                        stop_check.store(true, Ordering::SeqCst);
                                        break 'outer;
                                    }
                                    SendDatagramError::TooLarge => {
                                        let current_mtu = conn_send.max_datagram_size().unwrap_or(1360) as u16;
                                        let version = (packet_bytes[0] >> 4) & 0xF;
                                        let gw = if version == 4 {
                                            std::net::IpAddr::V4(gateway_v4)
                                        } else {
                                            std::net::IpAddr::V6(gateway_v6_opt.unwrap_or("2001:db8::1".parse().unwrap()))
                                        };
                                        warn!("Packet too large ({} bytes). Exceeds QUIC Path MTU ({} bytes). Sending ICMP Signal from {}.", packet_len, current_mtu, gw);
                                        if let Some(icmp_packet) = shared::icmp::generate_packet_too_big(&packet_bytes, current_mtu, Some(gw)) {
                                            let _ = tx_tun.try_send(icmp_packet);
                                        }
                                    }
                                    SendDatagramError::UnsupportedByPeer => {
                                        error!("Datagrams not supported by peer");
                                        stop_check.store(true, Ordering::SeqCst);
                                        break 'outer;
                                    }
                                }
                            }
                        }
                    }
                }
            });

            let tun_writer_for_loop = tun_writer.clone(); 
            let stop_flag_for_loop = stop_flag.clone();

            let quic_to_tun = tokio::spawn(async move {
                loop {
                    if stop_flag_for_loop.load(Ordering::Relaxed) { break; }
                    match connection_arc.receive_datagram().await {
                         Ok(first_datagram) => {
                            let first_packet = first_datagram.payload();
                            let mut batch: Vec<Bytes> = Vec::with_capacity(256);
                            batch.push(first_packet.clone());

                            for _ in 0..255 {
                                 match connection_arc.receive_datagram().now_or_never() {
                                     Some(Ok(dgram)) => batch.push(dgram.payload().clone()),
                                     _ => break,
                                 }
                            }

                            let mut batch_idx = 0;
                            'write: while batch_idx < batch.len() {
                                let mut guard = match tun_writer_for_loop.writable().await {
                                     Ok(g) => g,
                                     Err(_) => break,
                                };

                                let res = guard.try_io(|_inner| {
                                    while batch_idx < batch.len() {
                                         let packet = &batch[batch_idx];
                                         let n = unsafe { libc::write(dup_fd, packet.as_ptr() as *const libc::c_void, packet.len()) };
                                         if n < 0 {
                                             let err = std::io::Error::last_os_error();
                                             if err.kind() == std::io::ErrorKind::WouldBlock { return Err(err); }
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
                                        break 'write;
                                    },
                                    Err(_) => {},
                                }
                            }
                         }
                         Err(e) => { error!("Connection lost: {}", e); break; }
                    }
                }
            });

            let mut rx_tun_task = rx_tun;
            let tun_writer_icmp = tun_writer.clone();
            let stop_flag_icmp = stop_flag.clone();
            let icmp_task = tokio::spawn(async move {
                while !stop_flag_icmp.load(Ordering::Relaxed) {
                    if let Some(icmp_pkt) = rx_tun_task.recv().await {
                         let mut guard = match tun_writer_icmp.writable().await {
                             Ok(g) => g,
                             Err(_) => break,
                         };
                         let _ = guard.try_io(|_inner| {
                             unsafe { libc::write(dup_fd, icmp_pkt.as_ptr() as *const libc::c_void, icmp_pkt.len()) };
                             Ok(())
                         });
                    }
                }
            });

            // Wait for either task to finish or stop flag
            while !stop_flag_outer.load(Ordering::Relaxed) {
                if tun_to_quic.is_finished() || quic_to_tun.is_finished() || icmp_task.is_finished() { break; }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            
            stop_flag_outer.store(true, Ordering::SeqCst);
            tun_to_quic.abort();
            quic_to_tun.abort();
            icmp_task.abort();
        },
        ActiveConnection::Tcp { mut send_stream, mut recv_stream, mut leftover } => {
            let stop_check = stop_flag.clone();
            let read_fd = dup_fd;

            let tun_to_tcp = tokio::spawn(async move {
                let mut buf = BytesMut::with_capacity(65536); 
                loop {
                    if stop_check.load(Ordering::Relaxed) { break; }
                    
                    let mut guard = match tun_reader.readable().await {
                        Ok(g) => g,
                        Err(_) => break,
                    };

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
                        Err(_) => continue,
                    };

                    let mut frame = Vec::with_capacity(2 + packet.len());
                    frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
                    frame.extend_from_slice(&packet);
                    
                    send_stream.reserve_capacity(frame.len());
                    if send_stream.capacity() >= frame.len() {
                        if let Err(_) = send_stream.send_data(Bytes::from(frame), false) {
                            stop_check.store(true, Ordering::SeqCst);
                            break;
                        }
                    } else {
                        // Drop packet if saturated
                    }
                }
            });

            loop {
                if stop_flag.load(Ordering::Relaxed) { break; }
                
                while leftover.len() >= 2 {
                    let pkt_len = u16::from_be_bytes([leftover[0], leftover[1]]) as usize;
                    if leftover.len() >= 2 + pkt_len {
                        let packet = leftover.split_to(2 + pkt_len).split_off(2).freeze();
                        if packet.is_empty() { continue; }
                        
                        let mut guard = match tun_writer.writable().await {
                             Ok(g) => g,
                             Err(_) => break,
                        };
                        let _ = guard.try_io(|_inner| {
                             unsafe { libc::write(dup_fd, packet.as_ptr() as *const libc::c_void, packet.len()) };
                             Ok(())
                        });
                    } else { break; }
                }
                
                match recv_stream.data().await {
                    Some(Ok(chunk)) => {
                        leftover.extend_from_slice(&chunk);
                        let _ = recv_stream.flow_control().release_capacity(chunk.len());
                    }
                    Some(Err(_)) | None => { 
                        error!("TCP Connection lost");
                        break; 
                    }
                }
            }
            
            stop_flag.store(true, Ordering::SeqCst);
            tun_to_tcp.abort();
        },
        ActiveConnection::Consumed => {}
    }

}

#[cfg(not(target_os = "android"))]
async fn run_vpn_loop(_connection: ActiveConnection, _fd: jint, _stop_flag: Arc<AtomicBool>, _config: ControlMessage) {
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

fn find_fd_by_port(port: u16) -> Option<RawFd> {
    #[cfg(target_os = "android")]
    {
        use std::fs;
        let fds = fs::read_dir("/proc/self/fd").ok()?;
        for entry in fds {
            let entry = entry.ok()?;
            let fd_str = entry.file_name();
            let fd: RawFd = fd_str.to_str()?.parse().ok()?;
            
            let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of_val(&addr) as libc::socklen_t;
            
            if unsafe { libc::getsockname(fd, &mut addr as *mut _ as *mut _, &mut len) } == 0 {
                let local_port = if addr.sin6_family == libc::AF_INET6 as u16 {
                    u16::from_be(addr.sin6_port)
                } else if addr.sin6_family == libc::AF_INET as u16 {
                    let addr4: &libc::sockaddr_in = unsafe { std::mem::transmute(&addr) };
                    u16::from_be(addr4.sin_port)
                } else {
                    0
                };
                
                if local_port == port {
                    return Some(fd);
                }
            }
        }
    }
    let _ = port; // Silence warning on non-android
    None
}
