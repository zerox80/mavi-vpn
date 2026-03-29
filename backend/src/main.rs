//! # Mavi VPN Backend
//! 
//! High-performance VPN server leveraging QUIC as the transport layer and TUN devices
//! for network integration.
//! 
//! ## Performance Highlights
//! - **Zero-Copy Architecture**: Uses `BytesMut` and `split_to` for packet handling without memory copies.
//! - **Batched I/O**: Packets are queued and written to the TUN device in batches to reduce syscall overhead.
//! - **Pinned MTU**: Forces a stable MTU strategy (1280 Tun / 1360 QUIC Payload / ~1400 Wire) to minimize mobile fragmentation issues.
//! - **Async Pipeline**: Fully non-blocking architecture using `tokio` and `quinn`.

use anyhow::{Context, Result};
use bytes::Bytes;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use quinn::{Endpoint, ServerConfig};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn};

mod cert;
mod config;
mod state;
mod keycloak;

use crate::config::Config;
use crate::state::AppState;
use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice};
use tun::AbstractDevice;
use constant_time_eq::constant_time_eq;
use shared::icmp;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use shared::ControlMessage;
use futures_util::FutureExt;

/// RAII Guard to ensure IP addresses are returned to the pool even if the
/// connection handler panics or exits unexpectedly.
struct IpGuard {
    state: Arc<AppState>,
    ip4: Ipv4Addr,
    ip6: Ipv6Addr,
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        self.state.release_ips(self.ip4, self.ip6);
        info!("Released IPs for dropped connection: {} / {}", self.ip4, self.ip6);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialise logging with tracing-subscriber (defaulting to info level)
    tracing_subscriber::fmt::init();
    
    // Install the global crypto provider (required for rustls 0.23+ and jsonwebtoken 10.3+)
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    // 1. Load Configuration
    // Combines .env files, standard environment variables, and CLI arguments.
    let config = config::load();
    info!("Starting Mavi VPN Server...");
    info!("Network: {}", config.network_cidr);
    info!("Bind Address: {}", config.bind_addr);

    // 2. Initialize State
    // Manages the IP pool and active peer mapping (DashMap for thread-safe access).
    let state = Arc::new(AppState::new(&config.network_cidr)?);

    // 3. Setup Certificates
    // Generates a self-signed certificate if none exists at the configured paths.
    let cert_path = config.cert_path.clone();
    let key_path = config.key_path.clone();
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create certificate directory")?;
    }
    let (certs, key) = cert::load_or_generate_certs(cert_path, key_path)?;

    // 3b. Keycloak Initialization (Beta-Keycloak)
    let mut keycloak_validator = None;
    if config.keycloak_enabled {
        if let Some(url) = &config.keycloak_url {
            let kc = crate::keycloak::KeycloakValidator::new(
                url.clone(),
                config.keycloak_realm.clone(),
                config.keycloak_client_id.clone(),
            );
            match kc.init_and_fetch().await {
                Ok(_) => keycloak_validator = Some(Arc::new(kc)),
                Err(e) => {
                    tracing::error!("Failed to initialize Keycloak JWKS cache: {}. Ensure Keycloak is running and reachable at {}", e, url);
                    std::process::exit(1);
                }
            }
        } else {
            tracing::error!("KEYCLOAK_ENABLED is true but KEYCLOAK_URL is not set.");
            std::process::exit(1);
        }
    }

    // 4. Setup QUIC Server Config
    // Uses TLS 1.3 exclusively.
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into()
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
        .with_single_cert(certs, key)?;
    
    // Obfuscation Layer: Only offer "h3" in censorship-resistant mode to avoid fingerprinting.
    // Standard mode allows fallback to "mavivpn" for legacy clients.
    server_crypto.alpn_protocols = if config.censorship_resistant {
        vec![b"h3".to_vec()]
    } else {
        vec![b"h3".to_vec(), b"mavivpn".to_vec()]
    };
    
    if config.censorship_resistant {
        info!("Censorship Resistant Mode ENABLED. ALPN priority: h3");
    } else {
        info!("Standard Mode ENABLED. ALPN priority: h3 (Compatibility: mavivpn)");
    }
    
    let mut server_config = ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| anyhow::anyhow!("Failed to access transport config"))?;
    
    // QUIC Timeout settings
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(2)));
    
    // QUIC Performance Tuning: 
    // Large buffers are critical for throughput on high-latency mobile networks.
    transport_config.datagram_receive_buffer_size(Some(4 * 1024 * 1024)); // 4MB receive buffer
    transport_config.datagram_send_buffer_size(4 * 1024 * 1024); // 4MB send buffer
    transport_config.receive_window(quinn::VarInt::from(4u32 * 1024 * 1024)); // 4MB
    transport_config.stream_receive_window(quinn::VarInt::from(1024u32 * 1024)); // 1MB per stream
    transport_config.send_window(4 * 1024 * 1024); // 4MB send window
    
    // Enable BBR Congestion Control (standard for high bandwidth + lossy environments)
    transport_config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    
    // --- USER REQUESTED MTU PINNING (Target: 1360 QUIC Payload) ---
    // User confirmed 1460 MTU at Vodafone. 1360 Payload + 28/48 Header = 1388/1408 Wire.
    // This is safe for 1460 networks and provides maximum throughput for 1280 TUN packets.
    transport_config.mtu_discovery_config(None); 
    transport_config.initial_mtu(1360); 
    transport_config.min_mtu(1360);
    
    // Enable Generic Segmentation Offload (GSO) for OS-level performance boost
    transport_config.enable_segmentation_offload(true);
    
    // Manually configure the underlying UDP socket
    let socket = std::net::UdpSocket::bind(config.bind_addr)?;
    let socket2_sock = socket2::Socket::from(socket);
    let _ = socket2_sock.set_recv_buffer_size(4 * 1024 * 1024); // 4MB OS-level buffer
    let _ = socket2_sock.set_send_buffer_size(4 * 1024 * 1024); // 4MB OS-level buffer
    
    // Enable UDP fragmentation for packets > Path MTU (Handling the 1280 floor on bad paths)
    // This allows the OS to fragment the QUIC packets if needed, rather than dropping them.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket2_sock.as_raw_fd();
        
        unsafe {
            // Disable Path MTU Discovery "Don't Fragment" flag (IP_PMTUDISC_DONT)
            let val: libc::c_int = 0; 
            let _ = libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, &val as *const _ as *const libc::c_void, std::mem::size_of_val(&val) as libc::socklen_t);
            let _ = libc::setsockopt(fd, libc::IPPROTO_IPV6, 23, &val as *const _ as *const libc::c_void, std::mem::size_of_val(&val) as libc::socklen_t);
            info!("UDP Fragmentation enabled (PMTUDISC_DONT) for IPv4/IPv6");
        }
    }

    let socket = std::net::UdpSocket::from(socket2_sock);
    let endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    
    // 5. Setup TUN Interface
    let mut tun_config = tun::Configuration::default();
    let gateway_ip = state.gateway_ip();
    let netmask = state.network.mask();

    tun_config.address(gateway_ip)
              .netmask(netmask)
              .mtu(config.mtu as u16)
              .up();

    #[cfg(target_os = "linux")]
    tun_config.platform_config(|_config| {
        // PI header is now disabled by default or ignored in newer tun versions
    });

    if let Some(dev_path) = &config.tun_device_path {
        tun_config.tun_name(dev_path);
    }

    let dev = tun::create_as_async(&tun_config).context("Failed to create TUN device. Ensure NET_ADMIN cap is set.")?;
    let tun_name = std::ops::Deref::deref(&dev).tun_name().unwrap_or_else(|_| "tun0".into());
    let (mut tun_reader, mut tun_writer) = tokio::io::split(dev);

    info!("TUN Device created: {}. IP: {}", tun_name, gateway_ip);

    // Configure IPv6 on TUN via external command (tun-rs doesn't natively handle dual-stack well yet)
    let gateway_ip6 = state.gateway_ip_v6();
    match std::process::Command::new("ip")
        .args(&["-6", "addr", "add", &format!("{}/64", gateway_ip6), "dev", &tun_name])
        .output() {
            Ok(output) if output.status.success() => {
                 info!("IPv6 address {} successfully assigned to {}", gateway_ip6, tun_name);
            }
            Ok(output) => {
                 warn!("FAILED to assign IPv6 address to TUN: {}. IPv6 connectivity might be limited.", String::from_utf8_lossy(&output.stderr).trim());
            }
            Err(e) => {
                 warn!("FAILED to execute 'ip' command for IPv6 assignment: {}. Ensure 'iproute2' is installed.", e);
            }
        }

    // Cleanup legacy system rules to ensure a clean slate
    cleanup_legacy_rules();

    // 6. Packet Routing Hub
    //
    // Data Flow 1: Client -> QUIC Datagram -> Backend Hub -> TUN Writer -> Kernel
    // Data Flow 2: Kernel -> TUN Reader -> Backend Hub -> Active Session -> QUIC Datagram
    
    let (tx_tun, mut rx_tun) = tokio::sync::mpsc::channel::<Bytes>(2048);

    // Task: TUN Writer 
    // Processes packets from the internal queue and writes them to the kernel.
    // Implements BATCHED writes to reduce transition overhead.
    tokio::spawn(async move {
        let mut batch: Vec<Bytes> = Vec::with_capacity(64);
        loop {
            match rx_tun.recv().await {
                Some(packet) => batch.push(packet),
                None => break,
            }
            
            // Greedily drain additional packets from the channel
            while batch.len() < 64 {
                match rx_tun.try_recv() {
                    Ok(packet) => batch.push(packet),
                    Err(_) => break,
                }
            }
            
            for packet in batch.drain(..) {
                if let Err(e) = tun_writer.write_all(&packet).await {
                    error!("CRITICAL: Failed to write to TUN: {}. Exiting.", e);
                    std::process::exit(1); 
                }
            }
        }
    });

    // Task: TUN Reader
    // Reads raw IP packets from the kernel and routes them to the correct QUIC connection
    // based on the Destination IP.
    let state_reader = state.clone();
    tokio::spawn(async move {
        let mut buf = bytes::BytesMut::with_capacity(2048);
        loop {
            if buf.capacity() < 2048 { buf.reserve(2048); }
            
            match tun_reader.read_buf(&mut buf).await {
                Ok(0) => break, // Interface down
                Ok(n) => {
                    // ZERO-COPY: split_to creates a view into the buffer without cloning data
                    let packet = buf.split_to(n).freeze();
                    if packet.len() == 0 { continue; }
                    
                    let version = packet[0] >> 4;
                    if version == 4 {
                         if let Ok(ipv4_header) = Ipv4HeaderSlice::from_slice(&packet) {
                            let dest_ip = ipv4_header.destination_addr();
                            // Peer lookup: O(1) via DashMap
                            if let Some(tx_client) = state_reader.peers.get(&dest_ip) {
                                let _ = tx_client.try_send(packet);
                            }
                        }
                    } else if version == 6 {
                         if let Ok(ipv6_header) = Ipv6HeaderSlice::from_slice(&packet) {
                            let dest_ip = ipv6_header.destination_addr();
                            if let Some(tx_client) = state_reader.peers_v6.get(&dest_ip) {
                                let _ = tx_client.try_send(packet);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("CRITICAL: Error reading from TUN: {}. Exiting.", e);
                    std::process::exit(1);
                }
            }
        }
    });

    // 7. Accept incoming QUIC connections
    while let Some(conn) = endpoint.accept().await {
        let state = state.clone();
        let config = config.clone();
        let tx_tun = tx_tun.clone();
        let keycloak = keycloak_validator.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(conn, state, config, tx_tun, keycloak).await {
               // fine to fail, client disconnected or bad auth
               warn!("Connection terminated: {}", e);
            }
        });
    }

    Ok(())
}

/// Handles the lifecycle of a single client connection.
async fn handle_connection(
    conn: quinn::Incoming,
    state: Arc<AppState>,
    config: Config,
    tx_tun: tokio::sync::mpsc::Sender<Bytes>,
    keycloak: Option<Arc<crate::keycloak::KeycloakValidator>>,
) -> Result<()> {
    // 1. Establish QUIC connection (wait for TLS handshake)
    let connection = conn.await?;
    let remote_addr = connection.remote_address();
    info!("New connection from {}", remote_addr);

    // 2. Auth/Config Phase (on the bidirectional stream)
    let (mut send_stream, mut recv_stream) = connection.accept_bi().await?;
    
    let auth_result: Result<(std::net::Ipv4Addr, std::net::Ipv6Addr)> = async {
        // Read length-prefixed authentication message
        let len = tokio::time::timeout(std::time::Duration::from_secs(5), recv_stream.read_u32_le())
            .await
            .map_err(|_| anyhow::anyhow!("Handshake timeout"))?? as usize;
        
        // Increase maximum auth payload size from 1024 to 8192 to support large Keycloak JWTs
        if len > 8192 { anyhow::bail!("Auth message too big (max 8192 bytes for JWT)"); }
        let mut buf = vec![0u8; len];
        recv_stream.read_exact(&mut buf).await?;
        
        // Decode using bincode
        let msg: ControlMessage = bincode::serde::decode_from_slice(&buf, bincode::config::standard())
            .map(|(v, _)| v)
            .map_err(|e| anyhow::anyhow!("Protocol error: {}", e))?;
        
        match msg {
            ControlMessage::Auth { token } => {
                // Keycloak vs Static Token Authentication
                if let Some(kc) = &keycloak {
                    if !kc.validate_token(&token).await? {
                         anyhow::bail!("Access Denied: Invalid Keycloak JWT Token");
                    }
                } else {
                    // Time-constant comparison to protect against timing attacks
                    if !constant_time_eq(token.as_bytes(), config.auth_token.as_bytes()) {
                        anyhow::bail!("Access Denied: Invalid Token");
                    }
                }

                // Lease internal IPs
                let v4 = state.assign_ip()?;
                let v6 = state.assign_ipv6()?;
                Ok((v4, v6))
            }
            _ => anyhow::bail!("Protocol error: Expected Auth message"),
        }
    }.await;

    let (assigned_ip, assigned_ip6) = match auth_result {
        Ok(ips) => ips,
        Err(e) => {
            // PROBE RESISTANCE: If the server is in censorship_resistant mode,
            // we send a fake Nginx HTTP/3 response to any unauthorized probe.
            if config.censorship_resistant {
                warn!("Unauthorized probe from {}. Emulating HTTP/3 server.", remote_addr);
                
                // Emulate H3 control stream settings
                if let Ok(mut ctrl) = connection.open_uni().await {
                    let _ = ctrl.write_all(&[0x00, 0x04, 0x00]).await;
                    let _ = ctrl.finish();
                }

                let mut response = Vec::new();
                // HTTP/3 HEADERS Frame (Fake Nginx)
                response.push(0x01); 
                response.push(0x19); 
                let qpack_bytes: [u8; 25] = [0x00, 0x00, 0xd9, 0x5f, 0x4d, 0x84, 0xaa, 0x63, 0x55, 0xe7, 0x5f, 0x1d, 0x87, 0x49, 0x7c, 0xa5, 0x89, 0xd3, 0x4d, 0x1f, 0x54, 0x03, 0x31, 0x37, 0x33];
                response.extend_from_slice(&qpack_bytes);

                // HTTP/3 DATA Frame (Fake HTML)
                let fake_body = b"<html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed.</p></body></html>";
                response.push(0x00); 
                response.push(0x40); response.push(0xAD); // Length 173
                response.extend_from_slice(fake_body);

                let _ = send_stream.write_all(&response).await;
                let _ = send_stream.finish();
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                return Err(anyhow::anyhow!("HTTP/3 probe response sent to {}", remote_addr));
            } else {
                return Err(anyhow::anyhow!("Unauthorized access from {}: {}", remote_addr, e));
            }
        }
    };

    // RAII Guard: Release IPs back to state if this task ends for any reason.
    let _ip_guard = IpGuard { state: state.clone(), ip4: assigned_ip, ip6: assigned_ip6 };

    // 3. Send successful configuration back to client
    let success_msg = ControlMessage::Config {
        assigned_ip,
        netmask: state.network.mask(),
        gateway: state.gateway_ip(),
        dns_server: config.dns,
        mtu: config.mtu as u16,
        assigned_ipv6: Some(assigned_ip6),
        netmask_v6: Some(64),
        gateway_v6: Some(state.gateway_ip_v6()),
        dns_server_v6: Some("2001:4860:4860::8888".parse().unwrap()),
        whitelist_domains: Some(config.whitelist_domains.clone()),
    };
    let bytes = bincode::serde::encode_to_vec(&success_msg, bincode::config::standard())?;
    send_stream.write_u32_le(bytes.len() as u32).await?;
    send_stream.write_all(&bytes).await?;
    let _ = send_stream.finish();

    info!("Authenticated {} -> Assigned IPv4: {}, IPv6: {}", remote_addr, assigned_ip, assigned_ip6);

    // 4. Packet Pumping Phase
    let (tx_client, mut rx_client) = tokio::sync::mpsc::channel::<Bytes>(1024);
    state.register_client(assigned_ip, assigned_ip6, tx_client);

    let connection_arc = Arc::new(connection);
    
    // Task: Hub -> QUIC Datagram
    // Pulls packets meant for this specific client from the internal hub
    // and sends them as unreliable QUIC datagrams.
    let conn_send = connection_arc.clone();
    let tx_tun_icmp = tx_tun.clone();
    let gateway_v4 = state.gateway_ip();
    let gateway_v6 = state.gateway_ip_v6();
    let tun_to_quic = tokio::spawn(async move {
        while let Some(packet) = rx_client.recv().await {
            if let Err(e) = conn_send.send_datagram(packet.clone()) {
                if matches!(e, quinn::SendDatagramError::TooLarge) {
                    // PATH MTU DISCOVERY (PTB)
                    // If the packet exceeds the current path MTU, we synthesise an ICMP
                    // signal back into the TUN device so the client's stack knows to resize.
                    let current_mtu = conn_send.max_datagram_size().unwrap_or(1200) as u16;
                    let version = packet[0] >> 4;
                    let _gw = if version == 4 { std::net::IpAddr::V4(gateway_v4) } else { std::net::IpAddr::V6(gateway_v6) };
                    
                    // Report 1280 even if path is smaller (due to our fragmentation support)
                    let reported_mtu = if version == 6 { std::cmp::max(current_mtu, 1280) } else { current_mtu };

                    if let Some(icmp_packet) = icmp::generate_packet_too_big(&packet, reported_mtu, None) {
                        let _ = tx_tun_icmp.try_send(Bytes::from(icmp_packet));
                    }
                }
            }
        }
    });

    // Task: MTU Monitoring
    // Periodically logs changes in the path MTU (important for debugging).
    let conn_monitor = connection_arc.clone();
    tokio::spawn(async move {
        let mut last_mtu = 0;
        loop {
            let current_mtu = conn_monitor.max_datagram_size().unwrap_or(0);
            if current_mtu != last_mtu {
                if last_mtu != 0 {
                    warn!("[MTU] Path MTU changed: {} -> {} bytes", last_mtu, current_mtu);
                }
                last_mtu = current_mtu;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
            if conn_monitor.close_reason().is_some() { break; }
        }
    });

    // Loop: QUIC Datagram -> Backend Hub (Source-IP filtering)
    // Ensures clients don't spoof their source IP.
    let res = 'outer_loop: loop {
        let first_packet = match connection_arc.read_datagram().await {
            Ok(p) => p,
            Err(e) => break Err(anyhow::anyhow!("Connection lost: {}", e)),
        };

        // Batch processing of incoming datagrams
        let mut batch = Vec::with_capacity(64);
        batch.push(first_packet);

        for _ in 0..63 {
            if let Some(Ok(p)) = connection_arc.read_datagram().now_or_never() { batch.push(p); } else { break; }
        }

        for data in batch {
             if data.is_empty() { continue; }

             let version = data[0] >> 4;
             let mut valid = false;
             
             if version == 4 {
                 if let Ok(ipv4_header) = Ipv4HeaderSlice::from_slice(&data) {
                     if ipv4_header.source_addr() == assigned_ip { valid = true; }
                 }
             } else if version == 6 {
                  if let Ok(ipv6_header) = Ipv6HeaderSlice::from_slice(&data) {
                     let src = ipv6_header.source_addr();
                     // Allow assigned IP, Link-Local (fe80::), or Unspecified (::)
                     if src == assigned_ip6 || (src.segments()[0] & 0xffc0 == 0xfe80) || src.is_unspecified() { valid = true; }
                 }
             }

             if valid {
                  if let Err(_) = tx_tun.send(data).await { break 'outer_loop Err(anyhow::anyhow!("TUN hub closed")); }
             }
        }
    };

    tun_to_quic.abort();
    res
}

/// System helper to flush old iptables rules that might interfere with modern Mavi VPN routing.
fn cleanup_legacy_rules() {
    let _ = std::process::Command::new("iptables").args(&["-t", "mangle", "-F", "MAVI_CLAMP"]).output();
    let _ = std::process::Command::new("iptables").args(&["-t", "mangle", "-X", "MAVI_CLAMP"]).output();
}
