//! # Mavi VPN Backend
//! 
//! High-performance VPN server leveraging QUIC as the transport layer and TUN devices
//! for network integration.
//! 
//! ## Performance Highlights
//! - **Zero-Copy Architecture**: Uses `BytesMut` and `split_to` for packet handling without memory copies.
//! - **Batched I/O**: Packets are queued and written to the TUN device in batches to reduce syscall overhead.
//! - **Pinned MTU**: Forces a stable MTU strategy (1280 payload / 1360 wire) to minimize mobile fragmentation issues.
//! - **Async Pipeline**: Fully non-blocking architecture using `tokio` and `quinn`.

use anyhow::{Context, Result};
use bytes::Bytes;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use wtransport::{Endpoint, ServerConfig};
use wtransport::tls::{Certificate, CertificateChain, PrivateKey, Identity};
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


use std::net::{Ipv4Addr, Ipv6Addr};

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
    
    // Install the default crypto provider for rustls & jsonwebtoken to prevent panics
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();

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

    // 4. Setup WebTransport Server Config
    let w_certs: Vec<Certificate> = certs.clone().into_iter().map(|c| Certificate::from_der(c.to_vec()).expect("Valid DER")).collect();
    let w_chain = CertificateChain::new(w_certs);
    let w_key = PrivateKey::from_der_pkcs8(key.secret_der().to_vec());
    let identity = Identity::new(w_chain, w_key);
    
    if config.censorship_resistant {
        info!("Censorship Resistant Mode ENABLED. Only WebTransport will be served.");
    }
    
    // Server-side QUIC transport tuning (matches client-side config)
    let mut transport_config = quinn::TransportConfig::default();
    // BBR outperforms NewReno/Cubic (default) on Wi-Fi and high-latency paths.
    // Without this the server-side congestion window collapses to ~50Mbps on jittery links.
    transport_config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    // Pin MTU to avoid fragmentation issues on mobile/VPN paths
    transport_config.mtu_discovery_config(None);
    transport_config.initial_mtu(1360);
    transport_config.min_mtu(1360);
    // Large datagram buffers prevent drops during download bursts
    transport_config.datagram_receive_buffer_size(Some(4 * 1024 * 1024)); // 4MB
    transport_config.datagram_send_buffer_size(4 * 1024 * 1024);          // 4MB
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into().unwrap()));

    let mut server_config = ServerConfig::builder()
        .with_bind_address(config.bind_addr)
        .with_identity(identity)
        .keep_alive_interval(Some(std::time::Duration::from_secs(5)))
        .build();

    server_config.quic_config_mut().transport_config(Arc::new(transport_config));

    let endpoint = Endpoint::server(server_config)?;
    
    // 5. Setup TUN Interface
    let mut tun_config = tun::Configuration::default();
    let gateway_ip = state.gateway_ip();
    let netmask = state.network.mask();

    tun_config.address(gateway_ip)
              .netmask(netmask)
              .mtu(config.mtu as u16)
              .up();

    #[cfg(target_os = "linux")]
    tun_config.platform_config(|config| {
        // Disable packet information (PI) header for raw IP data
        config.packet_information(false); 
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
    let _ = std::process::Command::new("ip")
        .args(&["-6", "addr", "add", &format!("{}/64", gateway_ip6), "dev", &tun_name])
        .output();

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

    // 7. Accept incoming connections (QUIC and HTTP/2)
    let quic_state = state.clone();
    let quic_config = config.clone();
    let quic_tx_tun = tx_tun.clone();
    let quic_kc = keycloak_validator.clone();

    // 6b. Setup TLS config for TCP fallback
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into()
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)?;
    
    server_crypto.alpn_protocols = vec![b"mavivpn".to_vec(), b"h2".to_vec()];
    let server_crypto_arc = Arc::new(server_crypto);

    let quic_task = tokio::spawn(async move {
        // endpoint.accept() returns an IncomingSession awaitable.
        loop {
            let incoming_session = endpoint.accept().await;
            let state = quic_state.clone();
            let config = quic_config.clone();
            let tx_tun = quic_tx_tun.clone();
            let keycloak = quic_kc.clone();

            tokio::spawn(async move {
                // Wait for the HTTP/3 layer to parse the incoming request
                let session_req = match incoming_session.await {
                    Ok(req) => req,
                    Err(e) => {
                        warn!("WebTransport handhshake error: {}", e);
                        return;
                    }
                };
                
                if let Err(e) = handle_quic_connection(session_req, state, config, tx_tun, keycloak).await {
                   warn!("WebTransport connection terminated: {}", e);
                }
            });
        }
    });

    let tcp_listener = tokio::net::TcpListener::bind(config.bind_addr_tcp).await?;
    info!("TCP HTTP/2 Fallback Server listening on {}", config.bind_addr_tcp);
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_crypto_arc);

    let tcp_state = state.clone();
    let tcp_config = config.clone();
    let tcp_tx_tun = tx_tun.clone();
    let tcp_kc = keycloak_validator.clone();

    let tcp_task = tokio::spawn(async move {
        while let Ok((stream, remote_addr)) = tcp_listener.accept().await {
            let state = tcp_state.clone();
            let config = tcp_config.clone();
            let tx_tun = tcp_tx_tun.clone();
            let keycloak = tcp_kc.clone();
            let acceptor = tls_acceptor.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_h2_connection(stream, remote_addr, acceptor, state, config, tx_tun, keycloak).await {
                    warn!("TCP HTTP/2 connection terminated from {}: {}", remote_addr, e);
                }
            });
        }
    });

    let _ = tokio::join!(quic_task, tcp_task);

    Ok(())
}

/// Helper function to authenticate a user token and assign IPs
async fn authenticate_user(
    token: &str,
    state: &Arc<AppState>,
    config: &Config,
    keycloak: &Option<Arc<crate::keycloak::KeycloakValidator>>,
) -> Result<(std::net::Ipv4Addr, std::net::Ipv6Addr)> {
    if let Some(kc) = keycloak {
        if !kc.validate_token(token).await? {
             anyhow::bail!("Access Denied: Invalid Keycloak JWT Token");
        }
    } else {
        if !constant_time_eq(token.as_bytes(), config.auth_token.as_bytes()) {
            anyhow::bail!("Access Denied: Invalid Token");
        }
    }
    let v4 = state.assign_ip()?;
    let v6 = state.assign_ipv6()?;
    Ok((v4, v6))
}

/// Handles the lifecycle of a single WebTransport client connection.
async fn handle_quic_connection(
    session_req: wtransport::endpoint::SessionRequest,
    state: Arc<AppState>,
    config: Config,
    tx_tun: tokio::sync::mpsc::Sender<Bytes>,
    keycloak: Option<Arc<crate::keycloak::KeycloakValidator>>,
) -> Result<()> {
    // 1. Establish WebTransport session (Reject non-vpn paths)
    if session_req.path() != "/vpn" {
        if config.censorship_resistant {
           // We can just drop or reject the session cleanly. 
           // Wtransport sends a normal HTTP error (e.g. 404).
           session_req.not_found().await;
           return Err(anyhow::anyhow!("Ignored probe to non-vpn path"));
        } else {
           session_req.forbidden().await;
           return Err(anyhow::anyhow!("Unauthorized access: bad path"));
        }
    }
    
    let connection = session_req.accept().await?;
    let remote_addr = connection.remote_address();
    info!("New WebTransport connection from {}", remote_addr);

    // 2. Auth/Config Phase (on the bidirectional stream)
    let (mut send_stream, mut recv_stream) = connection.accept_bi().await?;
    
    let auth_result: Result<(std::net::Ipv4Addr, std::net::Ipv6Addr)> = async {
        // Read length-prefixed authentication message
        let len = tokio::time::timeout(std::time::Duration::from_secs(5), recv_stream.read_u32_le())
            .await
            .map_err(|_| anyhow::anyhow!("Handshake timeout"))?? as usize;
        
        if len > 8192 { anyhow::bail!("Auth message too big (max 8192 bytes for JWT)"); }
        let mut buf = vec![0u8; len];
        recv_stream.read_exact(&mut buf).await?;
        
        let msg: ControlMessage = bincode::serde::decode_from_slice(&buf, bincode::config::standard())
            .map(|(v, _)| v)
            .map_err(|e| anyhow::anyhow!("Protocol error: {}", e))?;
        
        match msg {
            ControlMessage::Auth { token } => {
                let (v4, v6) = authenticate_user(&token, &state, &config, &keycloak).await?;
                Ok((v4, v6))
            }
            _ => anyhow::bail!("Protocol error: Expected Auth message"),
        }
    }.await;

    let (assigned_ip, assigned_ip6) = match auth_result {
        Ok(ips) => ips,
        Err(e) => {
            return Err(anyhow::anyhow!("Unauthorized access from {}: {}", remote_addr, e));
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

    let tun_to_quic = tokio::spawn(async move {
        while let Some(packet) = rx_client.recv().await {
            if let Err(e) = conn_send.send_datagram(packet.clone()) {
                warn!("WebTransport Datagram error: {}", e);
            }
        }
    });

    // Task: MTU Monitoring is natively handled differently in wtransport, skipping for now

    // Loop: QUIC Datagram -> Backend Hub (Source-IP filtering)
    // Ensures clients don't spoof their source IP.
    let res = 'outer_loop: loop {
        let first_packet = match connection_arc.receive_datagram().await {
            Ok(p) => p,
            Err(e) => break Err(anyhow::anyhow!("Connection lost: {}", e)),
        };

        // Batch processing of incoming datagrams
        let mut batch = Vec::with_capacity(64);
        batch.push(first_packet);

        for _ in 0..63 {
            if let Some(Ok(p)) = connection_arc.receive_datagram().now_or_never() { batch.push(p); } else { break; }
        }

        for data in batch {
             if data.is_empty() { continue; }

             let payload = data.payload();
             let version = payload[0] >> 4;
             let mut valid = false;
             
             if version == 4 {
                 if let Ok(ipv4_header) = Ipv4HeaderSlice::from_slice(&payload) {
                     if ipv4_header.source_addr() == assigned_ip { valid = true; }
                 }
             } else if version == 6 {
                  if let Ok(ipv6_header) = Ipv6HeaderSlice::from_slice(&payload) {
                     let src = ipv6_header.source_addr();
                     // Allow assigned IP, Link-Local (fe80::), or Unspecified (::)
                     if src == assigned_ip6 || (src.segments()[0] & 0xffc0 == 0xfe80) || src.is_unspecified() { valid = true; }
                 }
             }

             if valid {
                  if let Err(_) = tx_tun.send(payload.clone()).await { break 'outer_loop Err(anyhow::anyhow!("TUN hub closed")); }
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

/// Handles a single TCP/HTTP2 fallback connection
async fn handle_h2_connection(
    stream: tokio::net::TcpStream,
    remote_addr: std::net::SocketAddr,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    state: Arc<AppState>,
    config: Config,
    tx_tun: tokio::sync::mpsc::Sender<Bytes>,
    keycloak: Option<Arc<crate::keycloak::KeycloakValidator>>,
) -> Result<()> {
    info!("New TCP connection from {}", remote_addr);
    let _ = stream.set_nodelay(true);

    let tls_stream = match tokio::time::timeout(std::time::Duration::from_secs(5), tls_acceptor.accept(stream)).await {
        Ok(Ok(s)) => s,
        _ => anyhow::bail!("TLS handshake failed or timed out"),
    };

    let mut h2_conn = match tokio::time::timeout(std::time::Duration::from_secs(5), h2::server::handshake(tls_stream)).await {
        Ok(Ok(c)) => c,
        _ => anyhow::bail!("HTTP/2 handshake failed or timed out"),
    };

    // Keep the h2 connection alive by spawning the drive task
    let (mut send_response, mut recv_stream) = match h2_conn.accept().await {
        Some(Ok((req, respond))) => (respond, req.into_body()),
        Some(Err(e)) => anyhow::bail!("h2 accept error: {}", e),
        None => anyhow::bail!("No h2 request sent"),
    };

    tokio::spawn(async move {
        while let Some(res) = h2_conn.accept().await {
           if res.is_err() { break; }
        }
    });

    // 1. Auth Phase (Length-prefixed bincode)
    let mut len_buf = [0u8; 4];
    let mut len_read = 0;
    while len_read < 4 {
        match recv_stream.data().await {
            Some(Ok(bytes)) => {
                let to_copy = std::cmp::min(4 - len_read, bytes.len());
                len_buf[len_read..len_read+to_copy].copy_from_slice(&bytes[..to_copy]);
                let _ = recv_stream.flow_control().release_capacity(bytes.len());
                len_read += to_copy;
            }
            _ => anyhow::bail!("Failed to read auth length"),
        }
    }
    let msg_len = u32::from_le_bytes(len_buf) as usize;
    if msg_len > 8192 { anyhow::bail!("Auth payload too large"); }

    let mut auth_buf = Vec::new();
    while auth_buf.len() < msg_len {
        match recv_stream.data().await {
            Some(Ok(bytes)) => {
               auth_buf.extend_from_slice(&bytes);
               let _ = recv_stream.flow_control().release_capacity(bytes.len());
            }
            _ => anyhow::bail!("Failed to read auth payload"),
        }
    }
    let auth_msg: ControlMessage = bincode::serde::decode_from_slice(&auth_buf, bincode::config::standard()).map(|(v,_)| v)?;

    let token = match auth_msg {
        ControlMessage::Auth { token } => token,
        _ => anyhow::bail!("Expected Auth message"),
    };

    let (assigned_ip, assigned_ip6) = match authenticate_user(&token, &state, &config, &keycloak).await {
        Ok(ips) => ips,
        Err(e) => {
             let response = http::Response::builder().status(403).body(()).unwrap();
             let _ = send_response.send_response(response, true);
             return Err(e);
        }
    };

    let _ip_guard = IpGuard { state: state.clone(), ip4: assigned_ip, ip6: assigned_ip6 };

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
    
    let config_bytes = bincode::serde::encode_to_vec(&success_msg, bincode::config::standard())?;
    let mut out_buf = Vec::with_capacity(4 + config_bytes.len());
    out_buf.extend_from_slice(&(config_bytes.len() as u32).to_le_bytes());
    out_buf.extend_from_slice(&config_bytes);

    let response = http::Response::builder().status(200).body(()).unwrap();
    let mut send_stream = send_response.send_response(response, false)?;
    let _ = send_stream.send_data(Bytes::from(out_buf), false);

    info!("Authenticated (H2) {} -> Assigned IPv4: {}, IPv6: {}", remote_addr, assigned_ip, assigned_ip6);

    let (tx_client, mut rx_client) = tokio::sync::mpsc::channel::<Bytes>(1024);
    state.register_client(assigned_ip, assigned_ip6, tx_client);

    let mut h2_send = send_stream;
    
    let tun_to_h2 = tokio::spawn(async move {
        while let Some(packet) = rx_client.recv().await {
            let mut buf = Vec::with_capacity(2 + packet.len());
            buf.extend_from_slice(&(packet.len() as u16).to_be_bytes());
            buf.extend_from_slice(&packet);
            
            h2_send.reserve_capacity(buf.len());
            if h2_send.capacity() < buf.len() {
                continue; // drop packet
            }
            if let Err(_) = h2_send.send_data(Bytes::from(buf), false) {
                break;
            }
        }
    });

    let mut leftover = bytes::BytesMut::new();
    let res = 'outer_loop: loop {
        let chunk = match recv_stream.data().await {
            Some(Ok(chunk)) => chunk,
            Some(Err(e)) => break Err(anyhow::anyhow!("H2 read error: {}", e)),
            None => break Err(anyhow::anyhow!("H2 connection closed by client")),
        };
        
        leftover.extend_from_slice(&chunk);
        let _ = recv_stream.flow_control().release_capacity(chunk.len());

        while leftover.len() >= 2 {
            let pkt_len = u16::from_be_bytes([leftover[0], leftover[1]]) as usize;
            if leftover.len() >= 2 + pkt_len {
                let packet = leftover.split_to(2 + pkt_len).split_off(2).freeze();
                
                if packet.is_empty() { continue; }
                let version = packet[0] >> 4;
                let mut valid = false;
                if version == 4 {
                    if let Ok(ipv4_header) = Ipv4HeaderSlice::from_slice(&packet) {
                        if ipv4_header.source_addr() == assigned_ip { valid = true; }
                    }
                } else if version == 6 {
                    if let Ok(ipv6_header) = Ipv6HeaderSlice::from_slice(&packet) {
                        let src = ipv6_header.source_addr();
                        if src == assigned_ip6 || (src.segments()[0] & 0xffc0 == 0xfe80) || src.is_unspecified() { valid = true; }
                    }
                }

                if valid {
                    if let Err(_) = tx_tun.send(packet).await { break 'outer_loop Err(anyhow::anyhow!("TUN hub closed")); }
                }
            } else {
                break;
            }
        }
    };

    tun_to_h2.abort();
    res
}
