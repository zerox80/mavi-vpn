//! # Mavi VPN Linux Core
//!
//! Implements the core VPN logic for Linux, including:
//! - TUN device management via /dev/net/tun.
//! - QUIC transport via Quinn.
//! - Linux-specific routing and DNS leak prevention.
//! - Dual-stack (IPv4/IPv6) support.

use anyhow::{Context, Result};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use shared::{icmp, ipc::Config, ControlMessage};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn, error};

use crate::network::NetworkConfig;
use crate::tun::TunDevice;

// --- Default timing parameters ---
const KEEPALIVE_SECS: u64 = 10;
const IDLE_TIMEOUT_SECS: u64 = 60;
const RECONNECT_INITIAL_SECS: u64 = 1;
const RECONNECT_MAX_SECS: u64 = 30;

/// TUN device name used by the VPN.
const TUN_DEVICE_NAME: &str = "mavi0";

/// Entry point for the VPN runner. Manages the reconnection loop and TUN lifecycle.
pub async fn run_vpn(config: Config, running: Arc<AtomicBool>) -> Result<()> {
    let cert_pin_bytes =
        decode_hex(&config.cert_pin).context("Invalid certificate PIN hex format")?;

    let mut backoff = Duration::from_secs(RECONNECT_INITIAL_SECS);

    while running.load(Ordering::Relaxed) {
        let outcome = run_session(&config, &cert_pin_bytes, &running).await;

        if !running.load(Ordering::Relaxed) {
            break;
        }

        let (reconnect_delay, next_backoff) = match outcome {
            Ok(SessionEnd::UserStopped) => break,
            Ok(SessionEnd::ConnectionLost) => (
                Duration::from_secs(RECONNECT_INITIAL_SECS),
                Duration::from_secs(RECONNECT_INITIAL_SECS),
            ),
            Err(e) => {
                warn!("Session failed: {}. Reconnecting...", e);
                (
                    backoff,
                    (backoff * 2).min(Duration::from_secs(RECONNECT_MAX_SECS)),
                )
            }
        };

        tokio::time::sleep(reconnect_delay).await;
        backoff = next_backoff;
    }

    info!("VPN stopped.");
    Ok(())
}

enum SessionEnd {
    UserStopped,
    ConnectionLost,
}

/// Creates a dual-stack UDP socket for QUIC transport.
fn create_udp_socket() -> Result<std::net::UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    socket.set_only_v6(false)?;
    socket.bind(&socket2::SockAddr::from(
        std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0),
    ))?;

    // Large socket buffers for high-throughput stability (try 4MB, fall back gracefully)
    for size in [4 * 1024 * 1024, 2 * 1024 * 1024, 1024 * 1024] {
        if socket.set_send_buffer_size(size).is_ok() && socket.set_recv_buffer_size(size).is_ok() {
            break;
        }
    }

    // Disable PMTU discovery on the UDP socket to let QUIC handle it
    // (prevents the kernel from dropping packets that exceed path MTU)
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let fd = socket.as_raw_fd();
        let val: libc::c_int = libc::IP_PMTUDISC_DONT;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            );
        }
    }

    Ok(socket.into())
}

/// Manages a single active VPN session (handshake + packet pumping).
async fn run_session(
    config: &Config,
    cert_pin_bytes: &[u8],
    global_running: &Arc<AtomicBool>,
) -> Result<SessionEnd> {
    let socket = create_udp_socket()?;

    // 1. QUIC Handshake & Auth
    let (connection, server_config) = match config.transport_mode {
        shared::TransportMode::Quic => {
            connect_and_handshake(
                socket,
                config.token.clone(),
                config.endpoint.clone(),
                cert_pin_bytes.to_vec(),
            )
            .await?
        }
        shared::TransportMode::Http3 => {
            return run_session_h3(config, cert_pin_bytes, global_running).await;
        }
        shared::TransportMode::Http2 => {
            return run_session_h2(config, cert_pin_bytes, global_running).await;
        }
    };

    // 2. Extract Network Configuration
    let (assigned_ip, netmask, gateway, dns, mtu, assigned_ipv6, netmask_v6, gateway_v6, dns_v6) =
        match server_config {
            ControlMessage::Config {
                assigned_ip,
                netmask,
                gateway,
                dns_server,
                mtu,
                assigned_ipv6,
                netmask_v6,
                gateway_v6,
                dns_server_v6,
                ..
            } => (
                assigned_ip,
                netmask,
                gateway,
                dns_server,
                mtu,
                assigned_ipv6,
                netmask_v6,
                gateway_v6,
                dns_server_v6,
            ),
            ControlMessage::Error { message } => {
                return Err(anyhow::anyhow!(
                    "Server rejected connection: {}",
                    message
                ))
            }
            _ => return Err(anyhow::anyhow!("Unexpected server response")),
        };

    info!("Handshake successful. Internal IPv4: {}", assigned_ip);

    // 3. Create TUN device
    let tun = TunDevice::create(TUN_DEVICE_NAME)?;
    let tun_name = tun.name().to_string();

    // 4. Configure Linux networking (IPs, routes, DNS)
    let remote_ip = connection.remote_address().ip();
    let endpoint_ip_str = match remote_ip {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(|v4| v4.to_string())
            .unwrap_or_else(|| v6.to_string()),
    };

    let net_config = NetworkConfig::apply(
        &tun_name,
        assigned_ip,
        netmask,
        gateway,
        dns,
        mtu,
        &endpoint_ip_str,
        assigned_ipv6,
        netmask_v6,
        gateway_v6,
        dns_v6,
    )?;

    // 5. Start async TUN I/O
    let async_tun = Arc::new(tun.into_async()?);
    let session_alive = Arc::new(AtomicBool::new(true));
    let connection = Arc::new(connection);

    // Task: MTU Monitor
    let conn_monitor = connection.clone();
    let alive_monitor = session_alive.clone();
    let running_monitor = global_running.clone();
    tokio::spawn(async move {
        let mut last_mtu = 0;
        loop {
            if !running_monitor.load(Ordering::Relaxed) || !alive_monitor.load(Ordering::Relaxed) {
                break;
            }
            let current_mtu = conn_monitor.max_datagram_size().unwrap_or(0);
            if current_mtu != last_mtu && last_mtu != 0 {
                info!(
                    "[MTU] QUIC Path MTU changed: {} -> {} bytes",
                    last_mtu, current_mtu
                );
            }
            last_mtu = current_mtu;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    // Task: TUN -> QUIC (Read from TUN, send via QUIC)
    let tun_reader = async_tun.clone();
    let conn_sender = connection.clone();
    let alive_tun = session_alive.clone();
    let run_tun = global_running.clone();
    let tun_to_quic = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            if !run_tun.load(Ordering::Relaxed) || !alive_tun.load(Ordering::Relaxed) {
                break;
            }
            match tun_reader.read(&mut buf).await {
                Ok(n) if n > 0 => {
                    let data = Bytes::copy_from_slice(&buf[..n]);
                    if let Err(e) = conn_sender.send_datagram(data) {
                        if matches!(e, quinn::SendDatagramError::TooLarge) {
                            let current_mtu =
                                conn_sender.max_datagram_size().unwrap_or(1200) as u16;
                            if let Some(icmp_packet) = icmp::generate_packet_too_big(
                                &buf[..n],
                                current_mtu,
                                Some(std::net::IpAddr::V4(gateway)),
                            ) {
                                let _ = tun_reader.write(&icmp_packet).await;
                            }
                        } else if matches!(e, quinn::SendDatagramError::ConnectionLost(_)) {
                            alive_tun.store(false, Ordering::SeqCst);
                            break;
                        }
                    }
                }
                Ok(_) => {} // zero-length read, continue
                Err(e) => {
                    warn!("TUN read error: {}", e);
                    alive_tun.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }
    });

    // Task: QUIC -> TUN (Read from QUIC, write to TUN)
    let tun_writer = async_tun.clone();
    let alive_quic = session_alive.clone();
    let run_quic = global_running.clone();
    let quic_to_tun = tokio::spawn(async move {
        loop {
            if !run_quic.load(Ordering::Relaxed) || !alive_quic.load(Ordering::Relaxed) {
                break;
            }
            match connection.read_datagram().await {
                Ok(data) => {
                    if data.is_empty() {
                        continue;
                    }
                    if let Err(e) = tun_writer.write(&data).await {
                        warn!("TUN write error: {}", e);
                        alive_quic.store(false, Ordering::SeqCst);
                        break;
                    }
                }
                Err(_) => {
                    alive_quic.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }
    });

    // Wait for termination
    while global_running.load(Ordering::Relaxed) && session_alive.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    tun_to_quic.abort();
    quic_to_tun.abort();

    // Cleanup networking
    net_config.cleanup();

    if global_running.load(Ordering::Relaxed) {
        Ok(SessionEnd::ConnectionLost)
    } else {
        Ok(SessionEnd::UserStopped)
    }
}

/// QUIC connection setup with custom certificate pinning.
async fn connect_and_handshake(
    socket: std::net::UdpSocket,
    token: String,
    endpoint_str: String,
    cert_pin: Vec<u8>,
) -> Result<(quinn::Connection, ControlMessage)> {
    let verifier = Arc::new(PinnedServerVerifier::new(cert_pin));

    let mut client_crypto = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_no_client_auth();

    // QUIC mode: advertise both protocols so we can connect to servers
    // regardless of their censorship_resistant setting.
    client_crypto.alpn_protocols = vec![b"mavivpn".to_vec(), b"h3".to_vec()];

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(
        Duration::from_secs(IDLE_TIMEOUT_SECS).try_into().unwrap(),
    ));
    transport_config.keep_alive_interval(Some(Duration::from_secs(KEEPALIVE_SECS)));

    // MTU PINNING: 1360 wire MTU to support 1280 payload over QUIC/UDP/IP.
    transport_config.mtu_discovery_config(None);
    transport_config.initial_mtu(1360);
    transport_config.min_mtu(1360);
    transport_config.enable_segmentation_offload(true);
    transport_config.congestion_controller_factory(Arc::new(
        quinn::congestion::BbrConfig::default(),
    ));

    // Datagram queue tuning (match Windows/Android: 2MB each direction)
    transport_config.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    transport_config.datagram_send_buffer_size(2 * 1024 * 1024);

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));
    client_config.transport_config(Arc::new(transport_config));

    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(client_config);

    // Resolve endpoint and connect
    let addr = tokio::net::lookup_host(&endpoint_str)
        .await?
        .next()
        .context("Failed to resolve endpoint")?;
    let server_name = endpoint_str.split(':').next().unwrap_or(&endpoint_str);
    let connection = endpoint
        .connect(addr, server_name)?
        .await
        .context("QUIC handshake failed")?;

    // Application-level handshake (Auth -> Config)
    let (mut send, mut recv) = connection.open_bi().await?;
    let auth_msg = ControlMessage::Auth { token };
    let encoded = bincode::serde::encode_to_vec(&auth_msg, bincode::config::standard())?;
    send.write_u32_le(encoded.len() as u32).await?;
    send.write_all(&encoded).await?;

    let len = recv.read_u32_le().await? as usize;
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    let config: ControlMessage =
        bincode::serde::decode_from_slice(&buf, bincode::config::standard()).map(|(v, _)| v)?;

    Ok((connection, config))
}

// =============================================================================
// HTTP/3 (WebTransport) Client Session
// =============================================================================

async fn run_session_h3(
    config: &Config,
    cert_pin_bytes: &[u8],
    global_running: &Arc<AtomicBool>,
) -> Result<SessionEnd> {
    // 1. Connect via WebTransport with certificate pinning
    let cert_hash: [u8; 32] = cert_pin_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Certificate PIN must be 32 bytes (SHA-256)"))?;

    let wt_config = wtransport::ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes([wtransport::tls::Sha256Digest::new(cert_hash)])
        .keep_alive_interval(Some(Duration::from_secs(KEEPALIVE_SECS)))
        .max_idle_timeout(Some(Duration::from_secs(IDLE_TIMEOUT_SECS)))
        .expect("valid idle timeout")
        .build();

    let wt_endpoint = wtransport::Endpoint::client(wt_config)?;

    let url = format!("https://{}/vpn", config.endpoint);
    info!("[HTTP/3] Connecting to {}", url);
    let connection = wt_endpoint.connect(&url).await
        .context("WebTransport connection failed")?;
    let remote_addr = connection.remote_address();
    info!("[HTTP/3] Connected to {}", remote_addr);

    // 2. Auth handshake via bi-stream
    let (mut send_stream, mut recv_stream) = connection.open_bi().await
        .context("Failed to open bi-stream")?;

    let auth_msg = ControlMessage::Auth { token: config.token.clone() };
    let encoded = bincode::serde::encode_to_vec(&auth_msg, bincode::config::standard())?;
    send_stream.write_u32_le(encoded.len() as u32).await?;
    send_stream.write_all(&encoded).await?;

    let len = recv_stream.read_u32_le().await? as usize;
    let mut buf = vec![0u8; len];
    recv_stream.read_exact(&mut buf).await?;
    let server_config: ControlMessage =
        bincode::serde::decode_from_slice(&buf, bincode::config::standard()).map(|(v, _)| v)?;

    // 3. Extract Network Configuration
    let (assigned_ip, netmask, gateway, dns, mtu, assigned_ipv6, netmask_v6, gateway_v6, dns_v6) =
        match server_config {
            ControlMessage::Config {
                assigned_ip, netmask, gateway, dns_server, mtu,
                assigned_ipv6, netmask_v6, gateway_v6, dns_server_v6, ..
            } => (assigned_ip, netmask, gateway, dns_server, mtu, assigned_ipv6, netmask_v6, gateway_v6, dns_server_v6),
            ControlMessage::Error { message } => return Err(anyhow::anyhow!("Server rejected: {}", message)),
            _ => return Err(anyhow::anyhow!("Unexpected server response")),
        };

    info!("[HTTP/3] Handshake successful. IPv4: {}", assigned_ip);

    // 4. Create TUN device and configure networking
    let tun = TunDevice::create(TUN_DEVICE_NAME)?;
    let tun_name = tun.name().to_string();

    let remote_ip = remote_addr.ip();
    let endpoint_ip_str = match remote_ip {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped()
            .map(|v4| v4.to_string())
            .unwrap_or_else(|| v6.to_string()),
    };

    let net_config = NetworkConfig::apply(
        &tun_name, assigned_ip, netmask, gateway, dns, mtu, &endpoint_ip_str,
        assigned_ipv6, netmask_v6, gateway_v6, dns_v6,
    )?;

    // 5. Start async TUN I/O
    let async_tun = Arc::new(tun.into_async()?);
    let session_alive = Arc::new(AtomicBool::new(true));

    // Task: TUN -> WebTransport datagram
    let tun_reader = async_tun.clone();
    let conn_send = connection.clone();
    let alive_tun = session_alive.clone();
    let run_tun = global_running.clone();
    let tun_to_h3 = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            if !run_tun.load(Ordering::Relaxed) || !alive_tun.load(Ordering::Relaxed) { break; }
            match tun_reader.read(&mut buf).await {
                Ok(n) if n > 0 => {
                    let data = buf[..n].to_vec();
                    if let Err(e) = conn_send.send_datagram(data) {
                        if matches!(e, wtransport::error::SendDatagramError::TooLarge) {
                            let current_mtu = 1200u16;
                            if let Some(icmp_packet) = icmp::generate_packet_too_big(
                                &buf[..n], current_mtu, Some(std::net::IpAddr::V4(gateway)),
                            ) {
                                let _ = tun_reader.write(&icmp_packet).await;
                            }
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("[HTTP/3] TUN read error: {}", e);
                    alive_tun.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }
    });

    // Task: WebTransport datagram -> TUN
    let tun_writer = async_tun.clone();
    let alive_wt = session_alive.clone();
    let run_wt = global_running.clone();
    let h3_to_tun = tokio::spawn(async move {
        loop {
            if !run_wt.load(Ordering::Relaxed) || !alive_wt.load(Ordering::Relaxed) { break; }
            match connection.receive_datagram().await {
                Ok(datagram) => {
                    let data = datagram.payload();
                    if data.is_empty() { continue; }
                    if let Err(e) = tun_writer.write(data).await {
                        warn!("[HTTP/3] TUN write error: {}", e);
                        alive_wt.store(false, Ordering::SeqCst);
                        break;
                    }
                }
                Err(_) => {
                    alive_wt.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }
    });

    // Wait for termination
    while global_running.load(Ordering::Relaxed) && session_alive.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    tun_to_h3.abort();
    h3_to_tun.abort();
    net_config.cleanup();

    if global_running.load(Ordering::Relaxed) { Ok(SessionEnd::ConnectionLost) } else { Ok(SessionEnd::UserStopped) }
}

// =============================================================================
// HTTP/2 (TCP) Client Session
// =============================================================================

async fn run_session_h2(
    config: &Config,
    cert_pin_bytes: &[u8],
    global_running: &Arc<AtomicBool>,
) -> Result<SessionEnd> {
    // 1. TCP + TLS connect
    let addr = tokio::net::lookup_host(&config.endpoint).await?
        .next().context("Failed to resolve endpoint")?;
    let host = config.endpoint.split(':').next().unwrap_or(&config.endpoint);

    info!("[HTTP/2] Connecting to {} (resolved: {})", config.endpoint, addr);
    let tcp_stream = tokio::net::TcpStream::connect(addr).await
        .context("TCP connection failed")?;

    let verifier = Arc::new(PinnedServerVerifier::new(cert_pin_bytes.to_vec()));
    let mut tls_config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into()
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h2".to_vec()];

    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| anyhow::anyhow!("Invalid server name: {}", e))?;
    let tls_stream = connector.connect(server_name, tcp_stream).await
        .context("TLS handshake failed")?;

    info!("[HTTP/2] TLS handshake complete");

    // 2. H2 handshake
    let (h2_send_req, h2_conn) = h2::client::Builder::new()
        .initial_window_size(4 * 1024 * 1024)
        .initial_connection_window_size(4 * 1024 * 1024)
        .handshake(tls_stream).await
        .context("H2 handshake failed")?;

    tokio::spawn(async move {
        if let Err(e) = h2_conn.await {
            error!("[HTTP/2] Connection driver error: {}", e);
        }
    });

    // 3. Open stream and authenticate
    let mut h2_send_req = h2_send_req.ready().await
        .context("H2 send not ready")?;
    let request = http::Request::builder()
        .method("POST")
        .uri("/vpn")
        .body(())
        .unwrap();
    let (response_future, mut send_stream) = h2_send_req.send_request(request, false)?;

    // Send auth: [u32 LE len][bincode]
    let auth_msg = ControlMessage::Auth { token: config.token.clone() };
    let encoded = bincode::serde::encode_to_vec(&auth_msg, bincode::config::standard())?;
    let mut auth_frame = Vec::with_capacity(4 + encoded.len());
    auth_frame.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
    auth_frame.extend_from_slice(&encoded);
    send_stream.send_data(Bytes::from(auth_frame), false)?;

    let response = response_future.await?;
    if response.status() != 200 {
        return Err(anyhow::anyhow!("[HTTP/2] Server returned status {}", response.status()));
    }
    let mut recv_body = response.into_body();

    // Read config: [u32 LE len][bincode]
    let config_data = recv_body.data().await
        .context("No config data")?.context("Error reading config")?;
    let _ = recv_body.flow_control().release_capacity(config_data.len());

    if config_data.len() < 4 { return Err(anyhow::anyhow!("[HTTP/2] Config too short")); }
    let len = u32::from_le_bytes([config_data[0], config_data[1], config_data[2], config_data[3]]) as usize;
    if 4 + len > config_data.len() { return Err(anyhow::anyhow!("[HTTP/2] Config length mismatch")); }

    let server_config: ControlMessage = bincode::serde::decode_from_slice(
        &config_data[4..4 + len], bincode::config::standard()
    ).map(|(v, _)| v)?;

    // 4. Extract Network Configuration
    let (assigned_ip, netmask, gateway, dns, mtu, assigned_ipv6, netmask_v6, gateway_v6, dns_v6) =
        match server_config {
            ControlMessage::Config {
                assigned_ip, netmask, gateway, dns_server, mtu,
                assigned_ipv6, netmask_v6, gateway_v6, dns_server_v6, ..
            } => (assigned_ip, netmask, gateway, dns_server, mtu, assigned_ipv6, netmask_v6, gateway_v6, dns_server_v6),
            ControlMessage::Error { message } => return Err(anyhow::anyhow!("Server rejected: {}", message)),
            _ => return Err(anyhow::anyhow!("Unexpected server response")),
        };

    info!("[HTTP/2] Handshake successful. IPv4: {}", assigned_ip);

    // 5. Create TUN and configure networking
    let tun = TunDevice::create(TUN_DEVICE_NAME)?;
    let tun_name = tun.name().to_string();

    let endpoint_ip_str = match addr.ip() {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped()
            .map(|v4| v4.to_string())
            .unwrap_or_else(|| v6.to_string()),
    };

    let net_config = NetworkConfig::apply(
        &tun_name, assigned_ip, netmask, gateway, dns, mtu, &endpoint_ip_str,
        assigned_ipv6, netmask_v6, gateway_v6, dns_v6,
    )?;

    // 6. Start async TUN I/O
    let async_tun = Arc::new(tun.into_async()?);
    let session_alive = Arc::new(AtomicBool::new(true));

    // Task: TUN -> H2 (read from TUN, frame as [u16 BE len][packet], send)
    let tun_reader = async_tun.clone();
    let alive_send = session_alive.clone();
    let run_send = global_running.clone();
    let tun_to_h2 = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            if !run_send.load(Ordering::Relaxed) || !alive_send.load(Ordering::Relaxed) { break; }
            match tun_reader.read(&mut buf).await {
                Ok(n) if n > 0 => {
                    let pkt_len = n as u16;
                    let mut frame = Vec::with_capacity(2 + n);
                    frame.extend_from_slice(&pkt_len.to_be_bytes());
                    frame.extend_from_slice(&buf[..n]);
                    if send_stream.send_data(Bytes::from(frame), false).is_err() {
                        alive_send.store(false, Ordering::SeqCst);
                        break;
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("[HTTP/2] TUN read error: {}", e);
                    alive_send.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }
    });

    // Task: H2 -> TUN (parse [u16 BE len][packet] frames, write to TUN)
    let tun_writer = async_tun.clone();
    let alive_recv = session_alive.clone();
    let run_recv = global_running.clone();
    let h2_to_tun = tokio::spawn(async move {
        let mut partial = Vec::new();
        loop {
            if !run_recv.load(Ordering::Relaxed) || !alive_recv.load(Ordering::Relaxed) { break; }
            match recv_body.data().await {
                Some(Ok(chunk)) => {
                    let _ = recv_body.flow_control().release_capacity(chunk.len());
                    partial.extend_from_slice(&chunk);

                    while partial.len() >= 2 {
                        let pkt_len = u16::from_be_bytes([partial[0], partial[1]]) as usize;
                        if partial.len() < 2 + pkt_len { break; }

                        let data = &partial[2..2 + pkt_len];
                        if !data.is_empty() {
                            if let Err(e) = tun_writer.write(data).await {
                                warn!("[HTTP/2] TUN write error: {}", e);
                                alive_recv.store(false, Ordering::SeqCst);
                                break;
                            }
                        }
                        partial.drain(..2 + pkt_len);
                    }
                }
                Some(Err(_)) | None => {
                    alive_recv.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }
    });

    // Wait for termination
    while global_running.load(Ordering::Relaxed) && session_alive.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    tun_to_h2.abort();
    h2_to_tun.abort();
    net_config.cleanup();

    if global_running.load(Ordering::Relaxed) { Ok(SessionEnd::ConnectionLost) } else { Ok(SessionEnd::UserStopped) }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Custom certificate verifier that trusts only a specific SHA-256 fingerprint.
#[derive(Debug)]
struct PinnedServerVerifier {
    expected_hash: Vec<u8>,
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PinnedServerVerifier {
    fn new(expected_hash: Vec<u8>) -> Self {
        Self {
            expected_hash,
            supported: rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms,
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
            Err(rustls::Error::General("Certificate PIN mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported.supported_schemes()
    }
}
