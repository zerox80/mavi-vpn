//! # Mavi VPN Windows Core
//! 
//! Implements the core VPN logic for Windows, including:
//! - WinTUN adapter management.
//! - QUIC transport via Quinn.
//! - Windows-specific routing and DNS leak prevention (NRPT).
//! - Dual-stack (IPv4/IPv6) support.

use anyhow::{Context, Result};
use bytes::{Buf, Bytes};
use h3_quinn::Connection as H3QuinnConnection;
use sha2::{Sha256, Digest};
use shared::{
    icmp,
    masque::{self, CAPSULE_MAVI_CONFIG},
    ControlMessage,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};
use wintun::Adapter;

/// Embedded WinTUN driver binary.
static WINTUN_DLL: &[u8] = include_bytes!("../wintun.dll");

// --- Default timing parameters ---
const KEEPALIVE_SECS: u64 = 10;
const IDLE_TIMEOUT_SECS: u64 = 60;
const RECONNECT_INITIAL_SECS: u64 = 1;
const RECONNECT_MAX_SECS: u64 = 30;
const TUN_MTU: u16 = 1280;
const QUIC_PAYLOAD_MTU: u16 = 1360;

pub use crate::ipc::Config;

/// Extracts the embedded `wintun.dll` to a temporary directory so it can be loaded.
fn extract_wintun_dll() -> Result<PathBuf> {
    let temp_dir = std::env::temp_dir();
    let dll_path = temp_dir.join("mavi_wintun.dll");
    
    if !dll_path.exists() {
        info!("Extracting wintun.dll to {}...", dll_path.display());
        std::fs::write(&dll_path, WINTUN_DLL)
            .context("Failed to extract wintun.dll to temp directory")?;
    }
    Ok(dll_path)
}

/// Entry point for the VPN runner. Manages the reconnection loop and WinTUN lifecycle.
pub async fn run_vpn(config: Config, running: Arc<AtomicBool>) -> Result<()> {
    // 1. Prepare environment
    let cert_pin_bytes = decode_hex(&config.cert_pin).context("Invalid certificate PIN hex format")?;
    let dll_path = extract_wintun_dll()?;
    let wintun = unsafe { wintun::load_from_path(&dll_path) }.context("Failed to load wintun.dll")?;

    // 2. Open or create the virtual adapter
    let adapter = get_or_create_adapter(&wintun)?;

    let mut backoff = Duration::from_secs(RECONNECT_INITIAL_SECS);

    // 3. Main Connection Loop
    while running.load(Ordering::Relaxed) {
        // Always clear stale routes before a new session so a previous
        // (possibly crashed) session does not leave orphaned routing entries.
        cleanup_routes(None);

        let outcome = run_session(&config, &cert_pin_bytes, &adapter, &running).await;

        if !running.load(Ordering::Relaxed) { break; }

        let (reconnect_delay, next_backoff) = match outcome {
            Ok(SessionEnd::UserStopped) => break,
            Ok(SessionEnd::ConnectionLost) => (
                Duration::from_secs(RECONNECT_INITIAL_SECS),
                Duration::from_secs(RECONNECT_INITIAL_SECS),
            ),
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("AUTH_FAILED") || err_str.contains("Server rejected connection") {
                    warn!("Authentication permanently denied: {}. Stopping VPN loop.", err_str);
                    running.store(false, Ordering::Relaxed);
                    break;
                }
                warn!("Session failed: {:#}. Reconnecting...", e);
                (backoff, (backoff * 2).min(Duration::from_secs(RECONNECT_MAX_SECS)))
            }
        };

        tokio::time::sleep(reconnect_delay).await;
        backoff = next_backoff;
    }

    // 4. Cleanup – routes first, then DNS/NRPT
    cleanup_routes(None);
    remove_nrpt_dns_rule();
    info!("VPN Service Stopped.");
    Ok(())
}

enum SessionEnd {
    UserStopped,
    ConnectionLost,
}

/// Holds the h3 `SendRequest` + driver task for the lifetime of the VPN session.
///
/// Dropping `h3::client::SendRequest` decrements its internal `sender_count`; when the
/// last one goes, its `Drop` impl calls `handle_connection_error_on_stream(H3_NO_ERROR,
/// "Connection closed by client")` which tears down the underlying quinn connection.
/// We therefore keep the SendRequest alive for the whole session so the VPN datagram
/// plane can keep using the same quinn::Connection.
struct H3SessionGuard {
    _send_request: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    drive_handle: tokio::task::JoinHandle<()>,
}

impl Drop for H3SessionGuard {
    fn drop(&mut self) {
        self.drive_handle.abort();
    }
}

struct SessionRouteGuard {
    host_route: Option<String>,
}

impl SessionRouteGuard {
    fn new(host_route: Option<String>) -> Self {
        Self { host_route }
    }
}

impl Drop for SessionRouteGuard {
    fn drop(&mut self) {
        cleanup_routes(self.host_route.as_deref());
    }
}

/// Helper to ensure the "MaviVPN" adapter exists in Windows.
fn get_or_create_adapter(wintun: &wintun::Wintun) -> Result<Arc<Adapter>> {
    if let Ok(adapter) = Adapter::open(wintun, "MaviVPN") {
        if let Ok(index) = adapter.get_adapter_index() {
            let name = adapter.get_name().unwrap_or_else(|_| "MaviVPN".to_string());
            info!("Opened existing WinTUN adapter '{}' (if={})", name, index);
        }
        return Ok(adapter);
    }

    let adapter = Adapter::create(wintun, "MaviVPN", "Mavi VPN Tunnel", None)
        .context("Failed to create WinTUN adapter. Admin privileges required.")?;

    if let Ok(index) = adapter.get_adapter_index() {
        let name = adapter.get_name().unwrap_or_else(|_| "MaviVPN".to_string());
        info!("Created WinTUN adapter '{}' (if={})", name, index);
    }

    Ok(adapter)
}

/// Creates a UDP socket configured for both IPv4 and IPv6 (dual-stack).
fn create_udp_socket() -> Result<std::net::UdpSocket> {
    let socket2_sock = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    // V6ONLY = false allows this socket to receive IPv4 traffic as well.
    socket2_sock.set_only_v6(false)?;
    socket2_sock.bind(&socket2::SockAddr::from(std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0)))?;
    // Set larger socket buffers for high-throughput stability on Windows (4MB for GSO bursts)
    let _ = socket2_sock.set_send_buffer_size(4 * 1024 * 1024); 
    let _ = socket2_sock.set_recv_buffer_size(4 * 1024 * 1024); 

    Ok(socket2_sock.into())
}

/// Manages a single active VPN session (handshake + packet pumping).
async fn run_session(
    config: &Config,
    cert_pin_bytes: &[u8],
    adapter: &Arc<Adapter>,
    global_running: &Arc<AtomicBool>,
) -> Result<SessionEnd> {
    let socket = create_udp_socket()?;

    // 1. QUIC Handshake & Auth
    //    `_h3_guard` keeps the h3 SendRequest + driver task alive for the entire
    //    session; dropping it earlier would send CONNECTION_CLOSE(H3_NO_ERROR) and
    //    kill the VPN datagram plane. It lives to the end of `run_session` scope.
    // Optional ECH GREASE + SNI-spoofing config, derived from the admin's
    // out-of-band ECHConfigList (hex in config.json). None → legacy path.
    let ech_bytes = config
        .ech_config
        .as_deref()
        .and_then(crate::ech_client::decode_hex);

    let (connection, server_config, _h3_guard) = connect_and_handshake(
        socket,
        config.token.clone(),
        config.endpoint.clone(),
        cert_pin_bytes.to_vec(),
        config.censorship_resistant,
        config.http3_framing,
        ech_bytes,
    ).await?;

    // 2. Extract Network Configuration
    let (assigned_ip, netmask, gateway, dns, mtu, assigned_ipv6, netmask_v6, gateway_v6, dns_v6) =
        match server_config {
            ControlMessage::Config {
                assigned_ip, netmask, gateway, dns_server, mtu,
                assigned_ipv6, netmask_v6, gateway_v6, dns_server_v6, ..
            } => (assigned_ip, netmask, gateway, dns_server, mtu, assigned_ipv6, netmask_v6, gateway_v6, dns_server_v6),
            ControlMessage::Error { message } => return Err(anyhow::anyhow!("Server rejected connection: {}", message)),
            _ => return Err(anyhow::anyhow!("Unexpected server response during handshake")),
        };

    info!("Handshake successful. Internal IPv4: {}", assigned_ip);

    // 3. Configure Windows Networking (IPs, Routes, DNS)
    let remote_ip = connection.remote_address().ip();
    let endpoint_ip_str = match remote_ip {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(|v4| v4.to_string()).unwrap_or_else(|| v6.to_string()),
    };

    let route_cleanup = SessionRouteGuard::new(set_adapter_network_config(
        adapter, assigned_ip, netmask, gateway, dns, mtu, &endpoint_ip_str,
        assigned_ipv6, netmask_v6, gateway_v6, dns_v6,
    )?);

    // 4. Start WinTUN Session
    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).context("Failed to start WinTUN session")?);
    let session_alive = Arc::new(AtomicBool::new(true));

    // 5. Data Hubs
    let connection = Arc::new(connection);
    
    // Task: MTU Monitor
    let conn_monitor = connection.clone();
    let alive_monitor = session_alive.clone();
    let running_monitor = global_running.clone();
    tokio::spawn(async move {
        let mut last_mtu = 0;
        loop {
            if !running_monitor.load(Ordering::Relaxed) || !alive_monitor.load(Ordering::Relaxed) { break; }
            let current_mtu = conn_monitor.max_datagram_size().unwrap_or(0);
            if current_mtu != last_mtu && last_mtu != 0 {
                info!("[MTU] QUIC Path MTU changed: {} -> {} bytes", last_mtu, current_mtu);
                last_mtu = current_mtu;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    // Thread: TUN -> QUIC (Read from WinTUN, Send via QUIC)
    let session_tun = session.clone();
    let conn_quic = connection.clone();
    let alive_pump = session_alive.clone();
    let run_pump = global_running.clone();
    let gateway_v6_for_ptb = gateway_v6;
    let is_h3_framing = config.http3_framing;
    let tun_to_quic = std::thread::spawn(move || {
        let mut pool = bytes::BytesMut::with_capacity(4 * 1024 * 1024);
        loop {
            if !run_pump.load(Ordering::Relaxed) || !alive_pump.load(Ordering::Relaxed) { break; }
            match session_tun.try_receive() {
                Ok(Some(packet)) => {
                    // In H3 mode, prepend [Quarter Stream ID] [Context ID]
                    // (connect-ip datagram framing, RFC 9484 §5 — 2 bytes).
                    let packet_bytes = packet.bytes();
                    if pool.capacity() < packet_bytes.len() + masque::DATAGRAM_PREFIX.len() {
                        pool.reserve(4 * 1024 * 1024);
                    }
                    let payload = if is_h3_framing {
                        pool.extend_from_slice(&masque::DATAGRAM_PREFIX);
                        pool.extend_from_slice(packet_bytes);
                        pool.split().freeze()
                    } else {
                        pool.extend_from_slice(packet_bytes);
                        pool.split().freeze()
                    };
                    if let Err(e) = conn_quic.send_datagram(payload) {
                        if matches!(e, quinn::SendDatagramError::TooLarge) {
                            if packet.bytes().is_empty() {
                                continue;
                            }

                            // Synthesise ICMP PTB signal back to OS
                            let version = packet.bytes()[0] >> 4;
                            let source_ip = if version == 4 {
                                Some(std::net::IpAddr::V4(gateway))
                            } else if version == 6 {
                                gateway_v6_for_ptb.map(std::net::IpAddr::V6)
                            } else {
                                None
                            };
                            let reported_mtu = if version == 6 {
                                TUN_MTU.max(1280)
                            } else {
                                TUN_MTU
                            };

                            if let Some(icmp_packet) = icmp::generate_packet_too_big(
                                packet.bytes(),
                                reported_mtu,
                                source_ip,
                            ) {
                                if let Ok(mut reply) = session_tun.allocate_send_packet(icmp_packet.len() as u16) {
                                    reply.bytes_mut().copy_from_slice(&icmp_packet);
                                    session_tun.send_packet(reply);
                                }
                            }
                        } else if matches!(e, quinn::SendDatagramError::ConnectionLost(_)) { break; }
                    }
                }
                Ok(None) => {
                    if let Ok(event) = session_tun.get_read_wait_event() {
                        unsafe { windows_sys::Win32::System::Threading::WaitForSingleObject(event as _, 50); }
                    } else {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                Err(_) => { alive_pump.store(false, Ordering::SeqCst); break; }
            }
        }
    });

    // Task: QUIC -> TUN (Read from QUIC, Write to WinTUN)
    let session_quic_in = session.clone();
    let alive_quic_in = session_alive.clone();
    let run_quic_in = global_running.clone();
    let conn_quic = connection.clone();
    let is_h3_framing_dl = config.http3_framing;
    let quic_to_tun = tokio::spawn(async move {
        let mut pending_datagram: Option<Bytes> = None;

        loop {
            if !run_quic_in.load(Ordering::Relaxed) || !alive_quic_in.load(Ordering::Relaxed) { break; }

            let data = match pending_datagram.take() {
                Some(data) => data,
                None => match conn_quic.read_datagram().await {
                    Ok(mut data) => {
                        // Strip [Quarter Stream ID] [Context ID] for connect-ip.
                        if is_h3_framing_dl {
                            let inner_len = match masque::unwrap_datagram(&data) {
                                Some(slice) => slice.len(),
                                None => continue,
                            };
                            if inner_len == 0 { continue; }
                            let prefix = data.len() - inner_len;
                            data.advance(prefix);
                            data
                        } else {
                            data
                        }
                    }
                    Err(_) => {
                        alive_quic_in.store(false, Ordering::SeqCst);
                        break;
                    }
                },
            };

            if data.is_empty() { continue; }

            match session_quic_in.allocate_send_packet(data.len() as u16) {
                Ok(mut packet) => {
                    packet.bytes_mut().copy_from_slice(&data);
                    session_quic_in.send_packet(packet);
                }
                Err(e) if is_wintun_ring_full(&e) => {
                    pending_datagram = Some(data);
                    // On Windows, the system timer resolution is typically ~15.6ms.
                    // Using `tokio::time::sleep(100us)` inadvertently sleeps for ~15ms,
                    // reintroducing the exact artificial backpressure we want to avoid.
                    // `yield_now` gracefully yields time to the runtime without the timer penalty.
                    tokio::task::yield_now().await;
                }
                Err(_) => {
                    alive_quic_in.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }
    });

    // Wait for termination
    while global_running.load(Ordering::Relaxed) && session_alive.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    quic_to_tun.abort();
    let _ = tun_to_quic.join();
    drop(route_cleanup);

    if global_running.load(Ordering::Relaxed) { Ok(SessionEnd::ConnectionLost) } else { Ok(SessionEnd::UserStopped) }
}

/// Checks if the WinTUN ring buffer is full.
fn is_wintun_ring_full(err: &wintun::Error) -> bool {
    matches!(err, wintun::Error::Io(io_err) if io_err.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW as i32))
}

/// QUIC connection setup with custom certificate pinning.
async fn connect_and_handshake(
    socket: std::net::UdpSocket,
    token: String,
    endpoint_str: String,
    cert_pin: Vec<u8>,
    censorship_resistant: bool,
    http3_framing: bool,
    ech_config_list: Option<Vec<u8>>,
) -> Result<(quinn::Connection, ControlMessage, Option<H3SessionGuard>)> {
    let verifier = Arc::new(PinnedServerVerifier::new(cert_pin));

    // Decide up-front whether we will offer ECH GREASE and which SNI to send on
    // the wire. The outer SNI spoof is safe because the server authenticates via
    // SHA-256 cert pinning and does not inspect the SNI.
    let ech_state = match ech_config_list.as_deref() {
        Some(bytes) => {
            let parsed = crate::ech_client::parse(bytes)
                .context("Failed to parse ECH config list")?
                .ok_or_else(|| anyhow::anyhow!("ECH config list contained no HPKE suites supported by aws-lc-rs"))?;
            info!("ECH GREASE enabled, outer SNI: {}", parsed.outer_sni);
            Some(parsed)
        }
        None => None,
    };

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let builder = rustls::ClientConfig::builder_with_provider(provider.into());
    let versioned = if let Some(ech) = ech_state.as_ref() {
        // `with_ech` implicitly pins TLS 1.3 (required by ECH) and registers the
        // GREASE extension, mimicking the server's advertised HPKE suite.
        builder
            .with_ech(rustls::client::EchMode::Grease(ech.grease.clone()))
            .context("failed to enable ECH GREASE on client config")?
    } else {
        builder
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
    };

    let mut client_crypto = versioned
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    // HTTP/3 transport requires h3. Raw mode keeps mavivpn as the preferred ALPN.
    client_crypto.alpn_protocols = if http3_framing || censorship_resistant {
        vec![b"h3".to_vec()]
    } else {
        vec![b"mavivpn".to_vec(), b"h3".to_vec()]
    };

    // Resolve endpoint and connect
    let addrs: Vec<_> = tokio::net::lookup_host(&endpoint_str).await?.collect();
    let addr = *addrs.first().context("Failed to resolve endpoint")?;
    // When ECH is active we send the config's `public_name` as the outer SNI
    // instead of the real server hostname. Cert-pin auth is unaffected.
    let server_name: String = match ech_state.as_ref() {
        Some(ech) => ech.outer_sni.clone(),
        None => {
            let (host, _) = split_endpoint(&endpoint_str);
            host.to_string()
        }
    };
    if server_name.is_empty() {
        anyhow::bail!("Endpoint host missing");
    }

    // Rule 2: Outgoing QUIC Payload (Initial MTU) MUST be 1360.
    // IPv4 Wire: 1360 + 20 (IP) + 8 (UDP) = 1388 bytes.
    // IPv6 Wire: 1360 + 40 (IP) + 8 (UDP) = 1408 bytes.
    let quic_mtu = QUIC_PAYLOAD_MTU;
    info!("Address family: {}. Setting QUIC MTU: 1360 (Target Wire: 1388-1408)", if addr.is_ipv4() { "IPv4" } else { "IPv6" });

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(IDLE_TIMEOUT_SECS).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(Duration::from_secs(KEEPALIVE_SECS)));
    
    // MTU PINNING
    transport_config.mtu_discovery_config(None);
    transport_config.initial_mtu(quic_mtu);
    transport_config.min_mtu(quic_mtu);

    // Rule 1: TUN MTU MUST be 1280. 
    // Handled in NetworkConfig::apply. Peer datagram size is implicitly limited by path MTU discovery.

    transport_config.enable_segmentation_offload(true);
    transport_config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    
    // Datagram queue tuning for high-speed GSO traffic (Avoiding 'dropping stale datagram' errors)
    transport_config.datagram_receive_buffer_size(Some(2 * 1024 * 1024)); // 2MB
    transport_config.datagram_send_buffer_size(2 * 1024 * 1024); // Increased from 256KB

    let mut client_config = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?));
    client_config.transport_config(Arc::new(transport_config));
    let mut endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, Arc::new(quinn::TokioRuntime))?;
    endpoint.set_default_client_config(client_config);

    let mut last_error = None;
    let mut connection = None;
    for addr in addrs {
        info!("Connecting to {} (resolved: {}, SNI: {})", endpoint_str, addr, server_name);
        match endpoint.connect(addr, &server_name) {
            Ok(connecting) => match connecting.await {
                Ok(conn) => {
                    connection = Some(conn);
                    break;
                }
                Err(err) => {
                    warn!("QUIC handshake to {} failed: {}", addr, err);
                    last_error = Some(anyhow::Error::from(err));
                }
            },
            Err(err) => {
                warn!("endpoint.connect() failed for {}: {}", addr, err);
                last_error = Some(anyhow::Error::from(err));
            }
        }
    }
    let connection = match connection {
        Some(conn) => conn,
        None => return Err(last_error.unwrap_or_else(|| anyhow::anyhow!("No reachable address for {}", endpoint_str))),
    };
    info!("QUIC handshake OK, sending auth token ({} bytes)", token.len());

    let (config, h3_guard) = if http3_framing {
        let (cfg, guard) = connect_and_handshake_h3(connection.clone(), token).await?;
        (cfg, Some(guard))
    } else {
        // Perform application-level handshake
        let (mut send, mut recv) = connection.open_bi().await?;
        let auth_msg = ControlMessage::Auth { token };
        let bytes = bincode::serde::encode_to_vec(&auth_msg, bincode::config::standard())?;
        send.write_u32_le(bytes.len() as u32).await?;
        send.write_all(&bytes).await?;
        let _ = send.finish(); // properly close the send side of the auth stream

        let len = recv.read_u32_le().await? as usize;
        if len > 65536 { anyhow::bail!("Server response too large: {} bytes", len); }
        if len == 0x1901 {
            // This magic length happens when the server sends the HTTP/3 spoof payload
            // [0x01, 0x19, 0x00, 0x00] in censorship_resistant mode due to Auth Failure.
            anyhow::bail!("AUTH_FAILED: Server rejected authentication token");
        }
        let mut buf = vec![0u8; len];
        recv.read_exact(&mut buf).await?;
        let cfg: ControlMessage = bincode::serde::decode_from_slice(&buf, bincode::config::standard()).map(|(v, _)| v)?;
        (cfg, None)
    };

    Ok((connection, config, h3_guard))
}

/// MASQUE connect-ip (RFC 9484) handshake.
///
/// Sends `CONNECT` with `:protocol=connect-ip` over HTTP/3, then parses the
/// capsule stream on the request body to extract the vendor `MAVI_CONFIG`
/// capsule which carries the full `ControlMessage::Config`.
///
/// Returns the decoded `ControlMessage` plus an `H3SessionGuard` that owns the
/// `SendRequest` handle and the background driver task. The caller MUST hold
/// the guard for the entire VPN session — dropping it sends
/// CONNECTION_CLOSE(H3_NO_ERROR) and terminates the underlying quinn connection.
async fn connect_and_handshake_h3(
    connection: quinn::Connection,
    token: String,
) -> Result<(ControlMessage, H3SessionGuard)> {
    let h3_conn = H3QuinnConnection::new(connection.clone());
    let mut builder = h3::client::builder();
    builder.enable_datagram(true);
    builder.enable_extended_connect(true);
    let (mut driver, mut send_request) = builder.build::<_, _, bytes::Bytes>(h3_conn).await
        .map_err(|e| anyhow::anyhow!("H3 client init failed: {}", e))?;

    // Drive the H3 connection in the background. This task lives for the whole
    // VPN session (via H3SessionGuard) so h3's control/QPACK streams keep being
    // serviced. A clean close at session end is reported at debug level.
    let drive_handle = tokio::spawn(async move {
        let e = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        tracing::debug!("H3 driver finished: {}", e);
    });

    // Extended CONNECT with :protocol=connect-ip (RFC 9484 §3).
    // The `:authority` component is the MASQUE target URI template result;
    // per RFC 9484 we use the well-known path `/.well-known/masque/ip/*/*/`.
    let req = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("https://mavi-vpn/.well-known/masque/ip/*/*/")
        .extension(h3::ext::Protocol::CONNECT_IP)
        .header("authorization", format!("Bearer {}", token))
        .header("capsule-protocol", "?1")
        .body(())
        .context("Failed to build H3 CONNECT request")?;

    let mut stream = send_request.send_request(req).await
        .map_err(|e| anyhow::anyhow!("H3 send_request failed: {}", e))?;
    // NB: do NOT finish the stream — connect-ip keeps the request stream open
    // for bidirectional capsule traffic throughout the session.

    let resp = stream.recv_response().await
        .map_err(|e| anyhow::anyhow!("H3 recv_response failed: {}", e))?;

    if resp.status() != http::StatusCode::OK {
        anyhow::bail!("AUTH_FAILED: Server returned HTTP {}", resp.status());
    }

    // Read capsules until we find MAVI_CONFIG. We collect into a rolling buffer
    // because capsule boundaries do not align with QUIC chunk boundaries.
    //
    // Every wait on `recv_data` is bounded by the remaining handshake budget so
    // a silent or slow-drip server cannot leave us blocked forever. The buffer
    // itself is capped at `masque::MAX_CAPSULE_BUF` as an extra defense against
    // an unbounded capsule stream.
    let mut capsule_buf: Vec<u8> = Vec::new();
    let mut config: Option<ControlMessage> = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    'read: while config.is_none() {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("Timed out waiting for MAVI_CONFIG capsule");
        }

        // Try to decode any fully-received capsules in the buffer first.
        loop {
            let (ctype, payload, consumed) = match masque::read_capsule(&capsule_buf) {
                Some(parts) => (parts.0, parts.1.to_vec(), parts.2),
                None => break,
            };
            capsule_buf.drain(..consumed);
            if ctype == CAPSULE_MAVI_CONFIG {
                config = Some(
                    bincode::serde::decode_from_slice(&payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| anyhow::anyhow!("Failed to decode MAVI_CONFIG: {}", e))?,
                );
                break 'read;
            }
            // Other capsule types (ADDRESS_ASSIGN, ROUTE_ADVERTISEMENT, …) are
            // acknowledged by being parsed; we rely on MAVI_CONFIG for the
            // authoritative Windows-side configuration.
        }

        let chunk = match tokio::time::timeout(remaining, stream.recv_data()).await {
            Ok(Ok(Some(data))) => data,
            Ok(Ok(None)) => {
                anyhow::bail!("Server closed connect-ip stream before MAVI_CONFIG")
            }
            Ok(Err(e)) => anyhow::bail!("H3 recv_data failed: {}", e),
            Err(_) => anyhow::bail!("Timed out waiting for MAVI_CONFIG capsule"),
        };
        capsule_buf.extend_from_slice(chunk.chunk());
        if capsule_buf.len() > masque::MAX_CAPSULE_BUF {
            anyhow::bail!(
                "connect-ip capsule buffer exceeded {} bytes",
                masque::MAX_CAPSULE_BUF
            );
        }
    }

    let config =
        config.ok_or_else(|| anyhow::anyhow!("connect-ip response lacked MAVI_CONFIG capsule"))?;

    // Intentionally do NOT abort drive_handle or drop send_request here.
    // Both are moved into the guard and kept alive for the whole session.
    let guard = H3SessionGuard { _send_request: send_request, drive_handle };
    Ok((config, guard))
}

/// Helper: run a command and log its outcome.
fn run_cmd(program: &str, args: &[&str]) -> bool {
    let display = format!("{} {}", program, args.join(" "));
    match std::process::Command::new(program).args(args).output() {
        Ok(out) if out.status.success() => {
            let msg = format!("[OK]  {}", display);
            info!(cmd = %msg);
            true
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let msg = format!("[FAIL] {} → {} {}", display, stdout, stderr);
            warn!(cmd = %msg);
            false
        }
        Err(e) => {
            let msg = format!("[ERR] {} → {}", display, e);
            warn!(cmd = %msg);
            false
        }
    }
}

fn run_powershell_cmd(display: &str, script: &str) -> bool {
    match std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output()
    {
        Ok(out) if out.status.success() => {
            let msg = format!("[OK]  {}", display);
            info!(cmd = %msg);
            true
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let msg = format!("[FAIL] {} → {} {}", display, stdout, stderr);
            warn!(cmd = %msg);
            false
        }
        Err(e) => {
            let msg = format!("[ERR] {} → {}", display, e);
            warn!(cmd = %msg);
            false
        }
    }
}

fn adapter_alias_by_index(adapter_index: u32) -> Option<String> {
    let script = format!(
        "$adapter = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object InterfaceIndex -eq {adapter_index} | Select-Object -First 1; if ($adapter) {{ $adapter.Name }}"
    );

    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .ok()?;

    if !out.status.success() {
        return None;
    }

    let alias = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if alias.is_empty() {
        None
    } else {
        Some(alias)
    }
}

fn wait_for_adapter_alias(adapter_index: u32, requested_name: &str) -> Result<String> {
    for attempt in 1..=30 {
        if let Some(alias) = adapter_alias_by_index(adapter_index) {
            if alias == requested_name {
                info!("WinTUN adapter '{}' is now visible in Windows (if={})", alias, adapter_index);
            } else {
                info!(
                    "WinTUN adapter requested as '{}' is visible in Windows as '{}' (if={})",
                    requested_name,
                    alias,
                    adapter_index
                );
            }
            return Ok(alias);
        }

        info!(
            "Waiting for adapter interface index {} to become available (attempt {}/30)...",
            adapter_index,
            attempt
        );
        std::thread::sleep(Duration::from_millis(1000));
    }

    anyhow::bail!(
        "Adapter '{}' (if={}) did not appear in Windows networking within 30 seconds.",
        requested_name,
        adapter_index
    )
}

fn wait_for_ipv4_address(adapter_index: u32, ip: Ipv4Addr) -> bool {
    let ip_str = ip.to_string();
    let script = format!(
        "$addr = Get-NetIPAddress -InterfaceIndex {adapter_index} -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object IPAddress -eq '{ip_str}' | Select-Object -First 1; if ($addr) {{ 'ok' }}"
    );

    for _ in 0..10 {
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .output();

        if let Ok(out) = out {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                if text.contains("ok") {
                    return true;
                }
            }
        }

        std::thread::sleep(Duration::from_millis(500));
    }

    false
}

fn split_endpoint(endpoint: &str) -> (&str, Option<&str>) {
    if let Some(rest) = endpoint.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let port = rest[end + 1..].strip_prefix(':');
            return (host, port);
        }
    }

    if endpoint.matches(':').count() == 1 {
        if let Some((host, port)) = endpoint.rsplit_once(':') {
            return (host, Some(port));
        }
    }

    (endpoint, None)
}

/// Comprehensive helper to apply all Windows networking settings for the VPN.
fn set_adapter_network_config(
    adapter: &Adapter,
    ip: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
    dns: Ipv4Addr,
    _mtu: u16,
    endpoint: &str,
    assigned_ipv6: Option<Ipv6Addr>,
    netmask_v6: Option<u8>,
    gateway_v6: Option<Ipv6Addr>,
    dns_v6: Option<Ipv6Addr>,
) -> Result<Option<String>> {
    let requested_adapter_name = adapter.get_name().unwrap_or_else(|_| "MaviVPN".to_string());
    let adapter_index = adapter.get_adapter_index()?;
    let if_str = adapter_index.to_string();
    let ip_str = ip.to_string();
    let mask_str = netmask.to_string();
    let gw_str = gateway.to_string();
    let dns_str = dns.to_string();
    let adapter_name = wait_for_adapter_alias(adapter_index, &requested_adapter_name)?;

    info!("Configuring adapter '{}' (if={}) ip={} mask={} gw={} dns={}",
        adapter_name, adapter_index, ip, netmask, gateway, dns);

    // 1. Ensure adapter is administratively up once it is visible in the OS.
    let enable_script = format!(
        "$adapter = Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object InterfaceIndex -eq {adapter_index} | Select-Object -First 1; if (-not $adapter) {{ throw 'Adapter not found' }}; if ($adapter.Status -eq 'Disabled') {{ $adapter | Enable-NetAdapter -Confirm:$false -ErrorAction Stop | Out-Null }}"
    );
    let _ = run_powershell_cmd(
        &format!("Enable-NetAdapter ifIndex={}", adapter_index),
        &enable_script,
    );

    // 2. Set IPv4 address — positional syntax is the most reliable across Windows versions.
    //    "netsh interface ipv4 set address <name> static <ip> <mask>"
    //    Do NOT set gateway here — we add split routes manually.
    if !run_cmd("netsh", &["interface", "ipv4", "set", "address", &adapter_name, "static", &ip_str, &mask_str]) {
        // Retry with "add" in case "set" fails on fresh adapter
        run_cmd("netsh", &["interface", "ipv4", "add", "address", &adapter_name, &ip_str, &mask_str]);
    }

    // Wait for Windows to register the on-link route for the new IP.
    info!("Waiting for IP to register on adapter...");
    std::thread::sleep(Duration::from_millis(500));

    // Verify the IP was actually set
    if wait_for_ipv4_address(adapter_index, ip) {
        info!("IP {} confirmed on adapter", ip);
    } else {
        anyhow::bail!(
            "IPv4 address {} was not applied to adapter '{}' (if={}). Aborting session setup.",
            ip,
            adapter_name,
            adapter_index
        );
    }

    // 3. Set IPv6 address if available
    if let (Some(ipv6), Some(plen)) = (assigned_ipv6, netmask_v6) {
        let ipv6_str = format!("{}/{}", ipv6, plen);
        run_cmd("netsh", &["interface", "ipv6", "add", "address", &adapter_name, &ipv6_str]);
    }

    // 4. Set DNS
    run_cmd("netsh", &["interface", "ipv4", "set", "dnsservers", &adapter_name, "static", &dns_str, "primary"]);
    if let Some(dv6) = dns_v6 {
        let dv6_str = dv6.to_string();
        run_cmd("netsh", &["interface", "ipv6", "add", "dnsservers", &adapter_name, &dv6_str, "index=1"]);
    }

    // 5. Set MTU (Rule 1: Always 1280)
    let _ = adapter.set_mtu(usize::from(TUN_MTU));
    let mtu_val = "mtu=1280";
    run_cmd("netsh", &["interface", "ipv4", "set", "subinterface", &adapter_name, mtu_val, "store=active"]);
    run_cmd("netsh", &["interface", "ipv6", "set", "subinterface", &adapter_name, mtu_val, "store=active"]);

    // 6. Host exception FIRST — must run before split routes so that
    //    Get-NetRoute still sees the real physical default route.
    let endpoint_route = add_host_route_exception_fixed(endpoint);

    // 7. Split routes 0.0.0.0/1 + 128.0.0.0/1 — override default route without deleting it.
    run_cmd("route", &["add", "0.0.0.0",   "mask", "128.0.0.0", &gw_str, "metric", "5", "if", &if_str]);
    run_cmd("route", &["add", "128.0.0.0", "mask", "128.0.0.0", &gw_str, "metric", "5", "if", &if_str]);

    if let Some(gv6) = gateway_v6 {
        let gv6_str = gv6.to_string();
        run_cmd("netsh", &["interface", "ipv6", "add", "route", "::/1",    &adapter_name, &gv6_str]);
        run_cmd("netsh", &["interface", "ipv6", "add", "route", "8000::/1", &adapter_name, &gv6_str]);
    }

    // Verify routes were added
    let route_check = std::process::Command::new("route").args(["print", "0.0.0.0"]).output();
    if let Ok(out) = route_check {
        let text = String::from_utf8_lossy(&out.stdout);
        if text.contains(&gw_str) {
            info!("Split routes confirmed (gateway {})", gw_str);
        } else {
            warn!("Split routes NOT visible! Check 'route print' output");
        }
    }

    // 8. DNS leak prevention (NRPT + SMHNR)
    set_nrpt_dns_rule(dns, dns_v6);

    info!("Network config complete: endpoint_exception={}",
        endpoint_route.as_deref().unwrap_or("none"));
    Ok(endpoint_route)
}

/// Remove the two split-tunnel routes and the host exception.
/// Called both before a new session (stale cleanup) and on disconnect.
fn cleanup_routes(host_route: Option<&str>) {
    let _ = std::process::Command::new("route").args(["delete", "0.0.0.0",   "mask", "128.0.0.0"]).output();
    let _ = std::process::Command::new("route").args(["delete", "128.0.0.0", "mask", "128.0.0.0"]).output();
    let mut host_routes = Vec::new();
    if let Some(prefix) = host_route {
        host_routes.push(prefix.to_string());
    }
    if let Some(prefix) = load_persisted_host_route() {
        if !host_routes.iter().any(|item| item == &prefix) {
            host_routes.push(prefix);
        }
    }
    for prefix in host_routes {
        let cmd = format!("Remove-NetRoute -DestinationPrefix '{}' -Confirm:$false -ErrorAction SilentlyContinue | Out-Null", prefix);
        let _ = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &cmd])
            .output();
    }
    clear_persisted_host_route();
    let _ = std::process::Command::new("netsh").args(["interface", "ipv6", "delete", "route", "::/1",    "MaviVPN"]).output();
    let _ = std::process::Command::new("netsh").args(["interface", "ipv6", "delete", "route", "8000::/1", "MaviVPN"]).output();
}

fn persisted_host_route_path() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("mavi-vpn").join("last_host_route.txt")
}

fn load_persisted_host_route() -> Option<String> {
    std::fs::read_to_string(persisted_host_route_path())
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn persist_host_route(prefix: &str) {
    let path = persisted_host_route_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, prefix);
}

fn clear_persisted_host_route() {
    let _ = std::fs::remove_file(persisted_host_route_path());
}

/// Routes the VPN server's own IP via the physical gateway rather than the tunnel.
/// Returns the server IP string so the caller can clean it up later.
/// Must be called BEFORE the split-tunnel routes are installed.
#[allow(dead_code)]
fn add_host_route_exception(endpoint: &str) -> Option<String> {
    let server_ip = endpoint
        .split(':').next().unwrap_or(endpoint)
        .trim_start_matches('[').trim_end_matches(']')
        .to_string();

    // Find the physical default gateway, explicitly excluding the VPN adapter
    // (important on reconnect where VPN routes might still exist).
    let ps = "Get-NetRoute -DestinationPrefix 0.0.0.0/0 -AddressFamily IPv4 \
        | Where-Object { (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).InterfaceDescription -notlike '*WireGuard*' -and \
          (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).Name -notlike 'MaviVPN*' } \
        | Sort-Object { $_.RouteMetric + $_.InterfaceMetric } \
        | Select-Object -First 1 -ExpandProperty NextHop";

    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", ps])
        .output();

    if let Ok(out) = output {
        let gateway = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !gateway.is_empty() && gateway != "0.0.0.0" {
            let _ = std::process::Command::new("route")
                .args(["add", &server_ip, "mask", "255.255.255.255", &gateway, "metric", "1"])
                .output();
            info!("Host exception: {} → {}", server_ip, gateway);
            return Some(server_ip);
        }
    }
    warn!("Could not determine physical gateway for host exception route");
    None
}

fn add_host_route_exception_fixed(endpoint: &str) -> Option<String> {
    let server_ip: IpAddr = match endpoint.parse() {
        Ok(ip) => ip,
        Err(_) => {
            warn!("Could not parse endpoint IP '{}' for host exception route", endpoint);
            return None;
        }
    };

    let route_prefix = match server_ip {
        IpAddr::V4(v4) => format!("{}/32", v4),
        IpAddr::V6(v6) => format!("{}/128", v6),
    };

    let (default_prefix, family, empty_next_hop) = match server_ip {
        IpAddr::V4(_) => ("0.0.0.0/0", "IPv4", "0.0.0.0"),
        IpAddr::V6(_) => ("::/0", "IPv6", "::"),
    };

    let ps = format!(
        "$best = Get-NetRoute -DestinationPrefix '{}' -AddressFamily {} \
        | Where-Object {{ (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).InterfaceDescription -notlike '*WireGuard*' -and \
          (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).Name -notlike 'MaviVPN*' }} \
        | Sort-Object {{ $_.RouteMetric + $_.InterfaceMetric }} \
        | Select-Object -First 1; \
        if ($best) {{ \
            if ($best.NextHop -and $best.NextHop -ne '{}') {{ \
                New-NetRoute -DestinationPrefix '{}' -InterfaceIndex $best.InterfaceIndex -NextHop $best.NextHop -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null; \
                Write-Output $best.NextHop \
            }} else {{ \
                New-NetRoute -DestinationPrefix '{}' -InterfaceIndex $best.InterfaceIndex -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null; \
                Write-Output 'On-Link' \
            }} \
        }}",
        default_prefix,
        family,
        empty_next_hop,
        route_prefix,
        route_prefix,
    );

    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps])
        .output();

    if let Ok(out) = output {
        let gateway = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !gateway.is_empty() && gateway != empty_next_hop {
            persist_host_route(&route_prefix);
            info!("Host exception: {} -> {}", route_prefix, gateway);
            return Some(route_prefix);
        }
    }

    warn!("Could not determine physical gateway for host exception route");
    None
}

const NRPT_COMMENT: &str = "MaviVPN";

/// Configures NRPT (Name Resolution Policy Table) to force all DNS through the VPN.
/// This prevents DNS leaks where Windows might try local DNS even when the VPN is up.
fn set_nrpt_dns_rule(dns_v4: Ipv4Addr, dns_v6: Option<Ipv6Addr>) {
    let dns_servers = match dns_v6 {
        Some(v6) => format!("'{}','{}'" , dns_v4, v6),
        None => format!("'{}'", dns_v4),
    };

    // 1. Add NRPT rule for the root namespace "." to capture all queries
    let nrpt_cmd = format!("Add-DnsClientNrptRule -Namespace '.' -NameServers {} -Comment '{}' -ErrorAction SilentlyContinue", dns_servers, NRPT_COMMENT);
    let _ = std::process::Command::new("powershell").args(["-NoProfile", "-Command", &nrpt_cmd]).output();

    // 2. Disable Smart Multi-Homed Name Resolution (SMHNR)
    // Windows sends DNS queries over ALL adapters simultaneously for speed.
    // This is the #1 cause of DNS leaks - it bypasses NRPT and sends queries
    // to physical adapter DNS servers (like Google 8.8.8.8 or ISP DNS).
    let _ = std::process::Command::new("reg").args([
        "add", r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
        "/v", "DisableSmartNameResolution", "/t", "REG_DWORD", "/d", "1", "/f"
    ]).output();
    // Also disable via the newer Group Policy path
    let _ = std::process::Command::new("reg").args([
        "add", r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
        "/v", "DisableParallelAandAAAA", "/t", "REG_DWORD", "/d", "1", "/f"
    ]).output();

    // 3. Set VPN adapter to highest priority
    let _ = std::process::Command::new("powershell").args(["-NoProfile", "-Command", "Get-NetAdapter -Name 'MaviVPN*' | Set-NetIPInterface -InterfaceMetric 1"]).output();

    // 4. Suppress DNS registration on physical adapters to prevent them from being used
    let _ = std::process::Command::new("powershell").args(["-NoProfile", "-Command",
        "Get-NetAdapter | Where-Object { $_.Name -notlike 'MaviVPN*' -and $_.Status -eq 'Up' } | ForEach-Object { Set-DnsClient -InterfaceIndex $_.ifIndex -RegisterThisConnectionsAddress $false -ErrorAction SilentlyContinue }"
    ]).output();

    // 5. Flush DNS cache and re-register to pick up the new NRPT rules
    let _ = std::process::Command::new("ipconfig").args(["/flushdns"]).output();
    let _ = std::process::Command::new("ipconfig").args(["/registerdns"]).output();

    // 6. Restart DNS Client service to ensure NRPT + SMHNR changes take effect
    let _ = std::process::Command::new("powershell").args(["-NoProfile", "-Command",
        "Restart-Service -Name Dnscache -Force -ErrorAction SilentlyContinue"
    ]).output();

    info!("DNS leak prevention configured: NRPT + SMHNR disabled");
}

/// Cleans up NRPT rules and restores DNS settings on exit.
fn remove_nrpt_dns_rule() {
    // 1. Remove NRPT rules
    let cmd = format!("Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{}' }} | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue", NRPT_COMMENT);
    let _ = std::process::Command::new("powershell").args(["-NoProfile", "-Command", &cmd]).output();

    // 2. Re-enable Smart Multi-Homed Name Resolution
    let _ = std::process::Command::new("reg").args([
        "delete", r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
        "/v", "DisableSmartNameResolution", "/f"
    ]).output();
    let _ = std::process::Command::new("reg").args([
        "delete", r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
        "/v", "DisableParallelAandAAAA", "/f"
    ]).output();

    // 3. Restore DNS registration on physical adapters
    let _ = std::process::Command::new("powershell").args(["-NoProfile", "-Command",
        "Get-NetAdapter | Where-Object { $_.Name -notlike 'MaviVPN*' -and $_.Status -eq 'Up' } | ForEach-Object { Set-DnsClient -InterfaceIndex $_.ifIndex -RegisterThisConnectionsAddress $true -ErrorAction SilentlyContinue }"
    ]).output();

    // 4. Flush DNS cache
    let _ = std::process::Command::new("ipconfig").args(["/flushdns"]).output();
    
    // 5. Restart DNS Client service to restore normal behavior
    let _ = std::process::Command::new("powershell").args(["-NoProfile", "-Command",
        "Restart-Service -Name Dnscache -Force -ErrorAction SilentlyContinue"
    ]).output();

    info!("DNS leak prevention removed, normal DNS restored");
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) { return None; }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Custom certificate verifier that trusts only a specific SHA-256 fingerprint.
#[derive(Debug)]
struct PinnedServerVerifier {
    expected_hash: Vec<u8>,
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PinnedServerVerifier {
    fn new(expected_hash: Vec<u8>) -> Self {
        Self { expected_hash, supported: rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms }
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

    fn verify_tls12_signature(&self, message: &[u8], cert: &rustls::pki_types::CertificateDer<'_>, dss: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &rustls::pki_types::CertificateDer<'_>, dss: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> { self.supported.supported_schemes() }
}
