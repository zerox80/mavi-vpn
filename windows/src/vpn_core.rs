use anyhow::{Context, Result};
use bytes::Bytes;
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use shared::{icmp, ControlMessage};
use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wintun::Adapter;

static WINTUN_DLL: &[u8] = include_bytes!("../wintun.dll");
const KEEPALIVE_SECS: u64 = 10;
const IDLE_TIMEOUT_SECS: u64 = 60;
const RECONNECT_INITIAL_SECS: u64 = 1;
const RECONNECT_MAX_SECS: u64 = 30;

pub use crate::ipc::Config;

fn extract_wintun_dll() -> Result<PathBuf> {
    let temp_dir = std::env::temp_dir();
    let dll_path = temp_dir.join("mavi_wintun.dll");
    
    info!("Embedded wintun.dll size: {} bytes", WINTUN_DLL.len());
    
    if dll_path.exists() {
        info!("Using cached wintun.dll at {}", dll_path.display());
    } else {
        info!("Extracting wintun.dll to {}...", dll_path.display());
        std::fs::write(&dll_path, WINTUN_DLL)
            .context("Failed to extract wintun.dll to temp directory")?;
        info!("wintun.dll extracted successfully");
    }
    
    Ok(dll_path)
}

pub async fn run_vpn(config: Config, running: Arc<AtomicBool>) -> Result<()> {
    let cert_pin_bytes = decode_hex(&config.cert_pin).context("Invalid certificate PIN hex")?;

    let dll_path = extract_wintun_dll()?;
    let wintun = unsafe { wintun::load_from_path(&dll_path) }
        .context("Failed to load wintun.dll")?;
    let adapter = get_or_create_adapter(&wintun)?;

    let mut backoff = Duration::from_secs(RECONNECT_INITIAL_SECS);

    while running.load(Ordering::Relaxed) {
        let outcome = run_session(&config, &cert_pin_bytes, &adapter, &running).await;
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
                warn!("Session failed: {}", e);
                (backoff, (backoff * 2).min(Duration::from_secs(RECONNECT_MAX_SECS)))
            }
        };

        info!("Reconnecting in {}s...", reconnect_delay.as_secs());
        tokio::time::sleep(reconnect_delay).await;
        backoff = next_backoff;
    }

    // Cleanup DNS leak prevention
    remove_nrpt_dns_rule();
    info!("Disconnected.");
    Ok(())
}

enum SessionEnd {
    UserStopped,
    ConnectionLost,
}

fn get_or_create_adapter(wintun: &wintun::Wintun) -> Result<Arc<Adapter>> {
    if let Ok(adapter) = Adapter::open(wintun, "MaviVPN") {
        return Ok(adapter);
    }

    Adapter::create(wintun, "MaviVPN", "Mavi VPN Tunnel", None)
        .context("Failed to create WinTUN adapter. Run as Administrator.")
}

fn create_udp_socket() -> Result<std::net::UdpSocket> {
    // Use IPv6 dual-stack socket to support both IPv4 and IPv6 endpoints
    let socket2_sock = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    // Enable dual-stack: allow IPv4-mapped IPv6 addresses
    socket2_sock.set_only_v6(false)?;

    socket2_sock.bind(&socket2::SockAddr::from(
        std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0),
    ))?;

    socket2_sock.set_nonblocking(true)?;

    let socket: std::net::UdpSocket = socket2_sock.into();
    info!("Socket bound to {}", socket.local_addr()?);
    Ok(socket)
}

async fn run_session(
    config: &Config,
    cert_pin_bytes: &[u8],
    adapter: &Arc<Adapter>,
    global_running: &Arc<AtomicBool>,
) -> Result<SessionEnd> {
    let socket = create_udp_socket()?;

    let (connection, server_config) = connect_and_handshake(
        socket,
        config.token.clone(),
        config.endpoint.clone(),
        cert_pin_bytes.to_vec(),
        config.censorship_resistant,
    )
    .await?;

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
                return Err(anyhow::anyhow!("Server error: {}", message));
            }
            _ => return Err(anyhow::anyhow!("Unexpected response")),
        };

    info!("Connected! Assigned IP: {}", assigned_ip);
    info!("Netmask: {}, Gateway: {}", netmask, gateway);
    info!("DNS: {}, MTU: {}", dns, mtu);
    if let Some(ipv6) = assigned_ipv6 {
        let prefix = netmask_v6.unwrap_or(64);
        info!("IPv6: {}/{}", ipv6, prefix);
    }

    // Get the actual resolved IP of the server to ensure the route exception works
    // even if DNS is unreachable later.
    // Get the actual resolved IP of the server to ensure the route exception works
    // even if DNS is unreachable later.
    let remote_ip = connection.remote_address().ip();
    let endpoint_ip = match remote_ip {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                v4.to_string()
            } else {
                v6.to_string()
            }
        }
    };

    set_adapter_ip(
        adapter,
        assigned_ip,
        netmask,
        gateway,
        dns,
        mtu,
        &endpoint_ip,
        assigned_ipv6,
        netmask_v6,
        gateway_v6,
        dns_v6,
    )?;

    let session = Arc::new(
        adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .context("Failed to start WinTUN session")?,
    );

    info!("VPN tunnel established. Press Ctrl+C to disconnect.");

    let connection = Arc::new(connection);
    let session_alive = Arc::new(AtomicBool::new(true));

    // Task: MTU Monitoring (10/10 Logging)
    let conn_monitor = connection.clone();
    let monitor_alive = session_alive.clone();
    let global_running_monitor = global_running.clone();
    tokio::spawn(async move {
        let mut last_mtu = 0;
        loop {
            if !global_running_monitor.load(Ordering::Relaxed) || !monitor_alive.load(Ordering::Relaxed) {
                break;
            }
            
            let current_mtu = conn_monitor.max_datagram_size().unwrap_or(0);
            
            if current_mtu != last_mtu {
                if last_mtu == 0 {
                    info!("[MTU] Initial QUIC Path MTU: {} bytes", current_mtu);
                } else if current_mtu > last_mtu {
                    info!("[MTU] QUIC Path MTU increased: {} -> {} bytes", last_mtu, current_mtu);
                } else {
                    warn!("[MTU] QUIC Path MTU decreased: {} -> {} bytes (Black Hole Detected)", last_mtu, current_mtu);
                }
                last_mtu = current_mtu;
            }
            
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    let session_rx = session.clone();
    let conn_tx = connection.clone();
    let alive_tx = session_alive.clone();
    let gateway_v4 = gateway;
    let gateway_v6_opt = gateway_v6;
    let run_tx = global_running.clone();
    let tun_to_quic = std::thread::spawn(move || {
        loop {
            if !run_tx.load(Ordering::Relaxed) || !alive_tx.load(Ordering::Relaxed) {
                break;
            }
            match session_rx.try_receive() {
                Ok(Some(packet)) => {
                    let packet_bytes = packet.bytes();
                    let packet_len = packet_bytes.len();
                    let data = Bytes::copy_from_slice(packet_bytes);
                    if let Err(e) = conn_tx.send_datagram(data) {
                        match e {
                            quinn::SendDatagramError::ConnectionLost(_) => {
                                warn!("Connection lost, stopping TUN reader");
                                break;
                            }
                            quinn::SendDatagramError::TooLarge => {
                                let current_mtu = conn_tx.max_datagram_size().unwrap_or(1200) as u16;
                                let version = (packet_bytes[0] >> 4) & 0xF;
                                let gw = if version == 4 { 
                                    std::net::IpAddr::V4(gateway_v4) 
                                } else { 
                                    std::net::IpAddr::V6(gateway_v6_opt.unwrap_or("2001:db8::1".parse().unwrap())) 
                                };

                                warn!("Packet too large ({} bytes). Exceeds QUIC Path MTU ({} bytes). Sending ICMP Signal from {}.", packet_len, current_mtu, gw);
                                if let Some(icmp_packet) = icmp::generate_packet_too_big(packet_bytes, current_mtu, Some(gw)) {
                                    if let Ok(mut icmp_send_packet) = session_rx.allocate_send_packet(icmp_packet.len() as u16) {
                                        icmp_send_packet.bytes_mut().copy_from_slice(&icmp_packet);
                                        session_rx.send_packet(icmp_send_packet);
                                    }
                                }
                            }
                            _ => {
                                error!("Send error: {:?}", e);
                                alive_tx.store(false, Ordering::SeqCst);
                                break;
                            }
                        }
                    }
                }
                Ok(None) => {
                    std::thread::sleep(Duration::from_micros(100));
                }
                Err(e) => {
                    if run_tx.load(Ordering::Relaxed) {
                        error!("TUN read error: {:?}", e);
                    }
                    alive_tx.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }
    });

    let session_tx = session.clone();
    let alive_rx = session_alive.clone();
    let run_rx = global_running.clone();
    let quic_to_tun = tokio::spawn(async move {
        loop {
            if !run_rx.load(Ordering::Relaxed) || !alive_rx.load(Ordering::Relaxed) {
                break;
            }
            tokio::select! {
                result = connection.read_datagram() => {
                    match result {
                        Ok(data) => {
                            if data.is_empty() {
                                continue;
                            }
                            match session_tx.allocate_send_packet(data.len() as u16) {
                                Ok(mut packet) => {
                                    packet.bytes_mut().copy_from_slice(&data);
                                    session_tx.send_packet(packet);
                                }
                                Err(e) => {
                                    if is_wintun_ring_full(&e) {
                                        tokio::time::sleep(Duration::from_millis(2)).await;
                                        continue;
                                    }
                                    warn!("Failed to allocate packet: {:?}", e);
                                    alive_rx.store(false, Ordering::SeqCst);
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            if run_rx.load(Ordering::Relaxed) {
                                error!("QUIC read error: {:?}", e);
                            }
                            alive_rx.store(false, Ordering::SeqCst);
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    if !run_rx.load(Ordering::Relaxed) {
                        break;
                    }
                }
            }
        }
    });

    while global_running.load(Ordering::Relaxed) && session_alive.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    quic_to_tun.abort();
    drop(session);
    let _ = tun_to_quic.join();

    if global_running.load(Ordering::Relaxed) {
        Ok(SessionEnd::ConnectionLost)
    } else {
        Ok(SessionEnd::UserStopped)
    }
}

fn is_wintun_ring_full(err: &wintun::Error) -> bool {
    match err {
        wintun::Error::Io(io_err) => {
            io_err.raw_os_error()
                == Some(windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW as i32)
        }
        _ => false,
    }
}

fn configure_socket(socket: &std::net::UdpSocket) -> Result<()> {
    let socket2_sock = socket2::SockRef::from(socket);

    let _ = socket2_sock.set_recv_buffer_size(1024 * 1024);
    let _ = socket2_sock.set_send_buffer_size(1024 * 1024);

    // Allow IP fragmentation by disabling "Don't Fragment" (MTU discovery)
    // NOTE: With DPLPMTUD enabled in Quinn, we generally want standard socket behavior.
    // However, keeping this doesn't hurt DPLPMTUD as Quinn sets DF on probes automatically.
    // We remove manual overrides to ensure a clean state and rely on Quinn's PMTUD.

    Ok(())
}

async fn connect_and_handshake(
    socket: std::net::UdpSocket,
    token: String,
    endpoint_str: String,
    cert_pin: Vec<u8>,
    censorship_resistant: bool,
) -> Result<(quinn::Connection, ControlMessage)> {
    info!("Connecting to {}...", endpoint_str);

    // Apply socket options directly on the socket before Quinn takes ownership.
    configure_socket(&socket)?;

    let verifier = Arc::new(PinnedServerVerifier::new(cert_pin));

    let mut client_crypto = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into()
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_no_client_auth();

    if censorship_resistant {
        client_crypto.alpn_protocols = vec![b"h3".to_vec()];
    } else {
        client_crypto.alpn_protocols = vec![b"mavivpn".to_vec()];
    }

    let mut transport_config = quinn::TransportConfig::default();
    transport_config
        .max_idle_timeout(Some(Duration::from_secs(IDLE_TIMEOUT_SECS).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(Duration::from_secs(KEEPALIVE_SECS)));
    // Disable MTU Discovery to enforce the 1350 limit.
    // We rely on OS-level fragmentation for paths < 1350 (e.g. 1280 IPv6).
    // If we enable discovery, Quinn will stick to 1280 and reject our 1350 datagrams.
    // Enable DPLPMTUD (Path MTU Discovery) - DISABLED
    // MTU Pinning: Set min_mtu = initial_mtu = 1360.
    // Prevents Black Hole detection from reducing MTU to 1280.
    transport_config.mtu_discovery_config(None);
    transport_config.initial_mtu(1360);
    transport_config.min_mtu(1360);
    transport_config.enable_segmentation_offload(true);
    transport_config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));

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

    // Quinn's Windows UDP backend enables DF by default.
    // We stick to this default for DPLPMTUD compatibility.
    
    let addr = tokio::net::lookup_host(&endpoint_str)
        .await?
        .find(|addr| addr.is_ipv4())
        .or_else(|| {
            // Fallback: try IPv6 if no IPv4 address found
            warn!("No IPv4 address found for endpoint, trying IPv6...");
            None
        });

    // If no IPv4, try again including IPv6
    let addr = match addr {
        Some(a) => a,
        None => tokio::net::lookup_host(&endpoint_str)
            .await?
            .next()
            .context("Failed to resolve endpoint (no address found)")?,
    };

    info!("Resolved to {}", addr);
    info!("Starting QUIC handshake...");
    
    let server_name = endpoint_str
        .rsplit_once(':')
        .map(|(host, _)| host)
        .filter(|host| !host.is_empty())
        .unwrap_or(endpoint_str.as_str());
    let connecting = endpoint.connect(addr, server_name)?;
    info!("Connect initiated, waiting for handshake...");
    
    let connection = tokio::select! {
        result = connecting => {
            match result {
                Ok(conn) => conn,
                Err(e) => {
                    error!("QUIC handshake failed: {:?}", e);
                    return Err(anyhow::anyhow!("QUIC handshake failed: {}", e));
                }
            }
        }
        _ = tokio::time::sleep(Duration::from_secs(10)) => {
            return Err(anyhow::anyhow!("Connection timeout (10s) - no response from server"));
        }
    };
    
    info!("QUIC connection established");

    let (mut send_stream, mut recv_stream) = connection.open_bi().await?;

    let auth_msg = ControlMessage::Auth { token };
    let bytes = bincode::serde::encode_to_vec(&auth_msg, bincode::config::standard()).map_err(|e| anyhow::anyhow!("{}", e))?;
    send_stream.write_u32_le(bytes.len() as u32).await?;
    send_stream.write_all(&bytes).await?;

    let len = recv_stream.read_u32_le().await? as usize;
    if len > 65536 {
        return Err(anyhow::anyhow!("Server response too large: {} bytes", len));
    }
    let mut buf = vec![0u8; len];
    recv_stream.read_exact(&mut buf).await?;
    let config: ControlMessage = bincode::serde::decode_from_slice(&buf, bincode::config::standard())
        .map(|(v, _)| v)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok((connection, config))
}

fn set_adapter_ip(
    adapter: &Adapter,
    ip: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
    dns: Ipv4Addr,
    mtu: u16,
    endpoint: &str,
    assigned_ipv6: Option<Ipv6Addr>,
    netmask_v6: Option<u8>,
    gateway_v6: Option<Ipv6Addr>,
    dns_v6: Option<Ipv6Addr>,
) -> Result<()> {
    let adapter_name = adapter.get_name().unwrap_or_else(|_| "MaviVPN".to_string());
    let luid = adapter.get_luid();
    let prefix_len = netmask_to_prefix_len(netmask)?;
    let has_ipv6 = assigned_ipv6.is_some();

    unsafe {
        use windows_sys::Win32::NetworkManagement::IpHelper::*;
        use windows_sys::Win32::Networking::WinSock::*;

        let mut row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
        InitializeUnicastIpAddressEntry(&mut row);

        row.InterfaceLuid = std::mem::transmute(luid);
        row.Address.si_family = AF_INET as u16;
        // Windows expects S_addr in network byte order; on little-endian this requires native bytes.
        row.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
        row.OnLinkPrefixLength = prefix_len;
        row.DadState = IpDadStatePreferred;

        let result = CreateUnicastIpAddressEntry(&row);
        if result != 0 && result != 5010 {
            return Err(anyhow::anyhow!(
                "Failed to set IP address: error code {}",
                result
            ));
        }
    }

    info!("Set adapter IP to {}/{}", ip, prefix_len);

    if let Some(ipv6) = assigned_ipv6 {
        let prefix_v6 = netmask_v6.unwrap_or(64);
        if let Err(e) = set_adapter_ipv6(adapter, ipv6, prefix_v6) {
            warn!("Failed to set IPv6 address: {}", e);
        } else {
            info!("Set adapter IPv6 to {}/{}", ipv6, prefix_v6);
        }
    }

    let adapter_index = adapter
        .get_adapter_index()
        .context("Failed to get adapter index")?;

    // Set DNS directly via netsh — bypassing wintun's set_dns_servers() which has
    // an internal quoting bug that causes "Falscher Parameter" on localized Windows.
    let out = std::process::Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            &adapter_name,
            "static",
            &dns.to_string(),
            "primary",
        ])
        .output();
    match out {
        Ok(out) if out.status.success() => {
            info!("DNS set to {} via netsh", dns);
        }
        Ok(out) => {
            warn!("netsh set dnsservers failed: {}", String::from_utf8_lossy(&out.stderr));
        }
        Err(e) => {
            warn!("Failed to run netsh for DNS: {}", e);
        }
    }

    if let Some(dns_v6) = dns_v6 {
        let out = std::process::Command::new("netsh")
            .args([
                "interface",
                "ipv6",
                "add",
                "dnsservers",
                &adapter_name,
                &dns_v6.to_string(),
                "index=1",
            ])
            .output();
        if let Ok(out) = out {
            if !out.status.success() {
                warn!(
                    "netsh add ipv6 dns failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            } else {
                info!("IPv6 DNS set to {} via netsh", dns_v6);
            }
        }
    }

    // Set MTU for both IPv4 and IPv6. 
    // We try the adapter API first, then reinforce with multiple netsh commands.
    let _ = adapter.set_mtu(mtu as usize);
    
    for proto in &["ipv4", "ipv6"] {
        for store in &["active", "persistent"] {
            // Reinforce with name-based setting
            let _ = std::process::Command::new("netsh")
                .args([
                    "interface",
                    proto,
                    "set",
                    "subinterface",
                    &adapter_name,
                    &format!("mtu={}", mtu),
                    &format!("store={}", store),
                ])
                .output();

            // Reinforce with index-based setting (sometimes more reliable)
            let _ = std::process::Command::new("netsh")
                .args([
                    "interface",
                    proto,
                    "set",
                    "interface",
                    &adapter_index.to_string(),
                    &format!("mtu={}", mtu),
                    &format!("store={}", store),
                ])
                .output();
        }
        info!("Applied MTU {} to {} (Name: {}, Index: {})", mtu, proto, adapter_name, adapter_index);
    }

    // Route first half of IPv4 space
    route_add_or_change(
        &[
            "add",
            "0.0.0.0",
            "mask",
            "128.0.0.0",
            &gateway.to_string(),
            "metric",
            "1",
            "if",
            &adapter_index.to_string(),
        ],
        &[
            "change",
            "0.0.0.0",
            "mask",
            "128.0.0.0",
            &gateway.to_string(),
            "metric",
            "1",
            "if",
            &adapter_index.to_string(),
        ],
        "0.0.0.0/1",
    );

    // Route second half of IPv4 space
    route_add_or_change(
        &[
            "add",
            "128.0.0.0",
            "mask",
            "128.0.0.0",
            &gateway.to_string(),
            "metric",
            "1",
            "if",
            &adapter_index.to_string(),
        ],
        &[
            "change",
            "128.0.0.0",
            "mask",
            "128.0.0.0",
            &gateway.to_string(),
            "metric",
            "1",
            "if",
            &adapter_index.to_string(),
        ],
        "128.0.0.0/1",
    );

    if has_ipv6 {
        if let Some(gateway_v6) = gateway_v6 {
            add_ipv6_routes(&adapter_name, gateway_v6);
        }
    }
    
    // CRITICAL: prevents routing loop
    // Add specific route for the VPN server IP via the PHYSICAL gateway
    if let Err(e) = add_host_route_exception(endpoint) {
        warn!("Failed to add host route exception: {}. Connection might be unstable.", e);
    }

    // Prevent DNS Leak: Force all DNS through VPN using NRPT (Name Resolution Policy Table)
    set_nrpt_dns_rule(dns, dns_v6);

    Ok(())
}

fn set_adapter_ipv6(adapter: &Adapter, ip: Ipv6Addr, prefix_len: u8) -> Result<()> {
    unsafe {
        use windows_sys::Win32::NetworkManagement::IpHelper::*;
        use windows_sys::Win32::Networking::WinSock::*;

        let mut row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
        InitializeUnicastIpAddressEntry(&mut row);

        row.InterfaceLuid = std::mem::transmute(adapter.get_luid());
        row.Address.si_family = AF_INET6 as u16;
        row.Address.Ipv6.sin6_addr.u.Byte = ip.octets();
        row.Address.Ipv6.Anonymous.sin6_scope_id = 0;
        row.OnLinkPrefixLength = prefix_len;
        row.DadState = IpDadStatePreferred;

        let result = CreateUnicastIpAddressEntry(&row);
        if result != 0 && result != 5010 {
            return Err(anyhow::anyhow!(
                "Failed to set IPv6 address: error code {}",
                result
            ));
        }
    }

    Ok(())
}

fn route_add_or_change(args_add: &[&str], args_change: &[&str], label: &str) {
    let out = std::process::Command::new("route").args(args_add).output();
    if let Ok(out) = out {
        if out.status.success() {
            return;
        }
    }

    let out = std::process::Command::new("route").args(args_change).output();
    match out {
        Ok(out) if !out.status.success() => {
            warn!("route {} failed: {}", label, String::from_utf8_lossy(&out.stderr));
        }
        Err(e) => {
            warn!("route {} failed to execute: {}", label, e);
        }
        _ => {}
    }
}

fn add_ipv6_routes(adapter_name: &str, gateway: Ipv6Addr) {
    add_ipv6_route(adapter_name, "::/1", gateway, "::/1");
    add_ipv6_route(adapter_name, "8000::/1", gateway, "8000::/1");
}

fn add_ipv6_route(adapter_name: &str, prefix: &str, gateway: Ipv6Addr, label: &str) {
    let out = std::process::Command::new("netsh")
        .args([
            "interface",
            "ipv6",
            "add",
            "route",
            prefix,
            adapter_name,
            &gateway.to_string(),
        ])
        .output();
    if let Ok(out) = out {
        if !out.status.success() {
            warn!(
                "netsh ipv6 add route {} failed: {}",
                label,
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

fn add_host_route_exception(endpoint: &str) -> Result<()> {
    let server_ip = if endpoint.starts_with('[') {
        // IPv6: [2001:db8::1]:443
        endpoint
            .strip_prefix('[')
            .and_then(|s| s.split(']').next())
            .context("Invalid IPv6 endpoint format")?
    } else {
        // IPv4 oder Hostname: vpn.example.com:443
        endpoint
            .rsplit_once(':')
            .map(|(host, _)| host)
            .unwrap_or(endpoint)
    };
    
    // Get default gateway IP via PowerShell
    let output = std::process::Command::new("powershell")
        .args([
            "-Command",
            "Get-NetRoute -DestinationPrefix 0.0.0.0/0 -AddressFamily IPv4 | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 -ExpandProperty NextHop",
        ])
        .output()?;

    let gateway = String::from_utf8(output.stdout)?
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("")
        .to_string();
    
    if !gateway.is_empty() {
        info!("Adding host route exception for {} via physical gateway {}", server_ip, gateway);
        let _ = std::process::Command::new("route")
            .args(["add", server_ip, "mask", "255.255.255.255", &gateway, "metric", "1"])
            .output();
    } else {
        warn!("Could not detect physical gateway. Skipping host route exception.");
    }
    
    Ok(())
}

fn netmask_to_prefix_len(netmask: Ipv4Addr) -> Result<u8> {
    let mask = u32::from_be_bytes(netmask.octets());
    let prefix = mask.count_ones() as u8;
    let expected = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix) };
    if mask != expected {
        return Err(anyhow::anyhow!("Invalid netmask {}", netmask));
    }
    Ok(prefix)
}

const NRPT_COMMENT: &str = "MaviVPN";

fn set_nrpt_dns_rule(dns_v4: Ipv4Addr, dns_v6: Option<Ipv6Addr>) {
    // Build DNS server list for NRPT
    let dns_servers = match dns_v6 {
        Some(v6) => format!("'{}','{}'", dns_v4, v6),
        None => format!("'{}'", dns_v4),
    };

    // 1. Add NRPT rule via PowerShell (catch-all namespace "." forces all DNS through VPN)
    let nrpt_cmd = format!(
        "Add-DnsClientNrptRule -Namespace '.' -NameServers {} -Comment '{}' -ErrorAction SilentlyContinue",
        dns_servers, NRPT_COMMENT
    );
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &nrpt_cmd])
        .output();
    match &out {
        Ok(o) if o.status.success() => info!("NRPT rule added: all DNS -> {}", dns_servers),
        Ok(o) => warn!("NRPT rule failed: {}", String::from_utf8_lossy(&o.stderr)),
        Err(e) => warn!("NRPT PowerShell failed: {}", e),
    }

    // 2. Set VPN adapter interface metric to 1 (highest priority)
    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", 
            "Get-NetAdapter -Name 'MaviVPN*' | Set-NetIPInterface -InterfaceMetric 1 -ErrorAction SilentlyContinue"])
        .output();

    // 3. Flush DNS cache
    let _ = std::process::Command::new("ipconfig")
        .args(["/flushdns"])
        .output();

    info!("DNS Leak Prevention enabled (NRPT + Interface Metric)");
}

fn remove_nrpt_dns_rule() {
    // Remove all NRPT rules with our comment
    let cmd = format!(
        "Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{}' }} | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue",
        NRPT_COMMENT
    );
    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &cmd])
        .output();

    // Flush DNS cache
    let _ = std::process::Command::new("ipconfig")
        .args(["/flushdns"])
        .output();

    info!("NRPT DNS rule removed (DNS Leak Prevention disabled)");
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

#[derive(Debug)]
struct PinnedServerVerifier {
    expected_hash: Vec<u8>,
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PinnedServerVerifier {
    fn new(expected_hash: Vec<u8>) -> Self {
        Self {
            expected_hash,
            supported: rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
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
