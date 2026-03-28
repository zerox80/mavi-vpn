//! # Mavi VPN Windows Core
//! 
//! Implements the core VPN logic for Windows, including:
//! - WinTUN adapter management.
//! - QUIC transport via Quinn.
//! - Windows-specific routing and DNS leak prevention (NRPT).
//! - Dual-stack (IPv4/IPv6) support.

use anyhow::{Context, Result};
use bytes::Bytes;
use sha2::{Sha256, Digest};
use wtransport::{Endpoint, ClientConfig};
use tracing::{info, warn};
use shared::{icmp, ControlMessage};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wintun::Adapter;

/// Embedded WinTUN driver binary.
static WINTUN_DLL: &[u8] = include_bytes!("../wintun.dll");

// --- Default timing parameters ---
const KEEPALIVE_SECS: u64 = 10;
const IDLE_TIMEOUT_SECS: u64 = 60;
const RECONNECT_INITIAL_SECS: u64 = 1;
const RECONNECT_MAX_SECS: u64 = 30;

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
    let cert_pin_bytes = if config.cert_pin.is_empty() {
        Vec::new()
    } else {
        decode_hex(&config.cert_pin).context("Invalid certificate PIN hex format")?
    };
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

/// Helper to ensure the "MaviVPN" adapter exists in Windows.
fn get_or_create_adapter(wintun: &wintun::Wintun) -> Result<Arc<Adapter>> {
    if let Ok(adapter) = Adapter::open(wintun, "MaviVPN") {
        return Ok(adapter);
    }
    Adapter::create(wintun, "MaviVPN", "Mavi VPN Tunnel", None)
        .context("Failed to create WinTUN adapter. Admin privileges required.")
}



/// Manages a single active VPN session (handshake + packet pumping).
async fn run_session(
    config: &Config,
    cert_pin_bytes: &[u8],
    adapter: &Arc<Adapter>,
    global_running: &Arc<AtomicBool>,
) -> Result<SessionEnd> {
    if config.prefer_tcp {
        return run_session_tcp(config, cert_pin_bytes, adapter, global_running).await;
    }

    // 1. QUIC Handshake & Auth
    let (connection, server_config) = connect_and_handshake(
        config.token.clone(),
        config.endpoint.clone(),
        cert_pin_bytes.to_vec(),
        config.censorship_resistant,
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

    set_adapter_network_config(
        adapter, assigned_ip, netmask, gateway, dns, mtu, &endpoint_ip_str,
        assigned_ipv6, netmask_v6, gateway_v6, dns_v6,
    )?;

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
    let tun_to_quic = std::thread::spawn(move || {
        loop {
            if !run_pump.load(Ordering::Relaxed) || !alive_pump.load(Ordering::Relaxed) { break; }
            match session_tun.try_receive() {
                Ok(Some(packet)) => {
                    let data = Bytes::copy_from_slice(packet.bytes());
                    if let Err(e) = conn_quic.send_datagram(data) {
                        if let wtransport::error::SendDatagramError::TooLarge = e {
                            // Synthesise ICMP PTB signal back to OS
                            let current_mtu = conn_quic.max_datagram_size().unwrap_or(1200) as u16;
                            if let Some(icmp_packet) = icmp::generate_packet_too_big(packet.bytes(), current_mtu, Some(std::net::IpAddr::V4(gateway))) {
                                if let Ok(mut reply) = session_tun.allocate_send_packet(icmp_packet.len() as u16) {
                                    reply.bytes_mut().copy_from_slice(&icmp_packet);
                                    session_tun.send_packet(reply);
                                }
                            }
                        } else if let wtransport::error::SendDatagramError::NotConnected = e { break; }
                    }
                }
                Ok(None) => std::thread::sleep(Duration::from_micros(100)),
                Err(_) => { alive_pump.store(false, Ordering::SeqCst); break; }
            }
        }
    });

    // Task: QUIC -> TUN (Read from QUIC, Write to WinTUN)
    let session_quic_in = session.clone();
    let alive_quic_in = session_alive.clone();
    let run_quic_in = global_running.clone();
    let quic_to_tun = tokio::spawn(async move {
        loop {
            if !run_quic_in.load(Ordering::Relaxed) || !alive_quic_in.load(Ordering::Relaxed) { break; }
            match connection.receive_datagram().await {
                Ok(data) => {
                    let payload = data.payload();
                    if payload.is_empty() { continue; }
                    match session_quic_in.allocate_send_packet(payload.len() as u16) {
                        Ok(mut packet) => {
                            packet.bytes_mut().copy_from_slice(&payload);
                            session_quic_in.send_packet(packet);
                        }
                        Err(e) if is_wintun_ring_full(&e) => {
                             tokio::time::sleep(Duration::from_millis(2)).await;
                             continue;
                        }
                        Err(_) => { alive_quic_in.store(false, Ordering::SeqCst); break; }
                    }
                }
                Err(_) => { alive_quic_in.store(false, Ordering::SeqCst); break; }
            }
        }
    });

    // Wait for termination
    while global_running.load(Ordering::Relaxed) && session_alive.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    quic_to_tun.abort();
    let _ = tun_to_quic.join();

    if global_running.load(Ordering::Relaxed) { Ok(SessionEnd::ConnectionLost) } else { Ok(SessionEnd::UserStopped) }
}

/// Checks if the WinTUN ring buffer is full.
fn is_wintun_ring_full(err: &wintun::Error) -> bool {
    matches!(err, wintun::Error::Io(io_err) if io_err.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW as i32))
}

/// QUIC connection setup with custom certificate pinning.
async fn connect_and_handshake(
    token: String,
    endpoint_str: String,
    cert_pin: Vec<u8>,
    censorship_resistant: bool,
) -> Result<(wtransport::Connection, ControlMessage)> {
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(IDLE_TIMEOUT_SECS).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(Duration::from_secs(KEEPALIVE_SECS)));
    
    transport_config.mtu_discovery_config(None);
    transport_config.initial_mtu(1360);
    transport_config.min_mtu(1360);
    transport_config.enable_segmentation_offload(true);
    transport_config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    
    transport_config.datagram_receive_buffer_size(Some(2 * 1024 * 1024)); // 2MB
    transport_config.datagram_send_buffer_size(2 * 1024 * 1024); // 2MB

    let mut client_config = if cert_pin.is_empty() {
        ClientConfig::builder()
            .with_bind_default()
            .with_native_certs()
            .build()
    } else {
        let verifier = Arc::new(PinnedServerVerifier::new(cert_pin));

        let mut client_crypto = rustls::ClientConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        // CR mode: only h3 (looks like HTTP/3 to DPI).
        // Normal mode: try both so it works regardless of server config.
        client_crypto.alpn_protocols = if censorship_resistant {
            vec![wtransport::tls::WEBTRANSPORT_ALPN.to_vec()]
        } else {
            vec![b"mavivpn".to_vec(), wtransport::tls::WEBTRANSPORT_ALPN.to_vec()]
        };

        ClientConfig::builder()
            .with_bind_default()
            .with_custom_tls(client_crypto)
            .build()
    };

    client_config.quic_config_mut().transport_config(Arc::new(transport_config));
        
    let endpoint = Endpoint::client(client_config)?;

    // Resolve endpoint and connect
    let addr = tokio::net::lookup_host(&endpoint_str).await?.next().context("Failed to resolve endpoint")?;
    let _server_name = endpoint_str.split(':').next().unwrap_or(&endpoint_str);
    info!("Connecting to WebTransport endpoint {} (resolved: {})", endpoint_str, addr);
    
    let connect_url = format!("https://{}/vpn", endpoint_str);
    let connection = endpoint.connect(&connect_url).await.context("WebTransport handshake failed TLS/Cert error?")?;
    info!("WebTransport handshake OK, sending auth token ({} bytes)", token.len());

    // Perform application-level handshake
    let (mut send, mut recv) = connection.open_bi().await?.await?;
    let auth_msg = ControlMessage::Auth { token };
    let bytes = bincode::serde::encode_to_vec(&auth_msg, bincode::config::standard())?;
    send.write_u32_le(bytes.len() as u32).await?;
    send.write_all(&bytes).await?;

    let len = recv.read_u32_le().await? as usize;
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    let config: ControlMessage = bincode::serde::decode_from_slice(&buf, bincode::config::standard()).map(|(v, _)| v)?;

    Ok((connection, config))
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

/// Comprehensive helper to apply all Windows networking settings for the VPN.
fn set_adapter_network_config(
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
    let adapter_index = adapter.get_adapter_index()?;
    let if_str = adapter_index.to_string();
    let ip_str = ip.to_string();
    let mask_str = netmask.to_string();
    let gw_str = gateway.to_string();
    let dns_str = dns.to_string();
    let mtu_str = mtu.to_string();

    info!("Configuring adapter '{}' (if={}) ip={} mask={} gw={} dns={}",
        adapter_name, adapter_index, ip, netmask, gateway, dns);

    // 1. Ensure adapter is administratively up
    run_cmd("netsh", &["interface", "set", "interface", &adapter_name, "admin=enabled"]);

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
    let verify = std::process::Command::new("netsh")
        .args(["interface", "ipv4", "show", "addresses", &adapter_name])
        .output();
    if let Ok(out) = verify {
        let text = String::from_utf8_lossy(&out.stdout);
        if text.contains(&ip_str) {
            info!("IP {} confirmed on adapter", ip);
        } else {
            warn!("IP {} NOT visible on adapter! Output: {}", ip, text.trim());
        }
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

    // 5. Set MTU
    let _ = adapter.set_mtu(mtu as usize);
    let mtu_val = format!("mtu={}", mtu_str);
    run_cmd("netsh", &["interface", "ipv4", "set", "subinterface", &adapter_name, &mtu_val, "store=active"]);
    run_cmd("netsh", &["interface", "ipv6", "set", "subinterface", &adapter_name, &mtu_val, "store=active"]);

    // 6. Host exception FIRST — must run before split routes so that
    //    Get-NetRoute still sees the real physical default route.
    let endpoint_ip = add_host_route_exception(endpoint);

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
        endpoint_ip.as_deref().unwrap_or("none"));
    Ok(())
}

/// Remove the two split-tunnel routes and the host exception.
/// Called both before a new session (stale cleanup) and on disconnect.
fn cleanup_routes(endpoint_ip: Option<&str>) {
    let _ = std::process::Command::new("route").args(["delete", "0.0.0.0",   "mask", "128.0.0.0"]).output();
    let _ = std::process::Command::new("route").args(["delete", "128.0.0.0", "mask", "128.0.0.0"]).output();
    if let Some(ip) = endpoint_ip {
        let _ = std::process::Command::new("route").args(["delete", ip]).output();
    }
    // Also remove any stored endpoint exception (best-effort, ignore errors)
    // IPv6 split routes
    let _ = std::process::Command::new("netsh").args(["interface", "ipv6", "delete", "route", "::/1",    "MaviVPN"]).output();
    let _ = std::process::Command::new("netsh").args(["interface", "ipv6", "delete", "route", "8000::/1", "MaviVPN"]).output();
}



/// Routes the VPN server's own IP via the physical gateway rather than the tunnel.
/// Returns the server IP string so the caller can clean it up later.
/// Must be called BEFORE the split-tunnel routes are installed.
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
        "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { Set-DnsClient -InterfaceIndex $_.ifIndex -RegisterThisConnectionsAddress $true -ErrorAction SilentlyContinue }"
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
    if s.len() % 2 != 0 { return None; }
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

async fn run_session_tcp(
    config: &Config,
    cert_pin_bytes: &[u8],
    adapter: &Arc<Adapter>,
    global_running: &Arc<AtomicBool>,
) -> Result<SessionEnd> {
    let endpoint_str = if config.endpoint.contains(':') { config.endpoint.clone() } else { format!("{}:443", config.endpoint) };
    let addr = tokio::net::lookup_host(&endpoint_str).await?.next().context("Failed to resolve TCP endpoint")?;
    
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let _ = stream.set_nodelay(true);

    let server_name = endpoint_str.split(':').next().unwrap_or(&endpoint_str);

    let client_crypto = if cert_pin_bytes.is_empty() {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut cfg = rustls::ClientConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        cfg
    } else {
        let mut cfg = rustls::ClientConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedServerVerifier::new(cert_pin_bytes.to_vec())))
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        cfg
    };

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_crypto));
    let domain = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|_| anyhow::anyhow!("Invalid server name"))?;
    
    let tls_stream = connector.connect(domain, stream).await?;

    let (mut h2_client, connection) = h2::client::handshake(tls_stream).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = http::Request::builder().uri("/vpn").method("POST").body(()).unwrap();
    let (response_future, mut send_stream) = h2_client.send_request(request, false)?;

    let auth_msg = ControlMessage::Auth { token: config.token.clone() };
    let bytes = bincode::serde::encode_to_vec(&auth_msg, bincode::config::standard())?;
    
    let mut auth_frame = Vec::with_capacity(4 + bytes.len());
    auth_frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    auth_frame.extend_from_slice(&bytes);
    
    send_stream.send_data(Bytes::from(auth_frame), false)?;

    let response = response_future.await?;
    if response.status() != http::StatusCode::OK {
        return Err(anyhow::anyhow!("Server rejected TCP connection: HTTP {}", response.status()));
    }

    let mut recv_stream = response.into_body();

    let mut len_buf = [0u8; 4];
    let mut len_read = 0;
    while len_read < 4 {
        if let Some(Ok(chunk)) = recv_stream.data().await {
            let to_copy = std::cmp::min(4 - len_read, chunk.len());
            len_buf[len_read..len_read+to_copy].copy_from_slice(&chunk[..to_copy]);
            len_read += to_copy;
            let _ = recv_stream.flow_control().release_capacity(chunk.len());
        } else {
            return Err(anyhow::anyhow!("Failed to read config length via h2"));
        }
    }
    let msg_len = u32::from_le_bytes(len_buf) as usize;
    
    let mut config_buf = Vec::new();
    while config_buf.len() < msg_len {
        if let Some(Ok(chunk)) = recv_stream.data().await {
            config_buf.extend_from_slice(&chunk);
            let _ = recv_stream.flow_control().release_capacity(chunk.len());
        } else {
            return Err(anyhow::anyhow!("Failed to read config payload via h2"));
        }
    }

    let server_config: ControlMessage = bincode::serde::decode_from_slice(&config_buf, bincode::config::standard()).map(|(v,_)| v)?;

    let (assigned_ip, netmask, gateway, dns, mtu, assigned_ipv6, netmask_v6, gateway_v6, dns_v6) =
        match server_config {
            ControlMessage::Config {
                assigned_ip, netmask, gateway, dns_server, mtu,
                assigned_ipv6, netmask_v6, gateway_v6, dns_server_v6, ..
            } => (assigned_ip, netmask, gateway, dns_server, mtu, assigned_ipv6, netmask_v6, gateway_v6, dns_server_v6),
            ControlMessage::Error { message } => return Err(anyhow::anyhow!("Server rejected connection: {}", message)),
            _ => return Err(anyhow::anyhow!("Unexpected server response during TCP handshake")),
        };

    info!("TCP Handshake successful. Internal IPv4: {}", assigned_ip);

    let endpoint_ip_str = match addr.ip() {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(|v4| v4.to_string()).unwrap_or_else(|| v6.to_string()),
    };

    set_adapter_network_config(
        adapter, assigned_ip, netmask, gateway, dns, mtu, &endpoint_ip_str,
        assigned_ipv6, netmask_v6, gateway_v6, dns_v6,
    )?;

    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).context("Failed to start WinTUN session")?);
    let session_alive = Arc::new(AtomicBool::new(true));

    let alive_pump = session_alive.clone();
    let run_pump = global_running.clone();
    let session_tun = session.clone();
    
    let tun_to_tcp = tokio::spawn(async move {
        while run_pump.load(Ordering::Relaxed) && alive_pump.load(Ordering::Relaxed) {
            match session_tun.try_receive() {
                 Ok(Some(packet)) => {
                      let data = packet.bytes();
                      let mut buf = Vec::with_capacity(2 + data.len());
                      buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
                      buf.extend_from_slice(data);
                      
                      send_stream.reserve_capacity(buf.len());
                      if send_stream.capacity() >= buf.len() {
                          if let Err(_) = send_stream.send_data(Bytes::from(buf), false) {
                              break;
                          }
                      }
                 }
                 Ok(None) => { tokio::time::sleep(Duration::from_micros(200)).await; }
                 Err(_) => { alive_pump.store(false, Ordering::SeqCst); break; }
            }
        }
    });

    let alive_tcp_in = session_alive.clone();
    let run_tcp_in = global_running.clone();
    let session_tcp_in = session.clone();
    let tcp_to_tun = tokio::spawn(async move {
        let mut leftover = bytes::BytesMut::new();
        while run_tcp_in.load(Ordering::Relaxed) && alive_tcp_in.load(Ordering::Relaxed) {
             match recv_stream.data().await {
                 Some(Ok(chunk)) => {
                     leftover.extend_from_slice(&chunk);
                     let _ = recv_stream.flow_control().release_capacity(chunk.len());
                     
                     while leftover.len() >= 2 {
                         let pkt_len = u16::from_be_bytes([leftover[0], leftover[1]]) as usize;
                         if leftover.len() >= 2 + pkt_len {
                             let packet = leftover.split_to(2 + pkt_len).split_off(2).freeze();
                             if packet.is_empty() { continue; }
                             
                             match session_tcp_in.allocate_send_packet(packet.len() as u16) {
                                  Ok(mut pt) => {
                                      pt.bytes_mut().copy_from_slice(&packet);
                                      session_tcp_in.send_packet(pt);
                                  }
                                  Err(e) if is_wintun_ring_full(&e) => {
                                      tokio::time::sleep(Duration::from_millis(2)).await;
                                  }
                                  Err(_) => { alive_tcp_in.store(false, Ordering::SeqCst); break; }
                             }
                         } else { break; }
                     }
                 }
                 Some(Err(_)) | None => { alive_tcp_in.store(false, Ordering::SeqCst); break; }
             }
        }
    });

    while global_running.load(Ordering::Relaxed) && session_alive.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    tun_to_tcp.abort();
    tcp_to_tun.abort();

    if global_running.load(Ordering::Relaxed) { Ok(SessionEnd::ConnectionLost) } else { Ok(SessionEnd::UserStopped) }
}
