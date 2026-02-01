use anyhow::{Context, Result};
use bytes::Bytes;
use ring::digest;
use serde::{Deserialize, Serialize};
use shared::ControlMessage;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::io::AsRawSocket;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn};
use wintun::Adapter;

const CONFIG_FILE: &str = "config.json";

static WINTUN_DLL: &[u8] = include_bytes!("../wintun.dll");
const KEEPALIVE_SECS: u64 = 10;
const IDLE_TIMEOUT_SECS: u64 = 60;
const RECONNECT_INITIAL_SECS: u64 = 1;
const RECONNECT_MAX_SECS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    endpoint: String,
    token: String,
    cert_pin: String,
    censorship_resistant: bool,
}

static RUNNING: AtomicBool = AtomicBool::new(true);

fn main() -> Result<()> {
    let env_filter = if std::env::var_os("RUST_LOG").is_some() {
        tracing_subscriber::EnvFilter::from_default_env()
    } else {
        tracing_subscriber::EnvFilter::new("mavi_vpn=info,quinn=warn,quinn_proto=warn")
    };
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    println!();
    println!("╔══════════════════════════════════════╗");
    println!("║         Mavi VPN - Windows           ║");
    println!("╚══════════════════════════════════════╝");
    println!();

    let config = load_or_prompt_config()?;

    info!("Endpoint: {}", config.endpoint);
    info!(
        "Mode: {}",
        if config.censorship_resistant {
            "Censorship Resistant (h3)"
        } else {
            "Standard (mavivpn)"
        }
    );

    ctrlc::set_handler(|| {
        info!("Shutdown signal received");
        RUNNING.store(false, Ordering::SeqCst);
    })?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(run_vpn(config))
}

fn config_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
        .join(CONFIG_FILE)
}

fn load_config() -> Option<Config> {
    let path = config_path();
    if path.exists() {
        let content = std::fs::read_to_string(&path).ok()?;
        serde_json::from_str(&content).ok()
    } else {
        None
    }
}

fn save_config(config: &Config) -> Result<()> {
    let path = config_path();
    let content = serde_json::to_string_pretty(config)?;
    std::fs::write(&path, content)?;
    info!("Config saved to {}", path.display());
    Ok(())
}

fn load_or_prompt_config() -> Result<Config> {
    if let Some(saved) = load_config() {
        println!("Gespeicherte Konfiguration gefunden:");
        println!("  Endpoint: {}", saved.endpoint);
        println!("  Token: {}...", &saved.token.chars().take(8).collect::<String>());
        println!("  CR Mode: {}", if saved.censorship_resistant { "Ja" } else { "Nein" });
        println!();
        
        print!("Diese Konfiguration verwenden? [J/n]: ");
        io::stdout().flush()?;
        let input = read_line()?.to_lowercase();
        
        if input.is_empty() || input == "j" || input == "ja" || input == "y" || input == "yes" {
            println!();
            return Ok(saved);
        }
        println!();
    }
    
    let config = prompt_new_config()?;
    save_config(&config)?;
    Ok(config)
}

fn prompt_new_config() -> Result<Config> {
    let mut stdout = io::stdout();

    print!("Server Endpoint (z.B. vpn.example.com:443): ");
    stdout.flush()?;
    let endpoint = read_line()?;

    print!("Auth Token: ");
    stdout.flush()?;
    let token = read_line()?;

    print!("Certificate PIN (SHA256 hex): ");
    stdout.flush()?;
    let cert_pin = read_line()?;

    print!("Censorship Resistant Mode? [j/N]: ");
    stdout.flush()?;
    let cr_input = read_line()?.to_lowercase();
    let censorship_resistant = cr_input == "j" || cr_input == "ja" || cr_input == "y" || cr_input == "yes";

    println!();

    Ok(Config {
        endpoint,
        token,
        cert_pin,
        censorship_resistant,
    })
}

fn read_line() -> Result<String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

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

async fn run_vpn(config: Config) -> Result<()> {
    let cert_pin_bytes = decode_hex(&config.cert_pin).context("Invalid certificate PIN hex")?;

    let dll_path = extract_wintun_dll()?;
    let wintun = unsafe { wintun::load_from_path(&dll_path) }
        .context("Failed to load wintun.dll")?;
    let adapter = get_or_create_adapter(&wintun)?;

    let mut backoff = Duration::from_secs(RECONNECT_INITIAL_SECS);

    while RUNNING.load(Ordering::Relaxed) {
        let outcome = run_session(&config, &cert_pin_bytes, &adapter).await;
        if !RUNNING.load(Ordering::Relaxed) {
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
    let socket2_sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    socket2_sock.bind(&socket2::SockAddr::from(
        std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
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

    set_adapter_ip(
        adapter,
        assigned_ip,
        netmask,
        gateway,
        dns,
        mtu,
        &config.endpoint,
        assigned_ipv6,
        netmask_v6,
        gateway_v6,
        dns_v6,
    )?;

    let session = Arc::new(
        adapter
            .start_session(0x20000)
            .context("Failed to start WinTUN session")?,
    );

    info!("VPN tunnel established. Press Ctrl+C to disconnect.");

    let connection = Arc::new(connection);
    let session_alive = Arc::new(AtomicBool::new(true));

    let session_rx = session.clone();
    let conn_tx = connection.clone();
    let alive_tx = session_alive.clone();
    let tun_to_quic = std::thread::spawn(move || {
        loop {
            if !RUNNING.load(Ordering::Relaxed) || !alive_tx.load(Ordering::Relaxed) {
                break;
            }
            match session_rx.try_receive() {
                Ok(Some(packet)) => {
                    let data = Bytes::copy_from_slice(packet.bytes());
                    if let Err(e) = conn_tx.send_datagram(data) {
                        match e {
                            quinn::SendDatagramError::ConnectionLost(_) => {
                                error!("Connection lost");
                                alive_tx.store(false, Ordering::SeqCst);
                                break;
                            }
                            quinn::SendDatagramError::TooLarge => {
                                warn!("Packet too large, dropping");
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
                    if RUNNING.load(Ordering::Relaxed) {
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
    let quic_to_tun = tokio::spawn(async move {
        loop {
            if !RUNNING.load(Ordering::Relaxed) || !alive_rx.load(Ordering::Relaxed) {
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
                                    warn!("Failed to allocate packet: {:?}", e);
                                    alive_rx.store(false, Ordering::SeqCst);
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            if RUNNING.load(Ordering::Relaxed) {
                                error!("QUIC read error: {:?}", e);
                            }
                            alive_rx.store(false, Ordering::SeqCst);
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    if !RUNNING.load(Ordering::Relaxed) {
                        break;
                    }
                }
            }
        }
    });

    while RUNNING.load(Ordering::Relaxed) && session_alive.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    quic_to_tun.abort();
    drop(session);
    let _ = tun_to_quic.join();

    if RUNNING.load(Ordering::Relaxed) {
        Ok(SessionEnd::ConnectionLost)
    } else {
        Ok(SessionEnd::UserStopped)
    }
}

fn configure_socket(socket: &std::net::UdpSocket) -> Result<()> {
    let socket2_sock = socket2::SockRef::from(socket);

    let _ = socket2_sock.set_recv_buffer_size(1024 * 1024);
    let _ = socket2_sock.set_send_buffer_size(1024 * 1024);

    // Allow IP fragmentation by disabling "Don't Fragment" (MTU discovery)
    let value: u32 = 0;
    unsafe {
        let rc = windows_sys::Win32::Networking::WinSock::setsockopt(
            socket.as_raw_socket() as usize,
            windows_sys::Win32::Networking::WinSock::IPPROTO_IP,
            windows_sys::Win32::Networking::WinSock::IP_DONTFRAGMENT,
            &value as *const _ as _,
            std::mem::size_of_val(&value) as i32,
        );
        if rc != 0 {
            return Err(anyhow::anyhow!(
                "Failed to disable IP_DONTFRAGMENT (IPv4): {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    if matches!(socket.local_addr(), Ok(addr) if addr.is_ipv6()) {
        unsafe {
            let rc = windows_sys::Win32::Networking::WinSock::setsockopt(
                socket.as_raw_socket() as usize,
                windows_sys::Win32::Networking::WinSock::IPPROTO_IPV6,
                windows_sys::Win32::Networking::WinSock::IPV6_DONTFRAG,
                &value as *const _ as _,
                std::mem::size_of_val(&value) as i32,
            );
            if rc != 0 {
                return Err(anyhow::anyhow!(
                    "Failed to disable IPV6_DONTFRAG (IPv6): {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
    }

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

    let socket_cfg = socket
        .try_clone()
        .context("Failed to clone UDP socket for configuration")?;

    // Apply socket options before Quinn takes ownership.
    configure_socket(&socket)?;

    let verifier = Arc::new(PinnedServerVerifier::new(cert_pin));

    let mut client_crypto = rustls::ClientConfig::builder()
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
    transport_config.mtu_discovery_config(None);
    transport_config.initial_mtu(1500);
    transport_config.min_mtu(1500);
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

    // Quinn's Windows UDP backend enables DF by default; disable it again to allow fragmentation.
    configure_socket(&socket_cfg)
        .context("Failed to disable DF after QUIC endpoint init")?;

    let addr = tokio::net::lookup_host(&endpoint_str)
        .await?
        .find(|addr| addr.is_ipv4())
        .context("Failed to resolve endpoint (no IPv4 address found)")?;

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
    let bytes = bincode::serialize(&auth_msg)?;
    send_stream.write_u32_le(bytes.len() as u32).await?;
    send_stream.write_all(&bytes).await?;

    let len = recv_stream.read_u32_le().await? as usize;
    let mut buf = vec![0u8; len];
    recv_stream.read_exact(&mut buf).await?;
    let config: ControlMessage = bincode::deserialize(&buf)?;

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

    let mut dns_servers = vec![IpAddr::V4(dns)];
    if let Some(dns_v6) = dns_v6 {
        dns_servers.push(IpAddr::V6(dns_v6));
    }

    if let Err(e) = adapter.set_dns_servers(&dns_servers) {
        warn!("Failed to set DNS via adapter API: {}", e);
        let out = std::process::Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                &format!("name=\"{}\"", adapter_name),
                "static",
                &dns.to_string(),
                "primary",
            ])
            .output();
        if let Ok(out) = out {
            if !out.status.success() {
                warn!("netsh set dnsservers failed: {}", String::from_utf8_lossy(&out.stderr));
            }
        }

        if let Some(dns_v6) = dns_servers.iter().find_map(|addr| match addr {
            IpAddr::V6(v6) => Some(*v6),
            _ => None,
        }) {
            let out = std::process::Command::new("netsh")
                .args([
                    "interface",
                    "ipv6",
                    "add",
                    "dnsservers",
                    &format!("name=\"{}\"", adapter_name),
                    &format!("address={}", dns_v6),
                    "index=1",
                ])
                .output();
            if let Ok(out) = out {
                if !out.status.success() {
                    warn!(
                        "netsh add ipv6 dns failed: {}",
                        String::from_utf8_lossy(&out.stderr)
                    );
                }
            }
        }
    }

    if let Err(e) = adapter.set_mtu(mtu as usize) {
        warn!("Failed to set MTU via adapter API: {}", e);
        let out = std::process::Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "subinterface",
                &format!("\"{}\"", adapter_name),
                &format!("mtu={}", mtu),
                "store=active",
            ])
            .output();
        if let Ok(out) = out {
            if !out.status.success() {
                warn!("netsh set mtu failed: {}", String::from_utf8_lossy(&out.stderr));
            }
        }
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
            &format!("\"{}\"", adapter_name),
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
    let server_ip = endpoint.split(':').next().context("Invalid endpoint format")?;
    
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
