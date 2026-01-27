use anyhow::{Context, Result};
use bytes::Bytes;
use quinn::{Endpoint, ServerConfig};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn};

mod cert;
mod config;
// mod protocol;
mod state;

use crate::config::Config;
use shared::ControlMessage;
use crate::state::AppState;
use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice};
use tun::Device;
use constant_time_eq::constant_time_eq;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    
    // 1. Load Configuration
    let config = config::load();
    info!("Starting Mavi VPN Server...");
    info!("Network: {}", config.network_cidr);
    info!("Bind Address: {}", config.bind_addr);

    // 2. Initialize State
    let state = Arc::new(AppState::new(&config.network_cidr)?);

    // 3. Setup Certificates
    let cert_path = config.cert_path.clone();
    let key_path = config.key_path.clone();
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create certificate directory")?;
    }
    let (certs, key) = cert::load_or_generate_certs(cert_path, key_path)?;

    // 4. Setup QUIC Server Config
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    
    server_crypto.alpn_protocols = vec![b"mavivpn".to_vec()];
    
    let mut server_config = ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| anyhow::anyhow!("Failed to access transport config"))?;
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(2)));
    
    // Performance Optimizations for high throughput
    // FIX: Reduced buffers from 8MB to 1MB to prevent bufferbloat/latency spikes
    transport_config.datagram_receive_buffer_size(Some(1024 * 1024)); // 1MB receive buffer
    transport_config.datagram_send_buffer_size(1024 * 1024); // 1MB send buffer
    
    // Increase receive window for better throughput
    transport_config.receive_window(quinn::VarInt::from(4u32 * 1024 * 1024)); // 4MB
    transport_config.stream_receive_window(quinn::VarInt::from(1024u32 * 1024)); // 1MB per stream
    transport_config.send_window(4 * 1024 * 1024); // 4MB send window
    
    // Enable BBR Congestion Control
    transport_config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    // Enable MTU discovery
    transport_config.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));
    // Enable Segmentation Offload (GSO)
    transport_config.enable_segmentation_offload(true);
    
    // Manually bind socket to set SO_RCVBUF and SO_SNDBUF
    let socket = std::net::UdpSocket::bind(config.bind_addr)?;
    let socket2_sock = socket2::Socket::from(socket);
    let _ = socket2_sock.set_recv_buffer_size(2 * 1024 * 1024); // 2MB
    let _ = socket2_sock.set_send_buffer_size(2 * 1024 * 1024); // 2MB
    let socket = std::net::UdpSocket::from(socket2_sock);

    let endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    
    // 5. Setup TUN Interface
    let mut tun_config = tun::Configuration::default();
    
    // Server IP is usually the .1 address
    let gateway_ip = state.gateway_ip();
    let netmask = state.network.mask();

    tun_config.address(gateway_ip)
              .netmask(netmask)
              .mtu(config.mtu as i32)
              .up();

    #[cfg(target_os = "linux")]
    tun_config.platform(|config| {
        config.packet_information(false); 
    });

    if let Some(dev_path) = &config.tun_device_path {
        tun_config.name(dev_path);
    }

    let dev = tun::create_as_async(&tun_config).context("Failed to create TUN device. Ensure NET_ADMIN cap is set.")?;
    let tun_name = dev.get_ref().name().unwrap_or_else(|_| "tun0".into());
    let (mut tun_reader, mut tun_writer) = tokio::io::split(dev);

    info!("TUN Device created: {}. IP: {}", tun_name, gateway_ip);

    // Configure IPv6 on TUN
    let gateway_ip6 = state.gateway_ip_v6();
    let output = std::process::Command::new("ip")
        .args(&["-6", "addr", "add", &format!("{}/64", gateway_ip6), "dev", &tun_name])
        .output();
    match output {
        Ok(out) if out.status.success() => info!("IPv6 address {} added to {}", gateway_ip6, tun_name),
        Ok(out) => error!("Failed to add IPv6: {:?}", String::from_utf8_lossy(&out.stderr)),
        Err(e) => error!("Failed to execute ip command: {}", e),
    }

    // 5b. MSS Clamping to prevent TCP fragmentation
    // For MTU 1280:
    // IPv4: 1280 - 20 (IP) - 20 (TCP) = 1240
    // IPv6: 1280 - 40 (IP) - 20 (TCP) = 1220
    let mss_v4 = config.mtu - 40;
    let mss_v6 = config.mtu - 60;

    info!("Applying MSS clamping: IPv4={} IPv6={} on {}", mss_v4, mss_v6, tun_name);

    // IPv4 Clamping
    let mss_v4_str = mss_v4.to_string();
    let rules_v4 = [
        vec!["-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", &mss_v4_str],
        vec!["-t", "mangle", "-A", "POSTROUTING", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-o", &tun_name, "-j", "TCPMSS", "--set-mss", &mss_v4_str]
    ];

    for args in rules_v4 {
        match std::process::Command::new("iptables").args(&args).output() {
            Ok(o) if !o.status.success() => warn!("iptables failed: {}", String::from_utf8_lossy(&o.stderr)),
            Err(e) => warn!("Failed to execute iptables: {}", e),
            _ => {}
        }
    }

    // IPv6 Clamping
    let mss_v6_str = mss_v6.to_string();
    let rules_v6 = [
        vec!["-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", &mss_v6_str],
        vec!["-t", "mangle", "-A", "POSTROUTING", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-o", &tun_name, "-j", "TCPMSS", "--set-mss", &mss_v6_str]
    ];

    for args in rules_v6 {
        match std::process::Command::new("ip6tables").args(&args).output() {
            Ok(o) if !o.status.success() => warn!("ip6tables failed: {}", String::from_utf8_lossy(&o.stderr)),
            Err(e) => warn!("Failed to execute ip6tables: {}", e),
            _ => {}
        }
    }

    // 6. Packet Routing Helper Channels
    // Client -> TUN (Multiple clients write to one TUN Writer)
    // Reduce buffer to prevent bufferbloat. 2048 * 1280 bytes = ~2.5MB max queue.
    let (tx_tun, mut rx_tun) = tokio::sync::mpsc::channel::<Bytes>(2048);

    // Task: TUN Writer (Receives from Clients, Writes to Kernel)
    // Batched writes for reduced syscall overhead
    tokio::spawn(async move {
        let mut batch: Vec<Bytes> = Vec::with_capacity(64);
        loop {
            // Wait for at least one packet
            match rx_tun.recv().await {
                Some(packet) => batch.push(packet),
                None => break, // Channel closed
            }
            
            // Drain any additional queued packets (non-blocking)
            while batch.len() < 64 {
                match rx_tun.try_recv() {
                    Ok(packet) => batch.push(packet),
                    Err(_) => break,
                }
            }
            
            // Write batch to TUN
            for packet in batch.drain(..) {
                if let Err(e) = tun_writer.write_all(&packet).await {
                    error!("CRITICAL: Failed to write to TUN: {}. Exiting.", e);
                    std::process::exit(1); 
                }
            }
        }
    });

    // Task: TUN Reader (Reads from Kernel, Routes to Specific Client)
    // Zero-Copy Implementation: Use BytesMut + split_to().freeze() to avoid memcpy
    let state_reader = state.clone();
    tokio::spawn(async move {
        // 2KB cache-aligned buffer for optimal performance
        let mut buf = bytes::BytesMut::with_capacity(2048);
        loop {
            // Ensure buffer has capacity for next read
            if buf.capacity() < 2048 {
                buf.reserve(2048);
            }
            
            // Read into BytesMut's spare capacity
            match tun_reader.read_buf(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    // Zero-copy extract: split off the packet without copying
                    let packet = buf.split_to(n).freeze();
                    
                    if packet.len() == 0 { continue; }
                    
                    // Check IP version
                    let version = packet[0] >> 4;
                    if version == 4 {
                         if let Ok(ipv4_header) = Ipv4HeaderSlice::from_slice(&packet) {
                            let dest_ip = ipv4_header.destination_addr();
                            // Avoid deadlock: clone the sender and drop the lock before awaiting
                            let tx_opt = state_reader.peers.get(&dest_ip).map(|r| r.clone());
                            if let Some(tx_client) = tx_opt {
                                // Zero-copy send: Bytes is reference-counted, clone is cheap
                                if let Err(e) = tx_client.try_send(packet) {
                                    tracing::warn!("Dropping packet for {} (Channel full or closed): {}", dest_ip, e);
                                }
                            }
                        }
                    } else if version == 6 {
                         if let Ok(ipv6_header) = Ipv6HeaderSlice::from_slice(&packet) {
                            let dest_ip = ipv6_header.destination_addr();
                            // Avoid deadlock: clone the sender and drop the lock before awaiting
                            let tx_opt = state_reader.peers_v6.get(&dest_ip).map(|r| r.clone());
                            if let Some(tx_client) = tx_opt {
                                // Zero-copy send: Bytes is reference-counted, clone is cheap
                                if let Err(e) = tx_client.try_send(packet) {
                                    tracing::warn!("Dropping packet for {} (Channel full or closed): {}", dest_ip, e);
                                }
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

    // 7. Accept Connections
    while let Some(conn) = endpoint.accept().await {
        let state = state.clone();
        let config = config.clone();
        let tx_tun = tx_tun.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(conn,state, config, tx_tun).await {
               // fine to fail, client disconnected or bad auth
               warn!("Connection terminated: {}", e);
            }
        });
    }

    Ok(())
}

async fn handle_connection(
    conn: quinn::Incoming,
    state: Arc<AppState>,
    config: Config,
    tx_tun: tokio::sync::mpsc::Sender<Bytes>
) -> Result<()> {
    let connection = conn.await?;
    let remote_addr = connection.remote_address();
    info!("New connection from {}", remote_addr);

    // --- Handshake Phase ---
    let (mut send_stream, mut recv_stream) = connection.accept_bi().await?;
    
    // Read auth message length (u32 LE)
    let len = recv_stream.read_u32_le().await? as usize;
    if len > 1024 { return Err(anyhow::anyhow!("Auth message too big")); }
    let mut buf = vec![0u8; len];
    recv_stream.read_exact(&mut buf).await?;
    
    let msg: ControlMessage = bincode::deserialize(&buf)?;
    
    let (assigned_ip, assigned_ip6) = match msg {
        ControlMessage::Auth { token } => {
            if !constant_time_eq(token.as_bytes(), config.auth_token.as_bytes()) {
                // Send Error
                let err_msg = ControlMessage::Error { message: "Invalid Token".into() };
                let bytes = bincode::serialize(&err_msg)?;
                send_stream.write_u32_le(bytes.len() as u32).await?;
                send_stream.write_all(&bytes).await?;
                let _ = send_stream.finish();
                return Err(anyhow::anyhow!("Invalid Token from {}", remote_addr));
            }
            // Assign IP
            let v4 = state.assign_ip()?;
            let v6 = state.assign_ipv6()?;
            (v4, v6)
        }
        _ => return Err(anyhow::anyhow!("Unexpected message type during handshake")),
    };

    // Send Success Config
    let success_msg = ControlMessage::Config {
        assigned_ip,
        netmask: state.network.mask(),
        gateway: state.gateway_ip(),
        dns_server: config.dns,
        mtu: config.mtu as u16,
        // Disable IPv6 for client until server has IPv6 uplink
        assigned_ipv6: Some(assigned_ip6),
        netmask_v6: Some(64), // Standard /64
        gateway_v6: Some(state.gateway_ip_v6()),
        // Cloudflare DNS64 or similar could be better, trying Google for now
        dns_server_v6: Some("2001:4860:4860::8888".parse().unwrap()),
    };
    let bytes = bincode::serialize(&success_msg)?;
    send_stream.write_u32_le(bytes.len() as u32).await?;
    send_stream.write_all(&bytes).await?;
    let _ = send_stream.finish();

    info!("Authenticated {} -> IPv4: {}, IPv6: {}", remote_addr, assigned_ip, assigned_ip6);

    // --- Session Phase ---
    let (tx_client, mut rx_client) = tokio::sync::mpsc::channel::<Bytes>(1024);
    state.register_client(assigned_ip, assigned_ip6, tx_client);

    let connection_arc = Arc::new(connection);
    
    // Task: Recv from TUN -> Send to QUIC Datagram
    let conn_send = connection_arc.clone();
    let tun_to_quic = tokio::spawn(async move {
        while let Some(packet) = rx_client.recv().await {
            let _ = conn_send.send_datagram(packet);
        }
    });

    // Loop: Recv from QUIC Datagram -> Send to TUN
    // We check Source IP to prevent spoofing
    use futures_util::FutureExt; // Ensure this is available or imported at top
    
    let res = 'outer_loop: loop {
        // 1. Read first packet (await)
        let first_packet = match connection_arc.read_datagram().await {
            Ok(p) => p,
            Err(e) => break Err(anyhow::anyhow!("Connection lost: {}", e)),
        };

        // 2. Try to read more (batching)
        let mut batch = Vec::with_capacity(64);
        batch.push(first_packet);

        for _ in 0..63 {
            match connection_arc.read_datagram().now_or_never() {
                Some(Ok(p)) => batch.push(p),
                _ => break,
            }
        }

        // 3. Process Batch
        for data in batch {
             if data.is_empty() {
                 tracing::debug!("Received empty packet (Keepalive/Migration)");
                 continue;
             }

             let version = data[0] >> 4;
             let mut valid = false;
             
             if version == 4 {
                 if let Ok(ipv4_header) = Ipv4HeaderSlice::from_slice(&data) {
                     if ipv4_header.source_addr() == assigned_ip {
                         valid = true;
                     } else {
                         static MSG_LIMIT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                         let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                         let last = MSG_LIMIT.load(std::sync::atomic::Ordering::Relaxed);
                         if now > last + 5 { // Log at most once every 5 seconds
                              tracing::warn!("Spoofed IPv4? Src: {}, Expected: {}", ipv4_header.source_addr(), assigned_ip);
                              MSG_LIMIT.store(now, std::sync::atomic::Ordering::Relaxed);
                         }
                     }
                 }
             } else if version == 6 {
                  if let Ok(ipv6_header) = Ipv6HeaderSlice::from_slice(&data) {
                     let src = ipv6_header.source_addr();
                     // Allow assigned IP OR Link-Local (fe80::/10) OR Unspecified (:: for DAD)
                     let is_link_local = src.segments()[0] & 0xffc0 == 0xfe80;
                     let is_unspecified = src.is_unspecified();
                     
                     if src == assigned_ip6 || is_link_local || is_unspecified {
                         valid = true;
                     } else {
                         tracing::warn!("Spoofed IPv6? Src: {}, Expected: {}", src, assigned_ip6);
                     }
                 }
             } else {
                  tracing::warn!("Unknown packet version: {}", version);
             }

             if valid {
                  if let Err(e) = tx_tun.send(data).await {
                      tracing::error!("Failed to send to TUN writer (Channel closed): {}", e);
                      break 'outer_loop Err(anyhow::anyhow!("TUN writer channel closed"));
                  }
             }
        }
    };

    // Cleanup
    tun_to_quic.abort();
    state.release_ips(assigned_ip, assigned_ip6);
    info!("Released IPs for {}", remote_addr);

    res
}
