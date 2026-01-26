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
use etherparse::Ipv4HeaderSlice;

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
    let cert_path = std::path::PathBuf::from("/app/data/cert.pem");
    let key_path = std::path::PathBuf::from("/app/data/key.pem");
    if let Some(parent) = cert_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let (certs, key) = cert::load_or_generate_certs(cert_path, key_path)?;

    // 4. Setup QUIC Server Config
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    
    server_crypto.alpn_protocols = vec![b"mavivpn".to_vec()];
    
    let mut server_config = ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    transport_config.datagram_receive_buffer_size(Some(1024 * 1024)); // 1MB buffer

    let endpoint = Endpoint::server(server_config, config.bind_addr)?;
    
    // 5. Setup TUN Interface
    let mut tun_config = tun::Configuration::default();
    
    // Server IP is usually the .1 address
    let gateway_ip = state.gateway_ip();
    let netmask = state.network.mask();

    tun_config.address(gateway_ip)
              .netmask(netmask)
              .mtu(1280)
              .up();

    #[cfg(target_os = "linux")]
    tun_config.platform(|config| {
        config.packet_information(false); 
    });

    if let Some(dev_path) = &config.tun_device_path {
        tun_config.name(dev_path);
    }

    let dev = tun::create_as_async(&tun_config).context("Failed to create TUN device. Ensure NET_ADMIN cap is set.")?;
    let (mut tun_reader, mut tun_writer) = tokio::io::split(dev);

    info!("TUN Device created. IP: {}", gateway_ip);

    // 6. Packet Routing Helper Channels
    // Client -> TUN (Multiple clients write to one TUN Writer)
    let (tx_tun, mut rx_tun) = tokio::sync::mpsc::channel::<Bytes>(10000);

    // Task: TUN Writer (Receives from Clients, Writes to Kernel)
    tokio::spawn(async move {
        while let Some(packet) = rx_tun.recv().await {
            if let Err(e) = tun_writer.write_all(&packet).await {
                error!("Failed to write to TUN: {}", e);
            } else {
                tracing::trace!("Wrote packet to TUN (len: {})", packet.len());
            }
        }
    });

    // Task: TUN Reader (Reads from Kernel, Routes to Specific Client)
    let state_reader = state.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            match tun_reader.read(&mut buf).await {
                Ok(n) => {
                    if n > 0 {
                        let packet = &buf[0..n];
                        // Safe parsing using etherparse
                        if let Ok(ipv4_header) = Ipv4HeaderSlice::from_slice(packet) {
                            let dest_ip = ipv4_header.destination_addr();
                            
                            // Route: Look up client in map
                            if let Some(tx_client) = state_reader.peers.get(&dest_ip) {
                                let _ = tx_client.send(Bytes::copy_from_slice(packet)).await;
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Error reading from TUN: {}", e);
                    break;
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
    // Wait for client to open a bi-directional stream for Auth
    let (mut send_stream, mut recv_stream) = connection.accept_bi().await?;
    
    // Read auth message length (u32 LE)
    let len = recv_stream.read_u32_le().await? as usize;
    if len > 1024 { return Err(anyhow::anyhow!("Auth message too big")); }
    let mut buf = vec![0u8; len];
    recv_stream.read_exact(&mut buf).await?;
    
    let msg: ControlMessage = bincode::deserialize(&buf)?;
    
    let assigned_ip = match msg {
        ControlMessage::Auth { token } => {
            if token != config.auth_token {
                // Send Error
                let err_msg = ControlMessage::Error { message: "Invalid Token".into() };
                let bytes = bincode::serialize(&err_msg)?;
                send_stream.write_u32_le(bytes.len() as u32).await?;
                send_stream.write_all(&bytes).await?;
                let _ = send_stream.finish();
                return Err(anyhow::anyhow!("Invalid Token from {}", remote_addr));
            }
            // Assign IP
            state.assign_ip()?
        }
        _ => return Err(anyhow::anyhow!("Unexpected message type during handshake")),
    };

    // Send Success Config
    let success_msg = ControlMessage::Config {
        assigned_ip,
        netmask: state.network.mask(),
        gateway: state.gateway_ip(),
        dns_server: config.dns,
        mtu: 1280,
    };
    let bytes = bincode::serialize(&success_msg)?;
    send_stream.write_u32_le(bytes.len() as u32).await?;
    send_stream.write_all(&bytes).await?;
    let _ = send_stream.finish();

    info!("Authenticated {} -> Assigned IP: {}", remote_addr, assigned_ip);

    // --- Session Phase ---
    let (tx_client, mut rx_client) = tokio::sync::mpsc::channel::<Bytes>(1000);
    state.register_client(assigned_ip, tx_client);

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
    let res = loop {
        match connection_arc.read_datagram().await {
            Ok(data) => {
                // Security Check: Ensure packet source IP matches assigned IP
                if let Ok(ipv4_header) = Ipv4HeaderSlice::from_slice(&data) {
                    if ipv4_header.source_addr() == assigned_ip {
                         // tracing::info!("Received valid packet from {} len {}", assigned_ip, data.len());
                         let _ = tx_tun.send(data).await;
                    } else {
                        tracing::warn!("Spoofed packet? Src: {}, Expected: {}", ipv4_header.source_addr(), assigned_ip);
                    }
                } else {
                    tracing::warn!("Failed to parse IPv4 packet from {}", assigned_ip);
                }
            }
            Err(e) => {
                break Err(anyhow::anyhow!("Connection lost: {}", e));
            }
        }
    };

    // Cleanup
    tun_to_quic.abort();
    state.release_ip(assigned_ip);
    info!("Released IP {} for {}", assigned_ip, remote_addr);

    res
}
