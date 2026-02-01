use anyhow::{Context, Result};
use bytes::Bytes;
use ring::digest;
use serde::{Deserialize, Serialize};
use shared::ControlMessage;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn};
use wintun::Adapter;

const CONFIG_FILE: &str = "config.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    endpoint: String,
    token: String,
    cert_pin: String,
    censorship_resistant: bool,
}

static RUNNING: AtomicBool = AtomicBool::new(true);

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .init();

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

async fn run_vpn(config: Config) -> Result<()> {
    let cert_pin_bytes = decode_hex(&config.cert_pin).context("Invalid certificate PIN hex")?;

    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    configure_socket(&socket)?;
    socket.set_nonblocking(true)?;

    let (connection, server_config) = connect_and_handshake(
        socket,
        config.token,
        config.endpoint,
        cert_pin_bytes,
        config.censorship_resistant,
    )
    .await?;

    let (assigned_ip, dns, mtu) = match server_config {
        ControlMessage::Config {
            assigned_ip,
            dns_server,
            mtu,
            ..
        } => (assigned_ip, dns_server, mtu),
        ControlMessage::Error { message } => {
            return Err(anyhow::anyhow!("Server error: {}", message));
        }
        _ => return Err(anyhow::anyhow!("Unexpected response")),
    };

    info!("Connected! Assigned IP: {}", assigned_ip);
    info!("DNS: {}, MTU: {}", dns, mtu);

    let wintun = unsafe { wintun::load_from_path("wintun.dll") }
        .context("Failed to load wintun.dll. Make sure it's in the current directory.")?;

    let adapter = Adapter::create(&wintun, "MaviVPN", "Mavi VPN Tunnel", None)
        .context("Failed to create WinTUN adapter. Run as Administrator.")?;

    set_adapter_ip(&adapter, assigned_ip, dns)?;

    let session = Arc::new(
        adapter
            .start_session(0x20000)
            .context("Failed to start WinTUN session")?,
    );

    info!("VPN tunnel established. Press Ctrl+C to disconnect.");

    let connection = Arc::new(connection);

    let session_rx = session.clone();
    let conn_tx = connection.clone();
    let tun_to_quic = std::thread::spawn(move || {
        while RUNNING.load(Ordering::Relaxed) {
            match session_rx.receive_blocking() {
                Ok(packet) => {
                    let data = Bytes::copy_from_slice(packet.bytes());
                    if let Err(e) = conn_tx.send_datagram(data) {
                        match e {
                            quinn::SendDatagramError::ConnectionLost(_) => {
                                error!("Connection lost");
                                RUNNING.store(false, Ordering::SeqCst);
                                break;
                            }
                            quinn::SendDatagramError::TooLarge => {
                                warn!("Packet too large, dropping");
                            }
                            _ => {
                                error!("Send error: {:?}", e);
                                RUNNING.store(false, Ordering::SeqCst);
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    if RUNNING.load(Ordering::Relaxed) {
                        error!("TUN read error: {:?}", e);
                    }
                    break;
                }
            }
        }
    });

    let session_tx = session.clone();
    let quic_to_tun = tokio::spawn(async move {
        while RUNNING.load(Ordering::Relaxed) {
            match connection.read_datagram().await {
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
                        }
                    }
                }
                Err(e) => {
                    if RUNNING.load(Ordering::Relaxed) {
                        error!("QUIC read error: {:?}", e);
                        RUNNING.store(false, Ordering::SeqCst);
                    }
                    break;
                }
            }
        }
    });

    while RUNNING.load(Ordering::Relaxed) {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    info!("Shutting down...");
    drop(session);
    let _ = tun_to_quic.join();
    quic_to_tun.abort();

    info!("Disconnected.");
    Ok(())
}

fn configure_socket(socket: &std::net::UdpSocket) -> Result<()> {
    let socket2_sock = socket2::SockRef::from(socket);

    let _ = socket2_sock.set_recv_buffer_size(1024 * 1024);
    let _ = socket2_sock.set_send_buffer_size(1024 * 1024);

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
        .max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    transport_config.mtu_discovery_config(None);
    transport_config.initial_mtu(1500);
    transport_config.min_mtu(1500);
    transport_config.enable_segmentation_offload(true);

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

    let addr = tokio::net::lookup_host(&endpoint_str)
        .await?
        .next()
        .context("Failed to resolve endpoint")?;

    info!("Resolved to {}", addr);
    let connection = endpoint.connect(addr, "localhost")?.await?;
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

fn set_adapter_ip(adapter: &Adapter, ip: Ipv4Addr, dns: Ipv4Addr) -> Result<()> {
    let luid = adapter.get_luid();

    unsafe {
        use windows_sys::Win32::NetworkManagement::IpHelper::*;
        use windows_sys::Win32::Networking::WinSock::*;

        let mut row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
        InitializeUnicastIpAddressEntry(&mut row);

        row.InterfaceLuid = std::mem::transmute(luid);
        row.Address.si_family = AF_INET as u16;
        row.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
        row.OnLinkPrefixLength = 24;
        row.DadState = IpDadStatePreferred;

        let result = CreateUnicastIpAddressEntry(&row);
        if result != 0 && result != 5010 {
            return Err(anyhow::anyhow!(
                "Failed to set IP address: error code {}",
                result
            ));
        }
    }

    info!("Set adapter IP to {}/24", ip);

    let index = adapter.get_adapter_index()?;
    let _ = std::process::Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            &format!("name={}", index),
            "static",
            &dns.to_string(),
            "primary",
        ])
        .output();

    let _ = std::process::Command::new("route")
        .args([
            "add",
            "0.0.0.0",
            "mask",
            "0.0.0.0",
            &ip.to_string(),
            "metric",
            "5",
        ])
        .output();

    Ok(())
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
