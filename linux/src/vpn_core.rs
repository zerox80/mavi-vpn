//! # Mavi VPN Linux Core
//!
//! Implements the core VPN logic for Linux, including:
//! - TUN device management via /dev/net/tun.
//! - WebTransport (HTTP/3 over QUIC) transport via wtransport — matching the Windows client.
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
use tracing::{error, info, warn};
use wtransport::{ClientConfig, Endpoint};
use wtransport::tls::Certificate;

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
    let cert_pin_bytes = if config.cert_pin.is_empty() {
        Vec::new()
    } else {
        decode_hex(&config.cert_pin).context("Invalid certificate PIN hex format")?
    };

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

/// Manages a single active VPN session (handshake + packet pumping).
async fn run_session(
    config: &Config,
    cert_pin_bytes: &[u8],
    global_running: &Arc<AtomicBool>,
) -> Result<SessionEnd> {
    // 1. WebTransport Handshake & Auth
    let (connection, server_config) = connect_and_handshake(
        config.token.clone(),
        config.endpoint.clone(),
        cert_pin_bytes.to_vec(),
        config.censorship_resistant,
    )
    .await?;

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
                return Err(anyhow::anyhow!("Server rejected connection: {}", message))
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

    // Task: TUN -> QUIC (Read from TUN, send via WebTransport datagram)
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
                        use wtransport::error::SendDatagramError;
                        match e {
                            SendDatagramError::TooLarge => {
                                let current_mtu =
                                    conn_sender.max_datagram_size().unwrap_or(1200) as u16;
                                if let Some(icmp_packet) = icmp::generate_packet_too_big(
                                    &buf[..n],
                                    current_mtu,
                                    Some(std::net::IpAddr::V4(gateway)),
                                ) {
                                    let _ = tun_reader.write(&icmp_packet).await;
                                }
                            }
                            SendDatagramError::NotConnected => {
                                alive_tun.store(false, Ordering::SeqCst);
                                break;
                            }
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

    // Task: QUIC -> TUN (Read WebTransport datagrams, write to TUN)
    let tun_writer = async_tun.clone();
    let alive_quic = session_alive.clone();
    let run_quic = global_running.clone();
    let quic_to_tun = tokio::spawn(async move {
        loop {
            if !run_quic.load(Ordering::Relaxed) || !alive_quic.load(Ordering::Relaxed) {
                break;
            }
            match connection.receive_datagram().await {
                Ok(datagram) => {
                    let payload = datagram.payload();
                    if payload.is_empty() {
                        continue;
                    }
                    if let Err(e) = tun_writer.write(&payload).await {
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

/// WebTransport connection setup — identical strategy to the Windows client.
async fn connect_and_handshake(
    token: String,
    endpoint_str: String,
    cert_pin: Vec<u8>,
    _censorship_resistant: bool,
) -> Result<(wtransport::Connection, ControlMessage)> {
    // Transport tuning (matches Windows client + server config)
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(
        Duration::from_secs(IDLE_TIMEOUT_SECS).try_into().unwrap(),
    ));
    transport_config.keep_alive_interval(Some(Duration::from_secs(KEEPALIVE_SECS)));
    transport_config.mtu_discovery_config(None);
    transport_config.initial_mtu(1400);
    transport_config.min_mtu(1400);
    transport_config.enable_segmentation_offload(true);
    transport_config.congestion_controller_factory(Arc::new(
        quinn::congestion::BbrConfig::default(),
    ));
    transport_config.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    transport_config.datagram_send_buffer_size(2 * 1024 * 1024);

    // Build wtransport ClientConfig
    let mut client_config = if cert_pin.is_empty() {
        // Trust native system certificates (Let's Encrypt etc.)
        ClientConfig::builder()
            .with_bind_default()
            .with_native_certs()
            .build()
    } else {
        // Custom pinned certificate verifier
        let verifier = Arc::new(PinnedServerVerifier::new(cert_pin));
        let mut client_crypto = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

        client_crypto.alpn_protocols = vec![wtransport::tls::WEBTRANSPORT_ALPN.to_vec()];

        ClientConfig::builder()
            .with_bind_default()
            .with_custom_tls(client_crypto)
            .build()
    };

    client_config.quic_config_mut().transport_config(Arc::new(transport_config));

    let endpoint = Endpoint::client(client_config)?;

    // Resolve endpoint (add default port if missing)
    let mut resolved_endpoint = endpoint_str.clone();
    if !resolved_endpoint.contains(':') {
        resolved_endpoint = format!("{}:10443", resolved_endpoint);
    }

    let connect_url = format!("https://{}/vpn", resolved_endpoint);
    info!("Connecting to WebTransport endpoint {}", connect_url);

    let connection = endpoint
        .connect(&connect_url)
        .await
        .context("WebTransport handshake failed")?;

    info!("WebTransport handshake OK, sending auth token ({} bytes)", token.len());

    // Application-level handshake (Auth → Config)
    let (mut send, mut recv) = connection.open_bi().await?.await?;
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
