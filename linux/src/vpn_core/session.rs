use super::cert_pin;
use anyhow::{Context, Result};
use bytes::Buf;
use shared::{icmp, ipc::Config, masque, ControlMessage};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

use crate::network::NetworkConfig;
use crate::tun::TunDevice;

const RECONNECT_INITIAL_SECS: u64 = 1;
const RECONNECT_MAX_SECS: u64 = 30;
const TUN_DEVICE_NAME: &str = "mavi0";

/// Entry point for the VPN runner. Manages the reconnection loop and TUN lifecycle.
pub async fn run_vpn(
    mut config: Config,
    running: Arc<AtomicBool>,
    connected: Arc<AtomicBool>,
    last_error: Arc<StdMutex<Option<String>>>,
    assigned_ip: Arc<StdMutex<Option<String>>>,
) -> Result<()> {
    config.normalize_transport();

    let cert_pin_bytes =
        cert_pin::decode_hex(&config.cert_pin).context("Invalid certificate PIN hex format")?;

    let mut backoff = Duration::from_secs(RECONNECT_INITIAL_SECS);

    while running.load(Ordering::Relaxed) {
        let outcome = run_session(
            &config,
            &cert_pin_bytes,
            &running,
            &connected,
            &last_error,
            &assigned_ip,
        )
        .await;

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
                warn!("Session failed: {:#}. Reconnecting...", e);
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
    connected_flag: &Arc<AtomicBool>,
    last_error_state: &Arc<StdMutex<Option<String>>>,
    assigned_ip_state: &Arc<StdMutex<Option<String>>>,
) -> Result<SessionEnd> {
    let socket = super::socket::create_udp_socket()?;

    // 1. QUIC Handshake & Auth
    //    `_h3_guard` keeps the h3 SendRequest + driver task alive for the entire
    //    session; dropping it earlier would send CONNECTION_CLOSE(H3_NO_ERROR) and
    //    kill the VPN datagram plane. It lives to the end of `run_session` scope.
    // Optional ECH GREASE + SNI-spoofing config, derived from the admin's
    // out-of-band ECHConfigList (hex in config.json / $VPN_ECH_CONFIG). None →
    // legacy path.
    let ech_bytes = config
        .ech_config
        .as_deref()
        .and_then(crate::ech_client::decode_hex);

    let (connection, server_config, _h3_guard) = super::handshake::connect_and_handshake(
        socket,
        config.token.clone(),
        config.endpoint.clone(),
        cert_pin_bytes.to_vec(),
        config.censorship_resistant,
        config.effective_http3_framing(),
        ech_bytes,
        config.vpn_mtu,
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
                let msg = format!("Server rejected connection: {}", message);
                if let Ok(mut last) = last_error_state.lock() {
                    *last = Some(msg.clone());
                }
                return Err(anyhow::anyhow!(msg));
            }
            _ => return Err(anyhow::anyhow!("Unexpected server response")),
        };

    info!("Handshake successful. Internal IPv4: {}", assigned_ip);
    connected_flag.store(true, Ordering::SeqCst);
    if let Ok(mut ip) = assigned_ip_state.lock() {
        *ip = Some(assigned_ip.to_string());
    }

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
    let mtu_monitor = tokio::spawn(async move {
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
    let is_h3_framing = config.effective_http3_framing();
    let tun_mtu_for_ptb = mtu;
    let gateway_v6_for_ptb = gateway_v6;
    let tun_to_quic = tokio::spawn(async move {
        let mut pool = bytes::BytesMut::with_capacity(4 * 1024 * 1024);
        let mut scratch = vec![0u8; 65536];
        loop {
            if !run_tun.load(Ordering::Relaxed) || !alive_tun.load(Ordering::Relaxed) {
                break;
            }
            if pool.capacity() < 65536 + masque::DATAGRAM_PREFIX.len() {
                pool.reserve(4 * 1024 * 1024);
            }
            match tun_reader.read(&mut scratch).await {
                Ok(n) if n > 0 => {
                    // In H3 mode, prepend [Quarter Stream ID] [Context ID]
                    // (connect-ip datagram framing, RFC 9484 §5 — 2 bytes).
                    let payload = if is_h3_framing {
                        pool.extend_from_slice(&masque::DATAGRAM_PREFIX);
                        pool.extend_from_slice(&scratch[..n]);
                        pool.split().freeze()
                    } else {
                        pool.extend_from_slice(&scratch[..n]);
                        pool.split().freeze()
                    };
                    if let Err(e) = conn_sender.send_datagram(payload) {
                        if matches!(e, quinn::SendDatagramError::TooLarge) {
                            let version = scratch[0] >> 4;
                            let source_ip = if version == 4 {
                                Some(std::net::IpAddr::V4(gateway))
                            } else if version == 6 {
                                gateway_v6_for_ptb.map(std::net::IpAddr::V6)
                            } else {
                                None
                            };
                            let reported_mtu = if version == 6 {
                                tun_mtu_for_ptb.max(1280)
                            } else {
                                tun_mtu_for_ptb
                            };
                            if let Some(icmp_packet) = icmp::generate_packet_too_big(
                                &scratch[..n],
                                reported_mtu,
                                source_ip,
                            ) {
                                let _ = tun_reader.write(&icmp_packet).await;
                            }
                        } else {
                            warn!("Datagram send error: {}", e);
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
    let is_h3_framing_dl = config.effective_http3_framing();
    let quic_to_tun = tokio::spawn(async move {
        loop {
            if !run_quic.load(Ordering::Relaxed) || !alive_quic.load(Ordering::Relaxed) {
                break;
            }
            match connection.read_datagram().await {
                Ok(mut data) => {
                    // Strip [Quarter Stream ID] [Context ID] for connect-ip.
                    if is_h3_framing_dl {
                        let inner_len = match masque::unwrap_datagram(&data) {
                            Some(slice) => slice.len(),
                            None => continue,
                        };
                        if inner_len == 0 {
                            continue;
                        }
                        let prefix = data.len() - inner_len;
                        data.advance(prefix);
                    }
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
    mtu_monitor.abort();

    // Cleanup networking
    net_config.cleanup();
    connected_flag.store(false, Ordering::SeqCst);
    if let Ok(mut ip) = assigned_ip_state.lock() {
        *ip = None;
    }

    if global_running.load(Ordering::Relaxed) {
        Ok(SessionEnd::ConnectionLost)
    } else {
        Ok(SessionEnd::UserStopped)
    }
}
