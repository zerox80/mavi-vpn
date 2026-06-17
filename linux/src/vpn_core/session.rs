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

mod reauth;

/// Sleeps up to `delay`, but returns as soon as `running` is cleared.
///
/// A Stop command only flips the `running` flag; without this, the reconnect
/// backoff (`tokio::time::sleep`, up to 30s) would block the loop so a disconnect
/// appears to hang and `vpn_stopping` stays set, rejecting fresh Start requests.
/// Polling in 100ms steps makes Stop take effect within ~100ms in any backoff.
async fn sleep_unless_stopped(delay: Duration, running: &Arc<AtomicBool>) {
    let deadline = std::time::Instant::now() + delay;
    while running.load(Ordering::Relaxed) && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Entry point for the VPN runner. Manages the reconnection loop and TUN lifecycle.
pub async fn run_vpn(
    mut config: Config,
    running: Arc<AtomicBool>,
    connected: Arc<AtomicBool>,
    last_error: Arc<StdMutex<Option<String>>>,
    assigned_ip: Arc<StdMutex<Option<String>>>,
    current_token: Arc<StdMutex<String>>,
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
            &current_token,
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
                let err_str = e.to_string();
                connected.store(false, Ordering::SeqCst);
                if let Ok(mut ip) = assigned_ip.lock() {
                    *ip = None;
                }
                if let Ok(mut last) = last_error.lock() {
                    *last = Some(err_str.clone());
                }
                if is_permanent_setup_error(&err_str) {
                    warn!(
                        "Permanent VPN setup failure: {}. Stopping VPN loop.",
                        err_str
                    );
                    running.store(false, Ordering::Relaxed);
                    break;
                }
                warn!("Session failed: {:#}. Reconnecting...", e);
                (
                    backoff,
                    (backoff * 2).min(Duration::from_secs(RECONNECT_MAX_SECS)),
                )
            }
        };

        sleep_unless_stopped(reconnect_delay, &running).await;
        backoff = next_backoff;
    }

    info!("VPN stopped.");
    Ok(())
}

fn is_permanent_setup_error(message: &str) -> bool {
    message.contains("AUTH_FAILED")
        || message.contains("Server rejected connection")
        || message.contains("MTU mismatch")
        || message.contains("unsupported VPN MTU")
        || message.contains("Failed to open /dev/net/tun")
        || message.contains("Failed to create TUN device")
        || message.contains("Failed to install IPv6 split route")
        || message.contains("Failed to execute: ip ")
        || message.contains("ip failed:")
}

enum SessionEnd {
    UserStopped,
    ConnectionLost,
}

/// Manages a single active VPN session (handshake + packet pumping).
#[allow(clippy::too_many_arguments)]
async fn run_session(
    config: &Config,
    cert_pin_bytes: &[u8],
    global_running: &Arc<AtomicBool>,
    connected_flag: &Arc<AtomicBool>,
    last_error_state: &Arc<StdMutex<Option<String>>>,
    assigned_ip_state: &Arc<StdMutex<Option<String>>>,
    current_token: &Arc<StdMutex<String>>,
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

    // Read the freshest access token (GUI may have refreshed it via UpdateToken
    // since this session's config was captured). Fall back to the seed token if
    // the lock is poisoned.
    let token = current_token
        .lock()
        .map(|t| t.clone())
        .unwrap_or_else(|_| config.token.clone());

    let (connection, server_config, _h3_guard) = super::handshake::connect_and_handshake(
        socket,
        // Clone so the plaintext token survives as the reauth task's initial
        // `last_token` baseline (the handshake takes ownership otherwise).
        token.clone(),
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
    let async_tun = match tun.into_async() {
        Ok(tun) => Arc::new(tun),
        Err(err) => {
            net_config.cleanup();
            return Err(err);
        }
    };

    info!("Handshake successful. Internal IPv4: {}", assigned_ip);
    connected_flag.store(true, Ordering::SeqCst);
    if let Ok(mut last) = last_error_state.lock() {
        *last = None;
    }
    if let Ok(mut ip) = assigned_ip_state.lock() {
        *ip = Some(assigned_ip.to_string());
    }

    let session_alive = Arc::new(AtomicBool::new(true));
    let connection = Arc::new(connection);

    // Task: in-band Keycloak token reauth. The GUI silently refreshes the access
    // token and pushes it via UpdateToken into current_token; present it to the
    // server over a fresh bidi stream so the live tunnel survives the original
    // token's expiry instead of being force-closed and reconnected.
    let reauth_task = reauth::spawn_reauth_task(
        connection.clone(),
        session_alive.clone(),
        global_running.clone(),
        current_token.clone(),
        token,
    );

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
                            let h3_prefix = if is_h3_framing {
                                masque::DATAGRAM_PREFIX.len()
                            } else {
                                0
                            };
                            let reported_mtu = shared::effective_ptb_mtu(
                                tun_mtu_for_ptb,
                                conn_sender.max_datagram_size(),
                                h3_prefix,
                                version == 6,
                            );
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
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(());
    let conn_clone = connection.clone();
    let quic_to_tun = tokio::spawn(async move {
        loop {
            if !run_quic.load(Ordering::Relaxed) || !alive_quic.load(Ordering::Relaxed) {
                break;
            }
            // Use select! to race read_datagram against a shutdown signal.
            // Without this, a Stop command blocks for up to 60s (QUIC idle
            // timeout) because read_datagram holds the .await indefinitely.
            let datagram = tokio::select! {
                biased;
                _ = shutdown_rx.changed() => { break; }
                result = conn_clone.read_datagram() => { result }
            };
            match datagram {
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

    // Capture WHY the tunnel dropped *before* we self-close below, so a
    // server-initiated close (e.g. "session token expired") or a QUIC idle
    // timeout is visible in the log instead of a silent reconnect.
    if global_running.load(Ordering::Relaxed) {
        match connection.close_reason() {
            Some(reason) => warn!("VPN session ended - QUIC close reason: {reason}"),
            None => warn!("VPN session ended without an explicit QUIC close reason"),
        }
    }

    // Signal shutdown to the QUIC->TUN task (unblocks read_datagram)
    drop(shutdown_tx);
    // Close the QUIC connection to unblock any remaining awaits
    connection.close(0u32.into(), b"session ending");

    tun_to_quic.abort();
    quic_to_tun.abort();
    mtu_monitor.abort();
    reauth_task.abort();

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

#[cfg(test)]
mod tests;
