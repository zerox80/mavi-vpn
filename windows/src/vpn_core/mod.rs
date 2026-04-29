//! # Mavi VPN Windows Core
//!
//! Implements the core VPN logic for Windows.

mod handshake;
mod network;
mod wintun_mod;

use crate::ipc::Config;
use anyhow::{Context, Result};
use bytes::{Buf, Bytes};
use shared::{icmp, masque, ControlMessage};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};
use wintun::Adapter;

use self::handshake::{connect_and_handshake, decode_hex};
use self::network::{
    cleanup_routes, create_udp_socket, remove_nrpt_dns_rule, set_adapter_network_config,
    SessionRouteGuard,
};
use self::wintun_mod::{extract_wintun_dll, get_or_create_adapter, is_wintun_ring_full};

// --- Default timing parameters ---
const RECONNECT_INITIAL_SECS: u64 = 1;
const RECONNECT_MAX_SECS: u64 = 30;

/// Entry point for the VPN runner. Manages the reconnection loop and WinTUN lifecycle.
pub async fn run_vpn(mut config: Config, running: Arc<AtomicBool>) -> Result<()> {
    config.normalize_transport();

    // 1. Prepare environment
    let cert_pin_bytes =
        decode_hex(&config.cert_pin).context("Invalid certificate PIN hex format")?;
    let dll_path = extract_wintun_dll()?;
    let wintun =
        unsafe { wintun::load_from_path(&dll_path) }.context("Failed to load wintun.dll")?;

    // 2. Open or create the virtual adapter
    let adapter = get_or_create_adapter(&wintun)?;

    let mut backoff = Duration::from_secs(RECONNECT_INITIAL_SECS);

    // 3. Main Connection Loop
    while running.load(Ordering::Relaxed) {
        // Always clear stale routes before a new session so a previous
        // (possibly crashed) session does not leave orphaned routing entries.
        cleanup_routes(None);

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
                let err_str = e.to_string();
                if err_str.contains("AUTH_FAILED") || err_str.contains("Server rejected connection")
                {
                    warn!(
                        "Authentication permanently denied: {}. Stopping VPN loop.",
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
                return Err(anyhow::anyhow!("Server rejected connection: {}", message))
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Unexpected server response during handshake"
                ))
            }
        };

    info!("Handshake successful. Internal IPv4: {}", assigned_ip);

    // 3. Configure Windows Networking (IPs, Routes, DNS)
    let remote_ip = connection.remote_address().ip();
    let endpoint_ip_str = match remote_ip {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(|v4| v4.to_string())
            .unwrap_or_else(|| v6.to_string()),
    };

    let route_cleanup = SessionRouteGuard::new(set_adapter_network_config(
        adapter,
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
    )?);

    // 4. Start WinTUN Session
    let session = Arc::new(
        adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .context("Failed to start WinTUN session")?,
    );
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
            if !running_monitor.load(Ordering::Relaxed) || !alive_monitor.load(Ordering::Relaxed) {
                break;
            }
            let current_mtu = conn_monitor.max_datagram_size().unwrap_or(0);
            if current_mtu != last_mtu {
                if last_mtu != 0 {
                    info!(
                        "[MTU] QUIC Path MTU changed: {} -> {} bytes",
                        last_mtu, current_mtu
                    );
                }
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
    let is_h3_framing = config.effective_http3_framing();
    let tun_mtu_for_ptb = mtu;
    let tun_to_quic = std::thread::spawn(move || {
        let mut pool = bytes::BytesMut::with_capacity(4 * 1024 * 1024);
        loop {
            if !run_pump.load(Ordering::Relaxed) || !alive_pump.load(Ordering::Relaxed) {
                break;
            }
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
                                tun_mtu_for_ptb.max(1280)
                            } else {
                                tun_mtu_for_ptb
                            };

                            if let Some(icmp_packet) = icmp::generate_packet_too_big(
                                packet.bytes(),
                                reported_mtu,
                                source_ip,
                            ) {
                                if let Ok(mut reply) =
                                    session_tun.allocate_send_packet(icmp_packet.len() as u16)
                                {
                                    reply.bytes_mut().copy_from_slice(&icmp_packet);
                                    session_tun.send_packet(reply);
                                }
                            }
                        } else if matches!(e, quinn::SendDatagramError::ConnectionLost(_)) {
                            break;
                        }
                    }
                }
                Ok(None) => {
                    if let Ok(event) = session_tun.get_read_wait_event() {
                        unsafe {
                            windows_sys::Win32::System::Threading::WaitForSingleObject(
                                event as _, 50,
                            );
                        }
                    } else {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                Err(_) => {
                    alive_pump.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }
    });

    // Task: QUIC -> TUN (Read from QUIC, Write to WinTUN)
    let session_quic_in = session.clone();
    let alive_quic_in = session_alive.clone();
    let run_quic_in = global_running.clone();
    let conn_quic = connection.clone();
    let is_h3_framing_dl = config.effective_http3_framing();
    let quic_to_tun = tokio::spawn(async move {
        let mut pending_datagram: Option<Bytes> = None;
        let mut yield_count = 0u8;

        loop {
            if !run_quic_in.load(Ordering::Relaxed) || !alive_quic_in.load(Ordering::Relaxed) {
                break;
            }

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
                            if inner_len == 0 {
                                continue;
                            }
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

            if data.is_empty() {
                continue;
            }

            match session_quic_in.allocate_send_packet(data.len() as u16) {
                Ok(mut packet) => {
                    yield_count = 0;
                    packet.bytes_mut().copy_from_slice(&data);
                    session_quic_in.send_packet(packet);
                }
                Err(e) if is_wintun_ring_full(&e) => {
                    pending_datagram = Some(data);
                    // Hybrid backoff: gracefully yield time to the runtime without triggering
                    // the ~15.6ms system timer penalty on Windows for short bursts of backpressure.
                    if yield_count < 10 {
                        yield_count += 1;
                        tokio::task::yield_now().await;
                    } else {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
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

    if global_running.load(Ordering::Relaxed) {
        Ok(SessionEnd::ConnectionLost)
    } else {
        Ok(SessionEnd::UserStopped)
    }
}
