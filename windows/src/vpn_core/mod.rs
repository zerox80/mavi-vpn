//! # Mavi VPN Windows Core
//!
//! Implements the core VPN logic for Windows.

mod handshake;
mod network;
mod reconnect;
mod wintun_mod;

use crate::ipc::Config;
use anyhow::{bail, Context, Result};
use bytes::{Buf, Bytes};
use shared::{icmp, masque, ControlMessage};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};
use wintun::Adapter;

use self::handshake::{connect_and_handshake, decode_hex};
use self::network::{
    cleanup_routes, create_udp_socket, remove_nrpt_dns_rule, set_adapter_network_config,
    SessionRouteGuard,
};
use self::reconnect::{
    compute_reconnect_delay, sleep_unless_stopped, ReconnectDecision, SessionEnd,
    RECONNECT_INITIAL_SECS,
};
use self::wintun_mod::{extract_wintun_dll, get_or_create_adapter, is_wintun_ring_full};

#[cfg_attr(test, allow(dead_code))]
pub fn cleanup_stale_network_state() {
    network::cleanup_stale_network_state();
}

use std::sync::OnceLock;

static WINTUN_ADAPTER: OnceLock<(wintun::Wintun, Arc<Adapter>)> = OnceLock::new();

fn get_global_adapter() -> Result<Arc<Adapter>> {
    if let Some((_, adapter)) = WINTUN_ADAPTER.get() {
        return Ok(adapter.clone());
    }

    let dll_path = extract_wintun_dll()?;
    let wintun =
        unsafe { wintun::load_from_path(&dll_path) }.context("Failed to load wintun.dll")?;
    let adapter = get_or_create_adapter(&wintun)?;

    let (_, adapter) = WINTUN_ADAPTER.get_or_init(|| (wintun, adapter));
    Ok(adapter.clone())
}

/// Entry point for the VPN runner. Manages the reconnection loop and `WinTUN` lifecycle.
pub async fn run_vpn(
    mut config: Config,
    running: Arc<AtomicBool>,
    connected: Arc<AtomicBool>,
    last_error: Arc<StdMutex<Option<String>>>,
    assigned_ip: Arc<StdMutex<Option<String>>>,
) -> Result<()> {
    config.normalize_transport();
    connected.store(false, Ordering::SeqCst);
    // 1. Prepare environment
    let cert_pin_bytes =
        decode_hex(&config.cert_pin).context("Invalid certificate PIN hex format")?;

    // 2. Open or create the virtual adapter (cached globally)
    let adapter = get_global_adapter()?;

    let mut backoff = Duration::from_secs(RECONNECT_INITIAL_SECS);

    // 3. Main Connection Loop
    while running.load(Ordering::Relaxed) {
        // Always clear stale routes before a new session so a previous
        // (possibly crashed) session does not leave orphaned routing entries.
        cleanup_routes(None);
        connected.store(false, Ordering::SeqCst);

        let outcome = run_session(
            &config,
            &cert_pin_bytes,
            &adapter,
            &running,
            &connected,
            &last_error,
            &assigned_ip,
        )
        .await;

        if !running.load(Ordering::Relaxed) {
            break;
        }

        let err_opt = outcome.as_ref().err().map(|e| e.to_string());
        if let Some(ref err_str) = err_opt {
            if let Ok(mut last) = last_error.lock() {
                *last = Some(err_str.clone());
            }
        }

        match compute_reconnect_delay(outcome, backoff) {
            ReconnectDecision::Break => break,
            ReconnectDecision::PermanentFailure { error } => {
                warn!("Permanent VPN setup failure: {}. Stopping VPN loop.", error);
                running.store(false, Ordering::Relaxed);
                break;
            }
            ReconnectDecision::Reconnect {
                delay,
                next_backoff,
            } => {
                if let Some(ref err_str) = err_opt {
                    warn!("Session failed: {err_str}. Reconnecting...");
                }
                sleep_unless_stopped(delay, &running).await;
                backoff = next_backoff;
            }
        }
    }

    // 4. Cleanup – routes first, then DNS/NRPT
    connected.store(false, Ordering::SeqCst);
    cleanup_routes(None);
    remove_nrpt_dns_rule();
    if let Ok(mut ip) = assigned_ip.lock() {
        *ip = None;
    }
    info!("VPN Service Stopped.");
    Ok(())
}

/// Extracts a displayable IP string from a remote address, mapping IPv6-mapped
/// IPv4 addresses back to their IPv4 representation.
fn extract_endpoint_ip(remote_ip: std::net::IpAddr) -> String {
    match remote_ip {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or_else(|| v6.to_string(), |v4| v4.to_string()),
    }
}

/// Determines the session outcome based on whether the VPN was still running.
fn determine_session_result(still_running: bool) -> SessionEnd {
    if still_running {
        SessionEnd::ConnectionLost
    } else {
        SessionEnd::UserStopped
    }
}

/// Manages a single active VPN session (handshake + packet pumping).
async fn run_session(
    config: &Config,
    cert_pin_bytes: &[u8],
    adapter: &Arc<Adapter>,
    global_running: &Arc<AtomicBool>,
    connected: &Arc<AtomicBool>,
    last_error: &Arc<StdMutex<Option<String>>>,
    assigned_ip_state: &Arc<StdMutex<Option<String>>>,
) -> Result<SessionEnd> {
    let socket = create_udp_socket()?;

    // 1. QUIC Handshake & Auth
    let ech_bytes = config
        .ech_config
        .as_deref()
        .and_then(crate::ech_client::decode_hex);

    let connect_started = Instant::now();
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
    info!(
        "Windows session handshake/config completed in {} ms",
        connect_started.elapsed().as_millis()
    );

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
                return Err(anyhow::anyhow!("Server rejected connection: {message}"))
            }
            ControlMessage::Auth { .. } => {
                return Err(anyhow::anyhow!(
                    "Unexpected server response during handshake"
                ))
            }
        };

    info!("Handshake successful. Internal IPv4: {}", assigned_ip);

    // 3. Configure Windows Networking (IPs, Routes, DNS)
    let remote_ip = connection.remote_address().ip();
    let endpoint_ip_str = extract_endpoint_ip(remote_ip);

    // Store the tunnel IP in shared state for CLI/GUI status.
    if let Ok(mut ip) = assigned_ip_state.lock() {
        *ip = Some(assigned_ip.to_string());
    }

    let adapter_config_started = Instant::now();
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
    info!(
        "Windows adapter/network config completed in {} ms",
        adapter_config_started.elapsed().as_millis()
    );

    // 4. Start WinTUN Session
    let session = Arc::new(
        adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .context("Failed to start WinTUN session")?,
    );

    // Hard verification for IPv6 if assigned
    if let Some(ipv6) = assigned_ipv6 {
        let idx = adapter
            .get_adapter_index()
            .context("Failed to get adapter index for IPv6 verification")?;

        // 1. Wait for IPv6 address confirmation (DAD, etc)
        // Marked IPV6_SETUP_FAILED so the reconnect classifier treats a
        // deterministic local IPv6 stack failure (e.g. IPv6 disabled, DAD
        // failure) as permanent instead of looping forever — matching Linux,
        // which already classifies IPv6 split-route failures as permanent.
        if !network::wait_for_ipv6_address(idx, ipv6).await {
            bail!("IPV6_SETUP_FAILED: IPv6 address {ipv6} failed verification (possibly duplicate or stack error)");
        }
        info!("IPv6 address {} verified", ipv6);

        // 2. Verify On-Link split routes exist
        if !network::verify_ipv6_split_routes(idx)? {
            bail!(
                "IPV6_SETUP_FAILED: IPv6 split routes (::/1, 8000::/1) not found in routing table"
            );
        }
        info!("IPv6 split routes verified as On-Link");
    }

    connected.store(true, Ordering::SeqCst);
    if let Ok(mut last) = last_error.lock() {
        *last = None;
    }
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
    let ptb_ctx = PtbContext {
        gateway,
        gateway_v6,
        is_h3_framing: config.effective_http3_framing(),
        tun_mtu: mtu,
    };
    let session_tx = session.clone();
    let conn_tx = connection.clone();
    let alive_tx = session_alive.clone();
    let run_tx = global_running.clone();
    let tun_to_quic = std::thread::spawn(move || {
        pump_tun_to_quic(&session_tx, &conn_tx, &run_tx, &alive_tx, &ptb_ctx);
    });

    // Task: QUIC -> TUN (Read from QUIC, Write to WinTUN)
    let session_rx = session.clone();
    let conn_rx = connection.clone();
    let alive_rx = session_alive.clone();
    let run_rx = global_running.clone();
    let is_h3_framing_dl = config.effective_http3_framing();
    let quic_to_tun = tokio::spawn(async move {
        pump_quic_to_tun(&session_rx, &conn_rx, &run_rx, &alive_rx, is_h3_framing_dl).await;
    });

    // Wait for termination
    while global_running.load(Ordering::Relaxed) && session_alive.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    quic_to_tun.abort();
    let _ = tun_to_quic.join();
    connected.store(false, Ordering::SeqCst);
    if let Ok(mut ip) = assigned_ip_state.lock() {
        *ip = None;
    }
    drop(route_cleanup);

    Ok(determine_session_result(
        global_running.load(Ordering::Relaxed),
    ))
}

/// Session-static inputs needed to synthesize ICMP "Packet Too Big" replies.
struct PtbContext {
    gateway: std::net::Ipv4Addr,
    gateway_v6: Option<std::net::Ipv6Addr>,
    is_h3_framing: bool,
    tun_mtu: u16,
}

/// Pumps packets from the WinTUN adapter into the QUIC connection as datagrams.
///
/// Runs on a dedicated OS thread (WinTUN's receive API is blocking). Exits when
/// either `running` or `alive` is cleared, or the connection is lost. On a
/// `TooLarge` error it emits an ICMP PTB reply back into the TUN so the source
/// host lowers its path MTU.
fn pump_tun_to_quic(
    session: &Arc<wintun::Session>,
    connection: &quinn::Connection,
    running: &AtomicBool,
    alive: &AtomicBool,
    ptb: &PtbContext,
) {
    let mut pool = bytes::BytesMut::with_capacity(4 * 1024 * 1024);
    while running.load(Ordering::Relaxed) && alive.load(Ordering::Relaxed) {
        match session.try_receive() {
            Ok(Some(packet)) => {
                let packet_bytes = packet.bytes();
                if pool.capacity() < packet_bytes.len() + masque::DATAGRAM_PREFIX.len() {
                    pool.reserve(4 * 1024 * 1024);
                }
                if ptb.is_h3_framing {
                    pool.extend_from_slice(&masque::DATAGRAM_PREFIX);
                }
                pool.extend_from_slice(packet_bytes);
                let payload = pool.split().freeze();
                match connection.send_datagram(payload) {
                    Ok(()) => {}
                    Err(quinn::SendDatagramError::TooLarge) => {
                        send_ptb_reply(session, connection, packet.bytes(), ptb);
                    }
                    Err(quinn::SendDatagramError::ConnectionLost(_)) => break,
                    Err(_) => {}
                }
            }
            Ok(None) => {
                if let Ok(event) = session.get_read_wait_event() {
                    unsafe {
                        windows_sys::Win32::System::Threading::WaitForSingleObject(event as _, 50);
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            Err(_) => {
                alive.store(false, Ordering::SeqCst);
                break;
            }
        }
    }
}

/// Synthesizes an ICMP "Packet Too Big" reply for `packet_bytes` and writes it
/// back into the TUN, so the originating host reduces its path MTU.
fn send_ptb_reply(
    session: &Arc<wintun::Session>,
    connection: &quinn::Connection,
    packet_bytes: &[u8],
    ptb: &PtbContext,
) {
    let Some(&first_byte) = packet_bytes.first() else {
        return;
    };
    let version = first_byte >> 4;
    let source_ip = match version {
        4 => Some(std::net::IpAddr::V4(ptb.gateway)),
        6 => ptb.gateway_v6.map(std::net::IpAddr::V6),
        _ => None,
    };
    let h3_prefix = if ptb.is_h3_framing {
        masque::DATAGRAM_PREFIX.len()
    } else {
        0
    };
    let reported_mtu = shared::effective_ptb_mtu(
        ptb.tun_mtu,
        connection.max_datagram_size(),
        h3_prefix,
        version == 6,
    );
    let Some(icmp_packet) = icmp::generate_packet_too_big(packet_bytes, reported_mtu, source_ip)
    else {
        return;
    };
    let Ok(len) = u16::try_from(icmp_packet.len()) else {
        return;
    };
    if let Ok(mut reply) = session.allocate_send_packet(len) {
        reply.bytes_mut().copy_from_slice(&icmp_packet);
        session.send_packet(reply);
    }
}

/// Pumps datagrams from the QUIC connection into the WinTUN adapter.
///
/// Runs as a Tokio task. Exits when either `running` or `alive` is cleared, or
/// the connection's datagram stream ends. When the WinTUN send ring is full it
/// backpressures by retaining the datagram and yielding before retrying.
async fn pump_quic_to_tun(
    session: &Arc<wintun::Session>,
    connection: &quinn::Connection,
    running: &AtomicBool,
    alive: &AtomicBool,
    is_h3_framing: bool,
) {
    let mut pending_datagram: Option<Bytes> = None;
    let mut yield_count = 0u8;
    while running.load(Ordering::Relaxed) && alive.load(Ordering::Relaxed) {
        let data = match pending_datagram.take() {
            Some(data) => data,
            None => {
                let Ok(mut data) = connection.read_datagram().await else {
                    alive.store(false, Ordering::SeqCst);
                    break;
                };
                if is_h3_framing {
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
                data
            }
        };
        if data.is_empty() {
            continue;
        }
        #[allow(clippy::cast_possible_truncation)]
        match session.allocate_send_packet(data.len() as u16) {
            Ok(mut packet) => {
                yield_count = 0;
                packet.bytes_mut().copy_from_slice(&data);
                session.send_packet(packet);
            }
            Err(e) if is_wintun_ring_full(&e) => {
                pending_datagram = Some(data);
                if yield_count < 10 {
                    yield_count += 1;
                    tokio::task::yield_now().await;
                } else {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
            Err(_) => {
                alive.store(false, Ordering::SeqCst);
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests;
