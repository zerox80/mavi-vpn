//! # Mavi VPN Windows Core
//!
//! Implements the core VPN logic for Windows.

mod handshake;
mod network;
mod pump;
mod reauth;
mod reconnect;
mod runtime_state;
mod wintun_mod;

use crate::ipc::Config;
use anyhow::{bail, Context, Result};
use shared::ControlMessage;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};
use wintun::Adapter;

use self::handshake::{connect_and_handshake, decode_hex, HandshakeRequest};
use self::network::{
    cleanup_routes, create_udp_socket, remove_nrpt_dns_rule, set_adapter_network_config,
    AdapterNetworkConfig, SessionRouteGuard,
};
use self::pump::{pump_quic_to_tun, pump_tun_to_quic, PtbContext};
use self::reconnect::{
    compute_reconnect_delay, sleep_unless_stopped, ReconnectDecision, SessionEnd,
    RECONNECT_INITIAL_SECS,
};
use self::runtime_state::VpnRuntimeState;
use self::wintun_mod::{extract_wintun_dll, get_or_create_adapter};

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

struct ServerNetworkAssignment {
    assigned_ip: std::net::Ipv4Addr,
    netmask: std::net::Ipv4Addr,
    gateway: std::net::Ipv4Addr,
    dns: std::net::Ipv4Addr,
    mtu: u16,
    assigned_ipv6: Option<std::net::Ipv6Addr>,
    netmask_v6: Option<u8>,
    gateway_v6: Option<std::net::Ipv6Addr>,
    dns_v6: Option<std::net::Ipv6Addr>,
}

impl ServerNetworkAssignment {
    fn from_control(message: ControlMessage) -> Result<Self> {
        match message {
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
            } => Ok(Self {
                assigned_ip,
                netmask,
                gateway,
                dns: dns_server,
                mtu,
                assigned_ipv6,
                netmask_v6,
                gateway_v6,
                dns_v6: dns_server_v6,
            }),
            ControlMessage::Error { message } => {
                Err(anyhow::anyhow!("Server rejected connection: {message}"))
            }
            ControlMessage::Auth { .. }
            | ControlMessage::Reauth { .. }
            | ControlMessage::ReauthResult { .. } => Err(anyhow::anyhow!(
                "Unexpected server response during handshake"
            )),
        }
    }

    fn adapter_config(&self) -> AdapterNetworkConfig {
        AdapterNetworkConfig {
            ip: self.assigned_ip,
            netmask: self.netmask,
            gateway: self.gateway,
            dns: self.dns,
            tun_mtu: self.mtu,
            assigned_ipv6: self.assigned_ipv6,
            netmask_v6: self.netmask_v6,
            gateway_v6: self.gateway_v6,
            dns_v6: self.dns_v6,
        }
    }
}

/// Entry point for the VPN runner. Manages the reconnection loop and `WinTUN` lifecycle.
pub async fn run_vpn(
    mut config: Config,
    running: Arc<AtomicBool>,
    connected: Arc<AtomicBool>,
    last_error: Arc<StdMutex<Option<String>>>,
    assigned_ip: Arc<StdMutex<Option<String>>>,
    current_token: Arc<StdMutex<String>>,
) -> Result<()> {
    let runtime = VpnRuntimeState::new(
        running,
        connected,
        last_error,
        assigned_ip,
        current_token,
    );

    config.normalize_transport();
    runtime.set_connected(false);
    // 1. Prepare environment
    let cert_pin_bytes =
        decode_hex(&config.cert_pin).context("Invalid certificate PIN hex format")?;

    // 2. Open or create the virtual adapter (cached globally)
    let adapter = get_global_adapter()?;

    let mut backoff = Duration::from_secs(RECONNECT_INITIAL_SECS);

    // 3. Main Connection Loop
    while runtime.is_running() {
        // Always clear stale routes before a new session so a previous
        // (possibly crashed) session does not leave orphaned routing entries.
        cleanup_routes(None);
        runtime.set_connected(false);

        let outcome = run_session(&config, &cert_pin_bytes, &adapter, &runtime).await;

        if !runtime.is_running() {
            break;
        }

        let err_opt = outcome.as_ref().err().map(|e| e.to_string());
        if let Some(ref err_str) = err_opt {
            runtime.set_last_error(Some(err_str.clone()));
        }

        match compute_reconnect_delay(outcome, backoff) {
            ReconnectDecision::Break => break,
            ReconnectDecision::PermanentFailure { error } => {
                warn!("Permanent VPN setup failure: {}. Stopping VPN loop.", error);
                runtime.stop_running();
                break;
            }
            ReconnectDecision::Reconnect {
                delay,
                next_backoff,
            } => {
                if let Some(ref err_str) = err_opt {
                    warn!("Session failed: {err_str}. Reconnecting...");
                }
                sleep_unless_stopped(delay, runtime.running()).await;
                backoff = next_backoff;
            }
        }
    }

    // 4. Cleanup - routes first, then DNS/NRPT
    runtime.set_connected(false);
    cleanup_routes(None);
    remove_nrpt_dns_rule();
    runtime.clear_assigned_ip();
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
    runtime: &VpnRuntimeState,
) -> Result<SessionEnd> {
    let socket = create_udp_socket()?;

    // 1. QUIC Handshake & Auth
    let ech_bytes = config
        .ech_config
        .as_deref()
        .and_then(crate::ech_client::decode_hex);

    // Read the freshest access token (GUI may have refreshed it via UpdateToken
    // since this session's config was captured). Fall back to the seed token if
    // the lock is poisoned.
    let token = runtime.current_token_or(&config.token);

    let connect_started = Instant::now();
    let (connection, server_config, _h3_guard) = connect_and_handshake(HandshakeRequest {
        socket,
        // Clone so the plaintext token survives as the reauth task's initial
        // `last_token` baseline (the request takes ownership otherwise).
        token: token.clone(),
        endpoint_str: config.endpoint.clone(),
        cert_pin: cert_pin_bytes.to_vec(),
        censorship_resistant: config.censorship_resistant,
        http3_framing: config.effective_http3_framing(),
        ech_config_list: ech_bytes,
        vpn_mtu: config.vpn_mtu,
    })
    .await?;
    info!(
        "Windows session handshake/config completed in {} ms",
        connect_started.elapsed().as_millis()
    );

    // 2. Extract Network Configuration
    let assignment = ServerNetworkAssignment::from_control(server_config)?;

    info!(
        "Handshake successful. Internal IPv4: {}",
        assignment.assigned_ip
    );

    // 3. Configure Windows Networking (IPs, Routes, DNS)
    let remote_ip = connection.remote_address().ip();
    let endpoint_ip_str = extract_endpoint_ip(remote_ip);

    // Store the tunnel IP in shared state for CLI/GUI status.
    runtime.set_assigned_ip(assignment.assigned_ip.to_string());

    let adapter_config_started = Instant::now();
    let route_cleanup = SessionRouteGuard::new(set_adapter_network_config(
        adapter,
        assignment.adapter_config(),
        &endpoint_ip_str,
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
    if let Some(ipv6) = assignment.assigned_ipv6 {
        let idx = adapter
            .get_adapter_index()
            .context("Failed to get adapter index for IPv6 verification")?;

        // 1. Wait for IPv6 address confirmation (DAD, etc)
        // Marked IPV6_SETUP_FAILED so the reconnect classifier treats a
        // deterministic local IPv6 stack failure (e.g. IPv6 disabled, DAD
        // failure) as permanent instead of looping forever - matching Linux,
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

    runtime.set_connected(true);
    runtime.clear_last_error();
    let session_alive = Arc::new(AtomicBool::new(true));

    // 5. Data Hubs
    let connection = Arc::new(connection);

    // Task: MTU Monitor
    let conn_monitor = connection.clone();
    let alive_monitor = session_alive.clone();
    let running_monitor = runtime.running().clone();
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

    // Task: in-band Keycloak token reauth. The GUI silently refreshes the access
    // token and pushes it via UpdateToken into current_token; present it to the
    // server over a fresh bidi stream so the live tunnel survives the original
    // token's expiry instead of being force-closed and reconnected.
    let reauth_task = reauth::spawn_reauth_task(
        connection.clone(),
        session_alive.clone(),
        runtime.running().clone(),
        runtime.current_token(),
        token,
    );

    // Thread: TUN -> QUIC (Read from WinTUN, Send via QUIC)
    let ptb_ctx = PtbContext {
        gateway: assignment.gateway,
        gateway_v6: assignment.gateway_v6,
        is_h3_framing: config.effective_http3_framing(),
        tun_mtu: assignment.mtu,
    };
    let session_tx = session.clone();
    let conn_tx = connection.clone();
    let alive_tx = session_alive.clone();
    let run_tx = runtime.running().clone();
    let tun_to_quic = std::thread::spawn(move || {
        pump_tun_to_quic(&session_tx, &conn_tx, &run_tx, &alive_tx, &ptb_ctx);
    });

    // Task: QUIC -> TUN (Read from QUIC, Write to WinTUN)
    let session_rx = session.clone();
    let conn_rx = connection.clone();
    let alive_rx = session_alive.clone();
    let run_rx = runtime.running().clone();
    let is_h3_framing_dl = config.effective_http3_framing();
    let quic_to_tun = tokio::spawn(async move {
        pump_quic_to_tun(&session_rx, &conn_rx, &run_rx, &alive_rx, is_h3_framing_dl).await;
    });

    // Wait for termination
    while runtime.is_running() && session_alive.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    quic_to_tun.abort();
    reauth_task.abort();
    let _ = tun_to_quic.join();

    // Surface WHY the tunnel dropped so disconnects are diagnosable instead of
    // silent reconnects: a server-initiated close carries its reason string
    // (e.g. "session token expired"), a QUIC idle timeout shows as `TimedOut`.
    if runtime.is_running() {
        match connection.close_reason() {
            Some(reason) => warn!("VPN session ended - QUIC close reason: {reason}"),
            None => warn!("VPN session ended without an explicit QUIC close reason"),
        }
    }

    runtime.set_connected(false);
    runtime.clear_assigned_ip();
    drop(route_cleanup);

    Ok(determine_session_result(runtime.is_running()))
}

#[cfg(test)]
mod tests;
