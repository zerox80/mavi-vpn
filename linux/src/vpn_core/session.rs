use super::cert_pin;
use anyhow::{Context, Result};
use shared::ipc::Config;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use tracing::{info, warn};

use crate::network::NetworkConfig;
use crate::tun::TunDevice;

const RECONNECT_INITIAL_SECS: u64 = 1;
const RECONNECT_MAX_SECS: u64 = 30;
const HANDSHAKE_TIMEOUT_SECS: u64 = 15;
const TUN_DEVICE_NAME: &str = "mavi0";

mod lifecycle;
mod network_assignment;
mod packet_pumps;
mod reauth;

use self::lifecycle::{is_permanent_setup_error, SessionEnd};
use self::network_assignment::{ServerNetworkAssignment, SessionSetupError};
use self::packet_pumps::{PacketPumpConfig, PacketPumpTasks};

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

async fn wait_until_stopped(running: &Arc<AtomicBool>) {
    while running.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Entry point for the VPN runner. Manages the reconnection loop and TUN lifecycle.
#[allow(clippy::too_many_arguments)]
pub async fn run_vpn(
    mut config: Config,
    running: Arc<AtomicBool>,
    connected: Arc<AtomicBool>,
    last_error: Arc<StdMutex<Option<String>>>,
    assigned_ip: Arc<StdMutex<Option<String>>>,
    current_token: Arc<StdMutex<String>>,
    refresh_token: Arc<StdMutex<Option<String>>>,
) -> Result<()> {
    config.normalize_transport();

    let cert_pin_hashes = cert_pin::decode_hex_pins(&config.cert_pin).context(
        "Invalid certificate PIN hex format (expected one or more comma-separated 64-char SHA-256 hex fingerprints)",
    )?;

    let mut backoff = Duration::from_secs(RECONNECT_INITIAL_SECS);

    while running.load(Ordering::Relaxed) {
        let outcome = run_session(
            &config,
            &cert_pin_hashes,
            &running,
            &connected,
            &last_error,
            &assigned_ip,
            &current_token,
            &refresh_token,
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

/// Manages a single active VPN session (handshake + packet pumping).
#[allow(clippy::too_many_arguments)]
async fn run_session(
    config: &Config,
    cert_pin_hashes: &[Vec<u8>],
    global_running: &Arc<AtomicBool>,
    connected_flag: &Arc<AtomicBool>,
    last_error_state: &Arc<StdMutex<Option<String>>>,
    assigned_ip_state: &Arc<StdMutex<Option<String>>>,
    current_token: &Arc<StdMutex<String>>,
    refresh_token: &Arc<StdMutex<Option<String>>>,
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

    let handshake = tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        super::handshake::connect_and_handshake(
            socket,
            // Clone so the plaintext token survives as the reauth task's initial
            // `last_token` baseline (the handshake takes ownership otherwise).
            token.clone(),
            config.endpoint.clone(),
            cert_pin_hashes.to_vec(),
            config.censorship_resistant,
            config.effective_http3_framing(),
            config.uses_http2(),
            ech_bytes,
            config.vpn_mtu,
        ),
    );
    let (connection, server_config, _h3_guard) = tokio::select! {
        result = handshake => result
            .map_err(|_| {
                anyhow::anyhow!(
                    "Connection attempt timed out after {}s. Check endpoint, port and firewall.",
                    HANDSHAKE_TIMEOUT_SECS
                )
            })??,
        () = wait_until_stopped(global_running) => return Ok(SessionEnd::UserStopped),
    };

    // 2. Extract Network Configuration
    let assignment = match ServerNetworkAssignment::from_control(server_config) {
        Ok(assignment) => assignment,
        Err(SessionSetupError::Rejected(message)) => {
            let msg = format!("Server rejected connection: {}", message);
            if let Ok(mut last) = last_error_state.lock() {
                *last = Some(msg.clone());
            }
            return Err(anyhow::anyhow!(msg));
        }
        Err(SessionSetupError::UnexpectedResponse) => {
            return Err(anyhow::anyhow!("Unexpected server response"));
        }
    };
    let ServerNetworkAssignment {
        assigned_ip,
        netmask,
        gateway,
        dns,
        mtu,
        assigned_ipv6,
        netmask_v6,
        gateway_v6,
        dns_v6,
        whitelist_domains,
    } = assignment;

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
        &whitelist_domains,
        config.split_tunnel_mode,
        &config.split_tunnel_apps,
        config.split_tunnel_uid,
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

    // Task: in-band Keycloak token reauth. The background refresh task pushes
    // fresh access tokens into current_token; present them to the server over a
    // transport's in-band control path so the live tunnel survives the original
    // token's expiry.
    let reauth_task = reauth::spawn_reauth_task(
        connection.clone(),
        session_alive.clone(),
        global_running.clone(),
        current_token.clone(),
        token,
    );

    // Task: background Keycloak access-token refresh. Renews the short-lived
    // access token using the long-lived refresh token and writes it into
    // current_token so the in-band reauth task can push it to the server.
    let kc_refresh_task = if config.kc_auth.unwrap_or(false) {
        let kc_url = config.kc_url.clone().unwrap_or_default();
        let realm = config.kc_realm.clone().unwrap_or_else(|| "mavi-vpn".into());
        let client_id = config
            .kc_client_id
            .clone()
            .unwrap_or_else(|| "mavi-client".into());
        Some(super::kc_refresh::spawn_refresh_task(
            current_token.clone(),
            refresh_token.clone(),
            global_running.clone(),
            session_alive.clone(),
            kc_url,
            realm,
            client_id,
        ))
    } else {
        None
    };

    // Task: MTU Monitor
    let conn_monitor = connection.quic().cloned();
    let alive_monitor = session_alive.clone();
    let running_monitor = global_running.clone();
    let mtu_monitor = conn_monitor.map(|conn_monitor| {
        tokio::spawn(async move {
            let mut last_mtu = 0;
            loop {
                if !running_monitor.load(Ordering::Relaxed)
                    || !alive_monitor.load(Ordering::Relaxed)
                {
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
        })
    });

    let packet_pumps = PacketPumpTasks::spawn(
        async_tun,
        connection.clone(),
        session_alive.clone(),
        global_running.clone(),
        PacketPumpConfig {
            uses_h3_framing: config.effective_http3_framing(),
            tun_mtu: mtu,
            gateway,
            gateway_v6,
        },
    );

    // Wait for termination
    while global_running.load(Ordering::Relaxed) && session_alive.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Capture WHY the tunnel dropped *before* we self-close below, so a
    // server-initiated close (e.g. "session token expired") or a QUIC idle
    // timeout is visible in the log instead of a silent reconnect.
    if global_running.load(Ordering::Relaxed) {
        match connection.quic().and_then(quinn::Connection::close_reason) {
            Some(reason) => warn!("VPN session ended - QUIC close reason: {reason}"),
            None => warn!("VPN session ended without an explicit transport close reason"),
        }
    }

    // Wake a blocked transport receive before closing the QUIC connection.
    packet_pumps.stop();

    // Close the QUIC connection to unblock any remaining awaits.
    if let Some(quic) = connection.quic() {
        quic.close(0u32.into(), b"session ending");
    }

    if let Some(task) = mtu_monitor {
        task.abort();
    }
    reauth_task.abort();
    if let Some(task) = kc_refresh_task {
        task.abort();
    }

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
