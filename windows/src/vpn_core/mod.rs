//! # Mavi VPN Windows Core
//!
//! Implements the core VPN logic for Windows.

mod handshake;
mod network;
mod pump;
mod reauth;
mod reconnect;
mod runtime_state;
mod session;
mod wintun_mod;

use crate::ipc::Config;
use anyhow::{Context, Result};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::Notify;
use tracing::{info, warn};
use wintun::Adapter;

use self::handshake::decode_hex_pins;
use self::network::{cleanup_routes, remove_nrpt_dns_rule};
use self::reconnect::{
    compute_reconnect_delay, sleep_unless_stopped, ReconnectDecision, RECONNECT_INITIAL_SECS,
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

/// Entry point for the VPN runner. Manages the reconnection loop and `WinTUN` lifecycle.
pub async fn run_vpn(
    mut config: Config,
    running: Arc<AtomicBool>,
    connected: Arc<AtomicBool>,
    last_error: Arc<StdMutex<Option<String>>>,
    assigned_ip: Arc<StdMutex<Option<String>>>,
    current_token: Arc<StdMutex<String>>,
    token_updated: Arc<Notify>,
) -> Result<()> {
    let runtime = VpnRuntimeState::new(
        running,
        connected,
        last_error,
        assigned_ip,
        current_token,
        token_updated,
    );

    config.normalize_transport();
    runtime.set_connected(false);
    // 1. Prepare environment
    let cert_pin_hashes = decode_hex_pins(&config.cert_pin).context(
        "Invalid certificate PIN hex format (expected one or more comma-separated 64-char SHA-256 hex fingerprints)",
    )?;

    // 2. Open or create the virtual adapter (cached globally)
    let adapter = get_global_adapter()?;

    let mut backoff = Duration::from_secs(RECONNECT_INITIAL_SECS);

    // 3. Main Connection Loop
    while runtime.is_running() {
        // Always clear stale routes before a new session so a previous
        // (possibly crashed) session does not leave orphaned routing entries.
        cleanup_routes(&[]);
        runtime.set_connected(false);

        let outcome = session::run(&config, &cert_pin_hashes, &adapter, &runtime).await;

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
    cleanup_routes(&[]);
    remove_nrpt_dns_rule();
    runtime.clear_assigned_ip();
    info!("VPN Service Stopped.");
    Ok(())
}

#[cfg(test)]
use self::reconnect::SessionEnd;
#[cfg(test)]
use self::session::{determine_session_result, extract_endpoint_ip};

#[cfg(test)]
mod tests;
