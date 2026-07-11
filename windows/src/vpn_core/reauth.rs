//! In-band Keycloak token reauth for the live Windows session.
//!
//! The service or IPC clients refresh the access token and push it into the
//! session's `current_token` cell. This task presents the fresh token to the
//! server over the active transport's in-band control path so the live tunnel
//! survives the original token's expiry instead of being force-closed and reconnected.

use super::handshake::TunnelConnection;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::Notify;
use tracing::{info, warn};

/// Fallback poll interval for checking whether a fresher token needs presenting
/// to the server. Service-side refresh also wakes the task immediately.
const REAUTH_POLL_SECS: u64 = 15;

/// Spawns the background reauth task. It watches `token_cell` and, when a
/// fresher token is available, presents it to the server. Exits when either
/// `running` (global) or `session_alive` is cleared. Returns the join handle so
/// the caller can abort it during teardown.
pub(super) fn spawn_reauth_task(
    connection: Arc<TunnelConnection>,
    session_alive: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    token_cell: Arc<StdMutex<String>>,
    token_updated: Arc<Notify>,
    initial_token: String,
) -> tokio::task::JoinHandle<()> {
    let mut last_token = initial_token;
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = token_updated.notified() => {}
                () = tokio::time::sleep(Duration::from_secs(REAUTH_POLL_SECS)) => {}
            }

            if !running.load(Ordering::Relaxed) || !session_alive.load(Ordering::Relaxed) {
                break;
            }
            let current = token_cell.lock().map(|t| t.clone()).unwrap_or_default();
            if current.is_empty() || current == last_token {
                continue;
            }
            match connection.reauthenticate(&current).await {
                Ok(true) => {
                    info!("In-band token reauth accepted; live session extended");
                    last_token = current;
                }
                Ok(false) => warn!("In-band token reauth rejected by server"),
                Err(e) => warn!("In-band token reauth attempt failed: {e}"),
            }
        }
    })
}
