//! In-band Keycloak token reauth for the live Linux session.
//!
//! The GUI silently refreshes the access token and pushes it (via `UpdateToken`)
//! into the session's `current_token` cell. This task presents the fresh token to
//! the server over a *fresh* bidirectional QUIC stream so the live tunnel survives
//! the original token's expiry instead of being force-closed and reconnected.

use anyhow::Result;
use shared::control;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tracing::{info, warn};

/// How often the in-band reauth task checks whether the GUI has pushed a fresher
/// access token (via `UpdateToken`) that needs presenting to the server. The GUI
/// refreshes ~300s before expiry, so a 15s poll applies it with ample margin.
const REAUTH_POLL_SECS: u64 = 15;

/// Spawns the background reauth task. It polls `token_cell` and, when the GUI has
/// pushed a fresher token, presents it to the server. Exits when either `running`
/// (global) or `session_alive` is cleared. Returns the join handle so the caller
/// can abort it during teardown.
pub(super) fn spawn_reauth_task(
    connection: Arc<quinn::Connection>,
    session_alive: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    token_cell: Arc<StdMutex<String>>,
    initial_token: String,
) -> tokio::task::JoinHandle<()> {
    let mut last_token = initial_token;
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(REAUTH_POLL_SECS)).await;
            if !running.load(Ordering::Relaxed) || !session_alive.load(Ordering::Relaxed) {
                break;
            }
            let current = token_cell.lock().map(|t| t.clone()).unwrap_or_default();
            if current.is_empty() || current == last_token {
                continue;
            }
            match send_reauth(&connection, &current).await {
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

/// Presents a refreshed access token to the server over a fresh bidirectional
/// QUIC stream so the *live* session's deadline is extended in place (no
/// reconnect). Returns whether the server accepted it. Bounded by a timeout so a
/// stalled stream cannot wedge the reauth task. Framing and the exchange itself
/// live in [`shared::control`], shared with the Windows and Android cores.
async fn send_reauth(connection: &quinn::Connection, token: &str) -> Result<bool> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (mut send, mut recv) = connection.open_bi().await?;
        let accepted = control::reauth_over_stream(&mut send, &mut recv, token).await?;
        Ok::<bool, anyhow::Error>(accepted)
    })
    .await
    .map_err(|_| anyhow::anyhow!("Reauth timed out"))?
}
