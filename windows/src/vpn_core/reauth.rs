//! In-band Keycloak token reauth for the live Windows session.
//!
//! The service or IPC clients refresh the access token and push it into the
//! session's `current_token` cell. This task presents the fresh token to the
//! server over a *fresh* bidirectional QUIC stream so the live tunnel survives
//! the original token's expiry instead of being force-closed and reconnected.

use anyhow::{Context, Result};
use shared::ControlMessage;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    connection: Arc<quinn::Connection>,
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
/// stalled stream cannot wedge the reauth task. Framed identically to the
/// handshake `Auth` message (`u32` length prefix + bincode payload).
async fn send_reauth(connection: &quinn::Connection, token: &str) -> Result<bool> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (mut send, mut recv) = connection.open_bi().await?;
        let msg = ControlMessage::Reauth {
            token: token.to_string(),
        };
        let bytes = bincode::serde::encode_to_vec(&msg, bincode::config::standard())?;
        #[allow(clippy::cast_possible_truncation)]
        send.write_u32_le(bytes.len() as u32).await?;
        send.write_all(&bytes).await?;
        let _ = send.finish();

        let len = recv
            .read_u32_le()
            .await
            .context("Server closed reauth response before sending length")?
            as usize;
        if len > 65_536 {
            anyhow::bail!("Reauth response too large: {len} bytes");
        }
        let mut buf = vec![0u8; len];
        recv.read_exact(&mut buf)
            .await
            .context("Server closed reauth response before sending the full body")?;
        let (resp, _): (ControlMessage, _) =
            bincode::serde::decode_from_slice(&buf, bincode::config::standard())?;
        match resp {
            ControlMessage::ReauthResult { accepted } => Ok(accepted),
            _ => anyhow::bail!("Unexpected reauth response"),
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("Reauth timed out"))?
}
