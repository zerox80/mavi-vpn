//! In-band re-authentication for active Keycloak sessions.
//!
//! A client opens a *fresh* bidirectional QUIC stream and presents a refreshed
//! access token; on a valid token *for the same subject* the session deadline is
//! pushed out so the live tunnel survives the original token's expiry without a
//! reconnect. Kept in its own module to keep [`super`] focused on the handshake
//! and tunnel lifecycle.

use anyhow::Result;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tracing::{info, warn};

use shared::ControlMessage;

use crate::keycloak::{KeycloakValidator, ValidatedToken};
use crate::state::AppState;

use super::{encode_control_message_frame, validate_raw_auth_len};

/// Upper bound on a single in-band reauth exchange (read request + send reply),
/// so a stalled reauth stream cannot linger against the bidi-stream budget.
const REAUTH_STREAM_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum number of reauth streams validated concurrently per session. A client
/// could otherwise open many bidi streams at once and force a burst of token
/// validations (each a possible JWKS fetch); the semaphore bounds that work while
/// still letting a legitimate single refresh proceed immediately.
const MAX_CONCURRENT_REAUTH: usize = 4;

/// Accepts in-band re-authentication streams for the lifetime of a Keycloak
/// session. The client opens a *fresh* bidirectional stream and sends a
/// length-prefixed [`ControlMessage::Reauth`] carrying a refreshed access token;
/// on a valid token *for the same subject* the session deadline is pushed out
/// through `expiry_tx` so the tunnel is not force-closed at the original token's
/// expiry.
///
/// Re-validation runs the *same* checks as the initial handshake (signature,
/// issuer, `azp`, expiry, role/scope policy) and additionally binds the refreshed
/// token to `expected_sub`, so neither a revoked/downgraded token nor a different
/// user's valid token can extend a session. Exits when the connection closes.
pub(super) async fn reauth_listener(
    connection: Arc<quinn::Connection>,
    state: Arc<AppState>,
    keycloak: Arc<KeycloakValidator>,
    expiry_tx: tokio::sync::watch::Sender<Option<i64>>,
    expected_sub: Arc<str>,
) {
    let remote = connection.remote_address();
    let limiter = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_REAUTH));
    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(streams) => streams,
            // Connection closed (or closing): no more reauths to service.
            Err(_) => break,
        };
        // Bound concurrent validations. `acquire_owned` only errors if the
        // semaphore is closed, which never happens here.
        let Ok(permit) = limiter.clone().acquire_owned().await else {
            break;
        };
        let state = state.clone();
        let keycloak = keycloak.clone();
        let expiry_tx = expiry_tx.clone();
        let expected_sub = expected_sub.clone();
        // Service each reauth on its own task so a slow client stream cannot
        // delay later refreshes. The work is bounded (one small frame + reply).
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_reauth_stream(
                send,
                recv,
                &state,
                &keycloak,
                &expiry_tx,
                &expected_sub,
                remote,
            )
            .await
            {
                warn!("In-band reauth from {remote} failed: {e}");
            }
        });
    }
}

/// Reads one [`ControlMessage::Reauth`] from a reauth stream, re-validates the
/// token, extends the session deadline on success, and replies with a
/// [`ControlMessage::ReauthResult`].
async fn handle_reauth_stream(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    state: &AppState,
    keycloak: &KeycloakValidator,
    expiry_tx: &tokio::sync::watch::Sender<Option<i64>>,
    expected_sub: &str,
    remote: std::net::SocketAddr,
) -> Result<()> {
    let token = tokio::time::timeout(REAUTH_STREAM_TIMEOUT, async {
        let len = recv.read_u32_le().await? as usize;
        validate_raw_auth_len(len)?;
        let mut buf = vec![0u8; len];
        recv.read_exact(&mut buf).await?;
        decode_reauth_payload(&buf)
    })
    .await
    .map_err(|_| anyhow::anyhow!("Reauth read timeout"))??;

    let remote_ip = remote.ip();
    if reauth_rate_limited(state, remote_ip) {
        warn!("Rejecting in-band reauth from {remote}: auth rate limited");
        send_reauth_result(send, false).await?;
        return Ok(());
    }

    let validated = match keycloak.validate_token(&token).await {
        Ok(opt) => opt,
        Err(e) => {
            warn!("In-band reauth from {remote} validation error: {e}");
            record_reauth_result(state, remote_ip, false);
            send_reauth_result(send, false).await?;
            return Ok(());
        }
    };

    let accepted = match reauth_decision(validated, expected_sub) {
        Some(exp) => {
            // Push the new expiry to the tunnel watcher. A send error only means
            // the session is already ending, which is harmless here.
            let _ = expiry_tx.send(Some(exp));
            record_reauth_result(state, remote_ip, true);
            info!("In-band reauth accepted from {remote}; session extended (exp={exp})");
            true
        }
        None => {
            record_reauth_result(state, remote_ip, false);
            warn!("In-band reauth from {remote} rejected (invalid token or subject mismatch)");
            false
        }
    };

    send_reauth_result(send, accepted).await?;
    Ok(())
}

async fn send_reauth_result(mut send: quinn::SendStream, accepted: bool) -> Result<()> {
    let reply = encode_control_message_frame(&ControlMessage::ReauthResult { accepted })?;
    tokio::time::timeout(REAUTH_STREAM_TIMEOUT, async {
        send.write_all(&reply).await?;
        let _ = send.finish();
        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("Reauth reply timeout"))??;
    Ok(())
}

/// Decides whether a re-validated token may extend the session: it must validate
/// (`Some`) *and* carry the same subject the session was opened with. Returns the
/// new expiry to extend to, or `None` to reject (invalid token or subject
/// mismatch). Pure and side-effect free so the policy is unit-testable.
pub(crate) fn reauth_decision(
    validated: Option<ValidatedToken>,
    expected_sub: &str,
) -> Option<i64> {
    let token = validated?;
    (token.sub == expected_sub).then_some(token.exp)
}

pub(crate) fn reauth_rate_limited(state: &AppState, remote_ip: IpAddr) -> bool {
    state.auth_rate_limiter.is_blocked(remote_ip)
}

pub(crate) fn record_reauth_result(state: &AppState, remote_ip: IpAddr, accepted: bool) {
    if accepted {
        state.auth_rate_limiter.record_success(remote_ip);
    } else {
        state.auth_rate_limiter.record_failure(remote_ip);
    }
}

/// Decodes a length-checked reauth payload into the carried token, rejecting any
/// other control message.
pub(crate) fn decode_reauth_payload(buf: &[u8]) -> Result<String> {
    let msg: ControlMessage = bincode::serde::decode_from_slice(buf, bincode::config::standard())
        .map(|(v, _)| v)
        .map_err(|e| anyhow::anyhow!("Protocol error: {e}"))?;
    match msg {
        ControlMessage::Reauth { token } => Ok(token),
        _ => anyhow::bail!("Protocol error: Expected Reauth"),
    }
}
