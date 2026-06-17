//! Background Keycloak access-token refresh for the live Windows session.
//!
//! When the VPN was started with a Keycloak refresh token, this task renews the
//! short-lived access token before it expires and writes the fresh token into
//! `current_token`. The existing in-band reauth task picks it up and presents it
//! to the server, so the live tunnel survives the original token's expiry.

use shared::kc_oauth::{self, RefreshOutcome};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tracing::{info, warn};

/// Refresh the access token this many seconds before its `exp`, leaving headroom
/// for the refresh round-trip and the in-band reauth exchange.
const REFRESH_SKEW_SECS: u64 = 300;

/// How often the background task checks whether the access token needs renewal.
const REFRESH_TICK: Duration = Duration::from_secs(30);

/// Spawns a background task that silently refreshes the Keycloak access token
/// while the VPN session is active. Exits when either `running` or
/// `session_alive` is cleared.
pub(super) fn spawn_refresh_task(
    current_token: Arc<StdMutex<String>>,
    refresh_token: Arc<StdMutex<Option<String>>>,
    running: Arc<AtomicBool>,
    session_alive: Arc<AtomicBool>,
    kc_url: String,
    realm: String,
    client_id: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while running.load(Ordering::Relaxed) && session_alive.load(Ordering::Relaxed) {
            tokio::time::sleep(REFRESH_TICK).await;
            if !running.load(Ordering::Relaxed) || !session_alive.load(Ordering::Relaxed) {
                break;
            }

            let token = match current_token.lock() {
                Ok(t) => t.clone(),
                Err(_) => continue,
            };
            if kc_oauth::is_access_token_usable(&token, REFRESH_SKEW_SECS) {
                continue;
            }

            let refresh = match refresh_token.lock() {
                Ok(guard) => guard.clone().filter(|r| !r.is_empty()),
                Err(_) => None,
            };
            let Some(refresh) = refresh else {
                warn!("Keycloak refresh token unavailable; session will expire");
                break;
            };

            match kc_oauth::refresh_access_token(&kc_url, &realm, &client_id, &refresh).await {
                RefreshOutcome::Success(tokens) => {
                    if let Ok(mut current) = current_token.lock() {
                        *current = tokens.access_token.clone();
                    }
                    if let Ok(mut stored) = refresh_token.lock() {
                        *stored = tokens.refresh_token.clone();
                    }
                    info!("Keycloak access token refreshed in the background");
                }
                RefreshOutcome::NetworkError(e) => {
                    warn!("Keycloak refresh failed (network): {e}; retrying later");
                }
                RefreshOutcome::NeedsLogin(e) => {
                    warn!("Keycloak refresh rejected: {e}; session cannot be extended");
                    session_alive.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }
    })
}
