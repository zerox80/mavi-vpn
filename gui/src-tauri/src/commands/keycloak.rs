use crate::ipc::send_ipc_request;
use crate::oauth;
use crate::secret_store::{connection_refresh_token_account, KeyringSecretStore, SecretStore};
use shared::ipc::{Config, IpcRequest};
use shared::kc_oauth::{self, RefreshOutcome};
use std::time::Duration;
use tauri::async_runtime::JoinHandle;
#[cfg(not(target_os = "windows"))]
use tauri::Emitter;
use tauri::{AppHandle, Manager};
use tracing::{debug, info, warn};

#[cfg(not(target_os = "windows"))]
mod refresh;
#[cfg(any(target_os = "windows", test))]
mod service_sync;

/// Refresh the access token this many seconds before its `exp`, leaving headroom
/// for the refresh round-trip and the reconnect handshake (matches Android's
/// active-session skew).
#[cfg(not(target_os = "windows"))]
const REFRESH_SKEW_SECS: u64 = 300;

/// How often the background ticker checks whether the access token needs a refresh.
#[cfg(not(target_os = "windows"))]
const REFRESH_TICK: Duration = Duration::from_secs(30);

/// On Windows the persistence loop lives for the GUI's entire lifetime.
/// Other platforms replace their access-token ticker on connect/disconnect.
#[derive(Default)]
pub(crate) struct TokenRefreshHandle(pub(crate) std::sync::Mutex<Option<JoinHandle<()>>>);

/// Keycloak coordinates captured at connect time so the active session can be
/// renewed without re-reading config.
#[cfg_attr(target_os = "windows", allow(dead_code))]
pub(super) struct KeycloakSession {
    pub(super) kc_url: String,
    pub(super) realm: String,
    pub(super) client_id: String,
    pub(super) connection_id: String,
    pub(super) access_token: String,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub(super) refresh_token: String,
}

/// Ensures `config.token` holds a fresh Keycloak access token before connecting.
///
/// When `force_login` is `true` (a manual, user-initiated connect) this always
/// runs the interactive browser login, so every manual connect re-authenticates.
/// When `false` (an automatic/programmatic connect) it prefers a **silent**
/// refresh using the stored refresh token and only falls back to the browser
/// login when there is no refresh token or it has been rejected, so auto-connect
/// does not pop a browser. Returns the session coordinates when Keycloak is in
/// use so the caller can start the platform-specific in-session refresh work.
pub(super) async fn prepare_keycloak_config(
    config: &mut Config,
    connection_id: &str,
    force_login: bool,
) -> Result<Option<KeycloakSession>, String> {
    if !config.kc_auth.unwrap_or(false) {
        debug!(connection_id = %connection_id, "Keycloak disabled for connection");
        return Ok(None);
    }

    let kc_url = config.kc_url.as_deref().unwrap_or("").to_string();
    let realm = config.kc_realm.clone().unwrap_or_else(|| "mavi-vpn".into());
    let client_id = config
        .kc_client_id
        .clone()
        .unwrap_or_else(|| "mavi-client".into());

    if kc_url.is_empty() {
        warn!(connection_id = %connection_id, "Keycloak URL missing");
        return Err("Keycloak URL is not configured.".into());
    }

    info!(
        connection_id = %connection_id,
        kc_url = %kc_url,
        realm = %realm,
        client_id = %client_id,
        force_login,
        "Preparing Keycloak session"
    );

    let store = KeyringSecretStore;
    let refresh_account = connection_refresh_token_account(connection_id);

    // Automatic (non-manual) connect: silently refresh using a stored refresh
    // token if we have one, so auto-connect does not pop a browser. A manual
    // connect (`force_login`) deliberately skips this and re-authenticates below.
    if !force_login {
        if let Some(refresh_token) = store
            .get_secret(&refresh_account)?
            .filter(|t| !t.is_empty())
        {
            info!(
                connection_id = %connection_id,
                "Attempting silent Keycloak refresh before connect"
            );
            match kc_oauth::refresh_access_token(&kc_url, &realm, &client_id, &refresh_token).await
            {
                RefreshOutcome::Success(tokens) => {
                    let active_refresh_token =
                        required_refresh_token(tokens.refresh_token.as_deref())?;
                    persist_refresh_token(&store, &refresh_account, Some(&active_refresh_token))?;
                    config.token = tokens.access_token.clone();
                    info!(
                        connection_id = %connection_id,
                        "Silent Keycloak refresh succeeded before connect"
                    );
                    return Ok(Some(KeycloakSession {
                        kc_url,
                        realm,
                        client_id,
                        connection_id: connection_id.to_string(),
                        access_token: tokens.access_token,
                        refresh_token: active_refresh_token,
                    }));
                }
                RefreshOutcome::NetworkError(e) => {
                    warn!(
                        connection_id = %connection_id,
                        error = %e,
                        "Silent Keycloak refresh failed due to network error"
                    );
                    return Err(format!(
                        "Could not reach Keycloak to refresh the session: {e}"
                    ));
                }
                RefreshOutcome::NeedsLogin(_) => {
                    info!(
                        connection_id = %connection_id,
                        "Stored Keycloak refresh token requires a fresh browser login"
                    );
                    // Refresh token is dead, so drop it and fall through to browser login.
                    let _ = store.delete_secret(&refresh_account);
                }
            }
        }
    }

    // Interactive browser login (PKCE). For a manual connect this always runs, so
    // every manual connect re-authenticates. The refresh token obtained now is
    // persisted. Windows hands the active refresh token to the service for this
    // session; other platforms use the GUI ticker + in-band reauth to keep the
    // live tunnel alive silently, without ever re-prompting mid-session.
    info!(connection_id = %connection_id, "Starting interactive Keycloak login");
    let tokens = oauth::start_oauth_flow(&kc_url, &realm, &client_id)
        .await
        .map_err(|e| format!("Keycloak login failed: {e}"))?;
    let active_refresh_token = required_refresh_token(tokens.refresh_token.as_deref())?;
    persist_refresh_token(&store, &refresh_account, Some(&active_refresh_token))?;
    config.token = tokens.access_token.clone();
    info!(connection_id = %connection_id, "Interactive Keycloak login succeeded");
    Ok(Some(KeycloakSession {
        kc_url,
        realm,
        client_id,
        connection_id: connection_id.to_string(),
        access_token: tokens.access_token,
        refresh_token: active_refresh_token,
    }))
}

fn required_refresh_token(refresh: Option<&str>) -> Result<String, String> {
    refresh
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "Keycloak did not issue a refresh token; please log in again.".to_string())
}

/// Stores a (possibly rotated) refresh token in the OS keyring. A `None`/empty
/// value leaves any existing token untouched.
fn persist_refresh_token(
    store: &dyn SecretStore,
    account: &str,
    refresh: Option<&str>,
) -> Result<(), String> {
    match refresh {
        Some(r) if !r.is_empty() => store.set_secret(account, r),
        _ => Ok(()),
    }
}

/// Spawns the non-Windows background refresh ticker, replacing any previous one.
#[cfg(not(target_os = "windows"))]
pub(super) fn start_token_refresh_ticker(app: &AppHandle, session: KeycloakSession) {
    stop_token_refresh_ticker(app);
    let app_for_task = app.clone();
    let handle = tauri::async_runtime::spawn(token_refresh_loop(app_for_task, session));
    if let Some(state) = app.try_state::<TokenRefreshHandle>() {
        if let Ok(mut slot) = state.0.lock() {
            *slot = Some(handle);
        }
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn start_service_refresh_token_sync(app: &AppHandle) {
    if let Some(state) = app.try_state::<TokenRefreshHandle>() {
        if let Ok(mut slot) = state.0.lock() {
            if slot.is_none() {
                info!("Starting Windows service refresh-token sync loop");
                let app_for_task = app.clone();
                *slot = Some(tauri::async_runtime::spawn(
                    service_refresh_token_sync_loop(app_for_task),
                ));
            }
        }
    }
}

/// Aborts the non-Windows access-token ticker. Windows keeps syncing pending
/// refresh tokens for the entire GUI lifetime, including after disconnect.
pub(super) fn stop_token_refresh_ticker(app: &AppHandle) {
    // Pending rotations still need saving after Stop or a cancelled Start.
    if cfg!(target_os = "windows") {
        return;
    }
    if let Some(state) = app.try_state::<TokenRefreshHandle>() {
        if let Ok(mut slot) = state.0.lock() {
            if let Some(handle) = slot.take() {
                handle.abort();
            }
        }
    }
}

#[cfg(target_os = "windows")]
async fn service_refresh_token_sync_loop(app: AppHandle) {
    loop {
        {
            // Serialize keyring writes with connect/login, so an old queued
            // update cannot overwrite credentials from a fresh browser login.
            let lifecycle = app.state::<super::ConnectionLifecycle>();
            let _operation = lifecycle.operation.lock().await;
            if let Err(error) = sync_service_refresh_tokens().await {
                warn!(error = %error, "Could not save service refresh-token updates; will retry");
            }
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

#[cfg(target_os = "windows")]
pub(super) async fn sync_service_refresh_tokens() -> Result<(), String> {
    while service_sync::sync_refresh_token_update(&KeyringSecretStore, |request| async move {
        send_ipc_request(&request).await
    })
    .await?
    {}
    Ok(())
}

/// Background loop: while connected, refresh the access token before it expires
/// and push it to the service via `UpdateToken`. Distinguishes transient network
/// failures (keep retrying) from a dead refresh token (`kc-needs-login` -> stop).
#[cfg(not(target_os = "windows"))]
async fn token_refresh_loop(app: AppHandle, mut session: KeycloakSession) {
    use refresh::{refresh_tick, TickError, TickOutcome};

    let store = KeyringSecretStore;
    let refresh_account = connection_refresh_token_account(&session.connection_id);
    let mut pending_token = None;
    info!(
        connection_id = %session.connection_id,
        "Starting GUI Keycloak access-token refresh loop"
    );

    loop {
        tokio::time::sleep(REFRESH_TICK).await;

        let (kc_url, realm, client_id) = (&session.kc_url, &session.realm, &session.client_id);
        let result = refresh_tick(
            &mut session.access_token,
            &mut pending_token,
            &store,
            &refresh_account,
            |token| async move {
                kc_oauth::refresh_access_token(kc_url, realm, client_id, &token).await
            },
            |token| async move { send_ipc_request(&IpcRequest::UpdateToken { token }).await },
        )
        .await;
        match result {
            Ok(TickOutcome::Skipped) => {}
            Ok(TickOutcome::Delivered) => info!(
                connection_id = %session.connection_id,
                "Refreshed Keycloak access token and notified service"
            ),
            Err(TickError::Delivery(error)) => warn!(
                connection_id = %session.connection_id,
                error = %error,
                "Failed to deliver refreshed Keycloak access token; will retry"
            ),
            // Transient: keep the tunnel up and try again on the next tick.
            Err(TickError::Network(error)) => {
                warn!(
                    connection_id = %session.connection_id,
                    error = %error,
                    "Keycloak access-token refresh failed due to network error"
                );
            }
            Err(TickError::NeedsLogin(msg)) => {
                warn!(
                    connection_id = %session.connection_id,
                    "Keycloak refresh token requires a fresh login during active session"
                );
                let _ = store.delete_secret(&refresh_account);
                let _ = send_ipc_request(&IpcRequest::Stop).await;
                let _ = app.emit("kc-needs-login", msg);
                break;
            }
            Err(TickError::Persistence(error)) => {
                warn!(connection_id = %session.connection_id, error = %error,
                    "Failed to persist rotated Keycloak refresh token");
                let _ = send_ipc_request(&IpcRequest::Stop).await;
                let _ = app.emit(
                    "kc-needs-login",
                    format!("Session could not be saved; please log in again. {error}"),
                );
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests;
