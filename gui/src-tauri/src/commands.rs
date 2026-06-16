use crate::ipc::send_ipc_request;
use crate::oauth;
use crate::secret_store::{
    connection_refresh_token_account, KeyringSecretStore, SecretStore,
};
use crate::storage::{load_config_from_dir, load_prefs_from_dir, save_config_to_dir};
use crate::storage::{save_prefs_to_dir, Prefs};
use shared::ipc::{Config, IpcRequest, IpcResponse, VpnState};
use shared::kc_oauth::{self, RefreshOutcome};
use std::time::Duration;
use tauri::async_runtime::JoinHandle;
use tauri::{AppHandle, Emitter, Manager};

/// Refresh the access token this many seconds before its `exp`, leaving headroom
/// for the refresh round-trip and the reconnect handshake (matches Android's
/// active-session skew).
const REFRESH_SKEW_SECS: u64 = 300;

/// How often the background ticker checks whether the access token needs a refresh.
const REFRESH_TICK: Duration = Duration::from_secs(30);

/// Tauri-managed handle to the running Keycloak refresh ticker, so a new connect
/// can replace it and a disconnect can abort it.
#[derive(Default)]
pub(crate) struct TokenRefreshHandle(pub(crate) std::sync::Mutex<Option<JoinHandle<()>>>);

/// Keycloak coordinates captured at connect time so the background ticker can
/// renew the access token without re-reading config.
struct KeycloakSession {
    kc_url: String,
    realm: String,
    client_id: String,
    connection_id: String,
    access_token: String,
}

#[derive(serde::Serialize, Clone)]
pub(crate) struct VpnStatus {
    pub(crate) running: bool,
    pub(crate) endpoint: Option<String>,
    pub(crate) service_available: bool,
    pub(crate) state: VpnState,
    pub(crate) last_error: Option<String>,
    pub(crate) assigned_ip: Option<String>,
}

#[tauri::command]
pub(crate) async fn vpn_connect(
    app: AppHandle,
    mut config: Config,
    connection_id: String,
) -> Result<String, String> {
    let kc_session = prepare_keycloak_config(&mut config, &connection_id).await?;
    config.normalize_transport();

    match send_ipc_request(&IpcRequest::Start(config)).await? {
        IpcResponse::Ok => {
            // Only once the service accepted the Start do we arm the refresh
            // ticker, so a rejected connect does not leave a ticker running.
            if let Some(session) = kc_session {
                start_token_refresh_ticker(&app, session);
            }
            Ok("Connected".into())
        }
        IpcResponse::Error(e) => Err(e),
        IpcResponse::Status { .. } => Err("Unexpected response: Status instead of Ok".into()),
    }
}

/// Ensures `config.token` holds a fresh Keycloak access token before connecting.
///
/// Prefers a **silent** refresh using the stored refresh token (no browser); only
/// falls back to the interactive browser login when there is no refresh token or
/// it has been rejected. Returns the session coordinates when Keycloak is in use
/// so the caller can start the background refresh ticker.
async fn prepare_keycloak_config(
    config: &mut Config,
    connection_id: &str,
) -> Result<Option<KeycloakSession>, String> {
    if !config.kc_auth.unwrap_or(false) {
        return Ok(None);
    }

    let kc_url = config.kc_url.as_deref().unwrap_or("").to_string();
    let realm = config.kc_realm.clone().unwrap_or_else(|| "mavi-vpn".into());
    let client_id = config
        .kc_client_id
        .clone()
        .unwrap_or_else(|| "mavi-client".into());

    if kc_url.is_empty() {
        return Err("Keycloak URL is not configured.".into());
    }

    let store = KeyringSecretStore;
    let refresh_account = connection_refresh_token_account(connection_id);

    // 1. Silent refresh if we already hold a refresh token for this connection.
    if let Some(refresh_token) = store
        .get_secret(&refresh_account)?
        .filter(|t| !t.is_empty())
    {
        match kc_oauth::refresh_access_token(&kc_url, &realm, &client_id, &refresh_token).await {
            RefreshOutcome::Success(tokens) => {
                persist_refresh_token(&store, &refresh_account, tokens.refresh_token.as_deref())?;
                config.token = tokens.access_token.clone();
                return Ok(Some(KeycloakSession {
                    kc_url,
                    realm,
                    client_id,
                    connection_id: connection_id.to_string(),
                    access_token: tokens.access_token,
                }));
            }
            RefreshOutcome::NetworkError(e) => {
                return Err(format!("Could not reach Keycloak to refresh the session: {e}"));
            }
            RefreshOutcome::NeedsLogin(_) => {
                // Refresh token is dead — drop it and fall through to a browser login.
                let _ = store.delete_secret(&refresh_account);
            }
        }
    }

    // 2. Interactive browser login (PKCE).
    let tokens = oauth::start_oauth_flow(&kc_url, &realm, &client_id)
        .await
        .map_err(|e| format!("Keycloak login failed: {e}"))?;
    persist_refresh_token(&store, &refresh_account, tokens.refresh_token.as_deref())?;
    config.token = tokens.access_token.clone();
    Ok(Some(KeycloakSession {
        kc_url,
        realm,
        client_id,
        connection_id: connection_id.to_string(),
        access_token: tokens.access_token,
    }))
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

/// Spawns the background refresh ticker, replacing any previous one.
fn start_token_refresh_ticker(app: &AppHandle, session: KeycloakSession) {
    stop_token_refresh_ticker(app);
    let app_for_task = app.clone();
    let handle = tauri::async_runtime::spawn(token_refresh_loop(app_for_task, session));
    if let Some(state) = app.try_state::<TokenRefreshHandle>() {
        if let Ok(mut slot) = state.0.lock() {
            *slot = Some(handle);
        }
    }
}

/// Aborts a running refresh ticker, if any.
pub(crate) fn stop_token_refresh_ticker(app: &AppHandle) {
    if let Some(state) = app.try_state::<TokenRefreshHandle>() {
        if let Ok(mut slot) = state.0.lock() {
            if let Some(handle) = slot.take() {
                handle.abort();
            }
        }
    }
}

/// Background loop: while connected, refresh the access token before it expires
/// and push it to the service via `UpdateToken`. Distinguishes transient network
/// failures (keep retrying) from a dead refresh token (`kc-needs-login` → stop).
async fn token_refresh_loop(app: AppHandle, mut session: KeycloakSession) {
    let store = KeyringSecretStore;
    let refresh_account = connection_refresh_token_account(&session.connection_id);

    loop {
        tokio::time::sleep(REFRESH_TICK).await;

        if kc_oauth::is_access_token_usable(&session.access_token, REFRESH_SKEW_SECS) {
            continue;
        }

        let Some(refresh_token) = store
            .get_secret(&refresh_account)
            .ok()
            .flatten()
            .filter(|t| !t.is_empty())
        else {
            let _ = send_ipc_request(&IpcRequest::Stop).await;
            let _ = app.emit("kc-needs-login", "Session expired; please log in again.");
            break;
        };

        match kc_oauth::refresh_access_token(
            &session.kc_url,
            &session.realm,
            &session.client_id,
            &refresh_token,
        )
        .await
        {
            RefreshOutcome::Success(tokens) => {
                if let Err(e) =
                    persist_refresh_token(&store, &refresh_account, tokens.refresh_token.as_deref())
                {
                    let _ = send_ipc_request(&IpcRequest::Stop).await;
                    let _ = app.emit(
                        "kc-needs-login",
                        format!("Session could not be saved; please log in again. {e}"),
                    );
                    break;
                }

                session.access_token = tokens.access_token.clone();
                let _ = send_ipc_request(&IpcRequest::UpdateToken {
                    token: tokens.access_token,
                })
                .await;
            }
            // Transient: keep the tunnel up and try again on the next tick.
            RefreshOutcome::NetworkError(_) => {}
            RefreshOutcome::NeedsLogin(msg) => {
                let _ = store.delete_secret(&refresh_account);
                let _ = send_ipc_request(&IpcRequest::Stop).await;
                let _ = app.emit("kc-needs-login", msg);
                break;
            }
        }
    }
}

#[tauri::command]
pub(crate) async fn vpn_disconnect(app: AppHandle) -> Result<String, String> {
    stop_token_refresh_ticker(&app);
    match send_ipc_request(&IpcRequest::Stop).await? {
        IpcResponse::Ok => Ok("Disconnected".into()),
        IpcResponse::Error(e) => Err(e),
        IpcResponse::Status { .. } => Err("Unexpected response: Status instead of Ok".into()),
    }
}

#[tauri::command]
pub(crate) async fn vpn_repair_network() -> Result<String, String> {
    match send_ipc_request(&IpcRequest::RepairNetwork).await? {
        IpcResponse::Ok => Ok("Network repaired".into()),
        IpcResponse::Error(e) => Err(e),
        IpcResponse::Status { .. } => Err("Unexpected response: Status instead of Ok".into()),
    }
}

#[tauri::command]
pub(crate) async fn vpn_status() -> Result<VpnStatus, String> {
    match send_ipc_request(&IpcRequest::Status).await {
        Ok(IpcResponse::Status {
            running,
            endpoint,
            state,
            last_error,
            assigned_ip,
        }) => Ok(VpnStatus {
            running,
            endpoint,
            service_available: true,
            state,
            last_error,
            assigned_ip,
        }),
        Ok(IpcResponse::Error(e)) => Err(e),
        Ok(_) => Err("Unexpected response".into()),
        Err(_) => Ok(VpnStatus::service_unavailable()),
    }
}

#[tauri::command]
pub(crate) async fn save_config(app: AppHandle, mut config: Config) -> Result<(), String> {
    let config_dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    save_config_to_dir(&config_dir, &mut config)
}

#[tauri::command]
pub(crate) async fn load_config(app: AppHandle) -> Result<Option<Config>, String> {
    let config_dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    load_config_from_dir(&config_dir)
}

#[tauri::command]
pub(crate) async fn load_prefs(app: AppHandle) -> Result<Prefs, String> {
    let config_dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    load_prefs_from_dir(&config_dir)
}

#[tauri::command]
pub(crate) async fn save_prefs(app: AppHandle, mut prefs: Prefs) -> Result<(), String> {
    let config_dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    save_prefs_to_dir(&config_dir, &mut prefs)
}

impl VpnStatus {
    pub(crate) const fn service_unavailable() -> Self {
        Self {
            running: false,
            endpoint: None,
            service_available: false,
            state: VpnState::Stopped,
            last_error: None,
            assigned_ip: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            endpoint: "vpn.example.com:443".to_string(),
            token: "token".to_string(),
            cert_pin: "pin".to_string(),
            censorship_resistant: false,
            http3_framing: false,
            kc_auth: None,
            kc_url: None,
            kc_realm: None,
            kc_client_id: None,
            ech_config: None,
            vpn_mtu: None,
        }
    }

    #[tokio::test]
    async fn keycloak_config_requires_url() {
        let mut config = test_config();
        config.kc_auth = Some(true);
        config.kc_url = Some(String::new());

        let result = prepare_keycloak_config(&mut config, "test-conn").await;

        // Avoid `unwrap_err` so the success type (which holds a token) needs no
        // Debug impl — `.err()` discards the Ok value entirely.
        assert_eq!(
            result.err(),
            Some("Keycloak URL is not configured.".to_string())
        );
    }

    #[tokio::test]
    async fn prepare_skips_when_keycloak_disabled() {
        let mut config = test_config();
        config.kc_auth = None;

        // No Keycloak → no session, token left as-is, no keyring/network touched.
        let result = prepare_keycloak_config(&mut config, "test-conn").await;

        assert!(result.unwrap().is_none());
        assert_eq!(config.token, "token");
    }

    #[test]
    fn persist_refresh_token_skips_empty_values() {
        use crate::secret_store::tests::MemorySecretStore;

        let store = MemorySecretStore::default();
        persist_refresh_token(&store, "acc", None).unwrap();
        persist_refresh_token(&store, "acc", Some("")).unwrap();
        assert!(store.secret("acc").is_none());

        persist_refresh_token(&store, "acc", Some("refresh-xyz")).unwrap();
        assert_eq!(store.secret("acc").as_deref(), Some("refresh-xyz"));
    }
}
