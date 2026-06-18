mod keycloak;

use crate::ipc::send_ipc_request;
use crate::storage::{load_config_from_dir, load_prefs_from_dir, save_config_to_dir};
use crate::storage::{save_prefs_to_dir, Prefs};
#[cfg(target_os = "windows")]
use keycloak::start_service_refresh_token_sync;
#[cfg(not(target_os = "windows"))]
use keycloak::start_token_refresh_ticker;
pub(crate) use keycloak::TokenRefreshHandle;
use keycloak::{prepare_keycloak_config, stop_token_refresh_ticker};
#[cfg(target_os = "windows")]
use shared::ipc::KeycloakRuntimeAuth;
use shared::ipc::{Config, IpcRequest, IpcResponse, VpnState};
use tauri::{AppHandle, Manager};
use tracing::{info, warn};

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
    // `true` for a user-initiated (manual) connect: forces a fresh interactive
    // Keycloak login. `false` for an automatic/programmatic connect: a stored
    // refresh token is used silently when available, so auto-connect does not
    // pop a browser. Defaults to `false` when the caller omits it.
    force_login: Option<bool>,
) -> Result<String, String> {
    let force_login = force_login.unwrap_or(false);
    let kc_session = prepare_keycloak_config(&mut config, &connection_id, force_login).await?;
    config.normalize_transport();
    let endpoint = config.endpoint.clone();
    let keycloak_enabled = kc_session.is_some();
    let transport = if config.effective_http3_framing() {
        "http3"
    } else {
        "raw"
    };

    info!(
        connection_id = %connection_id,
        endpoint = %endpoint,
        keycloak_enabled,
        transport,
        "VPN connect requested"
    );

    #[cfg(target_os = "windows")]
    let request = match kc_session.as_ref() {
        Some(session) => IpcRequest::StartWithKeycloak {
            config,
            keycloak: KeycloakRuntimeAuth {
                connection_id: session.connection_id.clone(),
                kc_url: session.kc_url.clone(),
                realm: session.realm.clone(),
                client_id: session.client_id.clone(),
                refresh_token: session.refresh_token.clone(),
            },
        },
        None => IpcRequest::Start(config),
    };

    #[cfg(not(target_os = "windows"))]
    let request = IpcRequest::Start(config);

    let response = match send_ipc_request(&request).await {
        Ok(response) => response,
        Err(error) => {
            warn!(
                connection_id = %connection_id,
                endpoint = %endpoint,
                error = %error,
                "VPN connect IPC request failed"
            );
            return Err(error);
        }
    };

    match response {
        IpcResponse::Ok => {
            info!(
                connection_id = %connection_id,
                endpoint = %endpoint,
                "VPN start accepted by service"
            );
            // Only once the service accepted the Start do we arm the Keycloak
            // background task, so a rejected connect does not leave one running.
            if let Some(session) = kc_session {
                #[cfg(target_os = "windows")]
                {
                    drop(session);
                    start_service_refresh_token_sync(&app);
                }
                #[cfg(not(target_os = "windows"))]
                start_token_refresh_ticker(&app, session);
            }
            Ok("Connected".into())
        }
        IpcResponse::Error(e) => {
            warn!(
                connection_id = %connection_id,
                endpoint = %endpoint,
                error = %e,
                "VPN start rejected by service"
            );
            Err(e)
        }
        IpcResponse::Status { .. } => Err("Unexpected response: Status instead of Ok".into()),
        IpcResponse::RefreshTokenUpdate { .. } => {
            Err("Unexpected response: RefreshTokenUpdate instead of Ok".into())
        }
    }
}

#[tauri::command]
pub(crate) async fn vpn_disconnect(app: AppHandle) -> Result<String, String> {
    info!("VPN disconnect requested");
    stop_token_refresh_ticker(&app);
    let response = match send_ipc_request(&IpcRequest::Stop).await {
        Ok(response) => response,
        Err(error) => {
            warn!(error = %error, "VPN disconnect IPC request failed");
            return Err(error);
        }
    };

    match response {
        IpcResponse::Ok => {
            info!("VPN stop accepted by service");
            Ok("Disconnected".into())
        }
        IpcResponse::Error(e) => {
            warn!(error = %e, "VPN stop rejected by service");
            Err(e)
        }
        IpcResponse::Status { .. } => Err("Unexpected response: Status instead of Ok".into()),
        IpcResponse::RefreshTokenUpdate { .. } => {
            Err("Unexpected response: RefreshTokenUpdate instead of Ok".into())
        }
    }
}

#[tauri::command]
pub(crate) async fn vpn_repair_network() -> Result<String, String> {
    info!("VPN network repair requested");
    let response = match send_ipc_request(&IpcRequest::RepairNetwork).await {
        Ok(response) => response,
        Err(error) => {
            warn!(error = %error, "VPN network repair IPC request failed");
            return Err(error);
        }
    };

    match response {
        IpcResponse::Ok => {
            info!("VPN network repair accepted by service");
            Ok("Network repaired".into())
        }
        IpcResponse::Error(e) => {
            warn!(error = %e, "VPN network repair rejected by service");
            Err(e)
        }
        IpcResponse::Status { .. } => Err("Unexpected response: Status instead of Ok".into()),
        IpcResponse::RefreshTokenUpdate { .. } => {
            Err("Unexpected response: RefreshTokenUpdate instead of Ok".into())
        }
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
