use crate::ipc::send_ipc_request;
use crate::oauth;
use crate::storage::{load_config_from_dir, load_prefs_from_dir, save_config_to_dir};
use crate::storage::{save_prefs_to_dir, Prefs};
use shared::ipc::{Config, IpcRequest, IpcResponse, VpnState};
use tauri::{AppHandle, Manager};

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
pub(crate) async fn vpn_connect(mut config: Config) -> Result<String, String> {
    prepare_keycloak_config(&mut config).await?;
    config.normalize_transport();

    match send_ipc_request(&IpcRequest::Start(config)).await? {
        IpcResponse::Ok => Ok("Connected".into()),
        IpcResponse::Error(e) => Err(e),
        IpcResponse::Status { .. } => Err("Unexpected response: Status instead of Ok".into()),
    }
}

async fn prepare_keycloak_config(config: &mut Config) -> Result<(), String> {
    if !config.kc_auth.unwrap_or(false) {
        return Ok(());
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

    let token = oauth::start_oauth_flow(&kc_url, &realm, &client_id)
        .await
        .map_err(|e| format!("Keycloak login failed: {e}"))?;

    config.token = token;
    Ok(())
}

#[tauri::command]
pub(crate) async fn vpn_disconnect() -> Result<String, String> {
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

        let result = prepare_keycloak_config(&mut config).await;

        assert_eq!(result.unwrap_err(), "Keycloak URL is not configured.");
    }
}
