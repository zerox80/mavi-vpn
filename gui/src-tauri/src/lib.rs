#![allow(clippy::multiple_crate_versions)]
//! # Mavi VPN GUI - Tauri Backend
//!
//! Communicates with the VPN daemon/service via TCP IPC on 127.0.0.1:14433.
//! Exposes Tauri commands for the web frontend and manages the system tray.

mod oauth;

use shared::ipc::{Config, IpcRequest, IpcResponse, VpnState, LOCAL_IPC_ADDR};
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    AppHandle, Emitter, Manager,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// =============================================================================
// IPC Communication with the VPN daemon/service
// =============================================================================

async fn send_ipc_request(req: &IpcRequest) -> Result<IpcResponse, String> {
    let token_path = shared::ipc::ipc_token_path();
    let auth_token = std::fs::read_to_string(&token_path)
        .map_err(|e| ipc_token_read_error(&token_path, e))?
        .trim()
        .to_string();

    let req_msg = shared::ipc::SecureIpcRequest {
        auth_token,
        request: req.clone(),
    };

    let mut stream = TcpStream::connect(LOCAL_IPC_ADDR)
        .await
        .map_err(|e| format!("Service not running: {e}"))?;

    let encoded = bincode::serde::encode_to_vec(&req_msg, bincode::config::standard())
        .map_err(|e| e.to_string())?;

    #[allow(clippy::cast_possible_truncation)]
    stream
        .write_u32_le(encoded.len() as u32)
        .await
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&encoded)
        .await
        .map_err(|e| e.to_string())?;

    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| e.to_string())?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 65536 {
        return Err("Response too large".into());
    }

    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| e.to_string())?;

    let (resp, _) = bincode::serde::decode_from_slice(&buf, bincode::config::standard())
        .map_err(|e| e.to_string())?;

    Ok(resp)
}

fn ipc_token_read_error(token_path: &std::path::Path, error: std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        if cfg!(target_os = "linux") {
            format!(
                "Failed to read IPC token at {}: permission denied. Your user must be in the 'mavivpn' group to control the daemon. Run `sudo usermod -aG mavivpn $USER`, log out and back in, then retry.",
                token_path.display()
            )
        } else if cfg!(target_os = "windows") {
            format!(
                "Failed to read IPC token at {}: permission denied. Your Windows user is not allowed to control the Mavi VPN service. Log in and restart the service so it can grant your desktop session access, or run the GUI as Administrator.",
                token_path.display()
            )
        } else {
            format!(
                "Failed to read IPC token at {}: permission denied.",
                token_path.display()
            )
        }
    } else {
        format!(
            "Failed to read IPC token (is the service running?) at {}: {error}",
            token_path.display()
        )
    }
}

// =============================================================================
// Tauri Commands (called from the frontend via invoke())
// =============================================================================

#[derive(serde::Serialize, Clone)]
struct VpnStatus {
    running: bool,
    endpoint: Option<String>,
    service_available: bool,
    state: VpnState,
    last_error: Option<String>,
    assigned_ip: Option<String>,
}

#[tauri::command]
async fn vpn_connect(mut config: Config) -> Result<String, String> {
    if config.kc_auth.unwrap_or(false) {
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
    }
    config.normalize_transport();

    match send_ipc_request(&IpcRequest::Start(config)).await? {
        IpcResponse::Ok => Ok("Connected".into()),
        IpcResponse::Error(e) => Err(e),
        IpcResponse::Status { .. } => Err("Unexpected response: Status instead of Ok".into()),
    }
}

#[tauri::command]
async fn vpn_disconnect() -> Result<String, String> {
    match send_ipc_request(&IpcRequest::Stop).await? {
        IpcResponse::Ok => Ok("Disconnected".into()),
        IpcResponse::Error(e) => Err(e),
        IpcResponse::Status { .. } => Err("Unexpected response: Status instead of Ok".into()),
    }
}

#[tauri::command]
async fn vpn_repair_network() -> Result<String, String> {
    match send_ipc_request(&IpcRequest::RepairNetwork).await? {
        IpcResponse::Ok => Ok("Network repaired".into()),
        IpcResponse::Error(e) => Err(e),
        IpcResponse::Status { .. } => Err("Unexpected response: Status instead of Ok".into()),
    }
}

#[tauri::command]
async fn vpn_status() -> Result<VpnStatus, String> {
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
        Err(_) => Ok(VpnStatus {
            running: false,
            endpoint: None,
            service_available: false,
            state: VpnState::Stopped,
            last_error: None,
            assigned_ip: None,
        }),
    }
}

#[tauri::command]
async fn save_config(app: AppHandle, mut config: Config) -> Result<(), String> {
    let config_dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&config_dir).map_err(|e| e.to_string())?;
    let config_path = config_dir.join("config.json");
    config.normalize_transport();
    let content = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
    std::fs::write(&config_path, content).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn load_config(app: AppHandle) -> Result<Option<Config>, String> {
    let config_dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    let config_path = config_dir.join("config.json");
    if !config_path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(config_path).map_err(|e| e.to_string())?;
    let mut config: Config = serde_json::from_str(&content).map_err(|e| e.to_string())?;
    config.normalize_transport();
    Ok(Some(config))
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Default)]
struct SavedConn {
    id: String,
    label: String,
    endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    cert_pin: String,
    #[serde(default)]
    ech_config: Option<String>,
    #[serde(default)]
    http3_framing: bool,
    #[serde(default)]
    censorship_resistant: bool,
    #[serde(default)]
    kc_auth: Option<bool>,
    #[serde(default)]
    kc_url: Option<String>,
    #[serde(default)]
    kc_realm: Option<String>,
    #[serde(default)]
    kc_client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vpn_mtu: Option<u16>,
}

impl SavedConn {
    const fn normalize_transport(&mut self) -> bool {
        let old_http3_framing = self.http3_framing;
        if self.censorship_resistant {
            self.http3_framing = true;
        }
        self.http3_framing != old_http3_framing
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct Prefs {
    #[serde(default = "default_theme")]
    theme: String,
    #[serde(default = "default_accent")]
    accent: String,
    #[serde(default)]
    connections: Vec<SavedConn>,
    #[serde(default)]
    active_id: Option<String>,
    #[serde(default)]
    legacy_config_migrated: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            theme: default_theme(),
            accent: default_accent(),
            connections: vec![],
            active_id: None,
            legacy_config_migrated: false,
        }
    }
}

impl Prefs {
    fn normalize_transport(&mut self) -> bool {
        let mut changed = false;
        for conn in &mut self.connections {
            changed |= conn.normalize_transport();
        }
        changed
    }
}

fn default_theme() -> String {
    "light".into()
}
fn default_accent() -> String {
    "#2B44FF".into()
}

#[tauri::command]
async fn load_prefs(app: AppHandle) -> Result<Prefs, String> {
    let config_dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    let prefs_path = config_dir.join("prefs.json");
    if !prefs_path.exists() {
        return Ok(Prefs::default());
    }
    let content = std::fs::read_to_string(prefs_path).map_err(|e| e.to_string())?;
    let mut prefs: Prefs = serde_json::from_str(&content).map_err(|e| e.to_string())?;
    prefs.normalize_transport();
    Ok(prefs)
}

#[tauri::command]
async fn save_prefs(app: AppHandle, mut prefs: Prefs) -> Result<(), String> {
    let config_dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&config_dir).map_err(|e| e.to_string())?;
    let prefs_path = config_dir.join("prefs.json");
    prefs.normalize_transport();
    let content = serde_json::to_string_pretty(&prefs).map_err(|e| e.to_string())?;
    std::fs::write(&prefs_path, content).map_err(|e| e.to_string())?;
    Ok(())
}

fn setup_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let show = MenuItem::with_id(app, "show", "Show", true, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle", "Connect", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &toggle, &quit])?;

    TrayIconBuilder::new()
        .menu(&menu)
        .tooltip("Mavi VPN - Disconnected")
        .on_menu_event(move |app, event| match event.id().as_ref() {
            "show" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "toggle" => {
                let _ = app.emit("tray-toggle", ());
            }
            "quit" => {
                app.exit(0);
            }
            _ => {}
        })
        .build(app)?;
    Ok(())
}

fn start_status_poller(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            let status = match send_ipc_request(&IpcRequest::Status).await {
                Ok(IpcResponse::Status {
                    running,
                    endpoint,
                    state,
                    last_error,
                    assigned_ip,
                }) => VpnStatus {
                    running,
                    endpoint,
                    service_available: true,
                    state,
                    last_error,
                    assigned_ip,
                },
                _ => VpnStatus {
                    running: false,
                    endpoint: None,
                    service_available: false,
                    state: VpnState::Stopped,
                    last_error: None,
                    assigned_ip: None,
                },
            };
            let _ = app.emit("vpn-status-update", &status);
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
/// Entry point for the Mavi VPN GUI application.
///
/// # Panics
/// Panics if the Tauri application fails to start.
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            vpn_connect,
            vpn_disconnect,
            vpn_repair_network,
            vpn_status,
            save_config,
            load_config,
            load_prefs,
            save_prefs,
        ])
        .setup(|app| {
            setup_tray(app)?;
            start_status_poller(app.handle().clone());
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Mavi VPN GUI");
}
