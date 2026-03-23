//! # Mavi VPN GUI - Tauri Backend
//!
//! Communicates with the VPN daemon/service via TCP IPC on 127.0.0.1:14433.
//! Exposes Tauri commands for the web frontend and manages the system tray.

mod oauth;

use shared::ipc::{Config, IpcRequest, IpcResponse, LOCAL_IPC_ADDR};
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
    let mut stream = TcpStream::connect(LOCAL_IPC_ADDR)
        .await
        .map_err(|e| format!("Service not running: {}", e))?;

    let encoded = bincode::serde::encode_to_vec(req, bincode::config::standard())
        .map_err(|e| e.to_string())?;

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

// =============================================================================
// Tauri Commands (called from the frontend via invoke())
// =============================================================================

#[derive(serde::Serialize, Clone)]
struct VpnStatus {
    running: bool,
    endpoint: Option<String>,
    service_available: bool,
}

#[tauri::command]
async fn vpn_connect(mut config: Config) -> Result<String, String> {
    // Keycloak OAuth must run in the GUI process (user session, can open browser).
    // The service runs as SYSTEM and cannot open a browser window.
    if config.kc_auth.unwrap_or(false) {
        let kc_url = config.kc_url.as_deref().unwrap_or("").to_string();
        let realm = config.kc_realm.clone().unwrap_or_else(|| "mavi-vpn".into());
        let client_id = config.kc_client_id.clone().unwrap_or_else(|| "mavi-client".into());

        if kc_url.is_empty() {
            return Err("Keycloak URL is not configured.".into());
        }

        let token = oauth::start_oauth_flow(&kc_url, &realm, &client_id)
            .await
            .map_err(|e| format!("Keycloak login failed: {}", e))?;

        config.token = token;
    }

    match send_ipc_request(&IpcRequest::Start(config)).await? {
        IpcResponse::Ok => Ok("Connected".into()),
        IpcResponse::Error(e) => Err(e),
        _ => Err("Unexpected response".into()),
    }
}

#[tauri::command]
async fn vpn_disconnect() -> Result<String, String> {
    match send_ipc_request(&IpcRequest::Stop).await? {
        IpcResponse::Ok => Ok("Disconnected".into()),
        IpcResponse::Error(e) => Err(e),
        _ => Err("Unexpected response".into()),
    }
}

#[tauri::command]
async fn vpn_status() -> Result<VpnStatus, String> {
    match send_ipc_request(&IpcRequest::Status).await {
        Ok(IpcResponse::Status { running, endpoint }) => Ok(VpnStatus {
            running,
            endpoint,
            service_available: true,
        }),
        Ok(IpcResponse::Error(e)) => Err(e),
        Ok(_) => Err("Unexpected response".into()),
        Err(_) => Ok(VpnStatus {
            running: false,
            endpoint: None,
            service_available: false,
        }),
    }
}

#[tauri::command]
async fn save_config(app: AppHandle, config: Config) -> Result<(), String> {
    let config_dir = app
        .path()
        .app_config_dir()
        .map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&config_dir).map_err(|e| e.to_string())?;
    let config_path = config_dir.join("config.json");
    let content = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
    std::fs::write(&config_path, content).map_err(|e| e.to_string())?;

    // Restrict permissions on Linux
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

#[tauri::command]
async fn load_config(app: AppHandle) -> Result<Option<Config>, String> {
    let config_dir = app
        .path()
        .app_config_dir()
        .map_err(|e| e.to_string())?;
    let config_path = config_dir.join("config.json");
    if !config_path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(config_path).map_err(|e| e.to_string())?;
    let config: Config = serde_json::from_str(&content).map_err(|e| e.to_string())?;
    Ok(Some(config))
}

// =============================================================================
// System Tray
// =============================================================================

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

// =============================================================================
// Status polling (emits events to frontend)
// =============================================================================

fn start_status_poller(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            let status = match send_ipc_request(&IpcRequest::Status).await {
                Ok(IpcResponse::Status { running, endpoint }) => VpnStatus {
                    running,
                    endpoint,
                    service_available: true,
                },
                _ => VpnStatus {
                    running: false,
                    endpoint: None,
                    service_available: false,
                },
            };
            let _ = app.emit("vpn-status-update", &status);
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    });
}

// =============================================================================
// App Entry
// =============================================================================

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            vpn_connect,
            vpn_disconnect,
            vpn_status,
            save_config,
            load_config,
        ])
        .setup(|app| {
            setup_tray(app)?;
            start_status_poller(app.handle().clone());
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Mavi VPN GUI");
}
