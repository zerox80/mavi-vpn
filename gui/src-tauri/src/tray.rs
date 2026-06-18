use crate::commands::VpnStatus;
use crate::ipc::send_ipc_request;
use shared::ipc::{IpcRequest, IpcResponse, KEYCLOAK_LOGIN_REQUIRED_PREFIX};
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    AppHandle, Emitter, Manager,
};
use tracing::{info, warn};

pub(crate) fn setup_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
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

pub(crate) fn start_status_poller(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut last_kc_login_error: Option<String> = None;
        let mut last_status_signature: Option<String> = None;

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
                _ => VpnStatus::service_unavailable(),
            };

            let status_signature = format!(
                "{:?}|{}|{:?}|{:?}|{:?}|{}",
                status.state,
                status.running,
                status.endpoint,
                status.assigned_ip,
                status.last_error,
                status.service_available
            );
            if last_status_signature.as_deref() != Some(status_signature.as_str()) {
                if let Some(error) = status.last_error.as_deref() {
                    warn!(
                        state = ?status.state,
                        running = status.running,
                        endpoint = ?status.endpoint,
                        assigned_ip = ?status.assigned_ip,
                        service_available = status.service_available,
                        error = %error,
                        "VPN status changed with error"
                    );
                } else {
                    info!(
                        state = ?status.state,
                        running = status.running,
                        endpoint = ?status.endpoint,
                        assigned_ip = ?status.assigned_ip,
                        service_available = status.service_available,
                        "VPN status changed"
                    );
                }
                last_status_signature = Some(status_signature);
            }

            let kc_login_error = status
                .last_error
                .as_deref()
                .and_then(|error| error.strip_prefix(KEYCLOAK_LOGIN_REQUIRED_PREFIX))
                .map(str::trim)
                .filter(|message| !message.is_empty())
                .map(str::to_string);

            if kc_login_error != last_kc_login_error {
                if let Some(message) = kc_login_error.as_deref() {
                    let _ = app.emit("kc-needs-login", message.to_string());
                }
                last_kc_login_error = kc_login_error;
            }

            let _ = app.emit("vpn-status-update", &status);
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    });
}
