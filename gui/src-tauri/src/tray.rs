use crate::commands::VpnStatus;
use crate::ipc::send_ipc_request;
use shared::ipc::{IpcRequest, IpcResponse};
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    AppHandle, Emitter, Manager,
};

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
            let _ = app.emit("vpn-status-update", &status);
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    });
}
