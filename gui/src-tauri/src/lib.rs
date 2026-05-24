#![allow(clippy::multiple_crate_versions)]
//! # Mavi VPN GUI - Tauri Backend
//!
//! Communicates with the VPN daemon/service via TCP IPC on 127.0.0.1:14433.
//! Exposes Tauri commands for the web frontend and manages the system tray.

mod commands;
mod ipc;
mod oauth;
mod storage;
mod tray;

use commands::{
    load_config, load_prefs, save_config, save_prefs, vpn_connect, vpn_disconnect,
    vpn_repair_network, vpn_status,
};
use tray::{setup_tray, start_status_poller};

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
