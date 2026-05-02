use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;
use wintun::Adapter;

/// Embedded `WinTUN` driver binary.
static WINTUN_DLL: &[u8] = include_bytes!("../../wintun.dll");

/// Extracts the embedded `wintun.dll` to a temporary directory so it can be loaded.
pub fn extract_wintun_dll() -> Result<PathBuf> {
    let temp_dir = std::env::temp_dir();
    let dll_path = temp_dir.join("mavi_wintun.dll");

    if !dll_path.exists() {
        info!("Extracting wintun.dll to {}...", dll_path.display());
        std::fs::write(&dll_path, WINTUN_DLL)
            .context("Failed to extract wintun.dll to temp directory")?;
    }
    Ok(dll_path)
}

/// Helper to ensure the "`MaviVPN`" adapter exists in Windows.
pub fn get_or_create_adapter(wintun: &wintun::Wintun) -> Result<Arc<Adapter>> {
    if let Ok(adapter) = Adapter::open(wintun, "MaviVPN") {
        if let Ok(index) = adapter.get_adapter_index() {
            let name = adapter.get_name().unwrap_or_else(|_| "MaviVPN".to_string());
            info!("Opened existing WinTUN adapter '{}' (if={})", name, index);
        }
        return Ok(adapter);
    }

    let adapter = Adapter::create(wintun, "MaviVPN", "Mavi VPN Tunnel", None)
        .context("Failed to create WinTUN adapter. Admin privileges required.")?;

    if let Ok(index) = adapter.get_adapter_index() {
        let name = adapter.get_name().unwrap_or_else(|_| "MaviVPN".to_string());
        info!("Created WinTUN adapter '{}' (if={})", name, index);
    }

    Ok(adapter)
}

/// Checks if the `WinTUN` ring buffer is full.
#[allow(clippy::cast_possible_wrap)]
pub fn is_wintun_ring_full(err: &wintun::Error) -> bool {
    matches!(err, wintun::Error::Io(io_err) if io_err.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW as i32))
}
