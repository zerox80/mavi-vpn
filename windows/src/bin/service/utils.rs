use std::path::Path;
use std::sync::atomic::Ordering;
use tracing::{info, warn};
use crate::ipc;
use crate::vpn_core;

#[cfg(not(test))]
pub fn run_network_repair_cleanup() {
    vpn_core::cleanup_stale_network_state();
}

#[cfg(test)]
pub fn run_network_repair_cleanup() {
    // In tests, we don't want to actually touch the network stack
}

pub const fn classify_status(
    connected: bool,
    stopping: bool,
    starting: bool,
    last_error: Option<&str>,
) -> ipc::VpnState {
    if connected {
        ipc::VpnState::Connected
    } else if last_error.is_some() {
        ipc::VpnState::Failed
    } else if stopping {
        ipc::VpnState::Stopping
    } else if starting {
        ipc::VpnState::Starting
    } else {
        ipc::VpnState::Stopped
    }
}

pub fn harden_ipc_token_permissions(token_path: &Path) {
    let mut args = vec![
        token_path.to_string_lossy().to_string(),
        "/inheritance:r".to_string(),
        "/grant:r".to_string(),
        "*S-1-5-18:(F)".to_string(),
        "*S-1-5-32-544:(F)".to_string(),
    ];

    if let Some(user_sid) = active_console_user_sid() {
        args.push(format!("*{user_sid}:(R)"));
    } else {
        warn!("No interactive user detected while hardening the IPC token ACL; local clients may need to run elevated until the service is restarted after login");
    }

    match std::process::Command::new("icacls").args(&args).output() {
        Ok(out) if out.status.success() => {
            info!("Locked down IPC token permissions at {:?}", token_path);
        }
        Ok(out) => {
            warn!(
                "Failed to harden IPC token permissions: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Err(e) => {
            warn!("Failed to execute icacls for IPC token hardening: {}", e);
        }
    }
}

pub fn active_console_user_sid() -> Option<String> {
    let ps = "$user = (Get-CimInstance Win32_ComputerSystem).UserName; if ($user) { try { (New-Object System.Security.Principal.NTAccount($user)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { '' } }";
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", ps])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let sid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if sid.is_empty() {
        None
    } else {
        Some(sid)
    }
}
