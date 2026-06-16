use crate::ipc;
use anyhow::{Context, Result};
use std::path::Path;
use tracing::{info, warn};

#[cfg(not(test))]
pub fn run_network_repair_cleanup() {
    crate::vpn_core::cleanup_stale_network_state();
}

#[cfg(test)]
pub fn run_network_repair_cleanup() {
    // In tests, we don't want to actually touch the network stack
}

/// Maps the service's atomic flags to a client-facing [`ipc::VpnState`].
///
/// `starting` is `vpn_running && !connected`, i.e. the reconnect loop is still
/// active. Crucially, a `last_error` while still running means the loop is
/// *retrying* a transient failure (e.g. the server closing an expired-token
/// session with `H3_NO_ERROR`), so it maps to `Reconnecting`, NOT `Failed`.
/// `Failed` is reserved for the terminal case where the loop has given up
/// (`!running`) yet an error is recorded - only then should the UI flip off and
/// surface the error. Without this ordering every transient reconnect flashed a
/// hard error and dropped the hero to "NOT CONNECTED".
pub const fn classify_status(
    connected: bool,
    stopping: bool,
    starting: bool,
    last_error: Option<&str>,
) -> ipc::VpnState {
    if connected {
        ipc::VpnState::Connected
    } else if stopping {
        ipc::VpnState::Stopping
    } else if starting {
        if last_error.is_some() {
            ipc::VpnState::Reconnecting
        } else {
            ipc::VpnState::Starting
        }
    } else if last_error.is_some() {
        ipc::VpnState::Failed
    } else {
        ipc::VpnState::Stopped
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcAclTarget {
    Directory,
    TokenFile,
}

pub fn prepare_ipc_auth_token(token_path: &Path, auth_token: &str) -> Result<()> {
    prepare_ipc_auth_token_with(token_path, auth_token, |path, target| {
        harden_ipc_permissions(path, target)
    })
}

fn prepare_ipc_auth_token_with<F>(
    token_path: &Path,
    auth_token: &str,
    mut harden_path: F,
) -> Result<()>
where
    F: FnMut(&Path, IpcAclTarget) -> Result<()>,
{
    let parent = token_path
        .parent()
        .context("IPC token path has no parent directory")?;

    std::fs::create_dir_all(parent)
        .with_context(|| format!("Failed to create IPC token directory {}", parent.display()))?;
    harden_path(parent, IpcAclTarget::Directory).with_context(|| {
        format!(
            "Failed to harden IPC token directory permissions at {}",
            parent.display()
        )
    })?;

    if token_path.exists() {
        harden_path(token_path, IpcAclTarget::TokenFile).with_context(|| {
            format!(
                "Failed to harden existing IPC token permissions at {} before rewrite",
                token_path.display()
            )
        })?;
    }

    std::fs::write(token_path, auth_token)
        .with_context(|| format!("Failed to write IPC token to {}", token_path.display()))?;
    harden_path(token_path, IpcAclTarget::TokenFile).with_context(|| {
        format!(
            "Failed to harden IPC token permissions at {}",
            token_path.display()
        )
    })?;

    Ok(())
}

pub fn reharden_ipc_token_permissions(token_path: &Path) -> Result<()> {
    let parent = token_path
        .parent()
        .context("IPC token path has no parent directory")?;
    harden_ipc_permissions(parent, IpcAclTarget::Directory)?;
    harden_ipc_token_permissions(token_path)
}

pub fn harden_ipc_token_permissions(token_path: &Path) -> Result<()> {
    harden_ipc_permissions(token_path, IpcAclTarget::TokenFile)
}

pub fn harden_ipc_permissions(path: &Path, target: IpcAclTarget) -> Result<()> {
    let user_sid = active_console_user_sid().filter(|sid| is_valid_sid(sid));
    if user_sid.is_none() {
        warn!("No interactive user detected while hardening IPC ACLs; local clients may need to run elevated until the service is restarted after login");
    }

    let script = ipc_acl_script(path, target, user_sid.as_deref());

    run_powershell_script(&script)
        .with_context(|| format!("Failed to harden IPC permissions at {}", path.display()))?;
    info!("Locked down IPC permissions at {:?}", path);
    Ok(())
}

/// Builds a protected (`P`) DACL in SDDL form with the complete ACE list:
/// SYSTEM and Administrators get full control, the active console user gets
/// read (token file) or read+traverse (directory) access. Because the DACL is
/// fully specified, applying it removes any ACEs left behind for previous
/// console users - `icacls /grant` only replaces rights of the SIDs it names,
/// so a user granted in an earlier session would otherwise keep access to the
/// token across fast-user-switching and service restarts.
fn ipc_acl_sddl(target: IpcAclTarget, user_sid: Option<&str>) -> String {
    let (inherit, user_rights) = match target {
        IpcAclTarget::Directory => ("OICI", "FRFX"),
        IpcAclTarget::TokenFile => ("", "FR"),
    };

    let mut sddl = String::from("D:P");
    for admin_sid in ["SY", "BA"] {
        sddl.push_str(&format!("(A;{inherit};FA;;;{admin_sid})"));
    }
    if let Some(user_sid) = user_sid {
        sddl.push_str(&format!("(A;{inherit};{user_rights};;;{user_sid})"));
    }
    sddl
}

/// PowerShell script that replaces the DACL of `path` with the fully
/// specified SDDL in a single `SetAccessControl` write (no transiently
/// permissive state, unlike an `icacls /reset` + re-grant sequence). Owner and
/// group are preserved by restricting `SetSecurityDescriptorSddlForm` to the
/// `Access` section.
///
/// We deliberately call the .NET `System.IO.File`/`System.IO.Directory`
/// `GetAccessControl`/`SetAccessControl` methods instead of the `Get-Acl`/
/// `Set-Acl` cmdlets. Those cmdlets live in the `Microsoft.PowerShell.Security`
/// module, which is unreliable on some hosts: where module auto-loading is
/// disabled the cmdlets resolve to "command was found ... but the module could
/// not be loaded", and where its type data is already partially registered an
/// explicit `Import-Module` fails with "the member ... is already present".
/// The .NET types live in `System.dll`, are always loaded, and never trigger
/// module auto-loading, so the hardening is deterministic regardless of the
/// caller's PowerShell session state.
fn ipc_acl_script(path: &Path, target: IpcAclTarget, user_sid: Option<&str>) -> String {
    let quoted_path = escape_powershell_single_quoted(&path.to_string_lossy());
    let sddl = ipc_acl_sddl(target, user_sid);
    let dotnet_class = match target {
        IpcAclTarget::Directory => "System.IO.Directory",
        IpcAclTarget::TokenFile => "System.IO.File",
    };
    format!(
        "$ErrorActionPreference = 'Stop'; \
         $acl = [{dotnet_class}]::GetAccessControl('{quoted_path}'); \
         $acl.SetSecurityDescriptorSddlForm('{sddl}', 'Access'); \
         [{dotnet_class}]::SetAccessControl('{quoted_path}', $acl)"
    )
}

fn escape_powershell_single_quoted(value: &str) -> String {
    value.replace('\'', "''")
}

/// Accepts only canonical `S-...` SID strings (digits separated by dashes) so
/// the value can be embedded into the SDDL string without escaping concerns.
fn is_valid_sid(sid: &str) -> bool {
    sid.strip_prefix("S-").is_some_and(|rest| {
        !rest.is_empty()
            && rest
                .split('-')
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    })
}

fn run_powershell_script(script: &str) -> Result<()> {
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .context("Failed to execute powershell for IPC ACL hardening")?;

    if !out.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }

    Ok(())
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

#[cfg(test)]
mod tests;
