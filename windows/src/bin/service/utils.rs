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
/// console users — `icacls /grant` only replaces rights of the SIDs it names,
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
/// specified SDDL in a single `Set-Acl` write (no transiently permissive
/// state, unlike an `icacls /reset` + re-grant sequence). Owner and group are
/// preserved by restricting `SetSecurityDescriptorSddlForm` to the `Access`
/// section.
fn ipc_acl_script(path: &Path, target: IpcAclTarget, user_sid: Option<&str>) -> String {
    let quoted_path = escape_powershell_single_quoted(&path.to_string_lossy());
    let sddl = ipc_acl_sddl(target, user_sid);
    format!(
        "$ErrorActionPreference = 'Stop'; \
         $acl = Get-Acl -LiteralPath '{quoted_path}'; \
         $acl.SetSecurityDescriptorSddlForm('{sddl}', 'Access'); \
         Set-Acl -LiteralPath '{quoted_path}' -AclObject $acl"
    )
}

fn escape_powershell_single_quoted(value: &str) -> String {
    value.replace('\'', "''")
}

/// Accepts only canonical `S-…` SID strings (digits separated by dashes) so
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
mod tests {
    use super::*;
    use anyhow::anyhow;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[test]
    fn token_file_sddl_grants_only_system_admins_and_user_read() {
        let sddl = ipc_acl_sddl(IpcAclTarget::TokenFile, Some("S-1-5-21-1000"));

        assert_eq!(
            sddl,
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;S-1-5-21-1000)"
        );
    }

    #[test]
    fn directory_sddl_allows_user_traverse_and_read_only() {
        let sddl = ipc_acl_sddl(IpcAclTarget::Directory, Some("S-1-5-21-1000"));

        assert_eq!(
            sddl,
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;S-1-5-21-1000)"
        );
    }

    #[test]
    fn sddl_without_user_grants_only_system_and_admins() {
        let sddl = ipc_acl_sddl(IpcAclTarget::TokenFile, None);

        assert_eq!(sddl, "D:P(A;;FA;;;SY)(A;;FA;;;BA)");
    }

    #[test]
    fn acl_script_replaces_dacl_atomically_and_preserves_owner() {
        let script = ipc_acl_script(
            Path::new(r"C:\ProgramData\mavi-vpn\ipc.token"),
            IpcAclTarget::TokenFile,
            Some("S-1-5-21-1000"),
        );

        assert!(script.contains("Get-Acl -LiteralPath 'C:\\ProgramData\\mavi-vpn\\ipc.token'"));
        // Only the Access (DACL) section is replaced, so owner/group survive.
        assert!(script.contains("SetSecurityDescriptorSddlForm('D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;S-1-5-21-1000)', 'Access')"));
        assert!(script.contains("Set-Acl -LiteralPath 'C:\\ProgramData\\mavi-vpn\\ipc.token'"));
    }

    #[test]
    fn acl_script_escapes_single_quotes_in_path() {
        let script = ipc_acl_script(
            Path::new(r"C:\pro'gram\ipc.token"),
            IpcAclTarget::TokenFile,
            None,
        );

        assert!(script.contains(r"'C:\pro''gram\ipc.token'"));
    }

    #[test]
    fn valid_sids_are_accepted() {
        assert!(is_valid_sid("S-1-5-18"));
        assert!(is_valid_sid("S-1-5-21-3623811015-3361044348-30300820-1013"));
    }

    #[test]
    fn malformed_sids_are_rejected() {
        assert!(!is_valid_sid(""));
        assert!(!is_valid_sid("S-"));
        assert!(!is_valid_sid("S-1-5-"));
        assert!(!is_valid_sid("Everyone"));
        assert!(!is_valid_sid("S-1-5-21abc"));
        // SDDL/script metacharacters must never pass.
        assert!(!is_valid_sid("S-1-5-18)';"));
    }

    /// End-to-end check on a real file: a stale ACE for another principal
    /// (here: Everyone) must be gone after the hardening script runs, which is
    /// exactly the residue the old additive `icacls /grant` flow left behind.
    #[cfg(windows)]
    #[test]
    fn hardening_script_removes_stale_aces() {
        let current_user_sid = {
            let out = std::process::Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
                ])
                .output()
                .expect("query current user SID");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        assert!(is_valid_sid(&current_user_sid), "got SID {current_user_sid:?}");

        let temp = tempfile::tempdir().unwrap();
        let token_path = temp.path().join("ipc.token");
        std::fs::write(&token_path, "secret").unwrap();

        // Plant a stale ACE for Everyone (S-1-1-0), as if granted by an
        // earlier service run for a different principal.
        let plant = std::process::Command::new("icacls")
            .args([token_path.to_str().unwrap(), "/grant", "*S-1-1-0:R"])
            .output()
            .expect("run icacls");
        assert!(plant.status.success(), "icacls grant failed");

        let script = ipc_acl_script(
            &token_path,
            IpcAclTarget::TokenFile,
            Some(&current_user_sid),
        );
        run_powershell_script(&script).expect("hardening script must succeed");

        let sddl_out = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "(Get-Acl -LiteralPath '{}').Sddl",
                    token_path.to_str().unwrap().replace('\'', "''")
                ),
            ])
            .output()
            .expect("read back SDDL");
        let sddl = String::from_utf8_lossy(&sddl_out.stdout).trim().to_string();

        assert!(!sddl.contains(";;;WD)"), "Everyone ACE must be removed: {sddl}");
        assert!(sddl.contains("(A;;FA;;;SY)"), "SYSTEM full control expected: {sddl}");
        assert!(sddl.contains("(A;;FA;;;BA)"), "Admins full control expected: {sddl}");
        assert!(
            sddl.contains(&format!(";;;{current_user_sid})")),
            "current user read expected: {sddl}"
        );
    }

    #[test]
    fn prepare_ipc_token_hardens_directory_before_writing_new_token() {
        let temp = tempfile::tempdir().unwrap();
        let token_path = temp.path().join("mavi-vpn").join("ipc.token");
        let calls = Rc::new(RefCell::new(Vec::new()));
        let calls_for_closure = calls.clone();

        prepare_ipc_auth_token_with(&token_path, "secret", |path, target| {
            calls_for_closure
                .borrow_mut()
                .push((path.to_path_buf(), target));
            Ok(())
        })
        .unwrap();

        assert_eq!(std::fs::read_to_string(&token_path).unwrap(), "secret");
        let calls = calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls[0],
            (
                token_path.parent().unwrap().to_path_buf(),
                IpcAclTarget::Directory
            )
        );
        assert_eq!(calls[1], (token_path.clone(), IpcAclTarget::TokenFile));
    }

    #[test]
    fn prepare_ipc_token_hardens_existing_token_before_rewrite() {
        let temp = tempfile::tempdir().unwrap();
        let token_path = temp.path().join("mavi-vpn").join("ipc.token");
        std::fs::create_dir_all(token_path.parent().unwrap()).unwrap();
        std::fs::write(&token_path, "old").unwrap();

        let calls = Rc::new(RefCell::new(Vec::new()));
        let calls_for_closure = calls.clone();

        prepare_ipc_auth_token_with(&token_path, "new", |path, target| {
            calls_for_closure
                .borrow_mut()
                .push((path.to_path_buf(), target));
            Ok(())
        })
        .unwrap();

        assert_eq!(std::fs::read_to_string(&token_path).unwrap(), "new");
        let calls = calls.borrow();
        assert_eq!(calls.len(), 3);
        assert_eq!(
            calls[0],
            (
                token_path.parent().unwrap().to_path_buf(),
                IpcAclTarget::Directory
            )
        );
        assert_eq!(calls[1], (token_path.clone(), IpcAclTarget::TokenFile));
        assert_eq!(calls[2], (token_path.clone(), IpcAclTarget::TokenFile));
    }

    #[test]
    fn prepare_ipc_token_fails_before_write_when_directory_hardening_fails() {
        let temp = tempfile::tempdir().unwrap();
        let token_path = temp.path().join("mavi-vpn").join("ipc.token");

        let err = prepare_ipc_auth_token_with(&token_path, "secret", |_path, target| {
            if target == IpcAclTarget::Directory {
                Err(anyhow!("acl failure"))
            } else {
                Ok(())
            }
        })
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("Failed to harden IPC token directory"));
        assert!(!token_path.exists());
    }

    #[test]
    fn prepare_ipc_token_reports_final_file_hardening_failure() {
        let temp = tempfile::tempdir().unwrap();
        let token_path = temp.path().join("mavi-vpn").join("ipc.token");
        let token_file_calls = Rc::new(RefCell::new(0usize));
        let token_file_calls_for_closure = token_file_calls.clone();

        let err = prepare_ipc_auth_token_with(&token_path, "secret", |_path, target| {
            if target == IpcAclTarget::TokenFile {
                let mut count = token_file_calls_for_closure.borrow_mut();
                *count += 1;
                if *count == 1 {
                    return Err(anyhow!("acl failure"));
                }
            }
            Ok(())
        })
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("Failed to harden IPC token permissions"));
        assert_eq!(std::fs::read_to_string(&token_path).unwrap(), "secret");
    }

    #[test]
    fn classify_connected_state() {
        assert_eq!(
            classify_status(true, false, false, None),
            ipc::VpnState::Connected
        );
    }

    #[test]
    fn classify_stopped_state() {
        assert_eq!(
            classify_status(false, false, false, None),
            ipc::VpnState::Stopped
        );
    }

    #[test]
    fn classify_failed_state_with_error() {
        assert_eq!(
            classify_status(false, false, false, Some("error")),
            ipc::VpnState::Failed
        );
    }

    #[test]
    fn classify_stopping_state() {
        assert_eq!(
            classify_status(false, true, false, None),
            ipc::VpnState::Stopping
        );
    }

    #[test]
    fn classify_starting_state() {
        assert_eq!(
            classify_status(false, false, true, None),
            ipc::VpnState::Starting
        );
    }

    #[test]
    fn classify_connected_takes_priority_over_error() {
        assert_eq!(
            classify_status(true, false, false, Some("error")),
            ipc::VpnState::Connected
        );
    }

    #[test]
    fn classify_error_takes_priority_over_stopping() {
        assert_eq!(
            classify_status(false, true, false, Some("error")),
            ipc::VpnState::Failed
        );
    }

    #[test]
    fn classify_stopping_takes_priority_over_starting() {
        assert_eq!(
            classify_status(false, true, true, None),
            ipc::VpnState::Stopping
        );
    }
}
