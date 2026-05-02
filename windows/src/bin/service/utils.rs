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
    let user_sid = active_console_user_sid();
    if user_sid.is_none() {
        warn!("No interactive user detected while hardening IPC ACLs; local clients may need to run elevated until the service is restarted after login");
    }

    let args = ipc_acl_args(path, target, user_sid.as_deref());

    run_icacls(&args)
        .with_context(|| format!("Failed to harden IPC permissions at {}", path.display()))?;
    info!("Locked down IPC permissions at {:?}", path);
    Ok(())
}

fn ipc_acl_args(path: &Path, target: IpcAclTarget, user_sid: Option<&str>) -> Vec<String> {
    let mut args = vec![
        path.to_string_lossy().to_string(),
        "/inheritance:r".to_string(),
        "/remove:g".to_string(),
        "*S-1-1-0".to_string(),
        "*S-1-5-11".to_string(),
        "*S-1-5-32-545".to_string(),
        "/grant:r".to_string(),
        admin_acl("S-1-5-18", target),
        admin_acl("S-1-5-32-544", target),
    ];

    if let Some(user_sid) = user_sid {
        args.push(user_acl(user_sid, target));
    }

    args
}

fn admin_acl(sid: &str, target: IpcAclTarget) -> String {
    match target {
        IpcAclTarget::Directory => format!("*{sid}:(OI)(CI)(F)"),
        IpcAclTarget::TokenFile => format!("*{sid}:(F)"),
    }
}

fn user_acl(sid: &str, target: IpcAclTarget) -> String {
    match target {
        IpcAclTarget::Directory => format!("*{sid}:(OI)(CI)(RX)"),
        IpcAclTarget::TokenFile => format!("*{sid}:(R)"),
    }
}

fn run_icacls(args: &[String]) -> Result<()> {
    let out = std::process::Command::new("icacls")
        .args(args)
        .output()
        .context("Failed to execute icacls for IPC ACL hardening")?;

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
    fn token_file_acl_args_grant_only_system_admins_and_user_read() {
        let args = ipc_acl_args(
            Path::new(r"C:\ProgramData\mavi-vpn\ipc.token"),
            IpcAclTarget::TokenFile,
            Some("S-1-5-21-1000"),
        );

        assert!(args.contains(&"/inheritance:r".to_string()));
        assert!(args.contains(&"*S-1-5-18:(F)".to_string()));
        assert!(args.contains(&"*S-1-5-32-544:(F)".to_string()));
        assert!(args.contains(&"*S-1-5-21-1000:(R)".to_string()));
        assert!(args.contains(&"/remove:g".to_string()));
        assert!(args.contains(&"*S-1-1-0".to_string()));
        assert!(args.contains(&"*S-1-5-11".to_string()));
        assert!(args.contains(&"*S-1-5-32-545".to_string()));
        assert!(!args.iter().any(|arg| arg.contains("S-1-1-0:")));
        assert!(!args.iter().any(|arg| arg.contains("S-1-5-32-545:")));
    }

    #[test]
    fn directory_acl_args_allow_user_traverse_and_read_only() {
        let args = ipc_acl_args(
            Path::new(r"C:\ProgramData\mavi-vpn"),
            IpcAclTarget::Directory,
            Some("S-1-5-21-1000"),
        );

        assert!(args.contains(&"*S-1-5-18:(OI)(CI)(F)".to_string()));
        assert!(args.contains(&"*S-1-5-32-544:(OI)(CI)(F)".to_string()));
        assert!(args.contains(&"*S-1-5-21-1000:(OI)(CI)(RX)".to_string()));
        assert!(args.contains(&"/remove:g".to_string()));
        assert!(args.contains(&"*S-1-1-0".to_string()));
        assert!(args.contains(&"*S-1-5-11".to_string()));
        assert!(args.contains(&"*S-1-5-32-545".to_string()));
        assert!(!args.iter().any(|arg| arg.contains("S-1-1-0:")));
        assert!(!args.iter().any(|arg| arg.contains("S-1-5-32-545:")));
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
}
