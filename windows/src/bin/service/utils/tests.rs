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

        // The .NET File ACL APIs are used (not the Get-Acl/Set-Acl cmdlets) so
        // the hardening does not depend on the Microsoft.PowerShell.Security
        // module, which is unreliable on some hosts.
        assert!(!script.contains("Get-Acl"));
        assert!(!script.contains("Set-Acl"));
        assert!(!script.contains("Import-Module"));
        assert!(script
            .contains("[System.IO.File]::GetAccessControl('C:\\ProgramData\\mavi-vpn\\ipc.token')"));
        // Only the Access (DACL) section is replaced, so owner/group survive.
        assert!(script.contains("SetSecurityDescriptorSddlForm('D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;S-1-5-21-1000)', 'Access')"));
        assert!(script
            .contains("[System.IO.File]::SetAccessControl('C:\\ProgramData\\mavi-vpn\\ipc.token', $acl)"));
    }

    #[test]
    fn acl_script_uses_directory_apis_for_directory_target() {
        let script = ipc_acl_script(
            Path::new(r"C:\ProgramData\mavi-vpn"),
            IpcAclTarget::Directory,
            Some("S-1-5-21-1000"),
        );

        assert!(script.contains("[System.IO.Directory]::GetAccessControl('C:\\ProgramData\\mavi-vpn')"));
        assert!(script.contains("[System.IO.Directory]::SetAccessControl('C:\\ProgramData\\mavi-vpn', $acl)"));
        // Inheritable directory ACEs (OICI) with traverse+read for the user.
        assert!(script.contains("SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;S-1-5-21-1000)', 'Access')"));
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

        // Read the DACL back via the .NET API for the same reason the script
        // does: the Get-Acl cmdlet's Microsoft.PowerShell.Security module is
        // unreliable on CI runners. Enumerate the access rules with explicit
        // SecurityIdentifier identities rather than reading the SDDL string,
        // because SDDL abbreviates well-known accounts to aliases (e.g. the
        // built-in Administrator becomes `LA`), which a raw-SID substring
        // check would miss.
        let aces_out = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "$acl = [System.IO.File]::GetAccessControl('{}'); \
                     $acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) | \
                     ForEach-Object {{ \"$($_.AccessControlType):$($_.IdentityReference.Value):$($_.FileSystemRights)\" }}",
                    token_path.to_str().unwrap().replace('\'', "''")
                ),
            ])
            .output()
            .expect("read back ACEs");
        let aces = String::from_utf8_lossy(&aces_out.stdout);
        let allow_with = |sid: &str, right: &str| {
            aces.lines().any(|line| {
                line.starts_with("Allow:")
                    && line.contains(&format!(":{sid}:"))
                    && line.contains(right)
            })
        };

        assert!(
            !aces.contains("S-1-1-0"),
            "Everyone ACE must be removed: {aces}"
        );
        assert!(
            allow_with("S-1-5-18", "FullControl"),
            "SYSTEM full control expected: {aces}"
        );
        assert!(
            allow_with("S-1-5-32-544", "FullControl"),
            "Admins full control expected: {aces}"
        );
        assert!(
            allow_with(&current_user_sid, "Read"),
            "current user read expected: {aces}"
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
