use super::*;

fn powershell(script: &str) -> String {
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

#[test]
fn pinned_file_cannot_be_overwritten_or_replaced() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("driver.dll");
    std::fs::write(&path, b"verified").unwrap();
    let guard = lock_path(&path, false).unwrap();
    assert!(std::fs::write(&path, b"replaced").is_err());
    assert!(std::fs::remove_file(&path).is_err());
    assert!(std::fs::rename(&path, temp.path().join("moved.dll")).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"verified");
    drop(guard);
    std::fs::write(&path, b"released").unwrap();
}

#[test]
fn already_open_writer_prevents_trusting_a_file() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("driver.dll");
    let _writer = File::create(&path).unwrap();
    assert!(lock_path(&path, false).is_err());
}

#[test]
fn hard_link_is_rejected_without_changing_its_target() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    let link = temp.path().join("driver.dll");
    std::fs::write(&target, b"unchanged").unwrap();
    std::fs::hard_link(&target, &link).unwrap();
    assert!(lock_path(&link, false)
        .unwrap_err()
        .to_string()
        .contains("Hard links"));
    assert_eq!(std::fs::read(target).unwrap(), b"unchanged");
}

#[test]
fn directory_junction_is_rejected_without_following_it() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    let link = temp.path().join("drivers");
    std::fs::create_dir(&target).unwrap();
    // Junction creation does not require symlink privileges or Developer Mode.
    powershell(&format!(
        "$ErrorActionPreference = 'Stop'; New-Item -ItemType Junction -Path '{}' -Target '{}' | Out-Null",
        link.display().to_string().replace('\'', "''"),
        target.display().to_string().replace('\'', "''"),
    ));
    assert!(lock_path(&link, true)
        .unwrap_err()
        .to_string()
        .contains("Reparse points"));
    std::fs::remove_dir(&link).unwrap();
    assert!(target.is_dir());
}

#[test]
fn user_owner_is_rejected_even_after_a_protected_dacl_is_applied() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("driver.dll");
    std::fs::write(&path, b"unchanged").unwrap();
    let quoted = path.display().to_string().replace('\'', "''");
    let sid = powershell(&format!(
        "$ErrorActionPreference = 'Stop'; \
         $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User; \
         $acl = [System.IO.File]::GetAccessControl('{quoted}'); \
         $acl.SetOwner($sid); [System.IO.File]::SetAccessControl('{quoted}', $acl); $sid.Value"
    ));
    let guard = lock_path(&path, false).unwrap();
    // The test retains its own access to permit cleanup on a non-admin runner.
    replace_dacl(
        &path,
        &format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{sid})"),
    )
    .unwrap();
    assert!(ensure_trusted_owner(&guard)
        .unwrap_err()
        .to_string()
        .contains("Untrusted owner"));
}

#[test]
fn complete_dacl_removes_an_unknown_explicit_user_ace() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("driver.dll");
    std::fs::write(&path, b"unchanged").unwrap();
    let sid = powershell("[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value");
    let guard = lock_path(&path, false).unwrap();
    let stale_user = "S-1-5-21-101-202-303-1001";
    replace_dacl(&path, &format!("D:P(A;;FA;;;{sid})(A;;FA;;;{stale_user})")).unwrap();
    replace_dacl(
        &path,
        &format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{sid})"),
    )
    .unwrap();
    let acl = powershell(&format!(
        "[System.IO.File]::GetAccessControl('{}').Sddl",
        path.display().to_string().replace('\'', "''"),
    ));
    assert!(
        !acl.contains(stale_user),
        "stale per-user ACE survived: {acl}"
    );
    assert!(acl.contains("D:P"));
    drop(guard);
}

#[test]
fn privileged_directory_must_be_local_and_absolute() {
    for path in [
        r"relative\drivers",
        r"C:drivers",
        r"\\server\share\drivers",
        r"C:\safe\..\drivers",
    ] {
        assert!(
            lock_directory_tree(Path::new(path), false).is_err(),
            "{path}"
        );
    }
}

#[test]
fn trusted_program_data_ancestors_can_be_pinned_without_modification() {
    let path = std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
    let guards = lock_directory_tree(&path, false).unwrap();
    assert!(guards.len() >= 2);
}
