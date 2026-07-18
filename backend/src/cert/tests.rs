use super::*;
use tempfile::tempdir;

#[test]
fn load_or_generate_creates_new_certs() {
    let dir = tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");

    assert!(!cert_path.exists());
    assert!(!key_path.exists());

    let (certs, _key) = load_or_generate_certs(&cert_path, &key_path).unwrap();
    assert!(!certs.is_empty());
    assert!(cert_path.exists());
    assert!(key_path.exists());
}

#[test]
fn load_or_generate_loads_existing() {
    let dir = tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");

    let (certs1, _key1) = load_or_generate_certs(&cert_path, &key_path).unwrap();
    let (certs2, _key2) = load_or_generate_certs(&cert_path, &key_path).unwrap();

    assert_eq!(certs1.len(), certs2.len());
    assert_eq!(certs1[0].as_ref(), certs2[0].as_ref());
}

#[test]
fn cert_pin_file_is_written() {
    let dir = tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");

    let _ = load_or_generate_certs(&cert_path, &key_path).unwrap();

    let pin_path = dir.path().join("cert_pin.txt");
    assert!(pin_path.exists());
    let pin = std::fs::read_to_string(&pin_path).unwrap();
    assert_eq!(pin.len(), 64); // SHA-256 hex is 64 chars
    assert!(pin.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn generated_key_file_permissions() {
    let dir = tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");

    let _ = load_or_generate_certs(&cert_path, &key_path).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(windows)]
    {
        let sddl = windows_file_sddl(&key_path);
        // Inheritance disabled, full control for SYSTEM and Administrators,
        // and no ACE for BUILTIN\Users (BU) or Everyone (WD).
        assert!(sddl.contains("D:P"), "DACL must be protected: {sddl}");
        assert!(
            sddl.contains("(A;;FA;;;SY)"),
            "SYSTEM grant expected: {sddl}"
        );
        assert!(
            sddl.contains("(A;;FA;;;BA)"),
            "Admins grant expected: {sddl}"
        );
        assert!(
            !sddl.contains(";;;BU)"),
            "Users must have no access: {sddl}"
        );
        assert!(
            !sddl.contains(";;;WD)"),
            "Everyone must have no access: {sddl}"
        );
    }
}

#[cfg(windows)]
fn windows_file_sddl(path: &std::path::Path) -> String {
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "(Get-Acl -LiteralPath '{}').Sddl",
                path.to_str().unwrap().replace('\'', "''")
            ),
        ])
        .output()
        .expect("read back SDDL");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn windows_key_acl_args_grant_only_system_admins_and_account() {
    let args = windows_key_acl_args(
        std::path::Path::new(r"C:\data\key.pem"),
        Some(r"VM\backend-svc"),
    );

    assert_eq!(
        args,
        vec![
            r"C:\data\key.pem".to_string(),
            "/inheritance:r".to_string(),
            "/grant:r".to_string(),
            "*S-1-5-18:(F)".to_string(),
            "*S-1-5-32-544:(F)".to_string(),
            r"VM\backend-svc:(F)".to_string(),
        ]
    );
    assert!(!args.iter().any(|a| a.contains("S-1-1-0")));
    assert!(!args.iter().any(|a| a.contains("S-1-5-32-545")));
}

#[test]
fn windows_key_acl_args_without_account_grants_system_and_admins_only() {
    let args = windows_key_acl_args(std::path::Path::new(r"C:\data\key.pem"), None);

    assert_eq!(args.len(), 5);
    assert!(args.contains(&"/inheritance:r".to_string()));
    assert!(args.contains(&"*S-1-5-18:(F)".to_string()));
    assert!(args.contains(&"*S-1-5-32-544:(F)".to_string()));
}

#[test]
fn invalid_cert_pem_fails() {
    let dir = tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");

    std::fs::write(&cert_path, "not a valid PEM").unwrap();
    std::fs::write(&key_path, "not a valid PEM").unwrap();

    let result = load_or_generate_certs(&cert_path, &key_path);
    assert!(result.is_err());
}

#[test]
fn cert_and_key_are_valid_rustls_types() {
    let dir = tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");

    let (certs, key) = load_or_generate_certs(&cert_path, &key_path).unwrap();
    assert!(!certs.is_empty());
    // PrivateKeyDer should be non-empty
    assert!(!key.secret_der().is_empty());
}

#[test]
fn regenerated_certs_are_different() {
    let dir1 = tempdir().unwrap();
    let dir2 = tempdir().unwrap();

    let (certs1, _) =
        load_or_generate_certs(&dir1.path().join("cert.pem"), &dir1.path().join("key.pem"))
            .unwrap();
    let (certs2, _) =
        load_or_generate_certs(&dir2.path().join("cert.pem"), &dir2.path().join("key.pem"))
            .unwrap();

    assert_ne!(certs1[0].as_ref(), certs2[0].as_ref());
}

#[test]
fn sha256_pin_is_correct_length() {
    use sha2::{Digest, Sha256};

    let dir = tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");

    let (certs, _) = load_or_generate_certs(&cert_path, &key_path).unwrap();
    let cert = &certs[0];

    let mut hasher = Sha256::new();
    hasher.update(cert.as_ref());
    let hash = hasher.finalize();
    let pin = hex::encode(hash);
    assert_eq!(pin.len(), 64);
}
