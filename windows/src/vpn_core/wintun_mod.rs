use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::info;
use wintun::Adapter;

/// Embedded `WinTUN` driver binary.
static WINTUN_DLL: &[u8] = include_bytes!("../../wintun.dll");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DriverAclTarget {
    Directory,
    File,
}

/// Extracts the embedded `wintun.dll` to a locked-down ProgramData directory.
pub fn extract_wintun_dll() -> Result<PathBuf> {
    let base = std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
        .join("mavi-vpn")
        .join("drivers");

    extract_wintun_dll_to(&base, harden_driver_path)
}

fn extract_wintun_dll_to<F>(driver_dir: &Path, mut harden_path: F) -> Result<PathBuf>
where
    F: FnMut(&Path, DriverAclTarget) -> Result<()>,
{
    std::fs::create_dir_all(driver_dir).with_context(|| {
        format!(
            "Failed to create WinTUN driver directory {}",
            driver_dir.display()
        )
    })?;
    harden_path(driver_dir, DriverAclTarget::Directory).with_context(|| {
        format!(
            "Failed to harden WinTUN driver directory {}",
            driver_dir.display()
        )
    })?;

    let dll_path = driver_dir.join("wintun.dll");
    let expected_hash = sha256_digest(WINTUN_DLL);

    if dll_path.exists() {
        let existing = std::fs::read(&dll_path)
            .with_context(|| format!("Failed to read existing {}", dll_path.display()))?;
        let existing_hash = sha256_digest(&existing);
        if existing_hash == expected_hash {
            harden_path(&dll_path, DriverAclTarget::File)
                .with_context(|| format!("Failed to harden {}", dll_path.display()))?;
            return Ok(dll_path);
        }

        info!(
            "Replacing WinTUN DLL at {} because its SHA-256 does not match the embedded driver",
            dll_path.display()
        );
        std::fs::remove_file(&dll_path)
            .with_context(|| format!("Failed to remove mismatched {}", dll_path.display()))?;
    }

    info!("Extracting wintun.dll to {}...", dll_path.display());
    std::fs::write(&dll_path, WINTUN_DLL)
        .with_context(|| format!("Failed to extract wintun.dll to {}", dll_path.display()))?;
    harden_path(&dll_path, DriverAclTarget::File)
        .with_context(|| format!("Failed to harden {}", dll_path.display()))?;

    let written = std::fs::read(&dll_path)
        .with_context(|| format!("Failed to verify {}", dll_path.display()))?;
    let written_hash = sha256_digest(&written);
    if written_hash != expected_hash {
        bail!("Extracted wintun.dll failed integrity verification");
    }

    Ok(dll_path)
}

fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn harden_driver_path(path: &Path, target: DriverAclTarget) -> Result<()> {
    #[cfg(not(windows))]
    {
        let _ = (path, target);
        Ok(())
    }

    #[cfg(windows)]
    {
        let args = driver_acl_args(path, target);
        let out = std::process::Command::new("icacls")
            .args(&args)
            .output()
            .context("Failed to execute icacls for WinTUN ACL hardening")?;

        if !out.status.success() {
            bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(())
    }
}

fn driver_acl_args(path: &Path, target: DriverAclTarget) -> Vec<String> {
    let system_acl = match target {
        DriverAclTarget::Directory => "*S-1-5-18:(OI)(CI)(F)",
        DriverAclTarget::File => "*S-1-5-18:(F)",
    };
    let admins_acl = match target {
        DriverAclTarget::Directory => "*S-1-5-32-544:(OI)(CI)(F)",
        DriverAclTarget::File => "*S-1-5-32-544:(F)",
    };

    vec![
        path.to_string_lossy().to_string(),
        "/inheritance:r".to_string(),
        "/remove:g".to_string(),
        "*S-1-1-0".to_string(),
        "*S-1-5-11".to_string(),
        "*S-1-5-32-545".to_string(),
        "/grant:r".to_string(),
        system_acl.to_string(),
        admins_acl.to_string(),
    ]
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
    matches!(
        err,
        wintun::Error::Io(io_err)
            if io_err.raw_os_error()
                == Some(windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW as i32)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[test]
    fn driver_acl_args_grant_only_system_and_admins() {
        let args = driver_acl_args(
            Path::new(r"C:\ProgramData\mavi-vpn\drivers"),
            DriverAclTarget::Directory,
        );

        assert!(args.contains(&"/inheritance:r".to_string()));
        assert!(args.contains(&"/remove:g".to_string()));
        assert!(args.contains(&"*S-1-1-0".to_string()));
        assert!(args.contains(&"*S-1-5-11".to_string()));
        assert!(args.contains(&"*S-1-5-32-545".to_string()));
        assert!(args.contains(&"*S-1-5-18:(OI)(CI)(F)".to_string()));
        assert!(args.contains(&"*S-1-5-32-544:(OI)(CI)(F)".to_string()));
        assert!(!args.iter().any(|arg| arg.contains("S-1-1-0:")));
        assert!(!args.iter().any(|arg| arg.contains("S-1-5-32-545:")));
    }

    #[test]
    fn extract_wintun_writes_embedded_dll_and_hardens_paths() {
        let dir = tempfile::tempdir().unwrap();
        let calls = Rc::new(RefCell::new(Vec::new()));
        let calls_for_closure = calls.clone();

        let dll_path = extract_wintun_dll_to(dir.path(), |path, target| {
            calls_for_closure
                .borrow_mut()
                .push((path.to_path_buf(), target));
            Ok(())
        })
        .unwrap();

        assert_eq!(dll_path, dir.path().join("wintun.dll"));
        assert_eq!(std::fs::read(&dll_path).unwrap(), WINTUN_DLL);
        let calls = calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls[0],
            (dir.path().to_path_buf(), DriverAclTarget::Directory)
        );
        assert_eq!(calls[1], (dll_path, DriverAclTarget::File));
    }

    #[test]
    fn extract_wintun_replaces_mismatched_existing_dll() {
        let dir = tempfile::tempdir().unwrap();
        let dll_path = dir.path().join("wintun.dll");
        std::fs::write(&dll_path, b"not the embedded driver").unwrap();

        let extracted = extract_wintun_dll_to(dir.path(), |_path, _target| Ok(())).unwrap();

        assert_eq!(extracted, dll_path);
        assert_eq!(std::fs::read(extracted).unwrap(), WINTUN_DLL);
    }

    #[test]
    fn extract_wintun_keeps_matching_existing_dll() {
        let dir = tempfile::tempdir().unwrap();
        let dll_path = dir.path().join("wintun.dll");
        std::fs::write(&dll_path, WINTUN_DLL).unwrap();

        let extracted = extract_wintun_dll_to(dir.path(), |_path, _target| Ok(())).unwrap();

        assert_eq!(extracted, dll_path);
        assert_eq!(std::fs::read(extracted).unwrap(), WINTUN_DLL);
    }
}
