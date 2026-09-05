use crate::secure_path::{ensure_trusted_owner, lock_directory_tree, lock_path, replace_dacl};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
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

/// Verified driver together with the handles that prevent its replacement.
pub struct ExtractedDriver {
    pub path: PathBuf,
    // Keep the verified object and all ancestors pinned through LoadLibrary
    // and for as long as the cached WinTUN adapter uses the library.
    _file: File,
    _directories: Vec<File>,
}

/// Extracts the embedded `wintun.dll` to a locked-down ProgramData directory.
pub fn extract_wintun_dll() -> Result<ExtractedDriver> {
    let base = std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
        .join("mavi-vpn")
        .join("drivers");

    let directories = lock_directory_tree(&base, true)?;
    let mut driver = extract_wintun_dll_to(&base, harden_driver_path)?;
    driver._directories = directories;
    Ok(driver)
}

fn extract_wintun_dll_to<F>(driver_dir: &Path, mut harden_path: F) -> Result<ExtractedDriver>
where
    F: FnMut(&Path, DriverAclTarget) -> Result<()>,
{
    std::fs::create_dir_all(driver_dir).with_context(|| {
        format!(
            "Failed to create WinTUN driver directory {}",
            driver_dir.display()
        )
    })?;
    let directory = lock_path(driver_dir, true)?;
    harden_path(driver_dir, DriverAclTarget::Directory).with_context(|| {
        format!(
            "Failed to harden WinTUN driver directory {}",
            driver_dir.display()
        )
    })?;

    let dll_path = driver_dir.join("wintun.dll");
    let expected_hash = sha256_digest(WINTUN_DLL);

    if dll_path.symlink_metadata().is_ok() {
        let mut file = lock_path(&dll_path, false)?;
        harden_path(&dll_path, DriverAclTarget::File)
            .with_context(|| format!("Failed to harden {}", dll_path.display()))?;
        let mut existing = Vec::new();
        if file.metadata()?.len() == WINTUN_DLL.len() as u64 {
            file.read_to_end(&mut existing)
                .with_context(|| format!("Failed to read existing {}", dll_path.display()))?;
        }
        let existing_hash = sha256_digest(&existing);
        if existing_hash == expected_hash {
            return Ok(ExtractedDriver {
                path: dll_path,
                _file: file,
                _directories: vec![directory],
            });
        }

        info!(
            "Replacing WinTUN DLL at {} because its SHA-256 does not match the embedded driver",
            dll_path.display()
        );
        drop(file);
        std::fs::remove_file(&dll_path)
            .with_context(|| format!("Failed to remove mismatched {}", dll_path.display()))?;
    }

    info!("Extracting wintun.dll to {}...", dll_path.display());
    // The directory is already protected. Never follow or truncate a file
    // planted at this name; create_new also rejects dangling symbolic links.
    let mut output = File::options()
        .write(true)
        .create_new(true)
        .open(&dll_path)
        .with_context(|| format!("Failed to create {}", dll_path.display()))?;
    output
        .write_all(WINTUN_DLL)
        .context("Failed to extract wintun.dll")?;
    drop(output);
    let mut file = lock_path(&dll_path, false)?;
    harden_path(&dll_path, DriverAclTarget::File)
        .with_context(|| format!("Failed to harden {}", dll_path.display()))?;

    let mut written = Vec::new();
    file.read_to_end(&mut written)
        .with_context(|| format!("Failed to verify {}", dll_path.display()))?;
    let written_hash = sha256_digest(&written);
    if written_hash != expected_hash {
        bail!("Extracted wintun.dll failed integrity verification");
    }

    Ok(ExtractedDriver {
        path: dll_path,
        _file: file,
        _directories: vec![directory],
    })
}

fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn harden_driver_path(path: &Path, target: DriverAclTarget) -> Result<()> {
    let guard = lock_path(path, target == DriverAclTarget::Directory)?;
    ensure_trusted_owner(&guard)?;
    replace_dacl(path, driver_acl_sddl(target))
}

fn driver_acl_sddl(target: DriverAclTarget) -> &'static str {
    match target {
        DriverAclTarget::Directory => "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
        DriverAclTarget::File => "D:P(A;;FA;;;SY)(A;;FA;;;BA)",
    }
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
    fn driver_dacl_has_a_complete_system_and_admins_only_allow_list() {
        assert_eq!(
            driver_acl_sddl(DriverAclTarget::Directory),
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        );
        assert_eq!(
            driver_acl_sddl(DriverAclTarget::File),
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
        );
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

        assert_eq!(dll_path.path, dir.path().join("wintun.dll"));
        assert_eq!(std::fs::read(&dll_path.path).unwrap(), WINTUN_DLL);
        let calls = calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls[0],
            (dir.path().to_path_buf(), DriverAclTarget::Directory)
        );
        assert_eq!(calls[1], (dll_path.path.clone(), DriverAclTarget::File));
        assert!(std::fs::write(&dll_path.path, b"replacement").is_err());
        assert!(std::fs::remove_file(&dll_path.path).is_err());
        assert!(std::fs::rename(dir.path(), dir.path().with_extension("moved")).is_err());
        // Only load/resolve exports; do not create an adapter or touch networking.
        let _library = unsafe { wintun::load_from_path(&dll_path.path) }.unwrap();
    }

    #[test]
    fn extract_wintun_replaces_mismatched_existing_dll() {
        let dir = tempfile::tempdir().unwrap();
        let dll_path = dir.path().join("wintun.dll");
        std::fs::write(&dll_path, b"not the embedded driver").unwrap();

        let extracted = extract_wintun_dll_to(dir.path(), |_path, _target| Ok(())).unwrap();

        assert_eq!(extracted.path, dll_path);
        assert_eq!(std::fs::read(&extracted.path).unwrap(), WINTUN_DLL);
    }

    #[test]
    fn extract_wintun_keeps_matching_existing_dll() {
        let dir = tempfile::tempdir().unwrap();
        let dll_path = dir.path().join("wintun.dll");
        std::fs::write(&dll_path, WINTUN_DLL).unwrap();

        let extracted = extract_wintun_dll_to(dir.path(), |_path, _target| Ok(())).unwrap();

        assert_eq!(extracted.path, dll_path);
        assert_eq!(std::fs::read(&extracted.path).unwrap(), WINTUN_DLL);
    }
}
