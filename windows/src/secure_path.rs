//! Pin privileged filesystem objects before inspecting or changing them.
//!
//! A protected DACL alone cannot secure an object owned by an ordinary user:
//! its owner can restore write access. Never adopt such objects in the service.

use anyhow::{bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
};

struct LocalAllocation(*mut std::ffi::c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: both security APIs below allocate their results with LocalAlloc.
        unsafe { LocalFree(self.0) };
    }
}

/// Denies other writers and deletion/renaming for the lifetime of the handle.
/// OPEN_REPARSE_POINT inspects the object itself instead of following a link.
pub fn lock_path(path: &Path, directory: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .with_context(|| format!("Cannot lock privileged path {}", path.display()))?;
    validate_object(&file, path, directory)?;
    Ok(file)
}

/// Open without truncation so ownership, links and the DACL can be checked
/// before writing a secret. The same handle is used for validation and I/O.
pub fn lock_writable_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("Cannot lock privileged file {}", path.display()))?;
    validate_object(&file, path, false)?;
    Ok(file)
}

fn validate_object(file: &File, path: &Path, directory: bool) -> Result<()> {
    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!(
            "Reparse points are forbidden in privileged path {}",
            path.display()
        );
    }
    if metadata.is_dir() != directory {
        bail!("Unexpected object type at {}", path.display());
    }
    if !directory {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: file is live and info is a writable buffer of the required type.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(std::io::Error::last_os_error()).context("Cannot inspect file links");
        }
        if info.nNumberOfLinks != 1 {
            bail!(
                "Hard links are forbidden for privileged file {}",
                path.display()
            );
        }
    }
    Ok(())
}

pub fn ensure_trusted_owner(file: &File) -> Result<()> {
    let mut owner = null_mut();
    let mut descriptor = null_mut();
    // SAFETY: file is live; returned owner points into the allocated descriptor.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32))
            .context("Cannot inspect privileged path owner");
    }
    let _descriptor = LocalAllocation(descriptor);
    let mut sid = null_mut();
    // SAFETY: owner is valid while _descriptor is alive; sid receives an allocation.
    if owner.is_null() || unsafe { ConvertSidToStringSidW(owner, &mut sid) } == 0 {
        bail!("Cannot read privileged path owner SID");
    }
    let _sid = LocalAllocation(sid.cast());
    let mut len = 0;
    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated UTF-16 string.
    let owner = unsafe {
        while *sid.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(sid, len))
    };
    if !matches!(
        owner.as_str(),
        "S-1-5-18" | "S-1-5-32-544" |
        // TrustedInstaller owns some Windows-managed parent directories.
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    ) {
        bail!("Untrusted owner {owner}; an administrator must recreate the service path");
    }
    Ok(())
}

/// Lock and validate every ancestor, top down, so renaming a parent cannot
/// redirect a later path-based ACL update or LoadLibrary call. Only local,
/// absolute drive paths are accepted. Missing directories are created singly.
pub fn lock_directory_tree(path: &Path, create: bool) -> Result<Vec<File>> {
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Prefix(p))
        if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
        || components.next() != Some(Component::RootDir)
        || components.any(|c| !matches!(c, Component::Normal(_)))
    {
        bail!(
            "Privileged path must be an absolute local drive path: {}",
            path.display()
        );
    }
    let mut current = PathBuf::new();
    let mut guards = Vec::new();
    for component in path.components() {
        current.push(component);
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        if create && matches!(component, Component::Normal(_)) {
            match std::fs::create_dir(&current) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("Cannot create {}", current.display()))
                }
            }
        }
        let guard = lock_path(&current, true)?;
        ensure_trusted_owner(&guard)
            .with_context(|| format!("Unsafe privileged directory {}", current.display()))?;
        guards.push(guard);
    }
    Ok(guards)
}

/// Replace the entire DACL, including unknown per-user ACEs. Callers must pin
/// the object and its ancestors and validate the owner before calling this.
pub fn replace_dacl(path: &Path, sddl: &str) -> Result<()> {
    let sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = null_mut();
    // SAFETY: input is NUL-terminated and the output pointer is writable.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("Invalid service DACL");
    }
    let _descriptor = LocalAllocation(descriptor);
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = null_mut();
    // SAFETY: descriptor is live; all output pointers refer to writable storage.
    if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
        == 0
        || present == 0
        || dacl.is_null()
    {
        bail!("Service DACL must be explicit and non-null");
    }
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: path is NUL-terminated, dacl is valid until _descriptor is dropped.
    let status = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32))
            .context("Cannot replace service DACL");
    }
    Ok(())
}

#[cfg(test)]
#[path = "secure_path/tests.rs"]
mod tests;
