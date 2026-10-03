//! Authenticate the server of an already connected pipe before sending secrets.
//! The pipe name and the ACL of the first instance do not identify later servers.

use std::io;
use std::mem::{offset_of, size_of};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{HANDLE, WAIT_TIMEOUT};
use windows_sys::Win32::Security::{
    GetTokenInformation, IsWellKnownSid, TokenGroups, WinBuiltinAdministratorsSid,
    SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_QUERY,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
    SERVICE_STATUS_PROCESS, SERVICE_WIN32_OWN_PROCESS,
};
use windows_sys::Win32::System::SystemServices::{SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY};
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, WaitForSingleObject,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "IPC endpoint is not the Mavi VPN service",
    )
}

/// Verify this exact connected handle. Callers must use it for all subsequent I/O.
/// A live process handle prevents PID reuse during authentication.
#[allow(unsafe_code)]
pub fn authenticate(pipe: &impl AsRawHandle) -> io::Result<()> {
    let mut pid = 0;
    // SAFETY: the caller retains the connected pipe; pid is writable.
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        return Err(denied());
    }
    // SAFETY: no inheritance; request only query/synchronization access.
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcess returned an owned, valid handle.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    let registered = service_status().is_ok_and(|status| matches_service(&status, pid));
    // Documented elevated --console mode has no SCM entry. It must be the
    // service executable running with an enabled Administrators SID, never
    // merely a same-named unelevated process or a permissive pipe descriptor.
    let console = !registered && is_elevated_console(process.as_raw_handle())?;
    // SAFETY: the owned handle remains open and is synchronizable.
    let alive = unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } == WAIT_TIMEOUT;
    if alive && (registered || console) {
        Ok(())
    } else {
        Err(denied())
    }
}

fn matches_service(status: &SERVICE_STATUS_PROCESS, pid: u32) -> bool {
    pid != 0
        && status.dwProcessId == pid
        && status.dwCurrentState == SERVICE_RUNNING
        && status.dwServiceType == SERVICE_WIN32_OWN_PROCESS
}

struct ServiceHandle(SC_HANDLE);

impl Drop for ServiceHandle {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: this wrapper owns exactly one non-null SCM/service handle.
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

#[allow(unsafe_code)]
fn service_status() -> io::Result<SERVICE_STATUS_PROCESS> {
    // SAFETY: null machine/database select the local SCM.
    let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(io::Error::last_os_error());
    }
    let manager = ServiceHandle(manager);
    let name: Vec<u16> = "MaviVPNService\0".encode_utf16().collect();
    // SAFETY: manager is live and the name is NUL terminated.
    let service = unsafe { OpenServiceW(manager.0, name.as_ptr(), SERVICE_QUERY_STATUS) };
    if service.is_null() {
        return Err(io::Error::last_os_error());
    }
    let service = ServiceHandle(service);
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0;
    // SAFETY: status has the documented buffer size/alignment for this info level.
    if unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            (&raw mut status).cast(),
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(status)
}

#[allow(unsafe_code)]
fn is_elevated_console(process: HANDLE) -> io::Result<bool> {
    let mut image = vec![0u16; 32_768];
    let mut len = image.len() as u32;
    // SAFETY: image is writable for len UTF-16 characters; process is held open.
    if unsafe { QueryFullProcessImageNameW(process, 0, image.as_mut_ptr(), &mut len) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let image = String::from_utf16_lossy(&image[..len as usize]);
    if !Path::new(&image).file_name().is_some_and(|name| {
        name.to_string_lossy()
            .eq_ignore_ascii_case("mavi-vpn-service.exe")
    }) {
        return Ok(false);
    }
    let mut token = null_mut();
    // SAFETY: process is held open and token is writable.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken returned an owned handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut needed = 0;
    // SAFETY: this first call only queries the required length.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenGroups,
            null_mut(),
            0,
            &mut needed,
        );
    }
    if needed < size_of::<TOKEN_GROUPS>() as u32 || needed > 65_536 {
        return Err(denied());
    }
    // usize storage provides the alignment required by TOKEN_GROUPS and its SIDs.
    let mut buffer = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    // SAFETY: the aligned allocation covers needed bytes and the handle is live.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenGroups,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful GetTokenInformation initialized TOKEN_GROUPS.
    let groups = unsafe { &*buffer.as_ptr().cast::<TOKEN_GROUPS>() };
    let count = groups.GroupCount as usize;
    let available =
        (needed as usize - offset_of!(TOKEN_GROUPS, Groups)) / size_of::<SID_AND_ATTRIBUTES>();
    if count > available {
        return Err(denied());
    }
    // SAFETY: the count was checked against the returned allocation.
    let entries = unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), count) };
    Ok(entries.iter().any(|group| {
        enabled_admin_group(group.Attributes)
            // SAFETY: each SID is returned by the OS in the retained token buffer.
            && unsafe { IsWellKnownSid(group.Sid, WinBuiltinAdministratorsSid) } != 0
    }))
}

fn enabled_admin_group(attributes: u32) -> bool {
    attributes & SE_GROUP_ENABLED as u32 != 0 && attributes & SE_GROUP_USE_FOR_DENY_ONLY as u32 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Services::{SERVICE_STOPPED, SERVICE_WIN32_SHARE_PROCESS};

    #[test]
    fn service_identity_requires_running_own_process_and_exact_nonzero_pid() {
        let mut status = SERVICE_STATUS_PROCESS {
            dwProcessId: 42,
            dwCurrentState: SERVICE_RUNNING,
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            ..Default::default()
        };
        assert!(matches_service(&status, 42));
        assert!(!matches_service(&status, 0));
        assert!(!matches_service(&status, 43));
        status.dwCurrentState = SERVICE_STOPPED;
        assert!(!matches_service(&status, 42));
        status.dwCurrentState = SERVICE_RUNNING;
        status.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
        assert!(!matches_service(&status, 42));
    }

    #[test]
    fn console_fallback_rejects_filtered_and_disabled_admin_membership() {
        assert!(enabled_admin_group(SE_GROUP_ENABLED as u32));
        assert!(!enabled_admin_group(0));
        assert!(!enabled_admin_group(SE_GROUP_USE_FOR_DENY_ONLY as u32));
        assert!(!enabled_admin_group(
            (SE_GROUP_ENABLED | SE_GROUP_USE_FOR_DENY_ONLY) as u32
        ));
    }
}
