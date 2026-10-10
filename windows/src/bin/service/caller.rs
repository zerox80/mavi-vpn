//! Authenticate the actual pipe sender, including handles opened before a switch.
#![allow(unsafe_code)]

use std::os::windows::io::AsRawHandle;
use std::ptr::{null_mut, NonNull};
use tokio::net::windows::named_pipe::NamedPipeServer;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetTokenInformation, RevertToSelf, TokenElevation, TokenSessionId, TokenStatistics, TokenUser,
    TOKEN_ELEVATION, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER,
};
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionOwner {
    pub sid: String,
    pub session_id: u32,
    // Unlike a WTS session number, AuthenticationId is unique for each logon.
    pub logon_id: (u32, i32),
}

pub struct Caller {
    pub owner: SessionOwner,
    pub privileged: bool,
}

impl Caller {
    pub fn authorized(&self, console: Option<&(String, u32)>) -> bool {
        self.privileged
            || console.is_some_and(|(sid, session)| {
                *sid == self.owner.sid && *session == self.owner.session_id
            })
    }

    /// Invoke after reading the request. No await may occur while impersonating:
    /// Windows binds impersonation to the OS thread, not the Tokio task.
    pub fn from_pipe(pipe: &NamedPipeServer) -> anyhow::Result<Self> {
        if unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle()) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let _revert = RevertGuard;
        let mut token = null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let token = TokenGuard(token);
        let sid = token_sid(token.0)?;
        let session_id = token_info::<u32>(token.0, TokenSessionId)?;
        let stats = token_info::<TOKEN_STATISTICS>(token.0, TokenStatistics)?;
        let elevation = token_info::<TOKEN_ELEVATION>(token.0, TokenElevation)?;
        Ok(Self {
            privileged: sid == "S-1-5-18" || elevation.TokenIsElevated != 0,
            owner: SessionOwner {
                sid,
                session_id,
                logon_id: (
                    stats.AuthenticationId.LowPart,
                    stats.AuthenticationId.HighPart,
                ),
            },
        })
    }

    #[cfg(test)]
    pub fn test_admin() -> Self {
        Self {
            owner: SessionOwner {
                sid: "S-1-5-18".into(),
                session_id: 0,
                logon_id: (999, 0),
            },
            privileged: true,
        }
    }
}

struct RevertGuard;
impl Drop for RevertGuard {
    fn drop(&mut self) {
        // Continuing a worker thread as the client would corrupt the service's
        // security context. Microsoft requires terminating on revert failure.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

struct TokenGuard(HANDLE);
impl Drop for TokenGuard {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn token_info<T>(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> anyhow::Result<T> {
    let mut value = std::mem::MaybeUninit::<T>::uninit();
    let mut written = 0;
    // All callers pair the documented fixed-size token class with its POD type.
    if unsafe {
        GetTokenInformation(
            token,
            class,
            value.as_mut_ptr().cast(),
            size_of::<T>() as u32,
            &mut written,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    anyhow::ensure!(
        written as usize == size_of::<T>(),
        "Invalid token information size"
    );
    Ok(unsafe { value.assume_init() })
}

fn token_sid(token: HANDLE) -> anyhow::Result<String> {
    let mut len = 0;
    unsafe {
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
    }
    anyhow::ensure!(
        len as usize >= size_of::<TOKEN_USER>() && len <= 4096,
        "Invalid token user size"
    );
    let mut storage = vec![0_usize; (len as usize).div_ceil(size_of::<usize>())];
    if unsafe { GetTokenInformation(token, TokenUser, storage.as_mut_ptr().cast(), len, &mut len) }
        == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    let mut text = null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let text = NonNull::new(text).ok_or_else(|| anyhow::anyhow!("Missing SID string"))?;
    let mut length = 0;
    unsafe {
        while *text.as_ptr().add(length) != 0 {
            length += 1;
        }
        let sid = String::from_utf16(std::slice::from_raw_parts(text.as_ptr(), length));
        LocalFree(text.as_ptr().cast());
        Ok(sid?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_console_handles_and_missing_console_are_rejected() {
        let caller = Caller {
            owner: SessionOwner {
                sid: "S-1-5-21-1".into(),
                session_id: 1,
                logon_id: (10, 0),
            },
            privileged: false,
        };
        assert!(caller.authorized(Some(&(caller.owner.sid.clone(), 1))));
        assert!(!caller.authorized(Some(&("S-1-5-21-2".into(), 2))));
        assert!(!caller.authorized(Some(&(caller.owner.sid.clone(), 2))));
        assert!(!caller.authorized(None));
        assert!(Caller::test_admin().authorized(None));
    }
}
