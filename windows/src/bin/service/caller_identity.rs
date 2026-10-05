//! Resolve the authenticated pipe caller, independently of the console-user ACL.
#![allow(unsafe_code)] // Windows owns the client token and allocated SID string.

use anyhow::{Context, Result};
use std::os::windows::io::AsRawHandle;
use std::ptr::null_mut;
use tokio::net::windows::named_pipe::NamedPipeServer;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER, HANDLE,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetTokenInformation, RevertToSelf, TokenUser, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

struct ImpersonationGuard;

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        // SAFETY: the guard exists only after successful pipe impersonation.
        // Continuing on a runtime worker as the client would be unsafe.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

struct TokenHandle(HANDLE);

impl Drop for TokenHandle {
    fn drop(&mut self) {
        // SAFETY: this guard owns an open token handle.
        unsafe { CloseHandle(self.0) };
    }
}

/// Call after reading the request: Windows identifies the sender of the last
/// pipe message. This entire operation is synchronous so impersonation cannot
/// migrate across async worker threads, and every return restores the service.
pub fn client_user_sid(pipe: &NamedPipeServer) -> Result<String> {
    // SAFETY: the connected server owns this handle for the entire call.
    if unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle()) } == 0 {
        return Err(std::io::Error::last_os_error()).context("Cannot identify IPC caller");
    }
    let _impersonation = ImpersonationGuard;
    let mut token = null_mut();
    // OpenAsSelf permits querying SECURITY_IDENTIFICATION tokens used by both
    // GUI and CLI clients. Never fall back to the service's process token.
    // SAFETY: valid thread pseudo-handle and writable output pointer.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error()).context("Cannot query IPC caller token");
    }
    let token = TokenHandle(token);
    token_user_sid(token.0)
}

fn token_user_sid(token: HANDLE) -> Result<String> {
    let mut byte_len = 0;
    // SAFETY: a zero-sized buffer asks Windows for the required allocation size.
    let ok = unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut byte_len) };
    if ok != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(std::io::Error::last_os_error()).context("Cannot size IPC caller SID");
    }
    anyhow::ensure!(
        byte_len as usize >= size_of::<TOKEN_USER>(),
        "Invalid caller token size"
    );
    // TOKEN_USER contains a pointer: use pointer-aligned storage for the row
    // and the variable-sized SID which Windows places in the same allocation.
    let mut buffer = vec![0_usize; (byte_len as usize).div_ceil(size_of::<usize>())];
    // SAFETY: the aligned output buffer has the size reported by Windows.
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            byte_len,
            &mut byte_len,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("Cannot read IPC caller SID");
    }
    // SAFETY: Windows initialized TOKEN_USER and its SID in the live allocation.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut text = null_mut();
    // SAFETY: the SID remains live and text is a valid output pointer.
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
        return Err(std::io::Error::last_os_error()).context("Cannot encode IPC caller SID");
    }
    // SAFETY: successful conversion returns a NUL-terminated allocation owned
    // by LocalFree. Consume it before freeing, including on a conversion error.
    unsafe {
        let mut len = 0;
        while *text.add(len) != 0 {
            len += 1;
        }
        let result = String::from_utf16(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        result.context("Invalid IPC caller SID encoding")
    }
}

#[cfg(test)]
#[path = "caller_identity/tests.rs"]
mod tests;
