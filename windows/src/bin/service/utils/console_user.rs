//! Resolve the live console user without starting PowerShell on every IPC request.
#![allow(unsafe_code)] // Windows allocates the WTS and SID buffers used below.

use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::LookupAccountNameW;
use windows_sys::Win32::System::RemoteDesktop::{
    WTSDomainName, WTSFreeMemory, WTSGetActiveConsoleSessionId, WTSQuerySessionInformationW,
    WTSUserName, WTS_CURRENT_SERVER_HANDLE, WTS_INFO_CLASS,
};

struct WtsBuffer(*mut u16);

impl Drop for WtsBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this allocation was returned by WTSQuerySessionInformationW.
            unsafe { WTSFreeMemory(self.0.cast()) };
        }
    }
}

/// Query each time so logoff and fast user switching cannot leave a cached SID
/// authorized on newly created pipes. Fail closed if no console user is known.
pub fn active_console_user_sid() -> Option<String> {
    // SAFETY: this query takes no pointers and has no preconditions.
    let session = unsafe { WTSGetActiveConsoleSessionId() };
    if session == u32::MAX {
        return None;
    }
    let user = session_string(session, WTSUserName)?;
    let domain = session_string(session, WTSDomainName)?;
    let account = qualified_account(&domain, &user)?;
    let sid = account_sid(&account)?;
    // A console switch while resolving the account must not authorize the old user.
    (unsafe { WTSGetActiveConsoleSessionId() } == session).then_some(sid)
}

fn session_string(session: u32, class: WTS_INFO_CLASS) -> Option<String> {
    let mut buffer = WtsBuffer(null_mut());
    let mut byte_len = 0;
    // SAFETY: valid output pointers; the RAII guard frees any returned buffer.
    let ok = unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            session,
            class,
            &mut buffer.0,
            &mut byte_len,
        )
    };
    if ok == 0 || buffer.0.is_null() || !byte_len.is_multiple_of(2) {
        return None;
    }
    // SAFETY: WTS reports the allocation's byte length; these classes return UTF-16.
    let text = unsafe { std::slice::from_raw_parts(buffer.0, byte_len as usize / 2) };
    let end = text.iter().position(|&c| c == 0)?;
    String::from_utf16(&text[..end]).ok()
}

fn qualified_account(domain: &str, user: &str) -> Option<String> {
    if domain.is_empty() || user.is_empty() || domain.contains('\0') || user.contains('\0') {
        return None;
    }
    Some(format!("{domain}\\{user}"))
}

fn account_sid(account: &str) -> Option<String> {
    let account: Vec<u16> = account.encode_utf16().chain(Some(0)).collect();
    let mut sid_len = 0;
    let mut domain_len = 0;
    let mut sid_type = 0;
    // SAFETY: zero-sized output buffers request the required lengths.
    unsafe {
        LookupAccountNameW(
            null(),
            account.as_ptr(),
            null_mut(),
            &mut sid_len,
            null_mut(),
            &mut domain_len,
            &mut sid_type,
        );
        if GetLastError() != ERROR_INSUFFICIENT_BUFFER || sid_len == 0 {
            return None;
        }
    }
    // SID contains u32 fields, so use aligned storage rather than a Vec<u8>.
    let mut sid = vec![0_u32; (sid_len as usize).div_ceil(size_of::<u32>())];
    let mut domain = vec![0_u16; domain_len as usize];
    // SAFETY: the output buffers have the lengths requested by Windows.
    if unsafe {
        LookupAccountNameW(
            null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut sid_type,
        )
    } == 0
    {
        return None;
    }
    let mut text = null_mut();
    // SAFETY: LookupAccountNameW returned a valid SID in aligned, live storage.
    if unsafe { ConvertSidToStringSidW(sid.as_ptr().cast_mut().cast(), &mut text) } == 0 {
        return None;
    }
    // SAFETY: successful conversion returns a NUL-terminated UTF-16 allocation.
    // Consume it while live and release it with the documented allocator.
    unsafe {
        let mut len = 0;
        while *text.add(len) != 0 {
            len += 1;
        }
        let result = String::from_utf16(std::slice::from_raw_parts(text, len)).ok();
        LocalFree(text.cast());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_lookup_requires_a_named_user_and_domain() {
        assert_eq!(qualified_account("", "alice"), None);
        assert_eq!(qualified_account("PC", ""), None);
        assert_eq!(qualified_account("PC", "alice\0bob"), None);
        assert_eq!(qualified_account("PC\0DOMAIN", "alice"), None);
        assert_eq!(
            qualified_account("DOMAIN", "alice"),
            Some("DOMAIN\\alice".into())
        );
    }
}
