use std::net::IpAddr;
use tracing::{info, warn};
use windows_sys::Win32::Foundation::WIN32_ERROR;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIfTable2, GetIpForwardTable2, GetUnicastIpAddressTable, MIB_IF_ROW2,
    MIB_IF_TABLE2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_UNICASTIPADDRESS_ROW,
    MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6, SOCKADDR_INET};

/// Win32 status meaning "the entry already exists" (`ERROR_OBJECT_ALREADY_EXISTS`).
/// Treated as success for our idempotent add operations (`CreateIpForwardEntry2` /
/// `CreateUnicastIpAddressEntry`), which may run again after a reconnect.
pub const ERROR_OBJECT_ALREADY_EXISTS: u32 = 5010;

/// Win32 status meaning "no matching entry was found" (`ERROR_NOT_FOUND`).
/// Treated as success for our idempotent delete operations: removing a route that
/// is already gone is the desired end state, not a failure.
pub const ERROR_NOT_FOUND: u32 = 1168;

/// `IP_DAD_STATE` value `IpDadStatePreferred`: the address has passed Duplicate
/// Address Detection and is fully usable. Typed `i32` to match `MIB_*::DadState`
/// (`NL_DAD_STATE`).
pub const IP_DAD_STATE_PREFERRED: i32 = 4;

/// `IP_DAD_STATE` value `IpDadStateDeprecated`: the address is still usable for
/// existing connections even though it should not be used for new ones — good
/// enough to consider the address "applied".
pub const IP_DAD_STATE_DEPRECATED: i32 = 3;

pub fn win_err(code: WIN32_ERROR) -> anyhow::Error {
    anyhow::anyhow!("Win32 error: {code}")
}

/// Fetches the interface table, hands the rows to `f`, then **always** releases the
/// table with `FreeMibTable`. Returns `f`'s result, or `None` if `GetIfTable2` failed.
///
/// Centralizing the fetch/borrow/free dance here keeps the `unsafe` Win32 table
/// lifecycle in one audited place so call sites cannot forget to free the table.
pub fn with_if_table<R>(f: impl FnOnce(&[MIB_IF_ROW2]) -> R) -> Option<R> {
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    // SAFETY: On success GetIfTable2 hands us an allocation we own. We build a slice
    // over exactly NumEntries rows (the documented layout of the trailing Table array)
    // and free the allocation before this scope ends, so the pointer never escapes.
    unsafe {
        if GetIfTable2(&raw mut table) != 0 {
            return None;
        }
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        let result = f(rows);
        FreeMibTable(table as _);
        Some(result)
    }
}

/// Fetches the IP forward (routing) table for `family`, hands the rows to `f`, then
/// **always** frees it. Returns `None` if `GetIpForwardTable2` failed. See
/// [`with_if_table`] for the safety rationale.
pub fn with_forward_table<R>(
    family: ADDRESS_FAMILY,
    f: impl FnOnce(&[MIB_IPFORWARD_ROW2]) -> R,
) -> Option<R> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: see `with_if_table` — same owned-allocation, slice, free contract.
    unsafe {
        if GetIpForwardTable2(family, &raw mut table) != 0 {
            return None;
        }
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        let result = f(rows);
        FreeMibTable(table as _);
        Some(result)
    }
}

/// Fetches the unicast IP address table for `family`, hands the rows to `f`, then
/// **always** frees it. Returns `None` if `GetUnicastIpAddressTable` failed. See
/// [`with_if_table`] for the safety rationale.
pub fn with_unicast_table<R>(
    family: ADDRESS_FAMILY,
    f: impl FnOnce(&[MIB_UNICASTIPADDRESS_ROW]) -> R,
) -> Option<R> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    // SAFETY: see `with_if_table` — same owned-allocation, slice, free contract.
    unsafe {
        if GetUnicastIpAddressTable(family, &raw mut table) != 0 {
            return None;
        }
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        let result = f(rows);
        FreeMibTable(table as _);
        Some(result)
    }
}

pub const fn to_sockaddr_inet(ip: IpAddr) -> SOCKADDR_INET {
    let mut addr: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match ip {
        IpAddr::V4(v4) => {
            addr.si_family = AF_INET;
            addr.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
            addr.Ipv4.sin_port = 0;
        }
        IpAddr::V6(v6) => {
            addr.si_family = AF_INET6;
            addr.Ipv6.sin6_addr.u.Byte = v6.octets();
            addr.Ipv6.sin6_port = 0;
        }
    }
    addr
}

pub fn run_cmd(program: &str, args: &[&str]) -> bool {
    let display = format!("{} {}", program, args.join(" "));
    match std::process::Command::new(program).args(args).output() {
        Ok(out) if out.status.success() => {
            let msg = format!("[OK]  {display}");
            info!(cmd = %msg);
            true
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let msg = format!("[FAIL] {display} -> {stdout} {stderr}");
            warn!(cmd = %msg);
            false
        }
        Err(e) => {
            let msg = format!("[ERR] {display} -> {e}");
            warn!(cmd = %msg);
            false
        }
    }
}

pub fn run_powershell_cmd(display: &str, script: &str) -> bool {
    match std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output()
    {
        Ok(out) if out.status.success() => {
            let msg = format!("[OK]  {display}");
            info!(cmd = %msg);
            true
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let msg = format!("[FAIL] {display} -> {stdout} {stderr}");
            warn!(cmd = %msg);
            false
        }
        Err(e) => {
            let msg = format!("[ERR] {display} -> {e}");
            warn!(cmd = %msg);
            false
        }
    }
}

pub fn split_endpoint(endpoint: &str) -> (&str, Option<&str>) {
    if let Some(rest) = endpoint.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let port = rest[end + 1..].strip_prefix(':');
            return (host, port);
        }
    }

    if endpoint.matches(':').count() == 1 {
        if let Some((host, port)) = endpoint.rsplit_once(':') {
            return (host, Some(port));
        }
    }

    (endpoint, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_endpoint_hostname_with_port() {
        assert_eq!(
            split_endpoint("vpn.example.com:4433"),
            ("vpn.example.com", Some("4433"))
        );
    }

    #[test]
    fn split_endpoint_hostname_without_port() {
        assert_eq!(split_endpoint("vpn.example.com"), ("vpn.example.com", None));
    }

    #[test]
    fn split_endpoint_ipv4_with_port() {
        assert_eq!(
            split_endpoint("192.168.1.1:4433"),
            ("192.168.1.1", Some("4433"))
        );
    }

    #[test]
    fn split_endpoint_ipv4_without_port() {
        assert_eq!(split_endpoint("192.168.1.1"), ("192.168.1.1", None));
    }

    #[test]
    fn split_endpoint_ipv6_bracketed_with_port() {
        assert_eq!(split_endpoint("[::1]:4433"), ("::1", Some("4433")));
        assert_eq!(
            split_endpoint("[2001:db8::1]:443"),
            ("2001:db8::1", Some("443"))
        );
    }

    #[test]
    fn split_endpoint_ipv6_bracketed_without_port() {
        assert_eq!(split_endpoint("[::1]"), ("::1", None));
        assert_eq!(split_endpoint("[2001:db8::1]"), ("2001:db8::1", None));
    }

    #[test]
    fn split_endpoint_ipv6_no_brackets() {
        assert_eq!(split_endpoint("::1"), ("::1", None));
        assert_eq!(split_endpoint("2001:db8::1"), ("2001:db8::1", None));
    }

    #[test]
    fn split_endpoint_empty_string() {
        assert_eq!(split_endpoint(""), ("", None));
    }

    #[test]
    fn to_sockaddr_inet_ipv4() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        let addr = to_sockaddr_inet(ip);
        unsafe {
            assert_eq!(addr.si_family, AF_INET);
            let expected = u32::from_ne_bytes([192, 168, 1, 1]);
            assert_eq!(addr.Ipv4.sin_addr.S_un.S_addr, expected);
        }
    }

    #[test]
    fn to_sockaddr_inet_ipv6() {
        let ip = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let addr = to_sockaddr_inet(ip);
        unsafe {
            assert_eq!(addr.si_family, AF_INET6);
            let expected = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            assert_eq!(addr.Ipv6.sin6_addr.u.Byte, expected);
        }
    }

    #[test]
    fn to_sockaddr_inet_ipv4_loopback() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let addr = to_sockaddr_inet(ip);
        unsafe {
            assert_eq!(addr.si_family, AF_INET);
            let expected = u32::from_ne_bytes([127, 0, 0, 1]);
            assert_eq!(addr.Ipv4.sin_addr.S_un.S_addr, expected);
        }
    }

    #[test]
    fn to_sockaddr_inet_ipv6_loopback() {
        let ip = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        let addr = to_sockaddr_inet(ip);
        unsafe {
            assert_eq!(addr.si_family, AF_INET6);
            let mut expected = [0u8; 16];
            expected[15] = 1;
            assert_eq!(addr.Ipv6.sin6_addr.u.Byte, expected);
        }
    }

    #[test]
    fn to_sockaddr_inet_port_is_zero() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
        let addr = to_sockaddr_inet(ip);
        unsafe {
            assert_eq!(addr.Ipv4.sin_port, 0);
        }

        let ip6 = IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED);
        let addr6 = to_sockaddr_inet(ip6);
        unsafe {
            assert_eq!(addr6.Ipv6.sin6_port, 0);
        }
    }

    #[test]
    fn win_err_formats_code() {
        let err = win_err(1168);
        assert!(err.to_string().contains("1168"));
    }

    #[test]
    fn win_err_zero() {
        let err = win_err(0);
        assert!(err.to_string().contains("0"));
    }
}
