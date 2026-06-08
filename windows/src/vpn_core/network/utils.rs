use std::net::IpAddr;
use tracing::{info, warn};
use windows_sys::Win32::Foundation::WIN32_ERROR;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_INET};

pub fn win_err(code: WIN32_ERROR) -> anyhow::Error {
    anyhow::anyhow!("Win32 error: {code}")
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
            let msg = format!("[FAIL] {display} → {stdout} {stderr}");
            warn!(cmd = %msg);
            false
        }
        Err(e) => {
            let msg = format!("[ERR] {display} → {e}");
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
            let msg = format!("[FAIL] {display} → {stdout} {stderr}");
            warn!(cmd = %msg);
            false
        }
        Err(e) => {
            let msg = format!("[ERR] {display} → {e}");
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
        assert_eq!(split_endpoint("vpn.example.com:4433"), ("vpn.example.com", Some("4433")));
    }

    #[test]
    fn split_endpoint_hostname_without_port() {
        assert_eq!(split_endpoint("vpn.example.com"), ("vpn.example.com", None));
    }

    #[test]
    fn split_endpoint_ipv4_with_port() {
        assert_eq!(split_endpoint("192.168.1.1:4433"), ("192.168.1.1", Some("4433")));
    }

    #[test]
    fn split_endpoint_ipv4_without_port() {
        assert_eq!(split_endpoint("192.168.1.1"), ("192.168.1.1", None));
    }

    #[test]
    fn split_endpoint_ipv6_bracketed_with_port() {
        assert_eq!(split_endpoint("[::1]:4433"), ("::1", Some("4433")));
        assert_eq!(split_endpoint("[2001:db8::1]:443"), ("2001:db8::1", Some("443")));
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
}
