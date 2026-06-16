use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;
use tracing::{info, warn};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateUnicastIpAddressEntry, DeleteUnicastIpAddressEntry, InitializeUnicastIpAddressEntry,
    MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use super::utils::{
    to_sockaddr_inet, win_err, with_unicast_table, ERROR_OBJECT_ALREADY_EXISTS,
    IP_DAD_STATE_DEPRECATED, IP_DAD_STATE_PREFERRED,
};

pub fn wait_for_ipv4_address(adapter_index: u32, ip: Ipv4Addr) -> bool {
    let started = Instant::now();
    let target_addr = u32::from_ne_bytes(ip.octets());

    for _ in 0..500 {
        let found = with_unicast_table(AF_INET, |rows| {
            rows.iter().any(|row| {
                // SAFETY: union access — IPv4 rows carry an Ipv4 sockaddr here.
                row.InterfaceIndex == adapter_index
                    && unsafe { row.Address.Ipv4.sin_addr.S_un.S_addr } == target_addr
            })
        })
        .unwrap_or(false);

        if found {
            info!(
                "IP {} confirmed on adapter in {} ms",
                ip,
                started.elapsed().as_millis()
            );
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    false
}

pub async fn wait_for_ipv6_address(adapter_index: u32, ip: Ipv6Addr) -> bool {
    let started = Instant::now();
    let target_octets = ip.octets();
    let mut last_state = 0;

    for _ in 0..500 {
        let found = with_unicast_table(AF_INET6, |rows| {
            for row in rows {
                // SAFETY: union access — IPv6 rows carry an Ipv6 sockaddr here.
                if row.InterfaceIndex == adapter_index
                    && unsafe { row.Address.Ipv6.sin6_addr.u.Byte } == target_octets
                {
                    last_state = row.DadState;
                    // Accept the address once it is preferred, or at least
                    // deprecated (still usable for existing connections).
                    if row.DadState == IP_DAD_STATE_PREFERRED
                        || row.DadState == IP_DAD_STATE_DEPRECATED
                    {
                        return true;
                    }
                }
            }
            false
        })
        .unwrap_or(false);

        if found {
            info!(
                "IPv6 {} confirmed on adapter in {} ms",
                ip,
                started.elapsed().as_millis()
            );
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    warn!("IPv6 {} DAD timeout! Last DadState: {}", ip, last_state);
    false
}

pub fn win32_add_ip(adapter_index: u32, ip: IpAddr, prefix_len: u8) -> Result<()> {
    // SAFETY: `zeroed()` yields a valid all-zero row, which `InitializeUnicastIpAddressEntry`
    // then populates with the documented defaults before we override specific fields.
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
    unsafe { InitializeUnicastIpAddressEntry(&raw mut row) };

    row.Address = to_sockaddr_inet(ip);
    row.InterfaceIndex = adapter_index;
    row.OnLinkPrefixLength = prefix_len;
    row.DadState = IP_DAD_STATE_PREFERRED;
    row.SkipAsSource = false;

    // SAFETY: `row` is fully initialized above and outlives this call.
    let res = unsafe { CreateUnicastIpAddressEntry(&raw const row) };
    if res == 0 || res == ERROR_OBJECT_ALREADY_EXISTS {
        Ok(())
    } else {
        Err(win_err(res))
    }
}

pub fn win32_cleanup_all_ips_on_interface(adapter_index: u32) {
    for family in [AF_INET, AF_INET6] {
        with_unicast_table(family, |rows| {
            for row in rows {
                if row.InterfaceIndex == adapter_index {
                    // SAFETY: `row` borrows a live table entry for the duration of this call.
                    unsafe { DeleteUnicastIpAddressEntry(row) };
                }
            }
        });
    }

    // Wait up to 1.5 seconds for the stack to actually clear the IPs asynchronously.
    let start = Instant::now();
    while start.elapsed() < std::time::Duration::from_millis(1500) {
        let still_has_ips = [AF_INET, AF_INET6].iter().any(|&family| {
            with_unicast_table(family, |rows| {
                rows.iter().any(|r| r.InterfaceIndex == adapter_index)
            })
            .unwrap_or(false)
        });

        if !still_has_ips {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    // NOTE: Functions in this module directly invoke Win32 APIs
    // (GetUnicastIpAddressTable, CreateUnicastIpAddressEntry, etc.)
    // and are therefore not suitable for automated unit tests.
    // They must be validated through integration / manual testing
    // on a real Windows host with an active network adapter.

    #[test]
    #[ignore = "Requires Windows host with live network adapter"]
    fn win32_ip_functions_smoke_test() {
        // Manual verification checklist:
        // 1. win32_add_ip adds an IP to a test adapter.
        // 2. wait_for_ipv4_address returns true after the IP appears.
        // 3. win32_cleanup_all_ips_on_interface removes all IPs.
        // 4. wait_for_ipv6_address (async) returns true for a valid IPv6.
    }
}
