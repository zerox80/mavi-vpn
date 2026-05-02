use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;
use tracing::{info, warn};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateUnicastIpAddressEntry, DeleteUnicastIpAddressEntry, FreeMibTable,
    GetUnicastIpAddressTable, InitializeUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW,
    MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use super::utils::{to_sockaddr_inet, win_err};

pub fn wait_for_ipv4_address(adapter_index: u32, ip: Ipv4Addr) -> bool {
    let started = Instant::now();
    let target_addr = u32::from_ne_bytes(ip.octets());

    for _ in 0..500 {
        let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
        if unsafe { GetUnicastIpAddressTable(AF_INET, &raw mut table) } == 0 {
            let mut found = false;
            let rows = unsafe {
                std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
            };
            for row in rows {
                unsafe {
                    if row.InterfaceIndex == adapter_index
                        && row.Address.Ipv4.sin_addr.S_un.S_addr == target_addr
                    {
                        found = true;
                        break;
                    }
                }
            }
            unsafe { FreeMibTable(table as _) };
            if found {
                info!(
                    "IP {} confirmed on adapter in {} ms",
                    ip,
                    started.elapsed().as_millis()
                );
                return true;
            }
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
        let mut found = false;
        {
            let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
            if unsafe { GetUnicastIpAddressTable(AF_INET6, &raw mut table) } == 0 {
                let rows = unsafe {
                    std::slice::from_raw_parts(
                        (*table).Table.as_ptr(),
                        (*table).NumEntries as usize,
                    )
                };
                for row in rows {
                    unsafe {
                        if row.InterfaceIndex == adapter_index
                            && row.Address.Ipv6.sin6_addr.u.Byte == target_octets
                        {
                            last_state = row.DadState;
                            // Check if it's preferred (4) or at least not duplicate
                            if row.DadState == 4 || row.DadState == 3 {
                                found = true;
                                break;
                            }
                        }
                    }
                }
                unsafe { FreeMibTable(table as _) };
            }
        }

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
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
    unsafe { InitializeUnicastIpAddressEntry(&raw mut row) };

    row.Address = to_sockaddr_inet(ip);
    row.InterfaceIndex = adapter_index;
    row.OnLinkPrefixLength = prefix_len;
    row.DadState = 4; // IpDadStatePreferred
    row.SkipAsSource = false;

    let res = unsafe { CreateUnicastIpAddressEntry(&raw const row) };
    if res == 0 || res == 5010 {
        Ok(())
    } else {
        Err(win_err(res))
    }
}

pub fn win32_cleanup_all_ips_on_interface(adapter_index: u32) {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    if unsafe { GetUnicastIpAddressTable(AF_INET, &raw mut table) } == 0 {
        let rows = unsafe {
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
        };
        for row in rows {
            if row.InterfaceIndex == adapter_index {
                unsafe { DeleteUnicastIpAddressEntry(row) };
            }
        }
        unsafe { FreeMibTable(table as _) };
    }
    // IPv6
    let mut table_v6: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    if unsafe { GetUnicastIpAddressTable(AF_INET6, &raw mut table_v6) } == 0 {
        let rows = unsafe {
            std::slice::from_raw_parts((*table_v6).Table.as_ptr(), (*table_v6).NumEntries as usize)
        };
        for row in rows {
            if row.InterfaceIndex == adapter_index {
                unsafe { DeleteUnicastIpAddressEntry(row) };
            }
        }
        unsafe { FreeMibTable(table_v6 as _) };
    }

    // Wait up to 1.5 seconds for the stack to actually clear the IPs asynchronously
    let start = Instant::now();
    while start.elapsed() < std::time::Duration::from_millis(1500) {
        let mut still_has_ips = false;

        let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
        if unsafe { GetUnicastIpAddressTable(AF_INET, &raw mut table) } == 0 {
            let rows = unsafe {
                std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
            };
            if rows.iter().any(|r| r.InterfaceIndex == adapter_index) {
                still_has_ips = true;
            }
            unsafe { FreeMibTable(table as _) };
        }

        let mut table_v6: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
        if unsafe { GetUnicastIpAddressTable(AF_INET6, &raw mut table_v6) } == 0 {
            let rows = unsafe {
                std::slice::from_raw_parts(
                    (*table_v6).Table.as_ptr(),
                    (*table_v6).NumEntries as usize,
                )
            };
            if rows.iter().any(|r| r.InterfaceIndex == adapter_index) {
                still_has_ips = true;
            }
            unsafe { FreeMibTable(table_v6 as _) };
        }

        if !still_has_ips {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}
