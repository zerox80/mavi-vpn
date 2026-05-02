use anyhow::{bail, Result};
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use tracing::{info, warn};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetIpForwardTable2,
    InitializeIpForwardEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use super::utils::{run_cmd, to_sockaddr_inet, win_err};

pub fn win32_add_route(
    adapter_index: u32,
    destination: IpAddr,
    prefix_len: u8,
    next_hop: Option<IpAddr>,
    metric: u32,
) -> Result<()> {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&raw mut row) };

    row.InterfaceIndex = adapter_index;
    row.DestinationPrefix.Prefix = to_sockaddr_inet(destination);
    row.DestinationPrefix.PrefixLength = prefix_len;
    if let Some(hop) = next_hop {
        row.NextHop = to_sockaddr_inet(hop);
    }
    row.Metric = metric;

    let res = unsafe { CreateIpForwardEntry2(&raw const row) };
    if res == 0 || res == 5010 {
        Ok(())
    } else {
        Err(win_err(res))
    }
}

pub fn win32_delete_route(adapter_index: u32, destination: IpAddr, prefix_len: u8) -> Result<()> {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&raw mut row) };
    row.InterfaceIndex = adapter_index;
    row.DestinationPrefix.Prefix = to_sockaddr_inet(destination);
    row.DestinationPrefix.PrefixLength = prefix_len;

    let res = unsafe { DeleteIpForwardEntry2(&raw const row) };
    if res == 0 || res == 1168 {
        Ok(())
    } else {
        Err(win_err(res))
    }
}

pub fn win32_cleanup_all_routes_on_interface(adapter_index: u32) {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIpForwardTable2(AF_INET, &raw mut table) } == 0 {
        let rows = unsafe {
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
        };
        for row in rows {
            if row.InterfaceIndex == adapter_index {
                unsafe { DeleteIpForwardEntry2(row) };
            }
        }
        unsafe { FreeMibTable(table as _) };
    }
    // Repeat for IPv6
    let mut table_v6: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIpForwardTable2(AF_INET6, &raw mut table_v6) } == 0 {
        let rows = unsafe {
            std::slice::from_raw_parts((*table_v6).Table.as_ptr(), (*table_v6).NumEntries as usize)
        };
        for row in rows {
            if row.InterfaceIndex == adapter_index {
                unsafe { DeleteIpForwardEntry2(row) };
            }
        }
        unsafe { FreeMibTable(table_v6 as _) };
    }
}

pub fn verify_ipv6_split_routes(adapter_index: u32) -> Result<bool> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIpForwardTable2(AF_INET6, &raw mut table) } != 0 {
        bail!("Failed to get IPv6 forward table");
    }

    let rows = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };

    let mut found_zero = false;
    let mut found_eight = false;

    for row in rows {
        if row.InterfaceIndex == adapter_index {
            let prefix = row.DestinationPrefix;
            let addr_bytes = unsafe { prefix.Prefix.Ipv6.sin6_addr.u.Byte };
            let plen = prefix.PrefixLength;

            if plen == 1 && addr_bytes.iter().all(|&b| b == 0) {
                found_zero = true;
            }
            if plen == 1 && addr_bytes[0] == 0x80 && addr_bytes[1..].iter().all(|&b| b == 0) {
                found_eight = true;
            }
        }
    }

    unsafe { FreeMibTable(table as _) };
    Ok(found_zero && found_eight)
}

fn prefix_policy_path() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
    base.join("mavi-vpn").join("last_prefix_policy.txt")
}

fn persist_prefix_policy(prefix: &str) {
    let path = prefix_policy_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, prefix);
}

pub fn load_persisted_prefix_policy() -> Option<String> {
    std::fs::read_to_string(prefix_policy_path())
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub fn clear_persisted_prefix_policy() {
    let _ = std::fs::remove_file(prefix_policy_path());
}

pub fn apply_ipv6_prefix_policy(prefix: &str) -> bool {
    let set_ok = run_cmd(
        "netsh",
        &[
            "interface",
            "ipv6",
            "set",
            "prefixpolicy",
            &format!("prefix={prefix}"),
            "precedence=100",
            "label=13",
            "store=active",
        ],
    );

    if set_ok {
        persist_prefix_policy(prefix);
        info!("Applied IPv6 prefix policy with set: {}", prefix);
        return true;
    }

    let add_ok = run_cmd(
        "netsh",
        &[
            "interface",
            "ipv6",
            "add",
            "prefixpolicy",
            &format!("prefix={prefix}"),
            "precedence=100",
            "label=13",
            "store=active",
        ],
    );

    if add_ok {
        persist_prefix_policy(prefix);
        info!("Applied IPv6 prefix policy with add: {}", prefix);
    } else {
        warn!("Failed to apply IPv6 prefix policy: {}", prefix);
    }

    add_ok
}

pub fn cleanup_ipv6_prefix_policy() {
    if let Some(prefix) = load_persisted_prefix_policy() {
        let ok = run_cmd(
            "netsh",
            &[
                "interface",
                "ipv6",
                "delete",
                "prefixpolicy",
                &format!("prefix={prefix}"),
            ],
        );

        if ok {
            info!("Removed MaviVPN IPv6 prefix policy: {}", prefix);
        } else {
            warn!("Failed to remove MaviVPN IPv6 prefix policy: {}", prefix);
        }

        clear_persisted_prefix_policy();
    }
}

pub fn ipv6_network_prefix(ip: Ipv6Addr, prefix_len: u8) -> String {
    let segments = ip.segments();
    let mut masked = [0u16; 8];
    let mut bits_left = prefix_len;
    for i in 0..8 {
        if bits_left >= 16 {
            masked[i] = segments[i];
            bits_left -= 16;
        } else if bits_left > 0 {
            let mask = 0xFFFFu16 << (16 - bits_left);
            masked[i] = segments[i] & mask;
            bits_left = 0;
        } else {
            masked[i] = 0;
        }
    }
    format!("{}/{}", Ipv6Addr::from(masked), prefix_len)
}
