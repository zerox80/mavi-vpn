use super::adapter::{cleanup_mavi_adapter_dns_state, remove_nrpt_dns_rule};
use super::host_route::{clear_persisted_host_route, load_persisted_host_route};
use super::ip::win32_cleanup_all_ips_on_interface;
use super::route::{
    cleanup_ipv6_prefix_policy, win32_cleanup_all_routes_on_interface, win32_delete_route,
};
use super::utils::run_powershell_cmd;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;
use tracing::info;
use windows_sys::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2};

pub fn cleanup_routes(host_route: Option<&str>) {
    info!("Cleaning up MaviVPN routes...");
    cleanup_ipv6_prefix_policy();

    let started = Instant::now();

    let _ = win32_delete_route(0, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1);
    let _ = win32_delete_route(0, IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1);

    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIfTable2(&raw mut table) } == 0 {
        let rows = unsafe {
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
        };
        for row in rows {
            let name = String::from_utf16_lossy(&row.Alias);
            if name.contains("MaviVPN") {
                win32_cleanup_all_routes_on_interface(row.InterfaceIndex);
                win32_cleanup_all_ips_on_interface(row.InterfaceIndex);
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
        unsafe { FreeMibTable(table as _) };
    }

    let mut host_prefixes = Vec::new();
    if let Some(prefix) = host_route {
        host_prefixes.push(prefix.to_string());
    }
    if let Some(prefix) = load_persisted_host_route() {
        if !host_prefixes.iter().any(|item| item == &prefix) {
            host_prefixes.push(prefix);
        }
    }

    if !host_prefixes.is_empty() {
        use std::fmt::Write;
        let mut ps_script = String::from("$ErrorActionPreference = 'SilentlyContinue'; ");
        for prefix in host_prefixes {
            let _ = write!(
                ps_script,
                "Remove-NetRoute -DestinationPrefix '{prefix}' -Confirm:$false; "
            );
        }
        let _ = run_powershell_cmd("Cleanup host routes", &ps_script);
    }

    info!(
        "Network cleanup completed in {} ms",
        started.elapsed().as_millis()
    );
    cleanup_mavi_adapter_dns_state();
    clear_persisted_host_route();
}

pub fn cleanup_stale_network_state() {
    cleanup_routes(None);
    remove_nrpt_dns_rule();
}
