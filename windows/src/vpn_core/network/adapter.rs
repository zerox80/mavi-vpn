use anyhow::Result;
use std::time::{Duration, Instant};
use tracing::info;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetIfEntry2, GetIpInterfaceEntry, InitializeIpInterfaceEntry, SetIpInterfaceEntry, MIB_IF_ROW2,
    MIB_IPINTERFACE_ROW,
};

use super::utils::{run_cmd, run_powershell_cmd};

pub fn wait_for_adapter_alias(adapter_index: u32, requested_name: &str) -> Result<String> {
    let started = Instant::now();
    let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    row.InterfaceIndex = adapter_index;

    for _ in 0..1500 {
        let res = unsafe { GetIfEntry2(&raw mut row) };
        if res == 0 {
            let alias = {
                let mut len = 0;
                while len < row.Alias.len() && row.Alias[len] != 0 {
                    len += 1;
                }
                String::from_utf16_lossy(&row.Alias[..len])
            };
            if !alias.is_empty() {
                info!(
                    "WinTUN adapter '{}' is visible in Windows as '{}' (if={}, waited {} ms)",
                    requested_name,
                    alias,
                    adapter_index,
                    started.elapsed().as_millis()
                );
                return Ok(alias);
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    anyhow::bail!(
        "Adapter '{requested_name}' (if={adapter_index}) did not appear in Windows networking within 30 seconds."
    );
}

pub fn win32_set_mtu(adapter_index: u32, mtu: u32, family: u16) {
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    unsafe {
        InitializeIpInterfaceEntry(&raw mut row);
        row.Family = family;
        row.InterfaceIndex = adapter_index;

        if GetIpInterfaceEntry(&raw mut row) == 0 {
            row.NlMtu = mtu;
            row.SitePrefixLength = 0;
            SetIpInterfaceEntry(&raw mut row);
        }
    }
}

pub fn powershell_configure_interface_aggressive(adapter_index: u32) -> bool {
    let script = format!(
        "$ErrorActionPreference = 'SilentlyContinue'; \
        Set-NetIPInterface -InterfaceIndex {adapter_index} -AddressFamily IPv4 -InterfaceMetric 1 -AutomaticMetric Disabled -Dhcp Disabled; \
        Set-NetIPInterface -InterfaceIndex {adapter_index} -AddressFamily IPv6 -InterfaceMetric 1 -AutomaticMetric Disabled -RouterDiscovery Disabled -Dhcp Disabled; \
        Clear-DnsClientCache; "
    );
    run_powershell_cmd("Aggressive interface configuration", &script)
}

pub fn configure_vpn_dns_preference(_adapter_name: &str, adapter_index: u32) {
    // 1. Force the interface metric to 1 (highest priority) for both IPv4 and IPv6
    run_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "interface",
            &adapter_index.to_string(),
            "metric=1",
        ],
    );
    run_cmd(
        "netsh",
        &[
            "interface",
            "ipv6",
            "set",
            "interface",
            &adapter_index.to_string(),
            "metric=1",
        ],
    );

    // 2. Add an NRPT rule to force all DNS queries through the VPN adapter's DNS
    // This is more effective than just metrics on modern Windows 10/11
    let nrpt_script = "$ErrorActionPreference = 'SilentlyContinue'; \
         Add-DnsClientNrptRule -Namespace '.' -NameServers '1.1.1.1','8.8.8.8' -Comment 'MaviVPN' -DisplayName 'MaviVPN DNS Force';".to_string();
    run_powershell_cmd("NRPT DNS Rule", &nrpt_script);
}

pub fn remove_nrpt_dns_rule() {
    let script = "$ErrorActionPreference = 'SilentlyContinue'; \
                  Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'MaviVPN' } | Remove-DnsClientNrptRule -ErrorAction SilentlyContinue -Confirm:$false;";
    run_powershell_cmd("Cleanup NRPT DNS Rule", script);
}
