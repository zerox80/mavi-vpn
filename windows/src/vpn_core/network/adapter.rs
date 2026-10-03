use anyhow::Result;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::info;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetIfEntry2, GetIpInterfaceEntry, InitializeIpInterfaceEntry, SetIpInterfaceEntry, MIB_IF_ROW2,
    MIB_IPINTERFACE_ROW,
};

use super::command_runner::{CommandRunner, SystemCommandRunner};
use super::utils::run_powershell_cmd;

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

pub fn configure_vpn_dns_preference(
    _adapter_name: &str,
    adapter_index: u32,
    dns_v4: Ipv4Addr,
    dns_v6: Option<Ipv6Addr>,
) -> Result<()> {
    configure_vpn_dns_preference_with_runner(&SystemCommandRunner, adapter_index, dns_v4, dns_v6)
}

fn configure_vpn_dns_preference_with_runner(
    runner: &dyn CommandRunner,
    adapter_index: u32,
    dns_v4: Ipv4Addr,
    dns_v6: Option<Ipv6Addr>,
) -> Result<()> {
    // 1. Force the interface metric to 1 (highest priority) for both IPv4 and IPv6
    if !runner.run_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "interface",
            &adapter_index.to_string(),
            "metric=1",
        ],
    ) {
        anyhow::bail!("DNS_SETUP_FAILED: Failed to set IPv4 DNS interface priority");
    }
    if !runner.run_cmd(
        "netsh",
        &[
            "interface",
            "ipv6",
            "set",
            "interface",
            &adapter_index.to_string(),
            "metric=1",
        ],
    ) {
        anyhow::bail!("DNS_SETUP_FAILED: Failed to set IPv6 DNS interface priority");
    }

    // 2. Add an NRPT rule to force all DNS queries through the VPN adapter's DNS
    // This is more effective than just metrics on modern Windows 10/11
    if !runner
        .run_powershell_cmd_result("NRPT DNS Rule", &nrpt_setup_script(dns_v4, dns_v6))
        .is_success()
    {
        anyhow::bail!("DNS_SETUP_FAILED: Failed to install NRPT DNS isolation rule");
    }
    Ok(())
}

fn nrpt_setup_script(dns_v4: Ipv4Addr, dns_v6: Option<Ipv6Addr>) -> String {
    let servers = match dns_v6 {
        Some(v6) => format!("'{dns_v4}','{v6}'"),
        None => format!("'{dns_v4}'"),
    };
    format!(
        "$ErrorActionPreference = 'Stop'; \
         try {{ \
             Get-DnsClientNrptRule -ErrorAction Stop | \
                 Where-Object {{ $_.Comment -eq 'MaviVPN' -or $_.DisplayName -eq 'MaviVPN DNS Force' }} | \
                 Remove-DnsClientNrptRule -Force -ErrorAction Stop; \
             Add-DnsClientNrptRule -Namespace '.' -NameServers {servers} -Comment 'MaviVPN' -DisplayName 'MaviVPN DNS Force' -ErrorAction Stop; \
             Clear-DnsClientCache -ErrorAction Stop; \
         }} catch {{ Write-Error $_ -ErrorAction Continue; exit 1; }}"
    )
}

pub fn remove_nrpt_dns_rule() {
    let script = nrpt_cleanup_script();
    run_powershell_cmd("Cleanup NRPT DNS Rule", &script);
}

pub fn cleanup_mavi_adapter_dns_state() {
    let script = mavi_adapter_dns_cleanup_script();
    run_powershell_cmd("Cleanup MaviVPN adapter DNS state", script);
}

fn mavi_adapter_dns_cleanup_script() -> &'static str {
    "$ErrorActionPreference = 'SilentlyContinue'; \
     Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | \
         Where-Object { $_.Name -like 'MaviVPN*' -or $_.InterfaceDescription -like '*Mavi VPN Tunnel*' } | \
         ForEach-Object { \
             Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue; \
             Set-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -InterfaceMetric 9000 -AutomaticMetric Disabled -ErrorAction SilentlyContinue; \
             Set-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv6 -InterfaceMetric 9000 -AutomaticMetric Disabled -ErrorAction SilentlyContinue; \
             Set-DnsClient -InterfaceIndex $_.ifIndex -RegisterThisConnectionsAddress $false -ErrorAction SilentlyContinue; \
         }; \
     Clear-DnsClientCache -ErrorAction SilentlyContinue; \
     Register-DnsClient -ErrorAction SilentlyContinue;"
}

fn nrpt_cleanup_script() -> String {
    nrpt_cleanup_script_for_path(&dns_servers_path())
}

fn nrpt_cleanup_script_for_path(path: &Path) -> String {
    format!(
        r#"
$ErrorActionPreference = 'SilentlyContinue'
# Resolver addresses are shared by unrelated VPNs and enterprise policies.
# Only Mavi's explicit ownership markers authorize removal.
function Test-MaviDnsPolicy {{
    param($Policy)
    return ($Policy.Comment -eq 'MaviVPN' -or $Policy.DisplayName -eq 'MaviVPN DNS Force')
}}

Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
    Where-Object {{ Test-MaviDnsPolicy $_ }} |
    Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue

$policyRoots = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNSClient\DnsPolicyConfig',
    'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig'
)
foreach ($root in $policyRoots) {{
    if (-not (Test-Path $root)) {{ continue }}
    Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {{
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($props -and (Test-MaviDnsPolicy $props)) {{
            Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
        }}
    }}
}}
# Remove obsolete resolver metadata without using it to identify owned rules.
Remove-Item -LiteralPath {persisted_dns_path} -Force -ErrorAction SilentlyContinue
Clear-DnsClientCache -ErrorAction SilentlyContinue
Register-DnsClient -ErrorAction SilentlyContinue
"#,
        persisted_dns_path = powershell_single_quoted(&path.to_string_lossy())
    )
}

fn powershell_single_quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn dns_servers_path() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
    base.join("mavi-vpn").join("last_dns_servers.txt")
}

#[cfg(test)]
mod tests;
