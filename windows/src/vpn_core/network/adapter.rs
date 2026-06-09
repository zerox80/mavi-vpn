use anyhow::Result;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::info;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetIfEntry2, GetIpInterfaceEntry, InitializeIpInterfaceEntry, SetIpInterfaceEntry, MIB_IF_ROW2,
    MIB_IPINTERFACE_ROW,
};

use super::utils::{run_cmd, run_powershell_cmd};

const DEFAULT_MAVI_DNS_V4: &str = "1.1.1.1";
const FALLBACK_MAVI_DNS_V4: &str = "8.8.8.8";
const DEFAULT_MAVI_DNS_V6: &str = "2606:4700:4700::1111";

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
) {
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
    persist_dns_servers();
    let dns_v4_str = dns_v4.to_string();
    let dns_v6_str = dns_v6.map(|v| v.to_string()).unwrap_or_default();
    let nrpt_script = if dns_v6.is_some() {
        format!(
            "$ErrorActionPreference = 'SilentlyContinue'; \
             Get-DnsClientNrptRule -ErrorAction SilentlyContinue | \
                 Where-Object {{ $_.Comment -eq 'MaviVPN' -or $_.DisplayName -eq 'MaviVPN DNS Force' }} | \
                 Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue; \
             Add-DnsClientNrptRule -Namespace '.' -NameServers '{dns_v4_str}','{dns_v6_str}' -Comment 'MaviVPN' -DisplayName 'MaviVPN DNS Force';"
        )
    } else {
        format!(
            "$ErrorActionPreference = 'SilentlyContinue'; \
             Get-DnsClientNrptRule -ErrorAction SilentlyContinue | \
                 Where-Object {{ $_.Comment -eq 'MaviVPN' -or $_.DisplayName -eq 'MaviVPN DNS Force' }} | \
                 Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue; \
             Add-DnsClientNrptRule -Namespace '.' -NameServers '{dns_v4_str}' -Comment 'MaviVPN' -DisplayName 'MaviVPN DNS Force';"
        )
    };
    run_powershell_cmd("NRPT DNS Rule", &nrpt_script);
}

pub fn remove_nrpt_dns_rule() {
    let script = nrpt_cleanup_script();
    run_powershell_cmd("Cleanup NRPT DNS Rule", &script);
    clear_persisted_dns_servers();
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
$maviDns = @('{DEFAULT_MAVI_DNS_V4}', '{FALLBACK_MAVI_DNS_V4}', '{DEFAULT_MAVI_DNS_V6}')
$persistedDnsPath = {persisted_dns_path}
if (Test-Path $persistedDnsPath) {{
    $maviDns += Get-Content $persistedDnsPath -ErrorAction SilentlyContinue |
        Where-Object {{ $_ -and $_.Trim() }} |
        ForEach-Object {{ $_.Trim() }}
}}
$maviDns = @($maviDns | Sort-Object -Unique)

function Test-MaviDnsPolicy {{
    param($Policy)
    $comment = "$($Policy.Comment)"
    $displayName = "$($Policy.DisplayName)"
    $name = "$($Policy.Name)"
    $namespace = @($Policy.Namespace)
    $servers = @($Policy.NameServers) | ForEach-Object {{ "$_" }}
    if ($comment -eq 'MaviVPN' -or $displayName -eq 'MaviVPN DNS Force') {{ return $true }}
    $isRootPolicy = ($namespace -contains '.') -or $name -eq '.'
    if (-not $isRootPolicy) {{ return $false }}
    foreach ($server in $servers) {{
        if ($maviDns -contains $server) {{ return $true }}
    }}
    return $false
}}

function Test-MaviDnsPolicyRegistryEntry {{
    param($Props)
    $comment = "$($Props.Comment)"
    $displayName = "$($Props.DisplayName)"
    $name = "$($Props.Name)"
    $namespace = "$($Props.Namespace)"
    $keyName = Split-Path -Leaf $Props.PSPath
    if ($comment -eq 'MaviVPN' -or $displayName -eq 'MaviVPN DNS Force') {{ return $true }}
    $isRootPolicy = $namespace -eq '.' -or $name -eq '.' -or $keyName -eq '.'
    if (-not $isRootPolicy) {{ return $false }}
    $valueText = ($Props.PSObject.Properties |
        Where-Object {{ $_.Name -notlike 'PS*' }} |
        ForEach-Object {{ "$($_.Value)" }}) -join ' '
    foreach ($server in $maviDns) {{
        if ($valueText -like "*$server*") {{ return $true }}
    }}
    return $false
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
        if ($props -and (Test-MaviDnsPolicyRegistryEntry $props)) {{
            Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
        }}
    }}
}}
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

fn persist_dns_servers() {
    let path = dns_servers_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let servers = format!("{DEFAULT_MAVI_DNS_V4}\n{FALLBACK_MAVI_DNS_V4}");
    let _ = std::fs::write(path, servers);
}

fn clear_persisted_dns_servers() {
    let _ = std::fs::remove_file(dns_servers_path());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nrpt_cleanup_removes_tagged_and_fingerprinted_policies() {
        let script = nrpt_cleanup_script_for_path(Path::new(
            r"C:\ProgramData\mavi-vpn\last_dns_servers.txt",
        ));

        assert!(script.contains("Remove-DnsClientNrptRule -Force"));
        assert!(script.contains("$comment -eq 'MaviVPN'"));
        assert!(script.contains("$displayName -eq 'MaviVPN DNS Force'"));
        assert!(script.contains("$namespace -eq '.'"));
        assert!(script.contains("1.1.1.1"));
        assert!(script.contains("8.8.8.8"));
        assert!(script.contains("2606:4700:4700::1111"));
        assert!(script.contains("last_dns_servers.txt"));
        assert!(script.contains("DnsPolicyConfig"));
    }

    #[test]
    fn adapter_dns_cleanup_only_resets_mavi_adapters() {
        let script = mavi_adapter_dns_cleanup_script();

        assert!(script.contains("Set-DnsClientServerAddress"));
        assert!(script.contains("$_.Name -like 'MaviVPN*'"));
        assert!(script.contains("$_.InterfaceDescription -like '*Mavi VPN Tunnel*'"));
        assert!(script.contains("RegisterThisConnectionsAddress $false"));
        assert!(!script.contains("$_.Name -notlike 'MaviVPN*'"));
        assert!(!script.contains("RegisterThisConnectionsAddress $true"));
    }

    #[test]
    fn powershell_single_quoted_wraps_value() {
        assert_eq!(powershell_single_quoted("hello"), "'hello'");
    }

    #[test]
    fn powershell_single_quoted_escapes_single_quotes() {
        assert_eq!(
            powershell_single_quoted("it's a test"),
            "'it''s a test'"
        );
    }

    #[test]
    fn powershell_single_quoted_empty_string() {
        assert_eq!(powershell_single_quoted(""), "''");
    }

    #[test]
    fn powershell_single_quoted_multiple_quotes() {
        assert_eq!(
            powershell_single_quoted("a'b'c"),
            "'a''b''c'"
        );
    }

    #[test]
    fn dns_servers_path_uses_programdata() {
        let path = dns_servers_path();
        assert!(path.to_string_lossy().contains("mavi-vpn"));
        assert!(path.to_string_lossy().contains("last_dns_servers.txt"));
    }

    #[test]
    fn nrpt_cleanup_script_includes_persisted_path() {
        let script = nrpt_cleanup_script_for_path(Path::new(r"C:\custom\path\dns.txt"));
        assert!(script.contains(r"C:\custom\path\dns.txt"));
        assert!(script.contains("Test-Path"));
    }

    #[test]
    fn nrpt_cleanup_script_handles_path_with_quotes() {
        let script = nrpt_cleanup_script_for_path(Path::new(r"C:\path with 'quotes'\dns.txt"));
        assert!(script.contains("''"));
    }

    #[test]
    fn nrpt_cleanup_script_contains_all_registry_roots() {
        let script = nrpt_cleanup_script_for_path(Path::new(r"C:\ProgramData\mavi-vpn\last_dns_servers.txt"));
        assert!(script.contains(r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig"));
        assert!(script.contains(r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNSClient\DnsPolicyConfig"));
        assert!(script.contains(r"HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig"));
    }

    #[test]
    fn nrpt_cleanup_script_clears_dns_cache() {
        let script = nrpt_cleanup_script_for_path(Path::new(r"C:\ProgramData\mavi-vpn\last_dns_servers.txt"));
        assert!(script.contains("Clear-DnsClientCache"));
        assert!(script.contains("Register-DnsClient"));
    }

    #[test]
    fn nrpt_cleanup_script_checks_persisted_path() {
        let script = nrpt_cleanup_script_for_path(Path::new(r"C:\ProgramData\mavi-vpn\last_dns_servers.txt"));
        assert!(script.contains("Test-Path $persistedDnsPath"));
        assert!(script.contains("Get-Content $persistedDnsPath"));
    }

    #[test]
    fn nrpt_cleanup_script_handles_unc_path() {
        let script = nrpt_cleanup_script_for_path(Path::new(r"\\server\share\dns.txt"));
        assert!(script.contains(r"\\server\share\dns.txt"));
    }

    #[test]
    fn mavi_adapter_dns_cleanup_sets_metric_9000() {
        let script = mavi_adapter_dns_cleanup_script();
        assert!(script.contains("InterfaceMetric 9000"));
        assert!(script.contains("AutomaticMetric Disabled"));
    }

    #[test]
    fn mavi_adapter_dns_cleanup_clears_cache() {
        let script = mavi_adapter_dns_cleanup_script();
        assert!(script.contains("Clear-DnsClientCache"));
        assert!(script.contains("Register-DnsClient"));
    }

    #[test]
    fn mavi_adapter_dns_cleanup_disables_dns_registration() {
        let script = mavi_adapter_dns_cleanup_script();
        assert!(script.contains("RegisterThisConnectionsAddress $false"));
    }

    #[test]
    fn mavi_adapter_dns_cleanup_resets_dns_servers() {
        let script = mavi_adapter_dns_cleanup_script();
        assert!(script.contains("Set-DnsClientServerAddress"));
        assert!(script.contains("ResetServerAddresses"));
    }

    #[test]
    fn mavi_adapter_dns_cleanup_includes_hidden_adapters() {
        let script = mavi_adapter_dns_cleanup_script();
        assert!(script.contains("Get-NetAdapter -IncludeHidden"));
    }

    #[test]
    fn powershell_single_quoted_handles_backslashes() {
        assert_eq!(
            powershell_single_quoted(r"C:\path\to\file"),
            r"'C:\path\to\file'"
        );
    }

    #[test]
    fn powershell_single_quoted_handles_newlines() {
        assert_eq!(
            powershell_single_quoted("line1\nline2"),
            "'line1\nline2'"
        );
    }

    #[test]
    fn powershell_single_quoted_handles_tabs() {
        assert_eq!(
            powershell_single_quoted("col1\tcol2"),
            "'col1\tcol2'"
        );
    }

    #[test]
    fn powershell_single_quoted_handles_unicode() {
        assert_eq!(
            powershell_single_quoted("Hello 世界"),
            "'Hello 世界'"
        );
    }

    #[test]
    fn powershell_single_quoted_handles_mixed_quotes_and_backslashes() {
        assert_eq!(
            powershell_single_quoted(r"C:\path'with\quotes"),
            r"'C:\path''with\quotes'"
        );
    }

    #[test]
    fn dns_servers_path_ends_with_correct_filename() {
        let path = dns_servers_path();
        assert_eq!(path.file_name().unwrap(), "last_dns_servers.txt");
    }

    #[test]
    fn dns_servers_path_contains_mavi_vpn_directory() {
        let path = dns_servers_path();
        let path_str = path.to_string_lossy();
        assert!(path_str.contains("mavi-vpn"));
    }
}
