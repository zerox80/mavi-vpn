use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Instant;
use tracing::{info, warn};
use windows_sys::Win32::Foundation::WIN32_ERROR;
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_INET};
use wintun::Adapter;

pub struct SessionRouteGuard {
    host_route: Option<String>,
}

impl SessionRouteGuard {
    pub fn new(host_route: Option<String>) -> Self {
        Self { host_route }
    }
}

impl Drop for SessionRouteGuard {
    fn drop(&mut self) {
        cleanup_routes(self.host_route.as_deref());
    }
}

fn to_sockaddr_inet(ip: IpAddr) -> SOCKADDR_INET {
    let mut addr: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match ip {
        IpAddr::V4(v4) => {
            addr.si_family = AF_INET;
            unsafe {
                addr.Ipv4.sin_family = AF_INET;
                addr.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
            }
        }
        IpAddr::V6(v6) => {
            addr.si_family = AF_INET6;
            unsafe {
                addr.Ipv6.sin6_family = AF_INET6;
                addr.Ipv6.sin6_addr.u.Byte = v6.octets();
            }
        }
    }
    addr
}

fn win_err(code: WIN32_ERROR) -> anyhow::Error {
    anyhow::anyhow!("Win32 error: {}", code)
}

/// Creates a UDP socket configured for both IPv4 and IPv6 (dual-stack).
pub fn create_udp_socket() -> Result<std::net::UdpSocket> {
    let socket2_sock = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    // V6ONLY = false allows this socket to receive IPv4 traffic as well.
    socket2_sock.set_only_v6(false)?;
    socket2_sock.bind(&socket2::SockAddr::from(std::net::SocketAddrV6::new(
        std::net::Ipv6Addr::UNSPECIFIED,
        0,
        0,
        0,
    )))?;
    // Set larger socket buffers for high-throughput stability on Windows (4MB for GSO bursts)
    let _ = socket2_sock.set_send_buffer_size(4 * 1024 * 1024);
    let _ = socket2_sock.set_recv_buffer_size(4 * 1024 * 1024);

    Ok(socket2_sock.into())
}

/// Helper: run a command and log its outcome.
fn run_cmd(program: &str, args: &[&str]) -> bool {
    let display = format!("{} {}", program, args.join(" "));
    match std::process::Command::new(program).args(args).output() {
        Ok(out) if out.status.success() => {
            let msg = format!("[OK]  {}", display);
            info!(cmd = %msg);
            true
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let msg = format!("[FAIL] {} → {} {}", display, stdout, stderr);
            warn!(cmd = %msg);
            false
        }
        Err(e) => {
            let msg = format!("[ERR] {} → {}", display, e);
            warn!(cmd = %msg);
            false
        }
    }
}

fn run_powershell_cmd(display: &str, script: &str) -> bool {
    match std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output()
    {
        Ok(out) if out.status.success() => {
            let msg = format!("[OK]  {}", display);
            info!(cmd = %msg);
            true
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let msg = format!("[FAIL] {} → {} {}", display, stdout, stderr);
            warn!(cmd = %msg);
            false
        }
        Err(e) => {
            let msg = format!("[ERR] {} → {}", display, e);
            warn!(cmd = %msg);
            false
        }
    }
}

fn wait_for_adapter_alias(adapter_index: u32, requested_name: &str) -> Result<String> {
    let started = Instant::now();
    let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    row.InterfaceIndex = adapter_index;

    for _ in 0..1500 {
        let res = unsafe { GetIfEntry2(&mut row) };
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
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    anyhow::bail!(
        "Adapter '{}' (if={}) did not appear in Windows networking within 30 seconds.",
        requested_name,
        adapter_index
    );
}

fn wait_for_ipv4_address(adapter_index: u32, ip: Ipv4Addr) -> bool {
    let started = Instant::now();
    let target_addr = u32::from_ne_bytes(ip.octets());

    for _ in 0..500 {
        let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
        if unsafe { GetUnicastIpAddressTable(AF_INET as u16, &mut table) } == 0 {
            let mut found = false;
            let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize) };
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

fn win32_add_ip(adapter_index: u32, ip: IpAddr, prefix_len: u8) -> Result<()> {
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };

    row.Address = to_sockaddr_inet(ip);
    row.InterfaceIndex = adapter_index;
    row.OnLinkPrefixLength = prefix_len;
    row.DadState = 4; // IpDadStatePreferred
    row.SkipAsSource = false;

    let res = unsafe { CreateUnicastIpAddressEntry(&row) };
    if res == 0 || res == 5010 {
        Ok(())
    } else {
        Err(win_err(res))
    }
}

fn win32_add_route(
    adapter_index: u32,
    destination: IpAddr,
    prefix_len: u8,
    next_hop: Option<IpAddr>,
    metric: u32,
) -> Result<()> {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };

    row.InterfaceIndex = adapter_index;
    row.DestinationPrefix.Prefix = to_sockaddr_inet(destination);
    row.DestinationPrefix.PrefixLength = prefix_len;
    if let Some(hop) = next_hop {
        row.NextHop = to_sockaddr_inet(hop);
    }
    row.Metric = metric;

    let res = unsafe { CreateIpForwardEntry2(&row) };
    if res == 0 || res == 5010 {
        Ok(())
    } else {
        Err(win_err(res))
    }
}

fn win32_set_mtu(adapter_index: u32, mtu: u32, family: u16) -> Result<()> {
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    unsafe {
        InitializeIpInterfaceEntry(&mut row);
        row.Family = family;
        row.InterfaceIndex = adapter_index;

        if GetIpInterfaceEntry(&mut row) == 0 {
            row.NlMtu = mtu;
            row.SitePrefixLength = 0;
            SetIpInterfaceEntry(&mut row);
        }
    }
    Ok(())
}

fn win32_delete_ip(adapter_index: u32, ip: IpAddr) -> Result<()> {
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.Address = to_sockaddr_inet(ip);
    row.InterfaceIndex = adapter_index;

    let res = unsafe { DeleteUnicastIpAddressEntry(&row) };
    if res == 0 || res == 1168 {
        // 1168 is ERROR_NOT_FOUND, which is fine for cleanup
        Ok(())
    } else {
        Err(win_err(res))
    }
}

fn win32_delete_route(adapter_index: u32, destination: IpAddr, prefix_len: u8) -> Result<()> {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceIndex = adapter_index;
    row.DestinationPrefix.Prefix = to_sockaddr_inet(destination);
    row.DestinationPrefix.PrefixLength = prefix_len;

    let res = unsafe { DeleteIpForwardEntry2(&row) };
    if res == 0 || res == 1168 {
        Ok(())
    } else {
        Err(win_err(res))
    }
}

fn win32_cleanup_all_routes_on_interface(adapter_index: u32) {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIpForwardTable2(AF_INET as u16, &mut table) } == 0 {
        let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize) };
        for row in rows {
            if row.InterfaceIndex == adapter_index {
                unsafe { DeleteIpForwardEntry2(row) };
            }
        }
        unsafe { FreeMibTable(table as _) };
    }
    // Repeat for IPv6
    let mut table_v6: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIpForwardTable2(AF_INET6 as u16, &mut table_v6) } == 0 {
        let rows = unsafe { std::slice::from_raw_parts((*table_v6).Table.as_ptr(), (*table_v6).NumEntries as usize) };
        for row in rows {
            if row.InterfaceIndex == adapter_index {
                unsafe { DeleteIpForwardEntry2(row) };
            }
        }
        unsafe { FreeMibTable(table_v6 as _) };
    }
}

fn win32_cleanup_all_ips_on_interface(adapter_index: u32) {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    if unsafe { GetUnicastIpAddressTable(AF_INET as u16, &mut table) } == 0 {
        let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize) };
        for row in rows {
            if row.InterfaceIndex == adapter_index {
                unsafe { DeleteUnicastIpAddressEntry(row) };
            }
        }
        unsafe { FreeMibTable(table as _) };
    }
    // IPv6
    let mut table_v6: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    if unsafe { GetUnicastIpAddressTable(AF_INET6 as u16, &mut table_v6) } == 0 {
        let rows = unsafe { std::slice::from_raw_parts((*table_v6).Table.as_ptr(), (*table_v6).NumEntries as usize) };
        for row in rows {
            if row.InterfaceIndex == adapter_index {
                unsafe { DeleteUnicastIpAddressEntry(row) };
            }
        }
        unsafe { FreeMibTable(table_v6 as _) };
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

#[allow(clippy::too_many_arguments)]
pub fn set_adapter_network_config(
    adapter: &Adapter,
    ip: Ipv4Addr,
    _netmask: Ipv4Addr,
    gateway: Ipv4Addr,
    dns: Ipv4Addr,
    tun_mtu: u16,
    endpoint: &str,
    assigned_ipv6: Option<Ipv6Addr>,
    netmask_v6: Option<u8>,
    gateway_v6: Option<Ipv6Addr>,
    _dns_v6: Option<Ipv6Addr>,
) -> Result<Option<String>> {
    let requested_adapter_name = adapter.get_name().unwrap_or_else(|_| "MaviVPN".to_string());
    let adapter_index = adapter.get_adapter_index()?;
    let adapter_name = wait_for_adapter_alias(adapter_index, &requested_adapter_name)?;

    info!(
        "Configuring adapter '{}' (if={}) ip={} gw={} dns={}",
        adapter_name, adapter_index, ip, gateway, dns
    );

    // 1. Set IPv4 address via Win32 (Non-persistent by default in API)
    let address_started = Instant::now();
    win32_add_ip(adapter_index, IpAddr::V4(ip), 24)?;

    // Verify the IP was actually set
    if wait_for_ipv4_address(adapter_index, ip) {
        info!(
            "IP {} confirmed on adapter in {} ms",
            ip,
            address_started.elapsed().as_millis()
        );
    } else {
        anyhow::bail!(
            "IPv4 address {} was not applied to adapter '{}' (if={}).",
            ip,
            adapter_name,
            adapter_index
        );
    }

    // 2. Set IPv6 address if available
    if let (Some(ipv6), Some(plen)) = (assigned_ipv6, netmask_v6) {
        let _ = win32_add_ip(adapter_index, IpAddr::V6(ipv6), plen);
    }

    // 3. Set stable public DNS on the VPN adapter
    run_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            &adapter_name,
            "static",
            "1.1.1.1",
            "primary",
            "validate=no",
        ],
    );
    run_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "add",
            "dnsservers",
            &adapter_name,
            "8.8.8.8",
            "index=2",
            "validate=no",
        ],
    );

    // 4. Set MTU via Win32
    let _ = win32_set_mtu(adapter_index, tun_mtu as u32, AF_INET);
    let _ = win32_set_mtu(adapter_index, tun_mtu as u32, AF_INET6);

    // 5. Host exception FIRST
    let route_started = Instant::now();
    let endpoint_route = add_host_route_exception_fixed(endpoint);

    // 6. Split routes via Win32 (Non-persistent)
    let _ = win32_add_route(adapter_index, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1, Some(IpAddr::V4(gateway)), 5);
    let _ = win32_add_route(adapter_index, IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1, Some(IpAddr::V4(gateway)), 5);

    if let Some(gv6) = gateway_v6 {
        let _ = win32_add_route(adapter_index, IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1, Some(IpAddr::V6(gv6)), 5);
        let _ = win32_add_route(adapter_index, IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)), 1, Some(IpAddr::V6(gv6)), 5);
    }

    info!(
        "Split routes applied in {} ms",
        route_started.elapsed().as_millis()
    );

    // 7. DNS preference
    configure_vpn_dns_preference(&adapter_name, adapter_index);

    info!(
        "Network config complete: endpoint_exception={}",
        endpoint_route.as_deref().unwrap_or("none")
    );
    Ok(endpoint_route)
}

pub fn cleanup_routes(host_route: Option<&str>) {
    let started = Instant::now();

    // 1. Fast Win32 cleanup for standard split routes
    let _ = win32_delete_route(0, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1);
    let _ = win32_delete_route(0, IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1);

    // 2. Identify MaviVPN adapter index to clean all its routes
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIfTable2(&mut table) } == 0 {
        let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize) };
        for row in rows {
            let name = String::from_utf16_lossy(&row.Alias);
            if name.contains("MaviVPN") {
                win32_cleanup_all_routes_on_interface(row.InterfaceIndex);
                win32_cleanup_all_ips_on_interface(row.InterfaceIndex);
            }
        }
        unsafe { FreeMibTable(table as _) };
    }

    // 3. Host route cleanup
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
        let mut ps_script = String::from("$ErrorActionPreference = 'SilentlyContinue'; ");
        for prefix in host_prefixes {
            ps_script.push_str(&format!("Remove-NetRoute -DestinationPrefix '{}' -Confirm:$false; ", prefix));
        }
        let _ = run_powershell_cmd("Cleanup host routes", &ps_script);
    }

    info!("Network cleanup completed in {} ms", started.elapsed().as_millis());
    clear_persisted_host_route();
}

fn persisted_host_route_path() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("mavi-vpn").join("last_host_route.txt")
}

fn load_persisted_host_route() -> Option<String> {
    std::fs::read_to_string(persisted_host_route_path())
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn persist_host_route(prefix: &str) {
    let path = persisted_host_route_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, prefix);
}

fn clear_persisted_host_route() {
    let _ = std::fs::remove_file(persisted_host_route_path());
}

fn add_host_route_exception_fixed(endpoint: &str) -> Option<String> {
    let server_ip: IpAddr = match endpoint.parse() {
        Ok(ip) => ip,
        Err(_) => {
            warn!("Could not parse endpoint IP '{}'", endpoint);
            return None;
        }
    };

    let route_prefix = match server_ip {
        IpAddr::V4(v4) => format!("{}/32", v4),
        IpAddr::V6(v6) => format!("{}/128", v6),
    };

    let (_ip_version, empty_next_hop) = match server_ip {
        IpAddr::V4(_) => ("4", "0.0.0.0"),
        IpAddr::V6(_) => ("6", "::"),
    };

    let ps = format!(
        "$gw = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {{ $_.InterfaceAlias -notlike 'MaviVPN*' -and $_.InterfaceAlias -notlike '*WireGuard*' -and $_.NextHop -ne '0.0.0.0' }} | Sort-Object InterfaceMetric, RouteMetric | Select-Object -First 1; \
        if ($gw) {{ \
            $hop = $gw.NextHop; \
            $ifIdx = $gw.InterfaceIndex; \
            if ($hop -and $hop -ne '{}') {{ \
                New-NetRoute -DestinationPrefix '{}' -InterfaceIndex $ifIdx -NextHop $hop -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null; \
                Write-Output $hop \
            }} else {{ \
                New-NetRoute -DestinationPrefix '{}' -InterfaceIndex $ifIdx -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null; \
                Write-Output 'On-Link' \
            }} \
        }}",
        empty_next_hop,
        route_prefix,
        route_prefix,
    );

    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps])
        .output();

    if let Ok(out) = output {
        let gateway = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !gateway.is_empty() && gateway != empty_next_hop {
            persist_host_route(&route_prefix);
            info!("Host exception: {} -> {}", route_prefix, gateway);
            return Some(route_prefix);
        }
    }

    warn!("Could not determine physical gateway");
    None
}

const NRPT_COMMENT: &str = "MaviVPN";

fn nrpt_cleanup_script() -> String {
    format!(r#"
$ErrorActionPreference = 'SilentlyContinue'
Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{}' -or $_.Namespace -eq '.' }} | Remove-DnsClientNrptRule -Force
Clear-DnsClientCache
"#, NRPT_COMMENT)
}

fn configure_vpn_dns_preference(adapter_name: &str, adapter_index: u32) {
    let started = Instant::now();
    let escaped_adapter_name = adapter_name.replace('\'', "''");

    let script = format!(
        "$ErrorActionPreference = 'SilentlyContinue'; \
        Add-DnsClientNrptRule -Namespace '.' -NameServers '1.1.1.1','8.8.8.8' -Comment '{}'; \
        Set-NetIPInterface -InterfaceIndex {} -InterfaceMetric 1; \
        Set-NetIPInterface -InterfaceAlias '{}' -InterfaceMetric 1; \
        New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name DisableSmartNameResolution -PropertyType DWord -Value 1 -Force | Out-Null; \
        Clear-DnsClientCache",
        NRPT_COMMENT,
        adapter_index,
        escaped_adapter_name
    );
    let _ = run_powershell_cmd("Configure VPN DNS preference", &script);

    info!(
        "VPN DNS preference configured ({} ms)",
        started.elapsed().as_millis()
    );
}

pub fn remove_nrpt_dns_rule() {
    let cmd = nrpt_cleanup_script();
    let _ = run_powershell_cmd("Remove DNS leak prevention", &cmd);
    info!("DNS leak prevention removed");
}

pub fn cleanup_stale_network_state() {
    info!("Cleaning stale MaviVPN network state");
    cleanup_routes(None);
    remove_nrpt_dns_rule();
}
