use anyhow::{bail, Context, Result};
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
            if unsafe { GetUnicastIpAddressTable(AF_INET6 as u16, &mut table) } == 0 {
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

fn powershell_configure_interface_aggressive(adapter_index: u32) -> bool {
    let script = format!(
        "$ErrorActionPreference = 'SilentlyContinue'; \
        Set-NetIPInterface -InterfaceIndex {} -AddressFamily IPv4 -InterfaceMetric 1 -AutomaticMetric Disabled -Dhcp Disabled; \
        Set-NetIPInterface -InterfaceIndex {} -AddressFamily IPv6 -InterfaceMetric 1 -AutomaticMetric Disabled -RouterDiscovery Disabled -Dhcp Disabled; \
        Clear-DnsClientCache; ",
        adapter_index, adapter_index
    );
    run_powershell_cmd("Aggressive interface configuration", &script)
}

// Neighbor functions removed - no longer needed for Layer 3 WinTUN On-Link routing

fn prefix_policy_path() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("mavi-vpn").join("last_prefix_policy.txt")
}

fn persist_prefix_policy(prefix: &str) {
    let path = prefix_policy_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, prefix);
}

fn load_persisted_prefix_policy() -> Option<String> {
    std::fs::read_to_string(prefix_policy_path())
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn clear_persisted_prefix_policy() {
    let _ = std::fs::remove_file(prefix_policy_path());
}

fn apply_ipv6_prefix_policy(prefix: &str) -> bool {
    // Attempt set first (idempotent if exists)
    let set_ok = run_cmd(
        "netsh",
        &[
            "interface",
            "ipv6",
            "set",
            "prefixpolicy",
            &format!("prefix={}", prefix),
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

    // Fallback to add if set failed (likely didn't exist)
    let add_ok = run_cmd(
        "netsh",
        &[
            "interface",
            "ipv6",
            "add",
            "prefixpolicy",
            &format!("prefix={}", prefix),
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

fn cleanup_ipv6_prefix_policy() {
    if let Some(prefix) = load_persisted_prefix_policy() {
        let ok = run_cmd(
            "netsh",
            &[
                "interface",
                "ipv6",
                "delete",
                "prefixpolicy",
                &format!("prefix={}", prefix),
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

pub fn verify_ipv6_split_routes(adapter_index: u32) -> Result<bool> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // AF_INET6 is a u16 in windows-sys
    if unsafe { GetIpForwardTable2(AF_INET6 as u16, &mut table) } != 0 {
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
            // sin6_addr.u.Byte is the [u8; 16] array
            let addr_bytes = unsafe { prefix.Prefix.Ipv6.sin6_addr.u.Byte };
            let plen = prefix.PrefixLength;

            // Check for ::/1 (all zeros)
            if plen == 1 && addr_bytes.iter().all(|&b| b == 0) {
                found_zero = true;
            }
            // Check for 8000::/1 (0x80 followed by zeros)
            if plen == 1 && addr_bytes[0] == 0x80 && addr_bytes[1..].iter().all(|&b| b == 0) {
                found_eight = true;
            }
        }
    }

    unsafe { FreeMibTable(table as _) };
    Ok(found_zero && found_eight)
}
fn ipv6_network_prefix(ip: Ipv6Addr, prefix_len: u8) -> String {
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

// win32_delete_ip removed as it was unused

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
    if unsafe { GetIpForwardTable2(AF_INET6 as u16, &mut table_v6) } == 0 {
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

fn win32_cleanup_all_ips_on_interface(adapter_index: u32) {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    if unsafe { GetUnicastIpAddressTable(AF_INET as u16, &mut table) } == 0 {
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
    if unsafe { GetUnicastIpAddressTable(AF_INET6 as u16, &mut table_v6) } == 0 {
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
    let start = std::time::Instant::now();
    while start.elapsed() < std::time::Duration::from_millis(1500) {
        let mut still_has_ips = false;

        let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
        if unsafe { GetUnicastIpAddressTable(AF_INET as u16, &mut table) } == 0 {
            let rows = unsafe {
                std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
            };
            if rows.iter().any(|r| r.InterfaceIndex == adapter_index) {
                still_has_ips = true;
            }
            unsafe { FreeMibTable(table as _) };
        }

        let mut table_v6: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
        if unsafe { GetUnicastIpAddressTable(AF_INET6 as u16, &mut table_v6) } == 0 {
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

    // 0. Aggressive PowerShell configuration (Metric, RD)
    let _ = powershell_configure_interface_aggressive(adapter_index);

    // 0b. Apply IPv6 Prefix Policy to favor VPN ULA over physical GUA (Hardening)
    if let (Some(ipv6), Some(plen)) = (assigned_ipv6, netmask_v6) {
        let prefix = ipv6_network_prefix(ipv6, plen);
        apply_ipv6_prefix_policy(&prefix);
    }

    // 1. Set IPv4 address via Win32 (Non-persistent by default in API)
    let address_started = Instant::now();
    win32_add_ip(adapter_index, IpAddr::V4(ip), 24)?;

    // 2. Set IPv6 address if available
    if let (Some(ipv6), Some(plen)) = (assigned_ipv6, netmask_v6) {
        win32_add_ip(adapter_index, IpAddr::V6(ipv6), plen as u8)?;
        info!("IPv6 address {}/{} set via Win32", ipv6, plen);
    }

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
    let _ = win32_add_route(
        adapter_index,
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        1,
        Some(IpAddr::V4(gateway)),
        1,
    );
    let _ = win32_add_route(
        adapter_index,
        IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)),
        1,
        Some(IpAddr::V4(gateway)),
        1,
    );

    // 6. Set IPv6 default split routes (::/1 and 8000::/1) as On-Link routes
    if gateway_v6.is_some() {
        win32_add_route(
            adapter_index,
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            1,
            None, // On-Link
            1,
        )
        .context("Failed to install IPv6 split route ::/1")?;

        win32_add_route(
            adapter_index,
            IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)),
            1,
            None, // On-Link
            1,
        )
        .context("Failed to install IPv6 split route 8000::/1")?;

        info!("IPv6 On-Link split routes installed via Win32");
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
    info!("Cleaning up MaviVPN routes...");

    // Clean up prefix policies first
    cleanup_ipv6_prefix_policy();

    let started = Instant::now();

    // 1. Fast Win32 cleanup for standard split routes
    let _ = win32_delete_route(0, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1);
    let _ = win32_delete_route(0, IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1);

    // 2. Identify MaviVPN adapter index to clean all its routes
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIfTable2(&mut table) } == 0 {
        let rows = unsafe {
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
        };
        for row in rows {
            let name = String::from_utf16_lossy(&row.Alias);
            if name.contains("MaviVPN") {
                win32_cleanup_all_routes_on_interface(row.InterfaceIndex);
                win32_cleanup_all_ips_on_interface(row.InterfaceIndex);
                // Small settling delay for the Windows network stack to process the deletions
                std::thread::sleep(std::time::Duration::from_millis(200));
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
            ps_script.push_str(&format!(
                "Remove-NetRoute -DestinationPrefix '{}' -Confirm:$false; ",
                prefix
            ));
        }
        let _ = run_powershell_cmd("Cleanup host routes", &ps_script);
    }

    info!(
        "Network cleanup completed in {} ms",
        started.elapsed().as_millis()
    );
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
    format!(
        r#"
$ErrorActionPreference = 'SilentlyContinue'
Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{}' -or $_.Namespace -eq '.' }} | Remove-DnsClientNrptRule -Force
Clear-DnsClientCache
"#,
        NRPT_COMMENT
    )
}

fn configure_vpn_dns_preference(adapter_name: &str, _adapter_index: u32) {
    let started = Instant::now();
    let _escaped_adapter_name = adapter_name.replace('\'', "''");

    let script = format!(
        "$ErrorActionPreference = 'SilentlyContinue'; \
        Add-DnsClientNrptRule -Namespace '.' -NameServers '1.1.1.1','8.8.8.8' -Comment '{}'; \
        New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name DisableSmartNameResolution -PropertyType DWord -Value 1 -Force | Out-Null; \
        Clear-DnsClientCache",
        NRPT_COMMENT
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
    info!("Cleaning up stale MaviVPN network state...");
    cleanup_routes(None);
    remove_nrpt_dns_rule();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn test_ipv6_network_prefix() {
        let ip = "fd00::5".parse::<Ipv6Addr>().unwrap();
        assert_eq!(ipv6_network_prefix(ip, 64), "fd00::/64");

        let ip2 = "fd00:1234::5".parse::<Ipv6Addr>().unwrap();
        assert_eq!(ipv6_network_prefix(ip2, 64), "fd00:1234::/64");

        let ip3 = "fd12:3456:789a::5".parse::<Ipv6Addr>().unwrap();
        assert_eq!(ipv6_network_prefix(ip3, 48), "fd12:3456:789a::/48");

        let ip4 = "2001:db8:abcd:ef01:2345:6789:abcd:ef01"
            .parse::<Ipv6Addr>()
            .unwrap();
        assert_eq!(ipv6_network_prefix(ip4, 32), "2001:db8::/32");
        assert_eq!(
            ipv6_network_prefix(ip4, 128),
            "2001:db8:abcd:ef01:2345:6789:abcd:ef01/128"
        );
    }
}
