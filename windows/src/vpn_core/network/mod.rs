pub mod adapter;
pub mod ip;
pub mod route;
pub mod utils;

use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Instant;
use tracing::info;
use windows_sys::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use wintun::Adapter;

pub use self::adapter::remove_nrpt_dns_rule;
use self::adapter::{
    configure_vpn_dns_preference, powershell_configure_interface_aggressive,
    wait_for_adapter_alias, win32_set_mtu,
};
pub use self::ip::wait_for_ipv6_address;
use self::ip::{wait_for_ipv4_address, win32_add_ip, win32_cleanup_all_ips_on_interface};
pub use self::route::verify_ipv6_split_routes;
use self::route::{
    apply_ipv6_prefix_policy, cleanup_ipv6_prefix_policy, ipv6_network_prefix, win32_add_route,
    win32_cleanup_all_routes_on_interface, win32_delete_route,
};
pub use self::utils::split_endpoint;
use self::utils::{run_cmd, run_powershell_cmd};

pub struct SessionRouteGuard {
    host_route: Option<String>,
}

impl SessionRouteGuard {
    pub const fn new(host_route: Option<String>) -> Self {
        Self { host_route }
    }
}

impl Drop for SessionRouteGuard {
    fn drop(&mut self) {
        cleanup_routes(self.host_route.as_deref());
    }
}

/// Creates a UDP socket configured for both IPv4 and IPv6 (dual-stack).
pub fn create_udp_socket() -> Result<std::net::UdpSocket> {
    let socket2_sock = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    socket2_sock.set_only_v6(false)?;
    socket2_sock.bind(&socket2::SockAddr::from(std::net::SocketAddrV6::new(
        std::net::Ipv6Addr::UNSPECIFIED,
        0,
        0,
        0,
    )))?;
    let _ = socket2_sock.set_send_buffer_size(4 * 1024 * 1024);
    let _ = socket2_sock.set_recv_buffer_size(4 * 1024 * 1024);

    Ok(socket2_sock.into())
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

    let _ = powershell_configure_interface_aggressive(adapter_index);

    if let (Some(ipv6), Some(plen)) = (assigned_ipv6, netmask_v6) {
        let prefix = ipv6_network_prefix(ipv6, plen);
        apply_ipv6_prefix_policy(&prefix);
    }

    let address_started = Instant::now();
    win32_add_ip(adapter_index, IpAddr::V4(ip), 24)?;

    if let (Some(ipv6), Some(plen)) = (assigned_ipv6, netmask_v6) {
        win32_add_ip(adapter_index, IpAddr::V6(ipv6), plen)?;
        info!("IPv6 address {}/{} set via Win32", ipv6, plen);
    }

    if wait_for_ipv4_address(adapter_index, ip) {
        info!(
            "IP {} confirmed on adapter in {} ms",
            ip,
            address_started.elapsed().as_millis()
        );
    } else {
        anyhow::bail!(
            "IPv4 address {ip} was not applied to adapter '{adapter_name}' (if={adapter_index})."
        );
    }

    configure_dns(&adapter_name);

    win32_set_mtu(adapter_index, u32::from(tun_mtu), AF_INET);
    win32_set_mtu(adapter_index, u32::from(tun_mtu), AF_INET6 as _);

    let route_started = Instant::now();
    let endpoint_route = add_host_route_exception_fixed(endpoint).ok_or_else(|| {
        anyhow::anyhow!("Failed to install host route exception for VPN endpoint")
    })?;

    let _ = win32_add_route(
        adapter_index,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
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

    if gateway_v6.is_some() {
        install_ipv6_split_routes(adapter_index)?;
    }

    info!(
        "Split routes applied in {} ms",
        route_started.elapsed().as_millis()
    );

    configure_vpn_dns_preference(&adapter_name, adapter_index);

    info!(
        "Network config complete: endpoint_exception={}",
        endpoint_route
    );
    Ok(Some(endpoint_route))
}

fn configure_dns(adapter_name: &str) {
    run_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            adapter_name,
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
            adapter_name,
            "8.8.8.8",
            "index=2",
            "validate=no",
        ],
    );
}

fn install_ipv6_split_routes(adapter_index: u32) -> Result<()> {
    win32_add_route(adapter_index, IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1, None, 1)
        .context("Failed to install IPv6 split route ::/1")?;

    win32_add_route(
        adapter_index,
        IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)),
        1,
        None,
        1,
    )
    .context("Failed to install IPv6 split route 8000::/1")?;

    info!("IPv6 On-Link split routes installed via Win32");
    Ok(())
}

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
    clear_persisted_host_route();
}

pub fn cleanup_stale_network_state() {
    cleanup_routes(None);
    remove_nrpt_dns_rule();
}

fn add_host_route_exception_fixed(endpoint: &str) -> Option<String> {
    let (host, _) = split_endpoint(endpoint);
    let host_ip = host.parse::<IpAddr>().ok()?;

    let (prefix, default_prefix) = match host_ip {
        IpAddr::V4(_) => (format!("{host_ip}/32"), "0.0.0.0/0"),
        IpAddr::V6(_) => (format!("{host_ip}/128"), "::/0"),
    };

    let script = format!(
        "$ErrorActionPreference = 'Stop'; \
         $gw = Get-NetRoute -DestinationPrefix '{default_prefix}' | Sort-Object RouteMetric | ForEach-Object {{ \
             $iface = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue; \
             if ($iface -and $iface.Status -eq 'Up' -and $iface.Name -notlike 'MaviVPN*' -and $iface.InterfaceDescription -notlike '*WireGuard*') {{ $_ }} \
         }} | Select-Object -First 1; \
         if ($gw) {{ \
             $args = @{{ \
                 DestinationPrefix = '{prefix}'; \
                 InterfaceIndex = $gw.InterfaceIndex; \
                 RouteMetric = 0; \
                 Confirm = $false; \
             }}; \
             if ($gw.NextHop -and $gw.NextHop -ne '0.0.0.0' -and $gw.NextHop -ne '::') {{ $args.NextHop = $gw.NextHop }}; \
             New-NetRoute @args; \
             if (-not (Get-NetRoute -DestinationPrefix '{prefix}' -ErrorAction SilentlyContinue)) {{ throw 'Verification failed' }} \
         }} else {{ throw 'No physical gateway for {default_prefix}' }}"
    );

    if run_powershell_cmd(&format!("Add host exception for {prefix}"), &script) {
        persist_host_route(&prefix);
        Some(prefix)
    } else {
        None
    }
}

fn host_route_path() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
    base.join("mavi-vpn").join("last_host_route.txt")
}

fn persist_host_route(prefix: &str) {
    let path = host_route_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, prefix);
}

fn load_persisted_host_route() -> Option<String> {
    std::fs::read_to_string(host_route_path())
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn clear_persisted_host_route() {
    let _ = std::fs::remove_file(host_route_path());
}
