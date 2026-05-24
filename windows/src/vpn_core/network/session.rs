use super::adapter::{
    configure_vpn_dns_preference, powershell_configure_interface_aggressive,
    wait_for_adapter_alias, win32_set_mtu,
};
use super::cleanup::cleanup_routes;
use super::dns::configure_dns;
use super::host_route::add_host_route_exception_fixed;
use super::ip::{wait_for_ipv4_address, win32_add_ip};
use super::route::{apply_ipv6_prefix_policy, ipv6_network_prefix, win32_add_route};
use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;
use tracing::info;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use wintun::Adapter;

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
