use super::adapter::{
    configure_vpn_dns_preference, powershell_configure_interface_aggressive,
    wait_for_adapter_alias, win32_set_mtu,
};
use super::cleanup::cleanup_routes;
use super::dns::configure_dns;
use super::host_route::{add_host_route_exception_fixed, add_host_route_exception_for_ip};
use super::ip::{wait_for_ipv4_address, win32_add_ip};
use super::route::{apply_ipv6_prefix_policy, ipv6_network_prefix, win32_add_route};
use super::whitelist::resolve_whitelist_ips;
use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;
use tracing::info;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use wintun::Adapter;

pub struct SessionRouteGuard {
    host_routes: Vec<String>,
}

impl SessionRouteGuard {
    pub const fn new(host_routes: Vec<String>) -> Self {
        Self { host_routes }
    }
}

impl Drop for SessionRouteGuard {
    fn drop(&mut self) {
        cleanup_routes(&self.host_routes);
    }
}

#[derive(Clone, Copy)]
pub struct AdapterNetworkConfig {
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns: Ipv4Addr,
    pub tun_mtu: u16,
    pub assigned_ipv6: Option<Ipv6Addr>,
    pub netmask_v6: Option<u8>,
    pub gateway_v6: Option<Ipv6Addr>,
    pub dns_v6: Option<Ipv6Addr>,
}

/// Converts an IPv4 netmask to a CIDR prefix length. Falls back to the safe
/// `/32` (host-only) prefix for a non-contiguous mask rather than guessing,
/// mirroring `linux::network::routes::netmask_to_prefix`.
fn netmask_to_prefix(netmask: Ipv4Addr) -> u8 {
    let bits = u32::from_be_bytes(netmask.octets());
    let ones = bits.count_ones() as u8;
    if bits.leading_ones() + bits.trailing_zeros() == 32 {
        ones
    } else {
        32
    }
}

pub fn set_adapter_network_config(
    adapter: &Adapter,
    config: AdapterNetworkConfig,
    endpoint: &str,
    whitelist_domains: &[String],
) -> Result<Vec<String>> {
    let AdapterNetworkConfig {
        ip,
        netmask,
        gateway,
        dns,
        tun_mtu,
        assigned_ipv6,
        netmask_v6,
        gateway_v6,
        dns_v6,
    } = config;

    // Resolve split-tunnel whitelist domains before this adapter's DNS server
    // or the split default routes are installed below, so this still queries
    // the physical (pre-VPN) resolver.
    let whitelist_ips = resolve_whitelist_ips(whitelist_domains, assigned_ipv6.is_some());

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
    win32_add_ip(adapter_index, IpAddr::V4(ip), netmask_to_prefix(netmask))?;

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

    configure_dns(&adapter_name, dns);

    win32_set_mtu(adapter_index, u32::from(tun_mtu), AF_INET);
    win32_set_mtu(adapter_index, u32::from(tun_mtu), AF_INET6 as _);

    let route_started = Instant::now();
    let endpoint_route = add_host_route_exception_fixed(endpoint).ok_or_else(|| {
        anyhow::anyhow!("Failed to install host route exception for VPN endpoint")
    })?;
    let mut host_routes = vec![endpoint_route];
    for ip in whitelist_ips {
        if let Some(prefix) = add_host_route_exception_for_ip(ip) {
            host_routes.push(prefix);
        }
    }

    let route_result = (|| -> Result<()> {
        install_ipv4_split_routes(adapter_index, gateway)?;

        if gateway_v6.is_some() {
            install_ipv6_split_routes(adapter_index)?;
        }

        Ok(())
    })();
    if let Err(err) = route_result {
        cleanup_routes(&host_routes);
        return Err(err);
    }

    info!(
        "Split routes applied in {} ms",
        route_started.elapsed().as_millis()
    );

    configure_vpn_dns_preference(&adapter_name, adapter_index, dns, dns_v6);

    info!(
        "Network config complete: host route exceptions={}",
        host_routes.len()
    );
    Ok(host_routes)
}

fn install_ipv4_split_routes(adapter_index: u32, gateway: Ipv4Addr) -> Result<()> {
    install_ipv4_split_routes_with(adapter_index, gateway, win32_add_route)
}

fn install_ipv4_split_routes_with<F>(
    adapter_index: u32,
    gateway: Ipv4Addr,
    mut add_route: F,
) -> Result<()>
where
    F: FnMut(u32, IpAddr, u8, Option<IpAddr>, u32) -> Result<()>,
{
    add_route(
        adapter_index,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        1,
        Some(IpAddr::V4(gateway)),
        1,
    )
    .context("Failed to install IPv4 split route 0.0.0.0/1")?;

    add_route(
        adapter_index,
        IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)),
        1,
        Some(IpAddr::V4(gateway)),
        1,
    )
    .context("Failed to install IPv4 split route 128.0.0.0/1")?;

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_split_routes_install_both_halves() {
        let gateway = Ipv4Addr::new(10, 8, 0, 1);
        let mut calls = Vec::new();

        install_ipv4_split_routes_with(
            7,
            gateway,
            |adapter_index, destination, prefix, hop, metric| {
                calls.push((adapter_index, destination, prefix, hop, metric));
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(
            calls,
            vec![
                (
                    7,
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    1,
                    Some(IpAddr::V4(gateway)),
                    1
                ),
                (
                    7,
                    IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)),
                    1,
                    Some(IpAddr::V4(gateway)),
                    1
                ),
            ]
        );
    }

    #[test]
    fn ipv4_split_route_failure_is_reported() {
        let gateway = Ipv4Addr::new(10, 8, 0, 1);
        let mut calls = Vec::new();

        let err = install_ipv4_split_routes_with(
            7,
            gateway,
            |adapter_index, destination, prefix, hop, metric| {
                calls.push((adapter_index, destination, prefix, hop, metric));
                if destination == IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)) {
                    anyhow::bail!("route denied");
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert_eq!(calls.len(), 2);
        assert!(err.to_string().contains("128.0.0.0/1"));
    }

    #[test]
    fn session_route_guard_stores_host_routes() {
        let guard = SessionRouteGuard::new(vec!["10.0.0.0/32".to_string()]);
        assert_eq!(guard.host_routes, vec!["10.0.0.0/32".to_string()]);
    }

    #[test]
    fn session_route_guard_stores_multiple_host_routes() {
        let guard = SessionRouteGuard::new(vec![
            "10.0.0.0/32".to_string(),
            "203.0.113.10/32".to_string(),
        ]);
        assert_eq!(guard.host_routes.len(), 2);
    }

    #[test]
    fn session_route_guard_empty_host_routes() {
        let guard = SessionRouteGuard::new(Vec::new());
        assert!(guard.host_routes.is_empty());
    }

    #[test]
    fn netmask_to_prefix_accepts_contiguous_masks() {
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(0, 0, 0, 0)), 0);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 0, 0, 0)), 8);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 255, 255)), 32);
    }

    #[test]
    fn netmask_to_prefix_rejects_non_contiguous_masks_with_safe_fallback() {
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 0, 255, 0)), 32);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 0, 255)), 32);
    }

    #[test]
    fn ipv4_split_routes_first_route_failure_is_reported() {
        let gateway = Ipv4Addr::new(10, 8, 0, 1);
        let mut calls = Vec::new();

        let err = install_ipv4_split_routes_with(
            7,
            gateway,
            |adapter_index, destination, prefix, hop, metric| {
                calls.push((adapter_index, destination, prefix, hop, metric));
                if destination == IpAddr::V4(Ipv4Addr::UNSPECIFIED) {
                    anyhow::bail!("route denied");
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert_eq!(calls.len(), 1);
        assert!(err.to_string().contains("0.0.0.0/1"));
    }

    #[test]
    fn ipv4_split_routes_use_correct_adapter_index() {
        let gateway = Ipv4Addr::new(10, 8, 0, 1);
        let mut calls = Vec::new();

        install_ipv4_split_routes_with(
            42,
            gateway,
            |adapter_index, destination, prefix, hop, metric| {
                calls.push((adapter_index, destination, prefix, hop, metric));
                Ok(())
            },
        )
        .unwrap();

        assert!(calls.iter().all(|(idx, _, _, _, _)| *idx == 42));
    }

    #[test]
    fn ipv4_split_routes_use_metric_one() {
        let gateway = Ipv4Addr::new(10, 8, 0, 1);
        let mut calls = Vec::new();

        install_ipv4_split_routes_with(
            7,
            gateway,
            |adapter_index, destination, prefix, hop, metric| {
                calls.push((adapter_index, destination, prefix, hop, metric));
                Ok(())
            },
        )
        .unwrap();

        assert!(calls.iter().all(|(_, _, _, _, m)| *m == 1));
    }
}
