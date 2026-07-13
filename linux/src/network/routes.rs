use super::command::{run_cmd, CommandRunner};
use anyhow::{Context, Result};
use shared::split_tunnel::SplitRoute;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use tracing::{info, warn};

const SPLIT_PHYSICAL_ROUTE_METRIC: &str = "42777";
const SPLIT_TUNNEL_ROUTE_METRIC: &str = "1";

/// Detects the current physical IPv4 default gateway and interface.
pub(super) fn detect_physical_gateway() -> (Option<String>, Option<String>) {
    detect_physical_gateway_for(&["route", "show", "default"], "IPv4")
}

/// Detects the current physical IPv6 default gateway and interface.
pub(super) fn detect_physical_gateway_v6() -> (Option<String>, Option<String>) {
    detect_physical_gateway_for(&["-6", "route", "show", "default"], "IPv6")
}

fn detect_physical_gateway_for(
    ip_args: &[&str],
    family_label: &str,
) -> (Option<String>, Option<String>) {
    let output = Command::new("ip").args(ip_args).output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse first default route only: "default via 192.168.1.1 dev eth0 ..."
        let first_line = stdout.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        let gateway = parts
            .iter()
            .position(|&p| p == "via")
            .and_then(|i| parts.get(i + 1))
            .map(|s| s.to_string());
        let device = parts
            .iter()
            .position(|&p| p == "dev")
            .and_then(|i| parts.get(i + 1))
            .map(|s| s.to_string());

        if let (Some(ref gw), Some(ref dev)) = (&gateway, &device) {
            info!(
                "Detected physical {} gateway: {} via {}",
                family_label, gw, dev
            );
        }
        (gateway, device)
    } else {
        warn!("Could not detect physical {} gateway", family_label);
        (None, None)
    }
}

/// Parses an endpoint IP string that may be plain (`1.2.3.4`, `2606:4700::1`)
/// or bracketed (`[2606:4700::1]`). Rejects host:port forms — callers are
/// expected to pass the IP only.
pub(super) fn parse_endpoint_ip(s: &str) -> Result<IpAddr> {
    let trimmed = s.trim();
    let cleaned = if let Some(rest) = trimmed.strip_prefix('[') {
        rest.strip_suffix(']')
            .ok_or_else(|| anyhow::anyhow!("bracketed IPv6 endpoint must not include a port"))?
    } else {
        trimmed
    };
    cleaned
        .parse::<IpAddr>()
        .with_context(|| format!("not a valid IP address: {:?}", s))
}

/// Adds a host route (`/32` for IPv4, `/128` for IPv6) for `ip` via the
/// physical (non-VPN) gateway/device, so traffic to it bypasses the tunnel.
/// Shared by the VPN endpoint's own route exception (preventing a routing
/// loop) and each resolved split-tunnel whitelist domain IP.
pub(super) fn add_host_route_exception<R: CommandRunner>(
    runner: &mut R,
    ip: IpAddr,
    physical_gateway: Option<&str>,
    physical_device: Option<&str>,
    physical_gateway_v6: Option<&str>,
    physical_device_v6: Option<&str>,
) -> Result<()> {
    match ip {
        IpAddr::V4(v4) => {
            let (gw, dev) = physical_gateway.zip(physical_device).ok_or_else(|| {
                anyhow::anyhow!("No physical IPv4 gateway found for host route exception")
            })?;
            let route = format!("{v4}/32");
            runner.run("ip", &["route", "add", &route, "via", gw, "dev", dev])?;
        }
        IpAddr::V6(v6) => {
            let (gw, dev) = physical_gateway_v6.zip(physical_device_v6).ok_or_else(|| {
                anyhow::anyhow!("No physical IPv6 gateway found for host route exception")
            })?;
            let route = format!("{v6}/128");
            runner.run("ip", &["-6", "route", "add", &route, "via", gw, "dev", dev])?;
        }
    }
    Ok(())
}

/// Adds an arbitrary IP prefix through the physical gateway.
pub(super) fn add_route_exception<R: CommandRunner>(
    runner: &mut R,
    route: SplitRoute,
    physical_gateway: Option<&str>,
    physical_device: Option<&str>,
    physical_gateway_v6: Option<&str>,
    physical_device_v6: Option<&str>,
) -> Result<()> {
    let prefix = route.prefix();
    if route.is_ipv4() {
        let (gateway, device) = physical_gateway.zip(physical_device).ok_or_else(|| {
            anyhow::anyhow!("No physical IPv4 gateway found for split-tunnel exception")
        })?;
        runner.run(
            "ip",
            &[
                "route",
                "add",
                &prefix,
                "via",
                gateway,
                "dev",
                device,
                "metric",
                SPLIT_PHYSICAL_ROUTE_METRIC,
            ],
        )
    } else {
        let (gateway, device) = physical_gateway_v6.zip(physical_device_v6).ok_or_else(|| {
            anyhow::anyhow!("No physical IPv6 gateway found for split-tunnel exception")
        })?;
        runner.run(
            "ip",
            &[
                "-6",
                "route",
                "add",
                &prefix,
                "via",
                gateway,
                "dev",
                device,
                "metric",
                SPLIT_PHYSICAL_ROUTE_METRIC,
            ],
        )
    }
}

pub(super) fn remove_route_exception(
    route: SplitRoute,
    physical_gateway: Option<&str>,
    physical_device: Option<&str>,
    physical_gateway_v6: Option<&str>,
    physical_device_v6: Option<&str>,
) {
    let prefix = route.prefix();
    if route.is_ipv4() {
        if let (Some(gateway), Some(device)) = (physical_gateway, physical_device) {
            let _ = run_cmd(
                "ip",
                &[
                    "route",
                    "del",
                    &prefix,
                    "via",
                    gateway,
                    "dev",
                    device,
                    "metric",
                    SPLIT_PHYSICAL_ROUTE_METRIC,
                ],
            );
        }
    } else if let (Some(gateway), Some(device)) = (physical_gateway_v6, physical_device_v6) {
        let _ = run_cmd(
            "ip",
            &[
                "-6",
                "route",
                "del",
                &prefix,
                "via",
                gateway,
                "dev",
                device,
                "metric",
                SPLIT_PHYSICAL_ROUTE_METRIC,
            ],
        );
    }
}

pub(super) fn add_tunnel_route<R: CommandRunner>(
    runner: &mut R,
    route: SplitRoute,
    tun_name: &str,
    gateway_v4: Ipv4Addr,
    gateway_v6: Option<std::net::Ipv6Addr>,
) -> Result<()> {
    let prefix = route.prefix();
    if route.is_ipv4() {
        let gateway = gateway_v4.to_string();
        runner.run(
            "ip",
            &[
                "route",
                "add",
                &prefix,
                "dev",
                tun_name,
                "via",
                &gateway,
                "metric",
                SPLIT_TUNNEL_ROUTE_METRIC,
            ],
        )
    } else {
        let gateway = gateway_v6
            .ok_or_else(|| anyhow::anyhow!("No VPN IPv6 gateway for split-tunnel route"))?
            .to_string();
        runner.run(
            "ip",
            &[
                "-6",
                "route",
                "add",
                &prefix,
                "dev",
                tun_name,
                "via",
                &gateway,
                "metric",
                SPLIT_TUNNEL_ROUTE_METRIC,
            ],
        )
    }
}

pub(super) fn remove_tunnel_route(
    route: SplitRoute,
    tun_name: &str,
    gateway_v4: Ipv4Addr,
    gateway_v6: Option<std::net::Ipv6Addr>,
) {
    let prefix = route.prefix();
    if route.is_ipv4() {
        let gateway = gateway_v4.to_string();
        let _ = run_cmd(
            "ip",
            &[
                "route",
                "del",
                &prefix,
                "dev",
                tun_name,
                "via",
                &gateway,
                "metric",
                SPLIT_TUNNEL_ROUTE_METRIC,
            ],
        );
    } else if let Some(gateway) = gateway_v6 {
        let gateway = gateway.to_string();
        let _ = run_cmd(
            "ip",
            &[
                "-6",
                "route",
                "del",
                &prefix,
                "dev",
                tun_name,
                "via",
                &gateway,
                "metric",
                SPLIT_TUNNEL_ROUTE_METRIC,
            ],
        );
    }
}

/// Removes only a route matching the physical gateway/device used when the
/// exception was added. This avoids deleting an unrelated host route.
pub(super) fn remove_host_route_exception(
    ip: IpAddr,
    physical_gateway: Option<&str>,
    physical_device: Option<&str>,
    physical_gateway_v6: Option<&str>,
    physical_device_v6: Option<&str>,
) {
    match ip {
        IpAddr::V4(v4) => {
            if let (Some(gw), Some(dev)) = (physical_gateway, physical_device) {
                let route = format!("{v4}/32");
                let _ = run_cmd("ip", &["route", "del", &route, "via", gw, "dev", dev]);
            }
        }
        IpAddr::V6(v6) => {
            if let (Some(gw), Some(dev)) = (physical_gateway_v6, physical_device_v6) {
                let route = format!("{v6}/128");
                let _ = run_cmd("ip", &["-6", "route", "del", &route, "via", gw, "dev", dev]);
            }
        }
    }
}

pub(super) fn netmask_to_prefix(netmask: Ipv4Addr) -> u8 {
    let bits = u32::from_be_bytes(netmask.octets());
    let ones = bits.count_ones() as u8;
    if bits.leading_ones() + bits.trailing_zeros() == 32 {
        ones
    } else {
        32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn parse_endpoint_ip_accepts_plain_ipv4() {
        assert_eq!(
            parse_endpoint_ip("203.0.113.10").unwrap(),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))
        );
    }

    #[test]
    fn parse_endpoint_ip_accepts_plain_ipv6() {
        assert_eq!(
            parse_endpoint_ip("2001:db8::1").unwrap(),
            IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap())
        );
    }

    #[test]
    fn parse_endpoint_ip_accepts_bracketed_ipv6_without_port() {
        assert_eq!(
            parse_endpoint_ip("[2001:db8::1]").unwrap(),
            IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap())
        );
    }

    #[test]
    fn parse_endpoint_ip_rejects_hostnames_and_host_ports() {
        assert!(parse_endpoint_ip("vpn.example.com").is_err());
        assert!(parse_endpoint_ip("203.0.113.10:443").is_err());
        assert!(parse_endpoint_ip("[2001:db8::1]:443").is_err());
    }

    #[test]
    fn netmask_to_prefix_accepts_contiguous_masks() {
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(0, 0, 0, 0)), 0);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 0, 0, 0)), 8);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 255, 255)), 32);
    }

    #[test]
    fn netmask_to_prefix_rejects_non_contiguous_masks_with_safe_fallback() {
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 0, 255, 0)), 32);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 0, 255)), 32);
    }
}
