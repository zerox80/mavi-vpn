use super::command::{CommandOutcome, CommandRunner};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr};

/// A host route newly installed by this session, with its cleanup selectors.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct HostRoute {
    pub(super) ip: IpAddr,
    pub(super) gateway: Option<String>,
    pub(super) device: String,
}

#[derive(Deserialize)]
struct RouteLookup {
    dev: String,
    gateway: Option<IpAddr>,
}

/// Capture the kernel's selected path to this destination before adding VPN
/// addresses or split routes, including connected and more-specific routes.
pub(super) fn resolve_host_route(runner: &mut impl CommandRunner, ip: IpAddr) -> Result<HostRoute> {
    let family = if ip.is_ipv4() { "-4" } else { "-6" };
    let destination = ip.to_string();
    let output = runner
        .output("ip", &["-j", family, "route", "get", &destination])
        .with_context(|| format!("Could not determine pre-VPN route to {ip}"))?;
    let route: RouteLookup = serde_json::from_str::<Vec<RouteLookup>>(&output)?
        .into_iter()
        .next()
        .context("No route returned for host exception")?;
    anyhow::ensure!(
        !route.dev.is_empty() && route.dev != "mavi0",
        "No physical interface found for host route exception to {ip}"
    );
    anyhow::ensure!(
        route.gateway.is_none_or(|gw| gw.is_ipv4() == ip.is_ipv4()),
        "Gateway address family does not match {ip}"
    );
    Ok(HostRoute {
        ip,
        gateway: route.gateway.map(|gw| gw.to_string()),
        device: route.dev,
    })
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
/// captured pre-VPN gateway/device, so traffic to it bypasses the tunnel.
/// Shared by the VPN endpoint's own route exception (preventing a routing
/// loop) and each resolved split-tunnel whitelist domain IP.
pub(super) fn add_host_route_exception<R: CommandRunner>(
    runner: &mut R,
    route: HostRoute,
) -> Result<Option<HostRoute>> {
    let args = host_route_args(route.ip, "add", route.gateway.as_deref(), &route.device);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match runner.run_with_outcome("ip", &args)? {
        CommandOutcome::AlreadyExists => Ok(None),
        CommandOutcome::Applied => Ok(Some(route)),
    }
}

fn host_route_args(ip: IpAddr, action: &str, gateway: Option<&str>, device: &str) -> Vec<String> {
    let mut args = Vec::new();
    if ip.is_ipv6() {
        args.push("-6".to_string());
    }
    args.extend([
        "route".to_string(),
        action.to_string(),
        format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }),
    ]);
    if let Some(gw) = gateway {
        args.extend(["via".to_string(), gw.to_string()]);
    }
    args.extend(["dev".to_string(), device.to_string()]);
    args
}

/// Removes only newly installed exceptions, using their original selectors.
pub(super) fn remove_host_route_exceptions(
    runner: &mut impl CommandRunner,
    owned_routes: &[HostRoute],
) {
    for route in owned_routes {
        let args = host_route_args(route.ip, "del", route.gateway.as_deref(), &route.device);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let _ = runner.run("ip", &args);
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
    fn host_exceptions_preserve_the_selected_path_for_each_destination() {
        use super::super::command::test_support::RecordingRunner;
        for (ip, lookup, expected) in [
            (
                "192.168.20.5",
                r#"[{"dst":"192.168.20.5","dev":"eth1"}]"#,
                vec!["route", "add", "192.168.20.5/32", "dev", "eth1"],
            ),
            (
                "203.0.113.10",
                r#"[{"dev":"eth1","gateway":"192.0.2.99"}]"#,
                vec![
                    "route",
                    "add",
                    "203.0.113.10/32",
                    "via",
                    "192.0.2.99",
                    "dev",
                    "eth1",
                ],
            ),
            (
                "2001:db8::10",
                r#"[{"dev":"eth1","gateway":"fe80::99"}]"#,
                vec![
                    "-6",
                    "route",
                    "add",
                    "2001:db8::10/128",
                    "via",
                    "fe80::99",
                    "dev",
                    "eth1",
                ],
            ),
        ] {
            let mut runner = RecordingRunner {
                outputs: [Ok(lookup.into())].into(),
                ..RecordingRunner::default()
            };
            let route = resolve_host_route(&mut runner, ip.parse().unwrap()).unwrap();
            add_host_route_exception(&mut runner, route).unwrap();
            assert_eq!(runner.calls[0].1.last().unwrap(), ip);
            assert_eq!(runner.calls[1].1, expected);
        }
    }

    #[test]
    fn unavailable_or_vpn_routes_are_rejected_without_installing_an_exception() {
        use super::super::command::test_support::RecordingRunner;
        for output in [
            "[]",
            r#"[{"dev":"mavi0"}]"#,
            r#"[{"dev":""}]"#,
            r#"[{"dev":"eth0","gateway":"fe80::1"}]"#,
        ] {
            let mut runner = RecordingRunner {
                outputs: [Ok(output.into())].into(),
                ..RecordingRunner::default()
            };
            assert!(resolve_host_route(&mut runner, "203.0.113.10".parse().unwrap()).is_err());
            assert_eq!(runner.calls.len(), 1);
        }
    }

    #[test]
    fn gatewayless_host_routes_use_the_physical_interface() {
        use super::super::command::test_support::RecordingRunner;

        for (ip, expected) in [
            (
                "203.0.113.10",
                vec!["route", "add", "203.0.113.10/32", "dev", "ppp0"],
            ),
            (
                "2001:db8::10",
                vec!["-6", "route", "add", "2001:db8::10/128", "dev", "ppp0"],
            ),
        ] {
            let mut runner = RecordingRunner::default();
            add_host_route_exception(
                &mut runner,
                HostRoute {
                    ip: ip.parse().unwrap(),
                    gateway: None,
                    device: "ppp0".into(),
                },
            )
            .unwrap();
            assert_eq!(
                runner.calls,
                vec![(
                    "ip".into(),
                    expected.into_iter().map(String::from).collect()
                )]
            );
        }
    }

    #[test]
    fn gatewayless_cleanup_keeps_the_original_interface_selector() {
        assert_eq!(
            host_route_args("203.0.113.10".parse().unwrap(), "del", None, "ppp0"),
            ["route", "del", "203.0.113.10/32", "dev", "ppp0"]
        );
        assert_eq!(
            host_route_args("2001:db8::10".parse().unwrap(), "del", None, "ppp0"),
            ["-6", "route", "del", "2001:db8::10/128", "dev", "ppp0"]
        );
    }

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
