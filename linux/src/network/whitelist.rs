//! Split-tunnel domain allow-list (`ControlMessage::Config::whitelist_domains`).
//!
//! Resolves each server-supplied domain and installs a host route exception
//! for it via the physical (non-VPN) gateway, the same mechanism `network.rs`
//! already uses to keep the VPN's own control connection out of the tunnel.
//! Domains are resolved once, at connect time — matching the Android
//! `VpnRouteUtils` reference implementation — so a CDN/geo-DNS domain whose
//! answer changes mid-session is not re-resolved until the next reconnect.

use super::command::CommandRunner;
use super::routes;
use std::net::{IpAddr, ToSocketAddrs};
use tracing::warn;

/// Resolves each whitelist domain via the system resolver. Must run before
/// `dns::configure_dns` rewrites resolv.conf, so this still queries the
/// physical (pre-VPN) DNS server rather than the tunnel's own.
pub(super) fn resolve_whitelist_ips(domains: &[String], ipv6_enabled: bool) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();
    for domain in domains {
        match (domain.as_str(), 0u16).to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    let ip = addr.ip();
                    if (ip.is_ipv4() || ipv6_enabled) && !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
            }
            Err(e) => warn!("Failed to resolve whitelist domain '{domain}': {e}"),
        }
    }
    ips
}

/// Adds a host route exception per resolved whitelist IP so it bypasses the
/// tunnel, mirroring the VPN endpoint's own route exception.
pub(super) fn add_whitelist_route_exceptions<R: CommandRunner>(
    runner: &mut R,
    routes: Vec<routes::HostRoute>,
) -> Vec<routes::HostRoute> {
    let mut owned_routes = Vec::new();
    for route in routes {
        let ip = route.ip;
        match routes::add_host_route_exception(runner, route) {
            Ok(Some(route)) => owned_routes.push(route),
            Ok(None) => {}
            Err(err) => warn!("Could not install whitelist route exception for {ip}: {err}"),
        }
    }
    owned_routes
}

/// Resolve each destination while the original routing table is still active.
pub(super) fn resolve_whitelist_routes(
    runner: &mut impl CommandRunner,
    ips: &[IpAddr],
) -> Vec<routes::HostRoute> {
    ips.iter()
        .filter_map(|&ip| match routes::resolve_host_route(runner, ip) {
            Ok(route) => Some(route),
            Err(err) => {
                warn!("Could not determine whitelist route for {ip}: {err}");
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::command::test_support::RecordingRunner;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn resolve_whitelist_ips_accepts_ip_literals_without_dns() {
        // IP literals resolve locally (no network I/O) per `ToSocketAddrs`,
        // so this stays deterministic in a sandboxed/offline test run.
        let domains = vec!["203.0.113.10".to_string(), "2001:db8::1".to_string()];

        let v4_only = resolve_whitelist_ips(&domains, false);
        assert_eq!(v4_only, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))]);

        let dual_stack = resolve_whitelist_ips(&domains, true);
        assert_eq!(
            dual_stack,
            vec![
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
            ]
        );
    }

    #[test]
    fn resolve_whitelist_ips_deduplicates() {
        let domains = vec!["203.0.113.10".to_string(), "203.0.113.10".to_string()];
        assert_eq!(
            resolve_whitelist_ips(&domains, false),
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))]
        );
    }

    #[test]
    fn add_whitelist_route_exceptions_installs_one_route_per_ip() {
        let mut runner = RecordingRunner::default();
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)),
        ];

        add_whitelist_route_exceptions(
            &mut runner,
            ips.into_iter()
                .map(|ip| routes::HostRoute {
                    ip,
                    gateway: Some("192.0.2.1".into()),
                    device: "eth0".into(),
                })
                .collect(),
        );

        assert_eq!(runner.calls.len(), 2);
        assert!(runner.calls.iter().all(|(cmd, _)| cmd == "ip"));
    }

    #[test]
    fn whitelist_cleanup_only_removes_newly_installed_routes() {
        use super::super::command::CommandOutcome;

        for ips in [
            ["203.0.113.10", "203.0.113.11", "203.0.113.12"],
            ["2001:db8::10", "2001:db8::11", "2001:db8::12"],
        ] {
            let mut runner = RecordingRunner {
                outcomes: [
                    Ok(CommandOutcome::AlreadyExists),
                    Ok(CommandOutcome::Applied),
                    Err(anyhow::anyhow!("route denied")),
                ]
                .into(),
                ..RecordingRunner::default()
            };
            let ips = ips.map(|ip| ip.parse::<IpAddr>().unwrap());
            let owned_routes = add_whitelist_route_exceptions(
                &mut runner,
                ips.iter()
                    .map(|&ip| routes::HostRoute {
                        ip,
                        gateway: None,
                        device: "ppp0".into(),
                    })
                    .collect(),
            );
            assert_eq!(owned_routes.len(), 1);
            routes::remove_host_route_exceptions(&mut runner, &owned_routes);
            assert_eq!(runner.calls.len(), 4);
            let cleanup = &runner.calls[3].1;
            assert!(cleanup.iter().any(|arg| arg == "del"));
            assert!(cleanup.contains(&format!(
                "{}/{}",
                ips[1],
                if ips[1].is_ipv4() { 32 } else { 128 }
            )));
        }
    }
}
