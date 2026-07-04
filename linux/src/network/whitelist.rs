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
    ips: &[IpAddr],
    physical_gateway: Option<&str>,
    physical_device: Option<&str>,
    physical_gateway_v6: Option<&str>,
    physical_device_v6: Option<&str>,
) {
    for &ip in ips {
        routes::add_host_route_exception(
            runner,
            ip,
            physical_gateway,
            physical_device,
            physical_gateway_v6,
            physical_device_v6,
        );
    }
}

/// Removes the host route exceptions installed by
/// [`add_whitelist_route_exceptions`], mirroring the VPN endpoint's own route
/// removal in [`super::NetworkConfig::cleanup`].
pub(super) fn remove_whitelist_route_exceptions(ips: &[IpAddr]) {
    for ip in ips {
        match ip {
            IpAddr::V4(v4) => {
                let _ = super::command::run_cmd("ip", &["route", "del", &format!("{v4}/32")]);
            }
            IpAddr::V6(v6) => {
                let _ =
                    super::command::run_cmd("ip", &["-6", "route", "del", &format!("{v6}/128")]);
            }
        }
    }
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
            &ips,
            Some("192.0.2.1"),
            Some("eth0"),
            None,
            None,
        );

        assert_eq!(runner.calls.len(), 2);
        assert!(runner.calls.iter().all(|(cmd, _)| cmd == "ip"));
    }
}
