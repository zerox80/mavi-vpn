//! Split-tunnel domain allow-list (`ControlMessage::Config::whitelist_domains`).
//!
//! Resolves each server-supplied domain so `session.rs` can install a host
//! route exception for it via [`super::host_route::add_host_route_exception_for_ip`]
//! — the same mechanism already used to keep the VPN's own control
//! connection out of the tunnel. Domains are resolved once, at connect time,
//! before this adapter's DNS server or the split default routes are
//! installed, matching the Android `VpnRouteUtils` reference implementation.

use std::net::{IpAddr, ToSocketAddrs};
use tracing::warn;

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

#[cfg(test)]
mod tests {
    use super::*;
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
}
