//! IP route exceptions supplied by the pinned, authenticated VPN server.
//! The server resolves configured names; legacy unresolved names stay tunneled.
//! Capture physical next hops before installing tunnel routes.

use std::net::IpAddr;
use tracing::warn;

pub(super) fn resolve_whitelist_ips(entries: &[String], ipv6_enabled: bool) -> Vec<IpAddr> {
    for entry in entries {
        if entry.parse::<IpAddr>().is_err() {
            warn!(
                "Ignoring non-numeric whitelist entry '{entry}'; update the server to resolve it"
            );
        }
    }
    shared::split_tunnel::parse_whitelist_ips(entries, ipv6_enabled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn resolve_whitelist_ips_accepts_ip_literals_without_dns() {
        // Literal parsing never consults the client's network resolver.
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
