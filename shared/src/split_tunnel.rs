//! Destination-based split tunneling shared by the desktop clients.

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, ToSocketAddrs};

/// Whether selected destinations use or bypass the VPN.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitTunnelMode {
    #[default]
    Disabled,
    /// Only selected destinations use the VPN.
    Include,
    /// Selected destinations bypass the VPN.
    Exclude,
}

/// A normalized route produced from an IP, CIDR prefix, or resolved domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SplitRoute {
    pub destination: IpAddr,
    pub prefix_len: u8,
}

impl SplitRoute {
    #[must_use]
    pub const fn is_ipv4(self) -> bool {
        self.destination.is_ipv4()
    }

    #[must_use]
    pub fn prefix(self) -> String {
        format!("{}/{}", self.destination, self.prefix_len)
    }
}

/// Resolves user-provided targets before the VPN changes routes or DNS.
///
/// IP/CIDR inputs remain prefixes; domain results become host routes. IPv6
/// results are omitted when the server did not assign IPv6 to the tunnel.
pub fn resolve_split_tunnel_targets(
    targets: &[String],
    ipv6_enabled: bool,
) -> Result<Vec<SplitRoute>, String> {
    let mut routes = Vec::new();

    for raw in targets {
        let target = raw.trim();
        if target.is_empty() {
            continue;
        }

        if target.contains('/') {
            let network = target
                .parse::<IpNetwork>()
                .map_err(|error| format!("Invalid split-tunnel CIDR '{target}': {error}"))?;
            let route = SplitRoute {
                destination: network.network(),
                prefix_len: network.prefix(),
            };
            push_route(&mut routes, route, ipv6_enabled);
            continue;
        }

        if let Ok(ip) = target.parse::<IpAddr>() {
            let route = SplitRoute {
                destination: ip,
                prefix_len: if ip.is_ipv4() { 32 } else { 128 },
            };
            push_route(&mut routes, route, ipv6_enabled);
            continue;
        }

        let addresses = (target, 0u16).to_socket_addrs().map_err(|error| {
            format!("Could not resolve split-tunnel target '{target}': {error}")
        })?;
        let mut has_usable_address = false;
        for address in addresses {
            let ip = address.ip();
            has_usable_address |= ip.is_ipv4() || ipv6_enabled;
            push_route(
                &mut routes,
                SplitRoute {
                    destination: ip,
                    prefix_len: if ip.is_ipv4() { 32 } else { 128 },
                },
                ipv6_enabled,
            );
        }
        if !has_usable_address {
            return Err(format!(
                "Split-tunnel target '{target}' has no usable IP addresses"
            ));
        }
    }

    Ok(routes)
}

fn push_route(routes: &mut Vec<SplitRoute>, route: SplitRoute, ipv6_enabled: bool) {
    if (route.is_ipv4() || ipv6_enabled) && !routes.contains(&route) {
        routes.push(route);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn resolves_and_normalizes_ip_targets() {
        let targets = vec![
            "203.0.113.9".to_string(),
            "10.8.4.9/24".to_string(),
            "2001:db8::1".to_string(),
        ];

        assert_eq!(
            resolve_split_tunnel_targets(&targets, true).unwrap(),
            vec![
                SplitRoute {
                    destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                    prefix_len: 32,
                },
                SplitRoute {
                    destination: IpAddr::V4(Ipv4Addr::new(10, 8, 4, 0)),
                    prefix_len: 24,
                },
                SplitRoute {
                    destination: IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
                    prefix_len: 128,
                },
            ]
        );
    }

    #[test]
    fn filters_ipv6_and_deduplicates() {
        let targets = vec![
            "203.0.113.9".to_string(),
            "203.0.113.9/32".to_string(),
            "2001:db8::1".to_string(),
        ];

        assert_eq!(
            resolve_split_tunnel_targets(&targets, false).unwrap(),
            vec![SplitRoute {
                destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                prefix_len: 32,
            }]
        );
    }

    #[test]
    fn rejects_invalid_cidr() {
        let error = resolve_split_tunnel_targets(&["10.0.0.0/99".to_string()], false).unwrap_err();
        assert!(error.contains("Invalid split-tunnel CIDR"));
    }
}
