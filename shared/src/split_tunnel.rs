//! Route exceptions must be literal addresses supplied by the authenticated server.
//! Never turn a client-side DNS answer into permission to bypass the VPN.

use std::net::IpAddr;

#[must_use]
pub fn parse_whitelist_ips(entries: &[String], ipv6_enabled: bool) -> Vec<IpAddr> {
    let mut addresses = Vec::new();
    for entry in entries {
        if let Ok(ip) = entry.parse::<IpAddr>() {
            if (ip.is_ipv4() || ipv6_enabled) && !addresses.contains(&ip) {
                addresses.push(ip);
            }
        }
    }
    addresses
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_strict_literals_can_become_route_exceptions() {
        let entries = [
            "localhost",
            "example.test",
            "127.1",
            "2130706433",
            "0x7f000001",
            "192.0.2.1.",
            "192.0.2.1:443",
            "[2001:db8::1]",
            "fe80::1%eth0",
            "192.0.2.1/24",
            " 192.0.2.1",
            "192.0.2.1",
            "2001:db8::1",
            "192.0.2.1",
        ]
        .map(str::to_string);
        assert_eq!(
            parse_whitelist_ips(&entries, true),
            [
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse().unwrap()
            ]
        );
        assert_eq!(
            parse_whitelist_ips(&entries, false),
            ["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
    }
}
