use super::*;
use std::net::Ipv4Addr;

fn config_with_mtu(mtu: u16) -> ControlMessage {
    ControlMessage::Config {
        assigned_ip: Ipv4Addr::new(10, 8, 0, 2),
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        gateway: Ipv4Addr::new(10, 8, 0, 1),
        dns_server: Ipv4Addr::new(1, 1, 1, 1),
        mtu,
        assigned_ipv6: None,
        netmask_v6: None,
        gateway_v6: None,
        dns_server_v6: None,
        whitelist_domains: None,
    }
}

#[test]
fn non_ipv6_endpoint_prefers_ipv4_addresses() {
    let mut addrs: Vec<SocketAddr> = vec![
        "[2001:db8::1]:443".parse().unwrap(),
        "203.0.113.10:443".parse().unwrap(),
        "[2001:db8::2]:443".parse().unwrap(),
        "203.0.113.11:443".parse().unwrap(),
    ];

    order_resolved_addrs(&mut addrs, "vpn.example.com:443");

    assert!(addrs[0].is_ipv4());
    assert!(addrs[1].is_ipv4());
    assert!(addrs[2].is_ipv6());
    assert!(addrs[3].is_ipv6());
}

#[test]
fn explicit_ipv6_endpoint_keeps_resolution_order() {
    let original: Vec<SocketAddr> = vec![
        "[2001:db8::1]:443".parse().unwrap(),
        "203.0.113.10:443".parse().unwrap(),
    ];
    let mut addrs = original.clone();

    order_resolved_addrs(&mut addrs, "[2001:db8::1]:443");

    assert_eq!(addrs, original);
}

#[test]
fn detects_explicit_ipv6_host() {
    assert!(endpoint_host_is_explicit_ipv6("[2001:db8::1]:443"));
    assert!(endpoint_host_is_explicit_ipv6("2001:db8::1"));
    assert!(!endpoint_host_is_explicit_ipv6("vpn.example.com:443"));
    assert!(!endpoint_host_is_explicit_ipv6("203.0.113.10:443"));
}

#[test]
fn server_mtu_is_accepted_when_client_uses_default() {
    let cfg = config_with_mtu(1340);

    assert!(validate_server_mtu(&cfg, 1280, TunMtuSource::Default).is_ok());
}

#[test]
fn explicit_client_mtu_must_match_server_mtu() {
    let cfg = config_with_mtu(1340);

    assert!(validate_server_mtu(&cfg, 1280, TunMtuSource::Config).is_err());
    assert!(validate_server_mtu(&cfg, 1280, TunMtuSource::Env).is_err());
    assert!(validate_server_mtu(&cfg, 1340, TunMtuSource::Config).is_ok());
}

#[test]
fn server_mtu_must_be_supported() {
    let cfg = config_with_mtu(1500);

    assert!(validate_server_mtu(&cfg, 1280, TunMtuSource::Default).is_err());
}
