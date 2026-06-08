use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn extract_endpoint_ip_ipv4_returns_direct_string() {
    let ip = std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(extract_endpoint_ip(ip), "192.168.1.1");
}

#[test]
fn extract_endpoint_ip_ipv6_no_mapping_returns_full() {
    let ip = std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    assert_eq!(extract_endpoint_ip(ip), "2001:db8::1");
}

#[test]
fn extract_endpoint_ip_ipv6_mapped_converts_to_ipv4() {
    let ip = std::net::IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0101));
    assert_eq!(extract_endpoint_ip(ip), "192.168.1.1");
}

#[test]
fn extract_endpoint_ip_ipv6_loopback() {
    let ip = std::net::IpAddr::V6(Ipv6Addr::LOCALHOST);
    assert_eq!(extract_endpoint_ip(ip), "::1");
}

#[test]
fn extract_endpoint_ip_ipv4_loopback() {
    let ip = std::net::IpAddr::V4(Ipv4Addr::LOCALHOST);
    assert_eq!(extract_endpoint_ip(ip), "127.0.0.1");
}

#[test]
fn determine_session_result_running_means_connection_lost() {
    assert!(matches!(
        determine_session_result(true),
        SessionEnd::ConnectionLost
    ));
}

#[test]
fn determine_session_result_not_running_means_user_stopped() {
    assert!(matches!(
        determine_session_result(false),
        SessionEnd::UserStopped
    ));
}
