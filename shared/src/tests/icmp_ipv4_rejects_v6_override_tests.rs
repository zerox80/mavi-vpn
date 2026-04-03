use super::*;

#[test]
fn ipv4_reply_rejects_ipv6_override_addresses() {
    let dropped = build_ipv4_udp_packet(32);

    assert!(generate_packet_too_big(
        &dropped,
        1280,
        Some(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
    )
    .is_none());
}
