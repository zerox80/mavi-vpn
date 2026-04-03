use super::*;

#[test]
fn ipv6_reply_rejects_ipv4_override_addresses() {
    let dropped = build_ipv6_udp_packet(32);

    assert!(generate_packet_too_big(
        &dropped,
        1280,
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
    )
    .is_none());
}
