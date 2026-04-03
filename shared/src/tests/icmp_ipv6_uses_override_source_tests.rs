use super::*;

#[test]
fn ipv6_reply_uses_vpn_gateway_override_when_provided() {
    let dropped = build_ipv6_udp_packet(32);
    let override_ip = std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    let reply = generate_packet_too_big(
        &dropped,
        1280,
        Some(std::net::IpAddr::V6(override_ip)),
    )
    .expect("reply");

    let header = etherparse::Ipv6HeaderSlice::from_slice(&reply).expect("ipv6 header");
    assert_eq!(header.source_addr(), override_ip);
}
