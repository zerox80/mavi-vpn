use super::*;

#[test]
fn ipv4_reply_uses_vpn_gateway_override_when_provided() {
    let dropped = build_ipv4_udp_packet(32);
    let override_ip = std::net::Ipv4Addr::new(10, 8, 0, 1);
    let reply = generate_packet_too_big(&dropped, 1280, Some(std::net::IpAddr::V4(override_ip)))
        .expect("reply");

    let header = etherparse::Ipv4HeaderSlice::from_slice(&reply).expect("ipv4 header");
    assert_eq!(header.source_addr(), override_ip);
}
