use super::*;

#[test]
fn ipv6_packets_generate_a_reply() {
    let dropped = build_ipv6_udp_packet(32);
    let reply = generate_packet_too_big(&dropped, 1280, None).expect("reply");

    let header = etherparse::Ipv6HeaderSlice::from_slice(&reply).expect("ipv6 header");
    assert_eq!(header.source_addr(), ipv6_server());
    assert_eq!(header.destination_addr(), ipv6_client());
}
