use super::*;

#[test]
fn ipv4_reply_targets_the_original_client() {
    let dropped = build_ipv4_udp_packet(32);
    let reply = generate_packet_too_big(&dropped, 1280, None).expect("reply");

    let header = etherparse::Ipv4HeaderSlice::from_slice(&reply).expect("ipv4 header");
    assert_eq!(header.destination_addr(), ipv4_client());
}
