use super::*;

#[test]
fn ipv6_reply_is_capped_at_the_minimum_ipv6_mtu() {
    let dropped = build_ipv6_udp_packet(1500);
    let reply = generate_packet_too_big(&dropped, 1280, None).expect("reply");

    assert_eq!(reply.len(), 1280);
}
