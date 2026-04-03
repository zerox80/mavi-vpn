use super::*;

#[test]
fn ipv6_reply_uses_packet_too_big_type_and_zero_code() {
    let dropped = build_ipv6_udp_packet(32);
    let reply = generate_packet_too_big(&dropped, 1280, None).expect("reply");

    assert_eq!(reply[40], 2);
    assert_eq!(reply[41], 0);
}
