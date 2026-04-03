use super::*;

#[test]
fn ipv4_reply_uses_fragmentation_needed_type_and_code() {
    let dropped = build_ipv4_udp_packet(32);
    let reply = generate_packet_too_big(&dropped, 1280, None).expect("reply");

    assert_eq!(reply[20], 3);
    assert_eq!(reply[21], 4);
}
