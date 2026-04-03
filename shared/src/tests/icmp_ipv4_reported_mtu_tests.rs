use super::*;

#[test]
fn ipv4_reply_embeds_the_reported_mtu() {
    let dropped = build_ipv4_udp_packet(32);
    let reply = generate_packet_too_big(&dropped, 1360, None).expect("reply");

    assert_eq!(u16::from_be_bytes([reply[26], reply[27]]), 1360);
}
