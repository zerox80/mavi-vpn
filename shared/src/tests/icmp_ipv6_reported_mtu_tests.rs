use super::*;

#[test]
fn ipv6_reply_embeds_the_reported_mtu() {
    let dropped = build_ipv6_udp_packet(32);
    let reply = generate_packet_too_big(&dropped, 1360, None).expect("reply");

    assert_eq!(u32::from_be_bytes([reply[44], reply[45], reply[46], reply[47]]), 1360);
}
