use super::*;

#[test]
fn ipv6_reply_embeds_a_truncated_original_packet() {
    let dropped = build_ipv6_udp_packet(1500);
    let reply = generate_packet_too_big(&dropped, 1280, None).expect("reply");

    let embedded = &reply[48..];
    assert_eq!(embedded, &dropped[..1232]);
}
