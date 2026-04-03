use super::*;

#[test]
fn ipv4_reply_includes_the_original_header_plus_eight_bytes() {
    let dropped = build_ipv4_udp_packet(40);
    let reply = generate_packet_too_big(&dropped, 1280, None).expect("reply");

    let embedded = &reply[28..];
    assert_eq!(embedded, &dropped[..28]);
}
