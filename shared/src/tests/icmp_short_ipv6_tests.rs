use super::*;

#[test]
fn malformed_ipv6_packets_are_rejected() {
    assert!(generate_packet_too_big(&[0x60, 0x00, 0x00, 0x00], 1280, None).is_none());
}
