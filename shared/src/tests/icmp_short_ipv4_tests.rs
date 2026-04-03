use super::*;

#[test]
fn malformed_ipv4_packets_are_rejected() {
    assert!(generate_packet_too_big(&[0x45, 0x00, 0x00], 1280, None).is_none());
}
