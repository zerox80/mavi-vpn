use super::*;

#[test]
fn empty_packets_are_rejected() {
    assert!(generate_packet_too_big(&[], 1280, None).is_none());
}
