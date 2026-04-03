use super::*;

#[test]
fn unknown_ip_versions_are_rejected() {
    assert!(generate_packet_too_big(&[0x70, 0, 0, 0], 1280, None).is_none());
}
