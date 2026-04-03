use super::*;

#[test]
fn config_message_preserves_absent_whitelist() {
    let mut config = sample_control_ipv4_only_config();
    if let ControlMessage::Config {
        whitelist_domains, ..
    } = &mut config
    {
        *whitelist_domains = None;
    }

    let decoded: ControlMessage = roundtrip(&config);

    match decoded {
        ControlMessage::Config {
            whitelist_domains, ..
        } => assert!(whitelist_domains.is_none()),
        other => panic!("expected config message, got {other:?}"),
    }
}
