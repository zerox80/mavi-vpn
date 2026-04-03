use super::*;

#[test]
fn config_message_preserves_whitelist_order() {
    let config = ControlMessage::Config {
        assigned_ip: std::net::Ipv4Addr::new(10, 8, 0, 2),
        netmask: std::net::Ipv4Addr::new(255, 255, 255, 0),
        gateway: std::net::Ipv4Addr::new(10, 8, 0, 1),
        dns_server: std::net::Ipv4Addr::new(1, 1, 1, 1),
        mtu: 1280,
        assigned_ipv6: None,
        netmask_v6: None,
        gateway_v6: None,
        dns_server_v6: None,
        whitelist_domains: Some(vec![
            "first.example".to_string(),
            "second.example".to_string(),
            "third.example".to_string(),
        ]),
    };

    let decoded: ControlMessage = roundtrip(&config);

    match decoded {
        ControlMessage::Config {
            whitelist_domains, ..
        } => assert_eq!(
            whitelist_domains,
            Some(vec![
                "first.example".to_string(),
                "second.example".to_string(),
                "third.example".to_string(),
            ])
        ),
        other => panic!("expected config message, got {other:?}"),
    }
}
