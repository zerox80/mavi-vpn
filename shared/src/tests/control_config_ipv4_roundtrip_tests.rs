use super::*;

#[test]
fn ipv4_only_config_roundtrips_through_bincode() {
    let decoded: ControlMessage = roundtrip(&sample_control_ipv4_only_config());

    match decoded {
        ControlMessage::Config {
            assigned_ip,
            netmask,
            gateway,
            dns_server,
            mtu,
            assigned_ipv6,
            netmask_v6,
            gateway_v6,
            dns_server_v6,
            whitelist_domains,
        } => {
            assert_eq!(assigned_ip, std::net::Ipv4Addr::new(10, 8, 0, 2));
            assert_eq!(netmask, std::net::Ipv4Addr::new(255, 255, 255, 0));
            assert_eq!(gateway, std::net::Ipv4Addr::new(10, 8, 0, 1));
            assert_eq!(dns_server, std::net::Ipv4Addr::new(1, 1, 1, 1));
            assert_eq!(mtu, 1280);
            assert!(assigned_ipv6.is_none());
            assert!(netmask_v6.is_none());
            assert!(gateway_v6.is_none());
            assert!(dns_server_v6.is_none());
            assert_eq!(whitelist_domains, Some(vec!["example.com".to_string()]));
        }
        other => panic!("expected config message, got {other:?}"),
    }
}
