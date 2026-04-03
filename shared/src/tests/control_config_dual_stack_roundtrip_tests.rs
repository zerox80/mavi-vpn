use super::*;

#[test]
fn dual_stack_config_roundtrips_through_bincode() {
    let decoded: ControlMessage = roundtrip(&sample_control_dual_stack_config());

    match decoded {
        ControlMessage::Config {
            assigned_ipv6,
            netmask_v6,
            gateway_v6,
            dns_server_v6,
            ..
        } => {
            assert_eq!(
                assigned_ipv6,
                Some(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2))
            );
            assert_eq!(netmask_v6, Some(64));
            assert_eq!(
                gateway_v6,
                Some(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
            );
            assert_eq!(dns_server_v6, Some(std::net::Ipv6Addr::LOCALHOST));
        }
        other => panic!("expected config message, got {other:?}"),
    }
}
