use super::*;

#[test]
fn config_message_clone_keeps_addresses() {
    let cloned = sample_control_dual_stack_config().clone();

    match cloned {
        ControlMessage::Config {
            assigned_ip,
            gateway,
            assigned_ipv6,
            gateway_v6,
            ..
        } => {
            assert_eq!(assigned_ip, std::net::Ipv4Addr::new(10, 8, 0, 2));
            assert_eq!(gateway, std::net::Ipv4Addr::new(10, 8, 0, 1));
            assert_eq!(assigned_ipv6, Some(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)));
            assert_eq!(gateway_v6, Some(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
        }
        other => panic!("expected config message, got {other:?}"),
    }
}
