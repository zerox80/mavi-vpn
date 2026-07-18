use super::*;
use std::net::Ipv4Addr;

fn config_with_mtu(mtu: u16) -> ControlMessage {
    ControlMessage::Config {
        assigned_ip: Ipv4Addr::new(10, 8, 0, 2),
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        gateway: Ipv4Addr::new(10, 8, 0, 1),
        dns_server: Ipv4Addr::new(1, 1, 1, 1),
        mtu,
        assigned_ipv6: None,
        netmask_v6: None,
        gateway_v6: None,
        dns_server_v6: None,
        whitelist_domains: None,
    }
}

fn encode(msg: &ControlMessage) -> Vec<u8> {
    bincode::serde::encode_to_vec(msg, bincode::config::standard()).unwrap()
}

#[test]
fn endpoint_host_parses_hostname_ipv4_and_ipv6_forms() {
    assert_eq!(endpoint_host("vpn.example.com:443"), "vpn.example.com");
    assert_eq!(endpoint_host("203.0.113.10:443"), "203.0.113.10");
    assert_eq!(endpoint_host("[2001:db8::1]:443"), "2001:db8::1");
    assert_eq!(endpoint_host("2001:db8::1"), "2001:db8::1");
    assert_eq!(endpoint_host("vpn.example.com"), "vpn.example.com");
}

#[test]
fn raw_response_body_decodes_config_and_error() {
    let config = decode_raw_response_body(&encode(&config_with_mtu(1280))).unwrap();
    assert!(matches!(config, ControlMessage::Config { mtu: 1280, .. }));

    let error = decode_raw_response_body(&encode(&ControlMessage::Error {
        message: "denied".to_string(),
    }))
    .unwrap();
    assert!(matches!(error, ControlMessage::Error { message } if message == "denied"));
}

#[test]
fn raw_response_body_rejects_malformed_bytes() {
    assert!(decode_raw_response_body(&[0xde, 0xad, 0xbe, 0xef]).is_err());
}

#[test]
fn server_mtu_must_match_linux_client() {
    // Strict equality regardless of how the local MTU was sourced: a
    // server MTU that differs from the pinned local budget is rejected.
    assert!(validate_server_mtu(&config_with_mtu(1280), 1280).is_ok());
    assert!(validate_server_mtu(&config_with_mtu(1340), 1340).is_ok());
    assert!(validate_server_mtu(&config_with_mtu(1340), 1280).is_err());
    assert!(validate_server_mtu(&config_with_mtu(1280), 1340).is_err());
    assert!(validate_server_mtu(&config_with_mtu(1400), 1280).is_err());
}

#[test]
fn raw_response_body_rejects_empty_buffer() {
    assert!(decode_raw_response_body(&[]).is_err());
}

#[test]
fn server_mtu_ignores_non_config_messages() {
    let auth = ControlMessage::Auth {
        token: "tok".to_string(),
    };
    assert!(validate_server_mtu(&auth, 1280).is_ok());

    let err = ControlMessage::Error {
        message: "bad".to_string(),
    };
    assert!(validate_server_mtu(&err, 1280).is_ok());
}

#[test]
fn server_mtu_boundary_values() {
    assert!(
        validate_server_mtu(&config_with_mtu(shared::MIN_TUN_MTU), shared::MIN_TUN_MTU).is_ok()
    );
    assert!(
        validate_server_mtu(&config_with_mtu(shared::MAX_TUN_MTU), shared::MAX_TUN_MTU).is_ok()
    );
    assert!(validate_server_mtu(&config_with_mtu(shared::MIN_TUN_MTU - 1), 1280).is_err());
    assert!(validate_server_mtu(&config_with_mtu(shared::MAX_TUN_MTU + 1), 1280).is_err());
}

#[test]
fn endpoint_host_handles_empty_and_port_only() {
    assert_eq!(endpoint_host(""), "");
    assert_eq!(endpoint_host(":443"), "");
}

#[test]
fn endpoint_host_bare_ipv6_without_brackets() {
    assert_eq!(endpoint_host("::1"), "::1");
    assert_eq!(endpoint_host("fe80::1"), "fe80::1");
}
