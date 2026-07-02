//! Unit tests for the shared protocol/control-message types.

use super::*;

fn roundtrip(msg: &ControlMessage) -> ControlMessage {
    let encoded = bincode::serde::encode_to_vec(msg, bincode::config::standard()).unwrap();
    let (decoded, _): (ControlMessage, _) =
        bincode::serde::decode_from_slice(&encoded, bincode::config::standard()).unwrap();
    decoded
}

#[test]
fn auth_message_roundtrip() {
    let msg = ControlMessage::Auth {
        token: "my-secret-token-123".to_string(),
    };
    let decoded = roundtrip(&msg);
    match decoded {
        ControlMessage::Auth { token } => assert_eq!(token, "my-secret-token-123"),
        other => panic!("Expected Auth, got {other:?}"),
    }
}

#[test]
fn config_message_roundtrip_full() {
    let msg = ControlMessage::Config {
        assigned_ip: Ipv4Addr::new(10, 8, 0, 2),
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        gateway: Ipv4Addr::new(10, 8, 0, 1),
        dns_server: Ipv4Addr::new(1, 1, 1, 1),
        mtu: 1280,
        assigned_ipv6: Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
        netmask_v6: Some(64),
        gateway_v6: Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
        dns_server_v6: Some(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
        whitelist_domains: Some(vec!["example.com".to_string(), "test.org".to_string()]),
    };
    let decoded = roundtrip(&msg);
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
            assert_eq!(assigned_ip, Ipv4Addr::new(10, 8, 0, 2));
            assert_eq!(netmask, Ipv4Addr::new(255, 255, 255, 0));
            assert_eq!(gateway, Ipv4Addr::new(10, 8, 0, 1));
            assert_eq!(dns_server, Ipv4Addr::new(1, 1, 1, 1));
            assert_eq!(mtu, 1280);
            assert_eq!(
                assigned_ipv6,
                Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2))
            );
            assert_eq!(netmask_v6, Some(64));
            assert_eq!(gateway_v6, Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)));
            assert_eq!(
                dns_server_v6,
                Some(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111))
            );
            assert_eq!(
                whitelist_domains,
                Some(vec!["example.com".to_string(), "test.org".to_string()])
            );
        }
        other => panic!("Expected Config, got {other:?}"),
    }
}

#[test]
fn config_message_roundtrip_ipv6_none() {
    let msg = ControlMessage::Config {
        assigned_ip: Ipv4Addr::new(10, 8, 0, 2),
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        gateway: Ipv4Addr::new(10, 8, 0, 1),
        dns_server: Ipv4Addr::new(1, 1, 1, 1),
        mtu: 1280,
        assigned_ipv6: None,
        netmask_v6: None,
        gateway_v6: None,
        dns_server_v6: None,
        whitelist_domains: None,
    };
    let decoded = roundtrip(&msg);
    match decoded {
        ControlMessage::Config {
            assigned_ipv6,
            netmask_v6,
            gateway_v6,
            dns_server_v6,
            whitelist_domains,
            ..
        } => {
            assert!(assigned_ipv6.is_none());
            assert!(netmask_v6.is_none());
            assert!(gateway_v6.is_none());
            assert!(dns_server_v6.is_none());
            assert!(whitelist_domains.is_none());
        }
        other => panic!("Expected Config, got {other:?}"),
    }
}

#[test]
fn error_message_roundtrip() {
    let msg = ControlMessage::Error {
        message: "Access Denied: Invalid Token".to_string(),
    };
    let decoded = roundtrip(&msg);
    match decoded {
        ControlMessage::Error { message } => {
            assert_eq!(message, "Access Denied: Invalid Token");
        }
        other => panic!("Expected Error, got {other:?}"),
    }
}

#[test]
fn reauth_message_roundtrip() {
    let msg = ControlMessage::Reauth {
        token: "fresh-access-token".to_string(),
    };
    match roundtrip(&msg) {
        ControlMessage::Reauth { token } => assert_eq!(token, "fresh-access-token"),
        other => panic!("Expected Reauth, got {other:?}"),
    }
}

#[test]
fn reauth_result_roundtrip() {
    for accepted in [true, false] {
        match roundtrip(&ControlMessage::ReauthResult { accepted }) {
            ControlMessage::ReauthResult { accepted: got } => assert_eq!(got, accepted),
            other => panic!("Expected ReauthResult, got {other:?}"),
        }
    }
}

#[test]
fn existing_variant_indices_are_stable() {
    // Appending Reauth/ReauthResult must not shift the wire index of the
    // original variants — older peers still decode Auth/Config/Error.
    let auth = bincode::serde::encode_to_vec(
        &ControlMessage::Auth {
            token: "t".to_string(),
        },
        bincode::config::standard(),
    )
    .unwrap();
    assert_eq!(auth[0], 0, "Auth must stay variant 0");

    let error = bincode::serde::encode_to_vec(
        &ControlMessage::Error {
            message: String::new(),
        },
        bincode::config::standard(),
    )
    .unwrap();
    assert_eq!(error[0], 2, "Error must stay variant 2");
}

#[test]
fn test_malformed_bincode_data() {
    // Try decoding garbage data
    let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let result: Result<(ControlMessage, usize), _> =
        bincode::serde::decode_from_slice(&garbage, bincode::config::standard());
    assert!(result.is_err(), "Decoding garbage data should fail");

    // Try decoding an incomplete message
    let msg = ControlMessage::Auth {
        token: "123".to_string(),
    };
    let encoded = bincode::serde::encode_to_vec(&msg, bincode::config::standard()).unwrap();
    let incomplete = &encoded[..encoded.len() - 1]; // strip last byte
    let result_incomplete: Result<(ControlMessage, usize), _> =
        bincode::serde::decode_from_slice(incomplete, bincode::config::standard());
    assert!(
        result_incomplete.is_err(),
        "Decoding incomplete data should fail"
    );
}

#[test]
fn test_empty_token_roundtrip() {
    let msg = ControlMessage::Auth {
        token: String::new(),
    };
    let decoded = roundtrip(&msg);
    match decoded {
        ControlMessage::Auth { token } => assert!(token.is_empty()),
        other => panic!("Expected Auth, got {other:?}"),
    }
}

#[test]
fn test_config_all_none_optional_fields() {
    let msg = ControlMessage::Config {
        assigned_ip: Ipv4Addr::new(10, 8, 0, 2),
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        gateway: Ipv4Addr::new(10, 8, 0, 1),
        dns_server: Ipv4Addr::new(1, 1, 1, 1),
        mtu: 1280,
        assigned_ipv6: None,
        netmask_v6: None,
        gateway_v6: None,
        dns_server_v6: None,
        whitelist_domains: Some(vec![]),
    };
    let decoded = roundtrip(&msg);
    match decoded {
        ControlMessage::Config {
            whitelist_domains, ..
        } => {
            assert_eq!(whitelist_domains, Some(vec![]));
        }
        other => panic!("Expected Config, got {other:?}"),
    }
}

#[test]
fn test_error_empty_message() {
    let msg = ControlMessage::Error {
        message: String::new(),
    };
    let decoded = roundtrip(&msg);
    match decoded {
        ControlMessage::Error { message } => assert!(message.is_empty()),
        other => panic!("Expected Error, got {other:?}"),
    }
}

#[test]
fn test_decode_empty_bytes() {
    let result: Result<(ControlMessage, usize), _> =
        bincode::serde::decode_from_slice(&[], bincode::config::standard());
    assert!(result.is_err());
}

#[test]
fn resolve_tun_mtu_explicit_valid() {
    assert_eq!(resolve_tun_mtu(Some(1300)), 1300);
    assert_eq!(resolve_tun_mtu(Some(1280)), 1280);
    assert_eq!(resolve_tun_mtu(Some(1360)), 1360);
}

#[test]
fn resolve_tun_mtu_env_var_scenarios() {
    // All env var scenarios are in a single test to avoid race conditions
    // from parallel tests mutating std::env concurrently.
    let prev = std::env::var("VPN_MTU").ok();

    // None + no env → default
    std::env::remove_var("VPN_MTU");
    assert_eq!(resolve_tun_mtu(None), DEFAULT_TUN_MTU);
    assert_eq!(
        resolve_tun_mtu_with_source(None),
        (DEFAULT_TUN_MTU, TunMtuSource::Default)
    );

    // Explicit out-of-range + no env → default (falls through)
    assert_eq!(resolve_tun_mtu(Some(500)), DEFAULT_TUN_MTU);
    assert_eq!(resolve_tun_mtu(Some(2000)), DEFAULT_TUN_MTU);
    assert_eq!(resolve_tun_mtu(Some(0)), DEFAULT_TUN_MTU);
    assert_eq!(
        resolve_tun_mtu_with_source(Some(1340)),
        (1340, TunMtuSource::Config)
    );

    // Env var fallback
    std::env::set_var("VPN_MTU", "1300");
    assert_eq!(resolve_tun_mtu(None), 1300);
    assert_eq!(resolve_tun_mtu_with_source(None), (1300, TunMtuSource::Env));

    // Explicit takes priority over env
    assert_eq!(resolve_tun_mtu(Some(1340)), 1340);

    // Invalid env falls through to default
    std::env::set_var("VPN_MTU", "not_a_number");
    assert_eq!(resolve_tun_mtu(None), DEFAULT_TUN_MTU);
    std::env::set_var("VPN_MTU", "99999");
    assert_eq!(resolve_tun_mtu(None), DEFAULT_TUN_MTU);

    // Invalid env with valid explicit → explicit wins
    std::env::set_var("VPN_MTU", "bad");
    assert_eq!(resolve_tun_mtu(Some(1300)), 1300);

    // Restore previous env state
    if let Some(v) = prev {
        std::env::set_var("VPN_MTU", v);
    } else {
        std::env::remove_var("VPN_MTU");
    }
}

#[test]
fn validate_keycloak_url_rules() {
    assert!(validate_keycloak_url("https://auth.example.com").is_ok());
    assert!(validate_keycloak_url("http://localhost").is_ok());
    assert!(validate_keycloak_url("http://localhost:8080/realms/x").is_ok());
    assert!(validate_keycloak_url("http://127.0.0.1:8080").is_ok());
    assert!(validate_keycloak_url("http://[::1]:8080").is_ok());
    assert!(validate_keycloak_url("http://auth.example.com").is_err());
    assert!(validate_keycloak_url("http://10.0.0.5:8080").is_err());
    assert!(validate_keycloak_url("ftp://auth.example.com").is_err());
    assert!(validate_keycloak_url("").is_err());
    // Substring tricks must not bypass the loopback exemption.
    assert!(validate_keycloak_url("http://localhost.evil.com").is_err());
    assert!(validate_keycloak_url("http://evil.com/localhost").is_err());
    let loopback_userinfo_bypass = format!("http://{}@evil.com/realms/x", "localhost:8080");
    assert!(validate_keycloak_url(&loopback_userinfo_bypass).is_err());
    assert!(validate_keycloak_url("http://localhost@evil.com").is_err());
}

#[test]
fn html_detection_doctype() {
    assert!(looks_like_html_response(b"<!DOCTYPE html><html>"));
    assert!(looks_like_html_response(b"  \n<!doctype html>"));
}

#[test]
fn html_detection_html_tag() {
    assert!(looks_like_html_response(b"<html><body>"));
    assert!(looks_like_html_response(b"<HTML><HEAD>"));
}

#[test]
fn html_detection_rejects_bincode() {
    // Typical bincode output: starts with enum variant index, not HTML
    assert!(!looks_like_html_response(&[0x01, 0x00, 0x00, 0x00]));
}

#[test]
fn html_detection_rejects_empty() {
    assert!(!looks_like_html_response(&[]));
}

#[test]
fn html_detection_rejects_ip_packet() {
    // IPv4 packet header
    let mut pkt = vec![0u8; 20];
    pkt[0] = 0x45;
    assert!(!looks_like_html_response(&pkt));
}
