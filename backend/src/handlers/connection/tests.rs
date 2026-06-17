use super::*;
use clap::Parser;
use std::net::{Ipv4Addr, Ipv6Addr};

fn test_config() -> Config {
    Config::parse_from([
        "mavi-vpn",
        "--auth-token",
        "secret",
        "--dns",
        "9.9.9.9",
        "--dns-v6",
        "2001:4860:4860::8888",
        "--whitelist-domains",
        "example.com,internal.test",
        "--mtu",
        "1340",
    ])
}

fn encode_message(msg: &ControlMessage) -> Vec<u8> {
    bincode::serde::encode_to_vec(msg, bincode::config::standard()).unwrap()
}

#[test]
fn preauth_phase_timeout_is_bounded_and_nonzero() {
    // Long enough for a slow handshake, short enough to free a stalled slot well before idle timeout.
    assert!(PREAUTH_PHASE_TIMEOUT > Duration::from_secs(0));
    assert!(PREAUTH_PHASE_TIMEOUT <= Duration::from_secs(30));
}

#[test]
fn raw_auth_len_accepts_boundary_and_rejects_oversize() {
    assert!(validate_raw_auth_len(RAW_AUTH_MAX_BYTES).is_ok());
    assert!(validate_raw_auth_len(RAW_AUTH_MAX_BYTES + 1)
        .unwrap_err()
        .to_string()
        .contains("too big"));
}

#[test]
fn raw_auth_payload_extracts_token() {
    let payload = encode_message(&ControlMessage::Auth {
        token: "token-123".to_string(),
    });

    assert_eq!(decode_raw_auth_payload(&payload).unwrap(), "token-123");
}

#[test]
fn raw_auth_payload_rejects_non_auth_and_malformed() {
    let payload = encode_message(&ControlMessage::Error {
        message: "nope".to_string(),
    });
    assert!(decode_raw_auth_payload(&payload)
        .unwrap_err()
        .to_string()
        .contains("Expected Auth"));

    assert!(decode_raw_auth_payload(&[0xde, 0xad, 0xbe, 0xef])
        .unwrap_err()
        .to_string()
        .contains("Protocol error"));
}

#[test]
fn reauth_payload_extracts_token() {
    let payload = encode_message(&ControlMessage::Reauth {
        token: "fresh-token".to_string(),
    });
    assert_eq!(decode_reauth_payload(&payload).unwrap(), "fresh-token");
}

#[test]
fn reauth_payload_rejects_non_reauth_and_malformed() {
    let payload = encode_message(&ControlMessage::Auth {
        token: "x".to_string(),
    });
    assert!(decode_reauth_payload(&payload)
        .unwrap_err()
        .to_string()
        .contains("Expected Reauth"));

    assert!(decode_reauth_payload(&[0xde, 0xad, 0xbe, 0xef])
        .unwrap_err()
        .to_string()
        .contains("Protocol error"));
}

#[test]
fn unauthorized_response_frame_is_generic() {
    let framed = encode_control_message_frame(&unauthorized_control_message()).unwrap();
    let len = u32::from_le_bytes(framed[..4].try_into().unwrap()) as usize;
    assert_eq!(len, framed.len() - 4);

    let (decoded, _): (ControlMessage, _) =
        bincode::serde::decode_from_slice(&framed[4..], bincode::config::standard()).unwrap();
    match decoded {
        ControlMessage::Error { message } => {
            // Must not leak the rejection reason to unauthenticated peers.
            assert_eq!(message, "Unauthorized");
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[test]
fn session_deadline_none_for_static_auth() {
    assert!(session_deadline(None).is_none());
}

#[tokio::test]
async fn session_deadline_expired_token_is_due_after_leeway() {
    #[allow(clippy::cast_possible_wrap)]
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Already-expired token: deadline is now + leeway only.
    let deadline = session_deadline(Some(now - 100)).unwrap();
    assert!(deadline <= tokio::time::Instant::now() + SESSION_EXPIRY_LEEWAY);

    // Future expiry: deadline is at least the remaining lifetime.
    let deadline = session_deadline(Some(now + 600)).unwrap();
    assert!(deadline >= tokio::time::Instant::now() + Duration::from_secs(590));
}

#[test]
fn config_message_omits_ipv6_when_disabled() {
    let state = AppState::new("10.8.0.0/24").unwrap();
    let config = test_config();
    let msg = build_config_message(
        &state,
        &config,
        Ipv4Addr::new(10, 8, 0, 2),
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
        false,
    );

    match msg {
        ControlMessage::Config {
            assigned_ipv6,
            netmask_v6,
            gateway_v6,
            dns_server_v6,
            whitelist_domains,
            mtu,
            ..
        } => {
            assert_eq!(mtu, 1340);
            assert!(assigned_ipv6.is_none());
            assert!(netmask_v6.is_none());
            assert!(gateway_v6.is_none());
            assert!(dns_server_v6.is_none());
            assert_eq!(
                whitelist_domains,
                Some(vec!["example.com".to_string(), "internal.test".to_string()])
            );
        }
        other => panic!("expected Config, got {other:?}"),
    }
}

#[test]
fn config_message_includes_ipv6_and_default_dns_v6() {
    let state = AppState::new("10.8.0.0/24").unwrap();
    let mut config = test_config();
    config.dns_v6 = None;
    let assigned_ip6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let msg = build_config_message(
        &state,
        &config,
        Ipv4Addr::new(10, 8, 0, 2),
        assigned_ip6,
        true,
    );

    match msg {
        ControlMessage::Config {
            assigned_ipv6,
            netmask_v6,
            gateway_v6,
            dns_server_v6,
            ..
        } => {
            assert_eq!(assigned_ipv6, Some(assigned_ip6));
            assert_eq!(netmask_v6, Some(64));
            assert_eq!(gateway_v6, Some(state.gateway_ip_v6()));
            assert_eq!(
                dns_server_v6,
                Some(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111))
            );
        }
        other => panic!("expected Config, got {other:?}"),
    }
}

#[test]
fn config_message_uses_configured_ipv6_prefix() {
    let state = AppState::new_with_ipv6("10.8.0.0/24", "fd12:3456::/80").unwrap();
    let config = test_config();
    let msg = build_config_message(
        &state,
        &config,
        Ipv4Addr::new(10, 8, 0, 2),
        Ipv6Addr::new(0xfd12, 0x3456, 0, 0, 0, 0, 0, 2),
        true,
    );

    match msg {
        ControlMessage::Config { netmask_v6, .. } => {
            assert_eq!(netmask_v6, Some(80));
        }
        other => panic!("expected Config, got {other:?}"),
    }
}
