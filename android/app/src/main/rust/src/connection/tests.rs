use super::*;

#[test]
fn endpoint_host_simple() {
    assert_eq!(endpoint_host("vpn.example.com:4433"), "vpn.example.com");
}

#[test]
fn endpoint_host_ipv4() {
    assert_eq!(endpoint_host("192.168.1.1:4433"), "192.168.1.1");
}

#[test]
fn endpoint_host_ipv6_bracketed() {
    assert_eq!(endpoint_host("[::1]:4433"), "::1");
}

#[test]
fn endpoint_host_no_port() {
    assert_eq!(endpoint_host("vpn.example.com"), "vpn.example.com");
}

#[test]
fn endpoint_host_ipv6_no_brackets() {
    assert_eq!(endpoint_host("::1"), "::1");
}

#[test]
fn effective_http3_framing_matches_transport_invariant() {
    assert!(!effective_http3_framing(false, false));
    assert!(effective_http3_framing(false, true));
    assert!(effective_http3_framing(true, false));
    assert!(effective_http3_framing(true, true));
}

#[test]
fn raw_mode_advertises_only_mavivpn_alpn() {
    assert_eq!(alpn_protocols(false), vec![b"mavivpn".to_vec()]);
}

#[test]
fn validate_server_mtu_accepts_match() {
    assert!(validate_server_mtu(&config_with_mtu(1280), 1280, TunMtuSource::Config).is_ok());
    assert!(validate_server_mtu(&config_with_mtu(1360), 1280, TunMtuSource::Default).is_ok());
}

#[test]
fn validate_server_mtu_rejects_mismatch() {
    let err = validate_server_mtu(&config_with_mtu(1360), 1280, TunMtuSource::Config).unwrap_err();
    assert!(err.to_string().contains("MTU mismatch"));
}

#[test]
fn h3_mode_advertises_only_h3_alpn() {
    assert_eq!(alpn_protocols(true), vec![b"h3".to_vec()]);
}

#[test]
fn camouflage_h3_headers_are_auth_failure_signal() {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::CONTENT_TYPE, "text/html".parse().unwrap());
    assert!(is_camouflage_h3_response(&headers));

    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::SERVER, "nginx".parse().unwrap());
    assert!(is_camouflage_h3_response(&headers));
}

#[test]
fn html_capsule_payload_is_auth_failure_signal() {
    assert!(looks_like_html_response(
        b"<!DOCTYPE html><html><body>Welcome</body></html>"
    ));
    assert!(looks_like_html_response(
        b"  <html><body>Welcome</body></html>"
    ));
    assert!(!looks_like_html_response(&[0x40, 0x00, 0x00]));
}

#[test]
fn validate_server_mtu_rejects_unsupported_value() {
    let err = validate_server_mtu(&config_with_mtu(1400), 1280, TunMtuSource::Default).unwrap_err();
    assert!(err.to_string().contains("unsupported VPN MTU"));
}

#[test]
fn raw_server_config_rejects_server_error() {
    let bytes = bincode::serde::encode_to_vec(
        &ControlMessage::Error {
            message: "denied".to_string(),
        },
        bincode::config::standard(),
    )
    .unwrap();

    let err = decode_raw_server_config(&bytes).unwrap_err();

    assert!(err.to_string().contains("Server Error: denied"));
}

#[test]
fn raw_server_config_rejects_malformed_bytes() {
    assert!(decode_raw_server_config(&[0xde, 0xad, 0xbe, 0xef]).is_err());
}

fn config_with_mtu(mtu: u16) -> ControlMessage {
    ControlMessage::Config {
        assigned_ip: "10.0.0.2".parse().unwrap(),
        netmask: "255.255.255.0".parse().unwrap(),
        gateway: "10.0.0.1".parse().unwrap(),
        dns_server: "8.8.8.8".parse().unwrap(),
        mtu,
        assigned_ipv6: None,
        netmask_v6: None,
        gateway_v6: None,
        dns_server_v6: None,
        whitelist_domains: None,
    }
}
