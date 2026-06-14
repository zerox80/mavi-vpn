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

#[test]
fn non_ipv6_endpoint_prefers_ipv4_addresses() {
    let mut addrs: Vec<SocketAddr> = vec![
        "[2001:db8::1]:443".parse().unwrap(),
        "203.0.113.10:443".parse().unwrap(),
        "[2001:db8::2]:443".parse().unwrap(),
        "203.0.113.11:443".parse().unwrap(),
    ];

    order_resolved_addrs(&mut addrs, "vpn.example.com:443");

    assert!(addrs[0].is_ipv4());
    assert!(addrs[1].is_ipv4());
    assert!(addrs[2].is_ipv6());
    assert!(addrs[3].is_ipv6());
}

#[test]
fn explicit_ipv6_endpoint_keeps_resolution_order() {
    let original: Vec<SocketAddr> = vec![
        "[2001:db8::1]:443".parse().unwrap(),
        "203.0.113.10:443".parse().unwrap(),
    ];
    let mut addrs = original.clone();

    order_resolved_addrs(&mut addrs, "[2001:db8::1]:443");

    assert_eq!(addrs, original);
}

#[test]
fn detects_explicit_ipv6_host() {
    assert!(endpoint_host_is_explicit_ipv6("[2001:db8::1]:443"));
    assert!(endpoint_host_is_explicit_ipv6("2001:db8::1"));
    assert!(!endpoint_host_is_explicit_ipv6("vpn.example.com:443"));
    assert!(!endpoint_host_is_explicit_ipv6("203.0.113.10:443"));
}

#[test]
fn server_mtu_mismatch_rejected_even_for_default_source() {
    // Strict equality: a server MTU that differs from the pinned local budget
    // is rejected regardless of how the local MTU was sourced.
    let cfg = config_with_mtu(1340);

    assert!(validate_server_mtu(&cfg, 1280).is_err());
    assert!(validate_server_mtu(&cfg, 1340).is_ok());
}

#[test]
fn explicit_client_mtu_must_match_server_mtu() {
    let cfg = config_with_mtu(1340);

    assert!(validate_server_mtu(&cfg, 1280).is_err());
    assert!(validate_server_mtu(&cfg, 1340).is_ok());
}

#[test]
fn server_mtu_must_be_supported() {
    let cfg = config_with_mtu(1500);

    assert!(validate_server_mtu(&cfg, 1280).is_err());
}

#[test]
fn validate_server_mtu_ignores_non_config_messages() {
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
fn validate_server_mtu_accepts_minimum_boundary() {
    let cfg = config_with_mtu(shared::MIN_TUN_MTU);
    assert!(validate_server_mtu(&cfg, shared::MIN_TUN_MTU).is_ok());
}

#[test]
fn validate_server_mtu_accepts_maximum_boundary() {
    let cfg = config_with_mtu(shared::MAX_TUN_MTU);
    assert!(validate_server_mtu(&cfg, shared::MAX_TUN_MTU).is_ok());
}

#[test]
fn validate_server_mtu_rejects_below_minimum() {
    let cfg = config_with_mtu(shared::MIN_TUN_MTU - 1);
    assert!(validate_server_mtu(&cfg, 1280).is_err());
}

#[test]
fn validate_server_mtu_rejects_server_pushed_difference() {
    // Previously the default source accepted a differing server MTU; now it is
    // a hard mismatch error (the client cannot adopt a different transport MTU).
    let cfg = config_with_mtu(1340);
    assert!(validate_server_mtu(&cfg, 1280).is_err());
}

#[test]
fn validate_server_mtu_requires_match() {
    let cfg = config_with_mtu(1300);
    assert!(validate_server_mtu(&cfg, 1300).is_ok());
    assert!(validate_server_mtu(&cfg, 1280).is_err());
}

#[test]
fn order_resolved_addrs_empty_list() {
    let mut addrs: Vec<SocketAddr> = vec![];
    order_resolved_addrs(&mut addrs, "vpn.example.com:443");
    assert!(addrs.is_empty());
}

#[test]
fn order_resolved_addrs_all_ipv4_unchanged() {
    let addrs: Vec<SocketAddr> = vec![
        "1.2.3.4:443".parse().unwrap(),
        "5.6.7.8:443".parse().unwrap(),
    ];
    let mut sorted = addrs.clone();
    order_resolved_addrs(&mut sorted, "vpn.example.com:443");
    assert_eq!(sorted, addrs);
}

#[test]
fn order_resolved_addrs_all_ipv6_unchanged() {
    let addrs: Vec<SocketAddr> = vec![
        "[2001:db8::1]:443".parse().unwrap(),
        "[2001:db8::2]:443".parse().unwrap(),
    ];
    let mut sorted = addrs.clone();
    order_resolved_addrs(&mut sorted, "vpn.example.com:443");
    assert_eq!(sorted, addrs);
}

#[test]
fn endpoint_host_is_explicit_ipv6_loopback() {
    assert!(endpoint_host_is_explicit_ipv6("[::1]:443"));
    assert!(endpoint_host_is_explicit_ipv6("::1"));
}

#[test]
fn endpoint_host_is_explicit_ipv6_full_address() {
    assert!(endpoint_host_is_explicit_ipv6(
        "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443"
    ));
}

#[test]
fn endpoint_host_is_not_ipv6_for_hostname() {
    assert!(!endpoint_host_is_explicit_ipv6("vpn.example.com"));
    assert!(!endpoint_host_is_explicit_ipv6("localhost:443"));
}

#[test]
fn order_resolved_addrs_single_ipv4() {
    let mut addrs: Vec<SocketAddr> = vec!["1.2.3.4:443".parse().unwrap()];
    order_resolved_addrs(&mut addrs, "vpn.example.com:443");
    assert!(addrs[0].is_ipv4());
}

#[test]
fn order_resolved_addrs_single_ipv6() {
    let mut addrs: Vec<SocketAddr> = vec!["[2001:db8::1]:443".parse().unwrap()];
    order_resolved_addrs(&mut addrs, "vpn.example.com:443");
    assert!(addrs[0].is_ipv6());
}

#[test]
fn order_resolved_addrs_mixed_with_duplicates() {
    let mut addrs: Vec<SocketAddr> = vec![
        "1.2.3.4:443".parse().unwrap(),
        "[2001:db8::1]:443".parse().unwrap(),
        "1.2.3.4:443".parse().unwrap(),
        "[2001:db8::2]:443".parse().unwrap(),
    ];
    order_resolved_addrs(&mut addrs, "vpn.example.com:443");
    assert!(addrs[0].is_ipv4());
    assert!(addrs[1].is_ipv4());
    assert!(addrs[2].is_ipv6());
    assert!(addrs[3].is_ipv6());
}

#[test]
fn validate_server_mtu_accepts_exact_match() {
    let cfg = config_with_mtu(1300);
    assert!(validate_server_mtu(&cfg, 1300).is_ok());
}

#[test]
fn validate_server_mtu_rejects_mtu_below_minimum() {
    let cfg = config_with_mtu(shared::MIN_TUN_MTU - 1);
    assert!(validate_server_mtu(&cfg, shared::MIN_TUN_MTU - 1).is_err());
}

#[test]
fn validate_server_mtu_rejects_mtu_above_maximum() {
    let cfg = config_with_mtu(shared::MAX_TUN_MTU + 1);
    assert!(validate_server_mtu(&cfg, shared::MAX_TUN_MTU + 1).is_err());
}

#[test]
fn validate_server_mtu_exact_match_ok() {
    let cfg = config_with_mtu(1320);
    assert!(validate_server_mtu(&cfg, 1320).is_ok());
}

#[test]
fn validate_server_mtu_mismatch_err() {
    let cfg = config_with_mtu(1320);
    assert!(validate_server_mtu(&cfg, 1300).is_err());
}

#[test]
fn order_resolved_addrs_preserves_ipv4_order() {
    let mut addrs: Vec<SocketAddr> = vec![
        "10.0.0.1:443".parse().unwrap(),
        "10.0.0.2:443".parse().unwrap(),
        "10.0.0.3:443".parse().unwrap(),
    ];
    let original = addrs.clone();
    order_resolved_addrs(&mut addrs, "vpn.example.com:443");
    assert_eq!(addrs, original);
}

#[test]
fn order_resolved_addrs_preserves_ipv6_order() {
    let mut addrs: Vec<SocketAddr> = vec![
        "[2001:db8::1]:443".parse().unwrap(),
        "[2001:db8::2]:443".parse().unwrap(),
        "[2001:db8::3]:443".parse().unwrap(),
    ];
    let original = addrs.clone();
    order_resolved_addrs(&mut addrs, "vpn.example.com:443");
    assert_eq!(addrs, original);
}

#[test]
fn endpoint_host_is_explicit_ipv6_ipv4_mapped() {
    assert!(endpoint_host_is_explicit_ipv6("[::ffff:192.168.1.1]:443"));
}

#[test]
fn endpoint_host_is_explicit_ipv6_unspecified() {
    assert!(endpoint_host_is_explicit_ipv6("[::]:443"));
    assert!(endpoint_host_is_explicit_ipv6("::"));
}

#[test]
fn endpoint_host_is_not_ipv6_for_ipv4() {
    assert!(!endpoint_host_is_explicit_ipv6("192.168.1.1:443"));
    assert!(!endpoint_host_is_explicit_ipv6("192.168.1.1"));
    assert!(!endpoint_host_is_explicit_ipv6("10.0.0.1:443"));
}

#[test]
fn raw_response_len_accepts_valid_sizes() {
    assert!(validate_raw_response_len(0).is_ok());
    assert!(validate_raw_response_len(1).is_ok());
    assert!(validate_raw_response_len(1024).is_ok());
    assert!(validate_raw_response_len(65_536).is_ok());
}

#[test]
fn raw_response_len_rejects_oversized() {
    assert!(validate_raw_response_len(65_537).is_err());
    assert!(validate_raw_response_len(100_000).is_err());
    assert!(validate_raw_response_len(usize::MAX).is_err());
}

#[test]
fn raw_response_len_accepts_formerly_magic_length() {
    // 0x1901 was the magic auth-failure length. Now handled by
    // looks_like_html_response() on content. validate_raw_response_len
    // only checks the size bound.
    assert!(validate_raw_response_len(0x1901).is_ok());
}

#[test]
fn raw_response_len_accepts_exact_max() {
    assert!(validate_raw_response_len(65_536).is_ok());
}

#[test]
fn raw_response_len_rejects_one_over_max() {
    assert!(validate_raw_response_len(65_537).is_err());
}

#[test]
fn raw_response_len_accepts_just_below_magic() {
    assert!(validate_raw_response_len(0x1900).is_ok());
}

#[test]
fn raw_response_len_accepts_just_above_magic() {
    assert!(validate_raw_response_len(0x1902).is_ok());
}

#[test]
fn validate_server_mtu_ignores_auth_message() {
    let auth = ControlMessage::Auth {
        token: "secret".to_string(),
    };
    assert!(validate_server_mtu(&auth, 1280).is_ok());
}

#[test]
fn validate_server_mtu_ignores_error_message() {
    let err = ControlMessage::Error {
        message: "server error".to_string(),
    };
    assert!(validate_server_mtu(&err, 1280).is_ok());
}

// --- compute_quic_mtu_config tests ---

#[test]
fn quic_mtu_config_default_uses_default_tun_mtu_ipv4() {
    let addr: SocketAddr = "1.2.3.4:443".parse().unwrap();
    let cfg = compute_quic_mtu_config(None);
    assert_eq!(cfg.transport_tun_mtu, shared::DEFAULT_TUN_MTU);
    assert_eq!(
        cfg.quic_mtu,
        shared::DEFAULT_TUN_MTU + shared::QUIC_OVERHEAD_BYTES
    );
    assert!(matches!(cfg.mtu_source, shared::TunMtuSource::Default));
    assert_eq!(cfg.local_tun_mtu, shared::DEFAULT_TUN_MTU);
    assert_eq!(wire_mtu_for_addr(cfg, &addr), cfg.quic_mtu + 20 + 8);
}

#[test]
fn quic_mtu_config_default_uses_default_tun_mtu_ipv6() {
    let addr: SocketAddr = "[::1]:443".parse().unwrap();
    let cfg = compute_quic_mtu_config(None);
    assert_eq!(cfg.transport_tun_mtu, shared::DEFAULT_TUN_MTU);
    assert_eq!(wire_mtu_for_addr(cfg, &addr), cfg.quic_mtu + 40 + 8);
}

#[test]
fn quic_mtu_config_explicit_mtu_uses_provided_value() {
    let cfg = compute_quic_mtu_config(Some(1340));
    assert_eq!(cfg.transport_tun_mtu, 1340);
    assert_eq!(cfg.local_tun_mtu, 1340);
    assert_eq!(cfg.quic_mtu, 1340 + shared::QUIC_OVERHEAD_BYTES);
    assert!(matches!(cfg.mtu_source, shared::TunMtuSource::Config));
}

#[test]
fn quic_mtu_config_minimum_explicit_mtu() {
    let cfg = compute_quic_mtu_config(Some(shared::MIN_TUN_MTU));
    assert_eq!(cfg.transport_tun_mtu, shared::MIN_TUN_MTU);
    assert_eq!(
        cfg.quic_mtu,
        shared::MIN_TUN_MTU + shared::QUIC_OVERHEAD_BYTES
    );
}

#[test]
fn quic_mtu_config_ipv4_wire_mtu_includes_ip_and_udp_headers() {
    let addr: SocketAddr = "10.0.0.1:443".parse().unwrap();
    let cfg = compute_quic_mtu_config(Some(1280));
    assert_eq!(wire_mtu_for_addr(cfg, &addr), cfg.quic_mtu + 28);
}

#[test]
fn quic_mtu_config_ipv6_wire_mtu_includes_larger_ip_header() {
    let addr: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
    let cfg = compute_quic_mtu_config(Some(1280));
    assert_eq!(wire_mtu_for_addr(cfg, &addr), cfg.quic_mtu + 48);
}

// --- resolve_server_name tests ---

#[test]
fn resolve_server_name_extracts_host_from_endpoint() {
    let name = resolve_server_name("vpn.example.com:4433", None).unwrap();
    assert_eq!(name, "vpn.example.com");
}

#[test]
fn resolve_server_name_uses_ech_outer_sni_when_provided() {
    let name = resolve_server_name("vpn.example.com:4433", Some("cover.example.com")).unwrap();
    assert_eq!(name, "cover.example.com");
}

#[test]
fn resolve_server_name_rejects_empty_host() {
    let result = resolve_server_name(":4433", None);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Endpoint host missing"));
}

#[test]
fn resolve_server_name_rejects_empty_ech_sni() {
    let result = resolve_server_name("vpn.example.com:4433", Some(""));
    assert!(result.is_err());
}

#[test]
fn resolve_server_name_ipv6_endpoint() {
    let name = resolve_server_name("[2001:db8::1]:443", None).unwrap();
    assert_eq!(name, "2001:db8::1");
}

#[test]
fn resolve_server_name_endpoint_without_port() {
    let name = resolve_server_name("vpn.example.com", None).unwrap();
    assert_eq!(name, "vpn.example.com");
}
