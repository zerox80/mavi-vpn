use super::*;
use clap::Parser;
use shared::masque::{
    decode_address_assign, decode_route_advertisement, read_capsule, CAPSULE_ADDRESS_ASSIGN,
    CAPSULE_MAVI_CONFIG, CAPSULE_ROUTE_ADVERTISEMENT,
};
use shared::ControlMessage;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn test_config(args: &[&str]) -> Config {
    let mut argv = vec!["mavi-vpn", "--auth-token", "secret"];
    argv.extend_from_slice(args);
    Config::parse_from(argv)
}

fn collect_capsules(mut bytes: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let mut capsules = Vec::new();
    while !bytes.is_empty() {
        let (ctype, payload, consumed) = read_capsule(bytes).expect("complete capsule");
        capsules.push((ctype, payload.to_vec()));
        bytes = &bytes[consumed..];
    }
    capsules
}

#[test]
fn non_connect_ip_response_depends_on_censorship_mode() {
    assert_eq!(
        non_connect_ip_response(true),
        NonConnectIpResponse::CamouflageOk
    );
    assert_eq!(
        non_connect_ip_response(false),
        NonConnectIpResponse::NotFound
    );
}

fn connect_ip_request() -> http::Request<()> {
    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(CONNECT_IP_PATH)
        .header("capsule-protocol", CAPSULE_PROTOCOL)
        .body(())
        .unwrap();
    request
        .extensions_mut()
        .insert(h3::ext::Protocol::CONNECT_IP);
    request
}

#[test]
fn connect_ip_request_requires_method_path_protocol_and_capsule_header() {
    let request = connect_ip_request();
    assert!(is_connect_ip_request(&request));

    let wrong_method = http::Request::builder()
        .method(http::Method::GET)
        .uri(CONNECT_IP_PATH)
        .header("capsule-protocol", CAPSULE_PROTOCOL)
        .body(())
        .unwrap();
    assert!(!is_connect_ip_request(&wrong_method));

    let wrong_path = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("/.well-known/masque/ip/192.0.2.1/6/")
        .header("capsule-protocol", CAPSULE_PROTOCOL)
        .extension(h3::ext::Protocol::CONNECT_IP)
        .body(())
        .unwrap();
    assert!(!is_connect_ip_request(&wrong_path));

    let missing_protocol = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(CONNECT_IP_PATH)
        .header("capsule-protocol", CAPSULE_PROTOCOL)
        .body(())
        .unwrap();
    assert!(!is_connect_ip_request(&missing_protocol));

    let missing_capsule_protocol = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(CONNECT_IP_PATH)
        .extension(h3::ext::Protocol::CONNECT_IP)
        .body(())
        .unwrap();
    assert!(!is_connect_ip_request(&missing_capsule_protocol));
}

#[test]
fn connect_ip_capsules_include_ipv4_only_assign_route_and_config() {
    let state = AppState::new("10.8.0.0/24").unwrap();
    let config = test_config(&["--whitelist-domains", "one.test,two.test"]);
    let capsules = collect_capsules(
        &build_connect_ip_capsules(
            &state,
            &config,
            Ipv4Addr::new(10, 8, 0, 2),
            Ipv6Addr::LOCALHOST,
            false,
        )
        .unwrap(),
    );

    assert_eq!(
        capsules.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
        vec![
            CAPSULE_ADDRESS_ASSIGN,
            CAPSULE_ROUTE_ADVERTISEMENT,
            CAPSULE_MAVI_CONFIG
        ]
    );

    let assigns = decode_address_assign(&capsules[0].1).unwrap();
    assert_eq!(assigns.len(), 1);
    assert_eq!(assigns[0].ip, IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)));
    assert_eq!(assigns[0].prefix_len, 24);

    let routes = decode_route_advertisement(&capsules[1].1).unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].start, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    assert_eq!(routes[0].end, IpAddr::V4(Ipv4Addr::BROADCAST));

    let (cfg, _): (ControlMessage, _) =
        bincode::serde::decode_from_slice(&capsules[2].1, bincode::config::standard()).unwrap();
    match cfg {
        ControlMessage::Config {
            assigned_ipv6,
            whitelist_domains,
            ..
        } => {
            assert!(assigned_ipv6.is_none());
            assert_eq!(
                whitelist_domains,
                Some(vec!["one.test".to_string(), "two.test".to_string()])
            );
        }
        other => panic!("expected Config, got {other:?}"),
    }
}

#[test]
fn connect_ip_capsules_include_dual_stack_and_default_dns_v6() {
    let state = AppState::new("10.8.0.0/24").unwrap();
    let config = test_config(&[]);
    let ip6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let capsules = collect_capsules(
        &build_connect_ip_capsules(&state, &config, Ipv4Addr::new(10, 8, 0, 2), ip6, true).unwrap(),
    );

    let assigns = decode_address_assign(&capsules[0].1).unwrap();
    assert_eq!(assigns.len(), 2);
    assert!(assigns
        .iter()
        .any(|a| a.ip == IpAddr::V6(ip6) && a.prefix_len == 64));

    let routes = decode_route_advertisement(&capsules[1].1).unwrap();
    assert_eq!(routes.len(), 2);
    assert!(routes
        .iter()
        .any(|r| r.start == IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            && r.end == IpAddr::V6(Ipv6Addr::from([0xff; 16]))));

    let (cfg, _): (ControlMessage, _) =
        bincode::serde::decode_from_slice(&capsules[2].1, bincode::config::standard()).unwrap();
    match cfg {
        ControlMessage::Config {
            assigned_ipv6,
            dns_server_v6,
            netmask_v6,
            ..
        } => {
            assert_eq!(assigned_ipv6, Some(ip6));
            assert_eq!(netmask_v6, Some(64));
            assert_eq!(
                dns_server_v6,
                Some(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111))
            );
        }
        other => panic!("expected Config, got {other:?}"),
    }
}

#[test]
fn connect_ip_capsules_use_configured_ipv6_prefix() {
    let state = AppState::new_with_ipv6("10.8.0.0/24", "fd12:3456::/80").unwrap();
    let config = test_config(&[]);
    let ip6 = Ipv6Addr::new(0xfd12, 0x3456, 0, 0, 0, 0, 0, 2);
    let capsules = collect_capsules(
        &build_connect_ip_capsules(&state, &config, Ipv4Addr::new(10, 8, 0, 2), ip6, true).unwrap(),
    );

    let assigns = decode_address_assign(&capsules[0].1).unwrap();
    assert!(assigns
        .iter()
        .any(|a| a.ip == IpAddr::V6(ip6) && a.prefix_len == 80));

    let (cfg, _): (ControlMessage, _) =
        bincode::serde::decode_from_slice(&capsules[2].1, bincode::config::standard()).unwrap();
    match cfg {
        ControlMessage::Config { netmask_v6, .. } => {
            assert_eq!(netmask_v6, Some(80));
        }
        other => panic!("expected Config, got {other:?}"),
    }
}
