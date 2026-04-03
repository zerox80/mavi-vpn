use crate::{icmp::generate_packet_too_big, ipc, ControlMessage};
use etherparse::PacketBuilder;
use serde::{de::DeserializeOwned, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

pub(super) fn roundtrip<T>(value: &T) -> T
where
    T: Serialize + DeserializeOwned,
{
    let encoded = bincode::serde::encode_to_vec(value, bincode::config::standard())
        .expect("serialize test fixture");
    bincode::serde::decode_from_slice(&encoded, bincode::config::standard())
        .expect("deserialize test fixture")
        .0
}

pub(super) fn sample_control_ipv4_only_config() -> ControlMessage {
    ControlMessage::Config {
        assigned_ip: Ipv4Addr::new(10, 8, 0, 2),
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        gateway: Ipv4Addr::new(10, 8, 0, 1),
        dns_server: Ipv4Addr::new(1, 1, 1, 1),
        mtu: 1280,
        assigned_ipv6: None,
        netmask_v6: None,
        gateway_v6: None,
        dns_server_v6: None,
        whitelist_domains: Some(vec!["example.com".to_string()]),
    }
}

pub(super) fn sample_control_dual_stack_config() -> ControlMessage {
    ControlMessage::Config {
        assigned_ip: Ipv4Addr::new(10, 8, 0, 2),
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        gateway: Ipv4Addr::new(10, 8, 0, 1),
        dns_server: Ipv4Addr::new(1, 1, 1, 1),
        mtu: 1280,
        assigned_ipv6: Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
        netmask_v6: Some(64),
        gateway_v6: Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        dns_server_v6: Some(Ipv6Addr::LOCALHOST),
        whitelist_domains: Some(vec![
            "example.com".to_string(),
            "internal.example".to_string(),
        ]),
    }
}

pub(super) fn sample_ipc_config_full() -> ipc::Config {
    ipc::Config {
        endpoint: "vpn.example.com:4433".to_string(),
        token: "jwt-token".to_string(),
        cert_pin: "abcd1234".to_string(),
        censorship_resistant: true,
        kc_auth: Some(true),
        kc_url: Some("https://sso.example.com".to_string()),
        kc_realm: Some("mavi".to_string()),
        kc_client_id: Some("desktop-client".to_string()),
    }
}

pub(super) fn sample_ipc_config_minimal() -> ipc::Config {
    ipc::Config {
        endpoint: "vpn.example.com:4433".to_string(),
        token: "plain-token".to_string(),
        cert_pin: "deadbeef".to_string(),
        censorship_resistant: false,
        kc_auth: None,
        kc_url: None,
        kc_realm: None,
        kc_client_id: None,
    }
}

pub(super) fn ipv4_client() -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, 2)
}

pub(super) fn ipv4_server() -> Ipv4Addr {
    Ipv4Addr::new(1, 1, 1, 1)
}

pub(super) fn ipv6_client() -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)
}

pub(super) fn ipv6_server() -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
}

pub(super) fn build_ipv4_udp_packet(payload_len: usize) -> Vec<u8> {
    let payload = vec![0xAB; payload_len];
    let builder =
        PacketBuilder::ipv4(ipv4_client().octets(), ipv4_server().octets(), 32).udp(40000, 4433);
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder
        .write(&mut packet, &payload)
        .expect("write ipv4 test packet");
    packet
}

pub(super) fn build_ipv6_udp_packet(payload_len: usize) -> Vec<u8> {
    let payload = vec![0xCD; payload_len];
    let builder =
        PacketBuilder::ipv6(ipv6_client().octets(), ipv6_server().octets(), 32).udp(40000, 4433);
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder
        .write(&mut packet, &payload)
        .expect("write ipv6 test packet");
    packet
}
mod control_auth_clone_tests;
mod control_auth_empty_token_tests;
mod control_auth_roundtrip_tests;
mod control_config_clone_tests;
mod control_config_dual_stack_roundtrip_tests;
mod control_config_ipv4_roundtrip_tests;
mod control_error_clone_tests;
mod control_error_roundtrip_tests;
mod control_whitelist_none_tests;
mod control_whitelist_order_tests;
mod icmp_empty_packet_tests;
mod icmp_ipv4_default_source_tests;
mod icmp_ipv4_embeds_header_plus_eight_tests;
mod icmp_ipv4_generates_reply_tests;
mod icmp_ipv4_rejects_v6_override_tests;
mod icmp_ipv4_reply_targets_client_tests;
mod icmp_ipv4_reported_mtu_tests;
mod icmp_ipv4_type_code_tests;
mod icmp_ipv4_uses_override_source_tests;
mod icmp_ipv6_default_source_tests;
mod icmp_ipv6_embeds_truncated_original_packet_tests;
mod icmp_ipv6_generates_reply_tests;
mod icmp_ipv6_rejects_v4_override_tests;
mod icmp_ipv6_reply_targets_client_tests;
mod icmp_ipv6_reported_mtu_tests;
mod icmp_ipv6_truncation_limit_tests;
mod icmp_ipv6_type_code_tests;
mod icmp_ipv6_uses_override_source_tests;
mod icmp_short_ipv4_tests;
mod icmp_short_ipv6_tests;
mod icmp_unknown_version_tests;
mod ipc_config_full_roundtrip_tests;
mod ipc_config_minimal_roundtrip_tests;
mod ipc_local_addr_tests;
mod ipc_request_start_roundtrip_tests;
mod ipc_request_status_roundtrip_tests;
mod ipc_request_stop_roundtrip_tests;
mod ipc_response_error_roundtrip_tests;
mod ipc_response_ok_roundtrip_tests;
mod ipc_response_status_roundtrip_tests;
mod ipc_secure_request_roundtrip_tests;
mod ipc_token_path_tests;
