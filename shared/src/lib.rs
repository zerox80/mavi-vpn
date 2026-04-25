use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

pub mod hex;
pub mod icmp;
pub mod ipc;
pub mod masque;

#[cfg(test)]
pub mod test_helpers;

/// Fixed overhead budget (in bytes) reserved on top of the inner TUN MTU to
/// cover QUIC short-header framing + AEAD tag + connection-ID bytes. The outer
/// QUIC payload MTU is derived as `tun_mtu + QUIC_OVERHEAD_BYTES`, so the inner
/// MTU remains the single knob operators turn. Server and client must agree on
/// `tun_mtu`, otherwise the larger side will send packets the smaller side
/// considers out-of-spec.
pub const QUIC_OVERHEAD_BYTES: u16 = 80;

/// Default inner TUN MTU when the operator has not overridden `VPN_MTU`.
/// 1280 is the IPv6 minimum (RFC 8200) and is safe on every residential path
/// we have measured. It yields a QUIC payload MTU of 1360, matching the
/// pre-knob pinning.
pub const DEFAULT_TUN_MTU: u16 = 1280;

/// Minimum allowed inner TUN MTU (inclusive).
pub const MIN_TUN_MTU: u16 = 1280;

/// Maximum allowed inner TUN MTU (inclusive).
pub const MAX_TUN_MTU: u16 = 1360;

/// Resolve the inner TUN MTU from an explicit config value, the `VPN_MTU`
/// environment variable, or the compiled-in default (1280). The explicit
/// `vpn_mtu` parameter takes highest priority; it must be within the
/// 1280–1360 range. Invalid or out-of-range values are silently ignored and
/// fall through to the next source.
///
/// QUIC Payload MTU is always derived as `tun_mtu + QUIC_OVERHEAD_BYTES`
/// (i.e. +80) and must never be set independently.
pub fn resolve_tun_mtu(vpn_mtu: Option<u16>) -> u16 {
    // 1. Explicit config field (highest priority)
    if let Some(v) = vpn_mtu {
        if (MIN_TUN_MTU..=MAX_TUN_MTU).contains(&v) {
            return v;
        }
        // Fall through to env / default on out-of-range values
    }

    // 2. Environment variable (CLI / daemon use)
    if let Ok(s) = std::env::var("VPN_MTU") {
        if let Ok(v) = s.trim().parse::<u16>() {
            if (MIN_TUN_MTU..=MAX_TUN_MTU).contains(&v) {
                return v;
            }
        }
    }

    // 3. Compiled-in default
    DEFAULT_TUN_MTU
}

/// Control-plane messages exchanged over the QUIC bidirectional stream during
/// connection setup (the "handshake phase").
///
/// Wire format: each message is length-prefixed with a little-endian `u32`
/// followed by the `bincode`-serialised payload.
///
/// # Flow
/// 1. Client opens a bidirectional QUIC stream.
/// 2. Client sends `Auth { token }`.
/// 3. Server responds with either `Config { … }` (success) or `Error { … }` (failure).
/// 4. The stream is then closed; all subsequent data is exchanged via datagrams.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ControlMessage {
    /// Sent by the client to authenticate against the server's pre-shared token.
    Auth { token: String },

    /// Sent by the server upon successful authentication.
    /// Contains all network configuration the client needs to bring up the tunnel.
    Config {
        /// IPv4 address assigned to the client's virtual network interface.
        assigned_ip: Ipv4Addr,
        /// IPv4 subnet mask of the VPN network (e.g. `255.255.255.0` for /24).
        netmask: Ipv4Addr,
        /// IPv4 address of the VPN gateway (server-side TUN interface), used
        /// as the next-hop for the default route.
        gateway: Ipv4Addr,
        /// IPv4 DNS server the client should use while connected.
        dns_server: Ipv4Addr,
        /// Maximum Transmission Unit for the virtual network interface in bytes.
        /// Clients should set their TUN/TAP adapter MTU to this value.
        mtu: u16,

        // --- Optional IPv6 configuration ---
        /// IPv6 address assigned to the client (dual-stack support). `None` if
        /// the server does not offer IPv6.
        assigned_ipv6: Option<Ipv6Addr>,
        /// IPv6 prefix length (e.g. `64` for a /64 network). IPv6 uses CIDR
        /// prefix lengths rather than dot-decimal netmasks.
        netmask_v6: Option<u8>,
        /// IPv6 gateway address (server-side TUN interface) for the default IPv6 route.
        gateway_v6: Option<Ipv6Addr>,
        /// IPv6 DNS server the client should use while connected.
        dns_server_v6: Option<Ipv6Addr>,
        /// Optional list of domain names that should bypass the VPN tunnel
        /// (split-tunnelling allow-list). An empty list means route all DNS through VPN.
        whitelist_domains: Option<Vec<String>>,
    },

    /// Sent by the server when it rejects the connection (e.g. bad token, no IPs available).
    /// The client should log `message` and may retry after a backoff.
    Error { message: String },
}

#[cfg(test)]
mod tests {
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
            other => panic!("Expected Auth, got {:?}", other),
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
            other => panic!("Expected Config, got {:?}", other),
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
            other => panic!("Expected Config, got {:?}", other),
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
            other => panic!("Expected Error, got {:?}", other),
        }
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
            token: "".to_string(),
        };
        let decoded = roundtrip(&msg);
        match decoded {
            ControlMessage::Auth { token } => assert!(token.is_empty()),
            other => panic!("Expected Auth, got {:?}", other),
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
            other => panic!("Expected Config, got {:?}", other),
        }
    }

    #[test]
    fn test_error_empty_message() {
        let msg = ControlMessage::Error {
            message: "".to_string(),
        };
        let decoded = roundtrip(&msg);
        match decoded {
            ControlMessage::Error { message } => assert!(message.is_empty()),
            other => panic!("Expected Error, got {:?}", other),
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

        // Explicit out-of-range + no env → default (falls through)
        assert_eq!(resolve_tun_mtu(Some(500)), DEFAULT_TUN_MTU);
        assert_eq!(resolve_tun_mtu(Some(2000)), DEFAULT_TUN_MTU);
        assert_eq!(resolve_tun_mtu(Some(0)), DEFAULT_TUN_MTU);

        // Env var fallback
        std::env::set_var("VPN_MTU", "1300");
        assert_eq!(resolve_tun_mtu(None), 1300);

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
}
