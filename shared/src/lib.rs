use std::net::{Ipv4Addr, Ipv6Addr};
use serde::{Deserialize, Serialize};

pub mod hex;
pub mod icmp;
pub mod ipc;
pub mod masque;

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
                assert_eq!(assigned_ipv6, Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)));
                assert_eq!(netmask_v6, Some(64));
                assert_eq!(gateway_v6, Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)));
                assert_eq!(dns_server_v6, Some(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)));
                assert_eq!(whitelist_domains, Some(vec!["example.com".to_string(), "test.org".to_string()]));
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
        let result: Result<(ControlMessage, usize), _> = bincode::serde::decode_from_slice(&garbage, bincode::config::standard());
        assert!(result.is_err(), "Decoding garbage data should fail");

        // Try decoding an incomplete message
        let msg = ControlMessage::Auth { token: "123".to_string() };
        let encoded = bincode::serde::encode_to_vec(&msg, bincode::config::standard()).unwrap();
        let incomplete = &encoded[..encoded.len() - 1]; // strip last byte
        let result_incomplete: Result<(ControlMessage, usize), _> = bincode::serde::decode_from_slice(incomplete, bincode::config::standard());
        assert!(result_incomplete.is_err(), "Decoding incomplete data should fail");
    }
}
