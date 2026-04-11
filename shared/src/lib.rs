use std::net::{Ipv4Addr, Ipv6Addr};
use serde::{Deserialize, Serialize};

pub mod icmp;
pub mod ipc;
pub mod masque;

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
