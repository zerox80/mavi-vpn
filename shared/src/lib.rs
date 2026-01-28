use std::net::{Ipv4Addr, Ipv6Addr};
use serde::{Deserialize, Serialize};

/// The control messages exchanged during the handshake.
#[derive(Debug, Serialize, Deserialize)]
pub enum ControlMessage {
    /// Client sends this to authenticate.
    Auth { token: String },
    /// Server responds with the assigned IP configuration.
    Config {
        assigned_ip: Ipv4Addr,
        netmask: Ipv4Addr,
        gateway: Ipv4Addr,
        dns_server: Ipv4Addr,
        mtu: u16,
        assigned_ipv6: Option<Ipv6Addr>,
        netmask_v6: Option<u8>, // CIDR prefix length is standard for v6
        gateway_v6: Option<Ipv6Addr>,
        gateway_v6: Option<Ipv6Addr>,
        dns_server_v6: Option<Ipv6Addr>,
        whitelist_domains: Option<Vec<String>>,
    },
    /// Server rejects the connection.
    Error { message: String },
}
