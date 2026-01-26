use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

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
    },
    /// Server rejects the connection.
    Error { message: String },
}
