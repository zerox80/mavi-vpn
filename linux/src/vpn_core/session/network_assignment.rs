//! Extracts the network configuration `NetworkConfig::apply` needs out of the
//! server's handshake `ControlMessage::Config`, mirroring
//! `windows::vpn_core::ServerNetworkAssignment`.

use shared::ControlMessage;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Why extracting the assignment failed. Kept distinct from a plain
/// `anyhow::Error` so the caller can decide whether to record `last_error`
/// (a real server rejection) or not (a protocol-level surprise).
pub(super) enum SessionSetupError {
    /// The server sent `ControlMessage::Error`.
    Rejected(String),
    /// The server sent something other than `Config`/`Error` during the
    /// handshake (e.g. a stray `Reauth`).
    UnexpectedResponse,
}

pub(super) struct ServerNetworkAssignment {
    pub(super) assigned_ip: Ipv4Addr,
    pub(super) netmask: Ipv4Addr,
    pub(super) gateway: Ipv4Addr,
    pub(super) dns: Ipv4Addr,
    pub(super) mtu: u16,
    pub(super) assigned_ipv6: Option<Ipv6Addr>,
    pub(super) netmask_v6: Option<u8>,
    pub(super) gateway_v6: Option<Ipv6Addr>,
    pub(super) dns_v6: Option<Ipv6Addr>,
    pub(super) whitelist_domains: Vec<String>,
}

impl ServerNetworkAssignment {
    pub(super) fn from_control(message: ControlMessage) -> Result<Self, SessionSetupError> {
        match message {
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
            } => Ok(Self {
                assigned_ip,
                netmask,
                gateway,
                dns: dns_server,
                mtu,
                assigned_ipv6,
                netmask_v6,
                gateway_v6,
                dns_v6: dns_server_v6,
                whitelist_domains: whitelist_domains.unwrap_or_default(),
            }),
            ControlMessage::Error { message } => Err(SessionSetupError::Rejected(message)),
            ControlMessage::Auth { .. }
            | ControlMessage::Reauth { .. }
            | ControlMessage::ReauthResult { .. } => Err(SessionSetupError::UnexpectedResponse),
        }
    }
}
