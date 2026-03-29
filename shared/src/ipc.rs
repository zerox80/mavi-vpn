//! # IPC Protocol
//!
//! Defines the Inter-Process Communication protocol used between the VPN
//! background service/daemon and frontend clients (CLI, GUI).
//!
//! The wire format uses length-prefixed bincode:
//! `[u32 little-endian length][bincode payload]`
//!
//! Transport: TCP on `127.0.0.1:14433`.

use serde::{Deserialize, Serialize};
use crate::TransportMode;

/// Address for the local TCP IPC server.
pub const LOCAL_IPC_ADDR: &str = "127.0.0.1:14433";

/// Configuration required to establish a VPN session.
/// Passed from the client to the service via IPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Remote VPN server address (e.g., "vpn.example.com:4433").
    pub endpoint: String,
    /// Pre-shared authentication token or Keycloak JWT.
    pub token: String,
    /// SHA-256 fingerprint (hex) of the server's TLS certificate.
    pub cert_pin: String,
    /// Transport mode selection.
    ///
    /// - `Quic` (default): Raw QUIC, fastest, no obfuscation.
    /// - `Http3`: WebTransport over HTTP/3, anti-censorship.
    /// - `Http2`: HTTP/2 over TCP/TLS, for UDP-blocked networks.
    #[serde(default)]
    pub transport_mode: TransportMode,
    /// Was Keycloak authentication used?
    pub kc_auth: Option<bool>,
    /// Keycloak Server URL.
    pub kc_url: Option<String>,
    /// Keycloak Realm.
    pub kc_realm: Option<String>,
    /// Keycloak Client ID.
    pub kc_client_id: Option<String>,
}

/// Commands sent from the client UI to the background service.
#[derive(Debug, Serialize, Deserialize)]
pub enum IpcRequest {
    /// Start the VPN tunnel with the given configuration.
    Start(Config),
    /// Stop the active VPN tunnel.
    Stop,
    /// Query the current tunnel status.
    Status,
}

/// Responses sent from the background service back to the client UI.
#[derive(Debug, Serialize, Deserialize)]
pub enum IpcResponse {
    /// Command accepted and executed successfully.
    Ok,
    /// An error occurred during command execution.
    Error(String),
    /// Current status of the VPN service.
    Status {
        /// Whether the tunnel is currently active.
        running: bool,
        /// The endpoint currently connected to (if any).
        endpoint: Option<String>,
    },
}
