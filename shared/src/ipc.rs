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

/// Address for the local TCP IPC server.
pub const LOCAL_IPC_ADDR: &str = "127.0.0.1:14433";

/// Path to the authentication token file used to secure the local TCP IPC socket.
#[cfg(windows)]
pub fn ipc_token_path() -> std::path::PathBuf {
    std::path::PathBuf::from(r"C:\ProgramData\mavi-vpn\ipc.token")
}

#[cfg(unix)]
pub fn ipc_token_path() -> std::path::PathBuf {
    std::path::PathBuf::from("/var/run/mavi-vpn.token")
}

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
    /// Enable Layer 7 obfuscation (pretend to be HTTP/3).
    pub censorship_resistant: bool,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcRequest {
    /// Start the VPN tunnel with the given configuration.
    Start(Config),
    /// Stop the active VPN tunnel.
    Stop,
    /// Query the current tunnel status.
    Status,
}

/// A wrapper around `IpcRequest` that includes the authentication token.
/// This ensures only authorized local users can command the background service.
#[derive(Debug, Serialize, Deserialize)]
pub struct SecureIpcRequest {
    /// The secret token read from `ipc_token_path()`.
    pub auth_token: String,
    /// The actual command.
    pub request: IpcRequest,
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
