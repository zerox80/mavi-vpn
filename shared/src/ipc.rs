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
#[must_use]
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
    /// Enable strict HTTP/3 Payload framing.
    #[serde(default)]
    pub http3_framing: bool,
    /// Was Keycloak authentication used?
    pub kc_auth: Option<bool>,
    /// Keycloak Server URL.
    pub kc_url: Option<String>,
    /// Keycloak Realm.
    pub kc_realm: Option<String>,
    /// Keycloak Client ID.
    pub kc_client_id: Option<String>,
    /// Hex-encoded `ECHConfigList` bytes. When present and the client's crypto
    /// provider supports HPKE (aws-lc-rs), the client offers ECH GREASE and
    /// spoofs the SNI to the config's `public_name`.
    #[serde(default)]
    pub ech_config: Option<String>,
    /// Inner TUN MTU override. Must match the server's `VPN_MTU` (1280–1360).
    /// `None` or absent → fall back to `VPN_MTU` env var, then `DEFAULT_TUN_MTU` (1280).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_mtu: Option<u16>,
}

impl Config {
    /// CR mode must look like HTTP/3 on the wire and therefore always uses
    /// CONNECT-IP/H3 framing internally as well.
    #[must_use]
    pub const fn effective_http3_framing(&self) -> bool {
        self.http3_framing || self.censorship_resistant
    }

    pub const fn normalize_transport(&mut self) -> bool {
        let old_http3_framing = self.http3_framing;
        self.http3_framing = self.effective_http3_framing();
        self.http3_framing != old_http3_framing
    }
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
    /// Remove stale `MaviVPN` routes and DNS/NRPT state without starting a tunnel.
    RepairNetwork,
}

/// More precise lifecycle state for clients that need to distinguish setup
/// from a fully usable tunnel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VpnState {
    Stopped,
    Starting,
    Connected,
    Failed,
    Stopping,
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
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
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
        /// Precise lifecycle state. `running` remains true only once the tunnel
        /// is fully connected for compatibility with older UI logic.
        state: VpnState,
        /// Last connection/setup error, if the service reached a failed state.
        last_error: Option<String>,
        /// The local IP address assigned to the VPN tunnel.
        assigned_ip: Option<String>,
    },
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_effective_http3_framing() {
        let mut config = Config {
            endpoint: "test".to_string(),
            token: "test".to_string(),
            cert_pin: "test".to_string(),
            censorship_resistant: false,
            http3_framing: false,
            kc_auth: None,
            kc_url: None,
            kc_realm: None,
            kc_client_id: None,
            ech_config: None,
            vpn_mtu: None,
        };

        // case: http3_framing=false, censorship_resistant=false => effective framing is false
        assert!(!config.effective_http3_framing());

        // case: http3_framing=true, censorship_resistant=false => effective framing is true
        config.http3_framing = true;
        assert!(config.effective_http3_framing());

        // case: http3_framing=false, censorship_resistant=true => effective framing is true
        config.http3_framing = false;
        config.censorship_resistant = true;
        assert!(config.effective_http3_framing());

        // case: http3_framing=true, censorship_resistant=true => effective framing is true
        config.http3_framing = true;
        assert!(config.effective_http3_framing());
    }

    #[test]
    fn test_normalize_transport() {
        let mut config = Config {
            endpoint: "test".to_string(),
            token: "test".to_string(),
            cert_pin: "test".to_string(),
            censorship_resistant: true,
            http3_framing: false,
            kc_auth: None,
            kc_url: None,
            kc_realm: None,
            kc_client_id: None,
            ech_config: None,
            vpn_mtu: None,
        };

        // normalize_transport() returns true only when it actually changes http3_framing
        // censorship_resistant=true requires http3_framing=true
        assert!(config.normalize_transport());
        assert!(config.http3_framing);

        // Second call should return false as no change is needed
        assert!(!config.normalize_transport());
        assert!(config.http3_framing);

        // Case where no change is needed from the start
        config.censorship_resistant = false;
        config.http3_framing = false;
        assert!(!config.normalize_transport());
        assert!(!config.http3_framing);
    }
}
