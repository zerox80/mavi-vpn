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
use std::fmt;

/// Address for the local TCP IPC server.
pub const LOCAL_IPC_ADDR: &str = "127.0.0.1:14433";

/// Prefix used in service status errors when Keycloak requires a fresh browser
/// login for the active session.
pub const KEYCLOAK_LOGIN_REQUIRED_PREFIX: &str = "KEYCLOAK_LOGIN_REQUIRED:";

/// Path to the authentication token file used to secure the local TCP IPC socket.
#[cfg(windows)]
#[must_use]
pub fn ipc_token_path() -> std::path::PathBuf {
    std::path::PathBuf::from(r"C:\ProgramData\mavi-vpn\ipc.token")
}

#[cfg(unix)]
pub fn ipc_token_path() -> std::path::PathBuf {
    std::path::PathBuf::from("/run/mavi-vpn/ipc.token")
}

/// Configuration required to establish a VPN session.
/// Passed from the client to the service via IPC.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Long-lived Keycloak refresh token. Used by the client to renew the
    /// short-lived access token without an interactive browser login. Never
    /// leaves the local machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
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

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("endpoint", &self.endpoint)
            .field("token", &"<redacted>")
            .field("cert_pin", &self.cert_pin)
            .field("censorship_resistant", &self.censorship_resistant)
            .field("http3_framing", &self.http3_framing)
            .field("kc_auth", &self.kc_auth)
            .field("kc_url", &self.kc_url)
            .field("kc_realm", &self.kc_realm)
            .field("kc_client_id", &self.kc_client_id)
            .field("ech_config", &self.ech_config)
            .field("vpn_mtu", &self.vpn_mtu)
            .finish()
    }
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

/// Active Keycloak session data passed to the Windows service for in-service
/// refresh. This data is for RAM-only runtime use; clients must not persist or
/// log the refresh token through IPC diagnostics.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeycloakRuntimeAuth {
    /// GUI connection identifier used as the keyring account for rotated tokens.
    pub connection_id: String,
    /// Keycloak issuer/server URL.
    pub kc_url: String,
    /// Keycloak realm.
    pub realm: String,
    /// Keycloak client ID.
    pub client_id: String,
    /// Current refresh token for the active session only.
    pub refresh_token: String,
}

impl fmt::Debug for KeycloakRuntimeAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeycloakRuntimeAuth")
            .field("connection_id", &self.connection_id)
            .field("kc_url", &self.kc_url)
            .field("realm", &self.realm)
            .field("client_id", &self.client_id)
            .field("refresh_token", &"<redacted>")
            .finish()
    }
}

/// Commands sent from the client UI to the background service.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpcRequest {
    /// Start the VPN tunnel with the given configuration.
    Start(Config),
    /// Stop the active VPN tunnel.
    Stop,
    /// Query the current tunnel status.
    Status,
    /// Remove stale `MaviVPN` routes and DNS/NRPT state without starting a tunnel.
    RepairNetwork,
    /// Replace the access token used for the next (re)handshake. Used by clients
    /// that refresh Keycloak outside the service so the reconnect loop
    /// authenticates with a valid token instead of the stale one captured at
    /// `Start`. Windows service-side refresh uses `StartWithKeycloak` instead.
    UpdateToken { token: String },
    /// Start the VPN tunnel and let the Windows service refresh the active
    /// Keycloak session in RAM while the tunnel is running.
    StartWithKeycloak {
        config: Config,
        keycloak: KeycloakRuntimeAuth,
    },
    /// Atomically fetch and clear the latest rotated refresh token produced by
    /// the service-side Keycloak refresh task, if any.
    TakeRefreshTokenUpdate,
}

impl fmt::Debug for IpcRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start(config) => f.debug_tuple("Start").field(config).finish(),
            Self::Stop => f.write_str("Stop"),
            Self::Status => f.write_str("Status"),
            Self::RepairNetwork => f.write_str("RepairNetwork"),
            Self::UpdateToken { .. } => f
                .debug_struct("UpdateToken")
                .field("token", &"<redacted>")
                .finish(),
            Self::StartWithKeycloak { config, keycloak } => f
                .debug_struct("StartWithKeycloak")
                .field("config", config)
                .field("keycloak", keycloak)
                .finish(),
            Self::TakeRefreshTokenUpdate => f.write_str("TakeRefreshTokenUpdate"),
        }
    }
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
    /// The tunnel dropped and the service is actively retrying (transient error).
    /// Distinct from `Failed`, which is terminal: the UI keeps showing
    /// "connecting" instead of flipping to a hard error during auto-reconnect.
    Reconnecting,
}

/// A wrapper around `IpcRequest` that includes the authentication token.
/// This ensures only authorized local users can command the background service.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureIpcRequest {
    /// The secret token read from `ipc_token_path()`.
    pub auth_token: String,
    /// The actual command.
    pub request: IpcRequest,
}

impl fmt::Debug for SecureIpcRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureIpcRequest")
            .field("auth_token", &"<redacted>")
            .field("request", &self.request)
            .finish()
    }
}

/// Responses sent from the background service back to the client UI.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
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
    /// Rotated Keycloak refresh token for the GUI to persist in the user
    /// keyring. Empty when there is no pending update to fetch.
    RefreshTokenUpdate {
        connection_id: Option<String>,
        refresh_token: Option<String>,
    },
}

impl fmt::Debug for IpcResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => f.write_str("Ok"),
            Self::Error(error) => f.debug_tuple("Error").field(error).finish(),
            Self::Status {
                running,
                endpoint,
                state,
                last_error,
                assigned_ip,
            } => f
                .debug_struct("Status")
                .field("running", running)
                .field("endpoint", endpoint)
                .field("state", state)
                .field("last_error", last_error)
                .field("assigned_ip", assigned_ip)
                .finish(),
            Self::RefreshTokenUpdate {
                connection_id,
                refresh_token,
            } => {
                let redacted = refresh_token.as_ref().map(|_| "<redacted>");
                f.debug_struct("RefreshTokenUpdate")
                    .field("connection_id", connection_id)
                    .field("refresh_token", &redacted)
                    .finish()
            }
        }
    }
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
            refresh_token: None,
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
            refresh_token: None,
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

    #[test]
    fn test_ipc_request_roundtrip() {
        let configs = vec![
            IpcRequest::Start(Config {
                endpoint: "vpn.example.com:4433".to_string(),
                token: "secret".to_string(),
                cert_pin: "pinned".to_string(),
                censorship_resistant: true,
                http3_framing: false,
                kc_auth: Some(true),
                kc_url: Some("https://auth.com".to_string()),
                kc_realm: Some("master".to_string()),
                kc_client_id: Some("vpn-client".to_string()),
                refresh_token: Some("refresh-secret".to_string()),
                ech_config: None,
                vpn_mtu: Some(1300),
            }),
            IpcRequest::Stop,
            IpcRequest::Status,
            IpcRequest::RepairNetwork,
            IpcRequest::UpdateToken {
                token: "fresh-access-token".to_string(),
            },
            IpcRequest::StartWithKeycloak {
                config: Config {
                    endpoint: "vpn.example.com:4433".to_string(),
                    token: "secret".to_string(),
                    cert_pin: "pinned".to_string(),
                    censorship_resistant: true,
                    http3_framing: true,
                    kc_auth: Some(true),
                    kc_url: Some("https://auth.com".to_string()),
                    kc_realm: Some("master".to_string()),
                    kc_client_id: Some("vpn-client".to_string()),
                    refresh_token: Some("refresh-secret".to_string()),
                    ech_config: None,
                    vpn_mtu: Some(1300),
                },
                keycloak: KeycloakRuntimeAuth {
                    connection_id: "conn-1".to_string(),
                    kc_url: "https://auth.com".to_string(),
                    realm: "master".to_string(),
                    client_id: "vpn-client".to_string(),
                    refresh_token: "refresh-token".to_string(),
                },
            },
            IpcRequest::TakeRefreshTokenUpdate,
        ];

        for req in configs {
            let encoded = bincode::serde::encode_to_vec(&req, bincode::config::standard()).unwrap();
            let (decoded, _): (IpcRequest, usize) =
                bincode::serde::decode_from_slice(&encoded, bincode::config::standard()).unwrap();
            assert_eq!(req, decoded);
        }
    }

    #[test]
    fn test_ipc_response_roundtrip() {
        let responses = vec![
            IpcResponse::Ok,
            IpcResponse::Error("Failed to start".to_string()),
            IpcResponse::Status {
                running: true,
                endpoint: Some("1.2.3.4:443".to_string()),
                state: VpnState::Connected,
                last_error: None,
                assigned_ip: Some("10.8.0.2".to_string()),
            },
            IpcResponse::Status {
                running: false,
                endpoint: None,
                state: VpnState::Failed,
                last_error: Some("Auth failed".to_string()),
                assigned_ip: None,
            },
            IpcResponse::Status {
                running: false,
                endpoint: Some("1.2.3.4:443".to_string()),
                state: VpnState::Reconnecting,
                last_error: Some("H3 recv_response failed".to_string()),
                assigned_ip: None,
            },
            IpcResponse::RefreshTokenUpdate {
                connection_id: Some("conn-1".to_string()),
                refresh_token: Some("rotated-refresh-token".to_string()),
            },
            IpcResponse::RefreshTokenUpdate {
                connection_id: None,
                refresh_token: None,
            },
        ];

        for res in responses {
            let encoded = bincode::serde::encode_to_vec(&res, bincode::config::standard()).unwrap();
            let (decoded, _): (IpcResponse, usize) =
                bincode::serde::decode_from_slice(&encoded, bincode::config::standard()).unwrap();
            assert_eq!(res, decoded);
        }
    }

    #[test]
    fn test_secure_ipc_request_roundtrip() {
        let req = SecureIpcRequest {
            auth_token: "local-secret".to_string(),
            request: IpcRequest::Status,
        };

        let encoded = bincode::serde::encode_to_vec(&req, bincode::config::standard()).unwrap();
        let (decoded, _): (SecureIpcRequest, usize) =
            bincode::serde::decode_from_slice(&encoded, bincode::config::standard()).unwrap();

        assert_eq!(req, decoded);
    }

    #[cfg(unix)]
    #[test]
    fn unix_ipc_token_lives_under_runtime_directory() {
        assert_eq!(
            ipc_token_path(),
            std::path::PathBuf::from("/run/mavi-vpn/ipc.token")
        );
    }
}
