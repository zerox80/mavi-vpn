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
    pub fn effective_http3_framing(&self) -> bool {
        self.http3_framing || self.censorship_resistant
    }

    pub fn normalize_transport(&mut self) -> bool {
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
#[derive(Debug, Serialize, Deserialize, PartialEq)]
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
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(censorship_resistant: bool, http3_framing: bool) -> Config {
        Config {
            endpoint: "vpn.example.com:4433".to_string(),
            token: "tok".to_string(),
            cert_pin: "deadbeef".to_string(),
            censorship_resistant,
            http3_framing,
            kc_auth: None,
            kc_url: None,
            kc_realm: None,
            kc_client_id: None,
            ech_config: None,
            vpn_mtu: None,
        }
    }

    fn roundtrip_request(req: &IpcRequest) -> IpcRequest {
        let encoded = bincode::serde::encode_to_vec(req, bincode::config::standard()).unwrap();
        let (decoded, _): (IpcRequest, _) =
            bincode::serde::decode_from_slice(&encoded, bincode::config::standard()).unwrap();
        decoded
    }

    fn roundtrip_response(resp: &IpcResponse) -> IpcResponse {
        let encoded = bincode::serde::encode_to_vec(resp, bincode::config::standard()).unwrap();
        let (decoded, _): (IpcResponse, _) =
            bincode::serde::decode_from_slice(&encoded, bincode::config::standard()).unwrap();
        decoded
    }

    #[test]
    fn effective_http3_framing_matches_transport_invariant() {
        assert!(!test_config(false, false).effective_http3_framing());
        assert!(test_config(false, true).effective_http3_framing());
        assert!(test_config(true, false).effective_http3_framing());
        assert!(test_config(true, true).effective_http3_framing());
    }

    #[test]
    fn normalize_transport_forces_cr_to_h3() {
        let mut config = test_config(true, false);
        assert!(config.normalize_transport());
        assert!(config.http3_framing);

        let mut raw_config = test_config(false, false);
        assert!(!raw_config.normalize_transport());
        assert!(!raw_config.http3_framing);
    }

    #[test]
    fn ipc_request_start_roundtrip() {
        let config = Config {
            endpoint: "vpn.example.com:4433".to_string(),
            token: "secret-token".to_string(),
            cert_pin: "abcdef1234567890".to_string(),
            censorship_resistant: true,
            http3_framing: true,
            kc_auth: Some(true),
            kc_url: Some("https://auth.example.com".to_string()),
            kc_realm: Some("mavi-vpn".to_string()),
            kc_client_id: Some("mavi-client".to_string()),
            ech_config: None,
            vpn_mtu: None,
        };
        let req = IpcRequest::Start(config);
        let decoded = roundtrip_request(&req);
        match decoded {
            IpcRequest::Start(c) => {
                assert_eq!(c.endpoint, "vpn.example.com:4433");
                assert_eq!(c.token, "secret-token");
                assert!(c.censorship_resistant);
                assert!(c.http3_framing);
                assert_eq!(c.kc_auth, Some(true));
            }
            other => panic!("Expected Start, got {:?}", other),
        }
    }

    #[test]
    fn ipc_request_stop_roundtrip() {
        let decoded = roundtrip_request(&IpcRequest::Stop);
        assert!(matches!(decoded, IpcRequest::Stop));
    }

    #[test]
    fn ipc_request_status_roundtrip() {
        let decoded = roundtrip_request(&IpcRequest::Status);
        assert!(matches!(decoded, IpcRequest::Status));
    }

    #[test]
    fn ipc_response_ok_roundtrip() {
        assert_eq!(roundtrip_response(&IpcResponse::Ok), IpcResponse::Ok);
    }

    #[test]
    fn ipc_response_error_roundtrip() {
        let resp = IpcResponse::Error("something broke".to_string());
        assert_eq!(
            roundtrip_response(&resp),
            IpcResponse::Error("something broke".to_string())
        );
    }

    #[test]
    fn ipc_response_status_roundtrip() {
        let resp = IpcResponse::Status {
            running: true,
            endpoint: Some("vpn.example.com:4433".to_string()),
            state: VpnState::Connected,
            last_error: None,
        };
        let decoded = roundtrip_response(&resp);
        match decoded {
            IpcResponse::Status {
                running,
                endpoint,
                state,
                last_error,
            } => {
                assert!(running);
                assert_eq!(endpoint.as_deref(), Some("vpn.example.com:4433"));
                assert_eq!(state, VpnState::Connected);
                assert!(last_error.is_none());
            }
            other => panic!("Expected Status, got {:?}", other),
        }
    }

    #[test]
    fn secure_ipc_request_roundtrip() {
        let secure = SecureIpcRequest {
            auth_token: "ipc-auth-token".to_string(),
            request: IpcRequest::Stop,
        };
        let encoded = bincode::serde::encode_to_vec(&secure, bincode::config::standard()).unwrap();
        let (decoded, _): (SecureIpcRequest, _) =
            bincode::serde::decode_from_slice(&encoded, bincode::config::standard()).unwrap();
        assert_eq!(decoded.auth_token, "ipc-auth-token");
        assert!(matches!(decoded.request, IpcRequest::Stop));
    }

    #[test]
    fn ipc_token_path_is_absolute() {
        assert!(ipc_token_path().is_absolute());
    }

    #[test]
    fn ipc_request_start_roundtrip_with_ech_config() {
        // Ensure that a non-None ech_config survives a bincode round-trip.
        let config = Config {
            endpoint: "vpn.example.com:4433".to_string(),
            token: "tok".to_string(),
            cert_pin: "deadbeef".to_string(),
            censorship_resistant: true,
            http3_framing: true,
            kc_auth: None,
            kc_url: None,
            kc_realm: None,
            kc_client_id: None,
            ech_config: Some("deadbeef01020304".to_string()),
            vpn_mtu: None,
        };
        let req = IpcRequest::Start(config);
        let decoded = roundtrip_request(&req);
        match decoded {
            IpcRequest::Start(c) => {
                assert_eq!(c.ech_config.as_deref(), Some("deadbeef01020304"));
            }
            other => panic!("Expected Start, got {:?}", other),
        }
    }

    #[test]
    fn ipc_request_start_roundtrip_minimal() {
        // All optional Keycloak fields are None – the minimal valid Config.
        let config = Config {
            endpoint: "vpn.example.com:4433".to_string(),
            token: "tok".to_string(),
            cert_pin: "deadbeef".to_string(),
            censorship_resistant: false,
            http3_framing: false,
            kc_auth: None,
            kc_url: None,
            kc_realm: None,
            kc_client_id: None,
            ech_config: None,
            vpn_mtu: None,
        };
        let req = IpcRequest::Start(config);
        let decoded = roundtrip_request(&req);
        match decoded {
            IpcRequest::Start(c) => {
                assert_eq!(c.endpoint, "vpn.example.com:4433");
                assert!(c.kc_auth.is_none());
                assert!(c.kc_url.is_none());
                assert!(c.kc_realm.is_none());
                assert!(c.kc_client_id.is_none());
            }
            other => panic!("Expected Start, got {:?}", other),
        }
    }

    #[test]
    fn ipc_response_status_not_running() {
        let resp = IpcResponse::Status {
            running: false,
            endpoint: None,
            state: VpnState::Stopped,
            last_error: None,
        };
        let decoded = roundtrip_response(&resp);
        match decoded {
            IpcResponse::Status {
                running,
                endpoint,
                state,
                last_error,
            } => {
                assert!(!running);
                assert!(endpoint.is_none());
                assert_eq!(state, VpnState::Stopped);
                assert!(last_error.is_none());
            }
            other => panic!("Expected Status, got {:?}", other),
        }
    }

    #[test]
    fn ipc_response_status_stopping_roundtrip() {
        let resp = IpcResponse::Status {
            running: false,
            endpoint: Some("vpn.example.com:4433".to_string()),
            state: VpnState::Stopping,
            last_error: None,
        };
        let decoded = roundtrip_response(&resp);
        match decoded {
            IpcResponse::Status {
                running,
                endpoint,
                state,
                last_error,
            } => {
                assert!(!running);
                assert_eq!(endpoint.as_deref(), Some("vpn.example.com:4433"));
                assert_eq!(state, VpnState::Stopping);
                assert!(last_error.is_none());
            }
            other => panic!("Expected Status, got {:?}", other),
        }
    }

    #[test]
    fn ipc_response_status_failed_roundtrip() {
        let resp = IpcResponse::Status {
            running: false,
            endpoint: Some("vpn.example.com:4433".to_string()),
            state: VpnState::Failed,
            last_error: Some("MTU mismatch".to_string()),
        };
        let decoded = roundtrip_response(&resp);
        match decoded {
            IpcResponse::Status {
                running,
                endpoint,
                state,
                last_error,
            } => {
                assert!(!running);
                assert_eq!(endpoint.as_deref(), Some("vpn.example.com:4433"));
                assert_eq!(state, VpnState::Failed);
                assert_eq!(last_error.as_deref(), Some("MTU mismatch"));
            }
            other => panic!("Expected Status, got {:?}", other),
        }
    }

    #[test]
    fn secure_ipc_request_with_start_config() {
        let config = Config {
            endpoint: "vpn.example.com:4433".to_string(),
            token: "secret".to_string(),
            cert_pin: "abcdef".to_string(),
            censorship_resistant: true,
            http3_framing: true,
            kc_auth: Some(true),
            kc_url: Some("https://auth.example.com".to_string()),
            kc_realm: Some("my-realm".to_string()),
            kc_client_id: Some("my-client".to_string()),
            ech_config: Some("deadbeef".to_string()),
            vpn_mtu: None,
        };
        let secure = SecureIpcRequest {
            auth_token: "ipc-token".to_string(),
            request: IpcRequest::Start(config),
        };
        let encoded = bincode::serde::encode_to_vec(&secure, bincode::config::standard()).unwrap();
        let (decoded, _): (SecureIpcRequest, _) =
            bincode::serde::decode_from_slice(&encoded, bincode::config::standard()).unwrap();
        assert_eq!(decoded.auth_token, "ipc-token");
        match decoded.request {
            IpcRequest::Start(c) => {
                assert_eq!(c.endpoint, "vpn.example.com:4433");
                assert!(c.censorship_resistant);
                assert!(c.http3_framing);
                assert_eq!(c.kc_auth, Some(true));
                assert_eq!(c.ech_config.as_deref(), Some("deadbeef"));
            }
            other => panic!("Expected Start, got {:?}", other),
        }
    }

    #[test]
    fn ipc_request_start_all_keycloak_fields() {
        let config = Config {
            endpoint: "vpn.test.com:4433".to_string(),
            token: "tok".to_string(),
            cert_pin: "pin".to_string(),
            censorship_resistant: false,
            http3_framing: true,
            kc_auth: Some(true),
            kc_url: Some("https://kc.test.com".to_string()),
            kc_realm: Some("test-realm".to_string()),
            kc_client_id: Some("test-client".to_string()),
            ech_config: None,
            vpn_mtu: None,
        };
        let req = IpcRequest::Start(config);
        let decoded = roundtrip_request(&req);
        match decoded {
            IpcRequest::Start(c) => {
                assert!(c.http3_framing);
                assert_eq!(c.kc_url.as_deref(), Some("https://kc.test.com"));
                assert_eq!(c.kc_realm.as_deref(), Some("test-realm"));
                assert_eq!(c.kc_client_id.as_deref(), Some("test-client"));
            }
            other => panic!("Expected Start, got {:?}", other),
        }
    }

    #[test]
    fn ipc_response_error_empty_string() {
        let resp = IpcResponse::Error("".to_string());
        assert_eq!(
            roundtrip_response(&resp),
            IpcResponse::Error("".to_string())
        );
    }
}
