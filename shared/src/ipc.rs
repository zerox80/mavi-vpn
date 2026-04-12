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
    },
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn ipc_request_start_roundtrip() {
        let config = Config {
            endpoint: "vpn.example.com:4433".to_string(),
            token: "secret-token".to_string(),
            cert_pin: "abcdef1234567890".to_string(),
            censorship_resistant: true,
            http3_framing: false,
            kc_auth: Some(true),
            kc_url: Some("https://auth.example.com".to_string()),
            kc_realm: Some("mavi-vpn".to_string()),
            kc_client_id: Some("mavi-client".to_string()),
        };
        let req = IpcRequest::Start(config);
        let decoded = roundtrip_request(&req);
        match decoded {
            IpcRequest::Start(c) => {
                assert_eq!(c.endpoint, "vpn.example.com:4433");
                assert_eq!(c.token, "secret-token");
                assert!(c.censorship_resistant);
                assert!(!c.http3_framing);
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
        assert_eq!(roundtrip_response(&resp), IpcResponse::Error("something broke".to_string()));
    }

    #[test]
    fn ipc_response_status_roundtrip() {
        let resp = IpcResponse::Status {
            running: true,
            endpoint: Some("vpn.example.com:4433".to_string()),
        };
        let decoded = roundtrip_response(&resp);
        match decoded {
            IpcResponse::Status { running, endpoint } => {
                assert!(running);
                assert_eq!(endpoint.as_deref(), Some("vpn.example.com:4433"));
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
        };
        let decoded = roundtrip_response(&resp);
        match decoded {
            IpcResponse::Status { running, endpoint } => {
                assert!(!running);
                assert!(endpoint.is_none());
            }
            other => panic!("Expected Status, got {:?}", other),
        }
    }
}
