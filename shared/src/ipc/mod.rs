//! # IPC Protocol
//!
//! Defines the Inter-Process Communication protocol used between the VPN
//! background service/daemon and frontend clients (CLI, GUI).
//!
//! The wire format uses length-prefixed bincode:
//! `[u32 little-endian length][bincode payload]`
//!
//! Transport: a Unix domain socket on Linux (see [`ipc_socket_path`]) or a
//! Windows Named Pipe on Windows (see [`ipc_pipe_name`]) — client and service
//! always run on the same machine, so this is local IPC, not a network
//! protocol. An auth token (see [`ipc_token_path`]) is layered on top as
//! defense-in-depth.

use serde::{Deserialize, Serialize};
use std::fmt;

mod transport;
#[cfg(windows)]
pub use transport::ipc_pipe_name;
#[cfg(unix)]
pub use transport::ipc_socket_path;
pub use transport::ipc_token_path;

/// Prefix used in service status errors when Keycloak requires a fresh browser
/// login for the active session.
pub const KEYCLOAK_LOGIN_REQUIRED_PREFIX: &str = "KEYCLOAK_LOGIN_REQUIRED:";

/// Configuration required to establish a VPN session.
/// Passed from the client to the service via IPC.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Remote VPN server address (e.g., "vpn.example.com:4433").
    pub endpoint: String,
    /// Pre-shared authentication token or Keycloak JWT.
    pub token: String,
    /// SHA-256 fingerprint(s) (hex) of the server's TLS certificate. Normally
    /// a single 64-char value; during a manual server cert rotation this may
    /// be a comma-separated list ("<old_pin>,<new_pin>") — see
    /// `shared::hex::decode_hex_pins`.
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
    /// Keep this serialized even when absent: IPC uses positional bincode, so
    /// skipping a middle field shifts all following fields on the wire.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Hex-encoded `ECHConfigList` bytes. When present and the client's crypto
    /// provider supports HPKE (aws-lc-rs), the client offers ECH GREASE and
    /// spoofs the SNI to the config's `public_name`.
    #[serde(default)]
    pub ech_config: Option<String>,
    /// Inner TUN MTU override. Must match the server's `VPN_MTU` (1280–1360).
    /// `None` or absent → fall back to `VPN_MTU` env var, then `DEFAULT_TUN_MTU` (1280).
    /// Keep this serialized even when absent; see `refresh_token`.
    #[serde(default)]
    pub vpn_mtu: Option<u16>,
    /// Use TLS over TCP with HTTP/2 CONNECT-IP capsules (RFC 9297 / RFC 9484)
    /// instead of QUIC. This is reliable and ordered by design.
    ///
    /// Appended to preserve the positional order of the established IPC fields.
    #[serde(default)]
    pub http2_framing: bool,
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
            .field("http2_framing", &self.http2_framing)
            .finish()
    }
}

impl Config {
    /// CR mode must look like HTTP/3 on the wire and therefore always uses
    /// CONNECT-IP/H3 framing internally as well.
    #[must_use]
    pub const fn effective_http3_framing(&self) -> bool {
        !self.http2_framing && (self.http3_framing || self.censorship_resistant)
    }

    /// Whether this session uses reliable CONNECT-IP over HTTP/2/TCP.
    #[must_use]
    pub const fn uses_http2(&self) -> bool {
        self.http2_framing
    }

    pub const fn normalize_transport(&mut self) -> bool {
        if self.http2_framing {
            let changed = self.censorship_resistant || self.http3_framing;
            self.censorship_resistant = false;
            self.http3_framing = false;
            return changed;
        }
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
mod tests;
