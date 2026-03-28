//! # Config Code (`mavi://`) encoding and decoding
//!
//! Provides a compact, shareable config code format for importing VPN
//! connection settings across clients. The format is:
//!
//! ```text
//! mavi://BASE64URL_ENCODED_JSON
//! ```
//!
//! The JSON payload uses short keys to minimise the encoded length.
//! The `token` field is intentionally excluded for security — users
//! enter it separately or authenticate via Keycloak OAuth.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::ipc::Config;

const PREFIX: &str = "mavi://";

/// Compact JSON representation used inside `mavi://` URLs.
/// Field names are shortened to keep the base64 payload small.
#[derive(Debug, Serialize, Deserialize)]
struct ConfigCodeV1 {
    /// Version tag (always 1).
    v: u8,
    /// Server endpoint with port (e.g. "vpn.example.com:4433").
    endpoint: String,
    /// SHA-256 certificate fingerprint (hex).
    cert_pin: String,
    /// Censorship resistant mode.
    cr: bool,
    /// Prefer HTTP/2 TCP fallback.
    tcp: bool,
    /// Keycloak authentication enabled.
    kc: bool,
    /// Keycloak server URL (only when `kc` is true).
    #[serde(skip_serializing_if = "Option::is_none")]
    kc_url: Option<String>,
    /// Keycloak realm (only when `kc` is true).
    #[serde(skip_serializing_if = "Option::is_none")]
    kc_realm: Option<String>,
    /// Keycloak client ID (only when `kc` is true).
    #[serde(skip_serializing_if = "Option::is_none")]
    kc_client_id: Option<String>,
}

/// Errors that can occur when decoding a `mavi://` config code.
#[derive(Debug)]
pub enum ConfigCodeError {
    /// Input does not start with `mavi://`.
    InvalidPrefix,
    /// Base64 decoding failed.
    Base64Error(base64::DecodeError),
    /// JSON deserialization failed.
    JsonError(serde_json::Error),
    /// Unsupported config code version.
    UnsupportedVersion(u8),
}

impl fmt::Display for ConfigCodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefix => write!(f, "Invalid config code: must start with mavi://"),
            Self::Base64Error(e) => write!(f, "Invalid config code (base64): {}", e),
            Self::JsonError(e) => write!(f, "Invalid config code (json): {}", e),
            Self::UnsupportedVersion(v) => {
                write!(f, "Unsupported config code version: {}", v)
            }
        }
    }
}

impl std::error::Error for ConfigCodeError {}

/// Encode a [`Config`] into a `mavi://` config code string.
///
/// The token is stripped — the resulting code is safe to share.
pub fn encode_config_code(config: &Config) -> String {
    let kc = config.kc_auth.unwrap_or(false);
    let v1 = ConfigCodeV1 {
        v: 1,
        endpoint: config.endpoint.clone(),
        cert_pin: config.cert_pin.clone(),
        cr: config.censorship_resistant,
        tcp: config.prefer_tcp,
        kc,
        kc_url: if kc { config.kc_url.clone() } else { None },
        kc_realm: if kc { config.kc_realm.clone() } else { None },
        kc_client_id: if kc {
            config.kc_client_id.clone()
        } else {
            None
        },
    };
    let json = serde_json::to_string(&v1).expect("ConfigCodeV1 is always serializable");
    let encoded = URL_SAFE_NO_PAD.encode(json.as_bytes());
    format!("{}{}", PREFIX, encoded)
}

/// Decode a `mavi://` config code string into a [`Config`].
///
/// The returned config has an empty `token` — the user must provide
/// it separately (or use Keycloak OAuth).
pub fn decode_config_code(code: &str) -> Result<Config, ConfigCodeError> {
    let b64 = code
        .strip_prefix(PREFIX)
        .ok_or(ConfigCodeError::InvalidPrefix)?;

    let bytes = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(ConfigCodeError::Base64Error)?;

    let v1: ConfigCodeV1 =
        serde_json::from_slice(&bytes).map_err(ConfigCodeError::JsonError)?;

    if v1.v != 1 {
        return Err(ConfigCodeError::UnsupportedVersion(v1.v));
    }

    Ok(Config {
        endpoint: v1.endpoint,
        token: String::new(),
        cert_pin: v1.cert_pin,
        censorship_resistant: v1.cr,
        prefer_tcp: v1.tcp,
        kc_auth: if v1.kc { Some(true) } else { Some(false) },
        kc_url: v1.kc_url,
        kc_realm: v1.kc_realm,
        kc_client_id: v1.kc_client_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_simple() {
        let config = Config {
            endpoint: "vpn.example.com:4433".into(),
            token: "secret_token".into(),
            cert_pin: "abcdef1234567890".into(),
            censorship_resistant: false,
            prefer_tcp: false,
            kc_auth: Some(false),
            kc_url: None,
            kc_realm: None,
            kc_client_id: None,
        };

        let code = encode_config_code(&config);
        assert!(code.starts_with("mavi://"));

        let decoded = decode_config_code(&code).unwrap();
        assert_eq!(decoded.endpoint, config.endpoint);
        assert_eq!(decoded.cert_pin, config.cert_pin);
        assert_eq!(decoded.censorship_resistant, config.censorship_resistant);
        assert_eq!(decoded.prefer_tcp, config.prefer_tcp);
        assert_eq!(decoded.kc_auth, Some(false));
        // Token must be empty after decode
        assert!(decoded.token.is_empty());
    }

    #[test]
    fn round_trip_keycloak() {
        let config = Config {
            endpoint: "vpn.mycompany.de:4433".into(),
            token: "jwt_would_be_here".into(),
            cert_pin: "ff00ff00".into(),
            censorship_resistant: true,
            prefer_tcp: true,
            kc_auth: Some(true),
            kc_url: Some("https://auth.mycompany.de".into()),
            kc_realm: Some("mavi-vpn".into()),
            kc_client_id: Some("mavi-client".into()),
        };

        let code = encode_config_code(&config);
        let decoded = decode_config_code(&code).unwrap();

        assert_eq!(decoded.endpoint, config.endpoint);
        assert_eq!(decoded.cert_pin, config.cert_pin);
        assert!(decoded.censorship_resistant);
        assert!(decoded.prefer_tcp);
        assert_eq!(decoded.kc_auth, Some(true));
        assert_eq!(decoded.kc_url.as_deref(), Some("https://auth.mycompany.de"));
        assert_eq!(decoded.kc_realm.as_deref(), Some("mavi-vpn"));
        assert_eq!(decoded.kc_client_id.as_deref(), Some("mavi-client"));
        assert!(decoded.token.is_empty());
    }

    #[test]
    fn invalid_prefix() {
        let err = decode_config_code("https://example.com").unwrap_err();
        assert!(matches!(err, ConfigCodeError::InvalidPrefix));
    }

    #[test]
    fn invalid_base64() {
        let err = decode_config_code("mavi://!!!not-base64!!!").unwrap_err();
        assert!(matches!(err, ConfigCodeError::Base64Error(_)));
    }

    #[test]
    fn unsupported_version() {
        let json = r#"{"v":99,"endpoint":"x","cert_pin":"x","cr":false,"tcp":false,"kc":false}"#;
        let encoded = URL_SAFE_NO_PAD.encode(json.as_bytes());
        let code = format!("mavi://{}", encoded);
        let err = decode_config_code(&code).unwrap_err();
        assert!(matches!(err, ConfigCodeError::UnsupportedVersion(99)));
    }
}
