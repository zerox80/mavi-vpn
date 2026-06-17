use anyhow::Result;
use constant_time_eq::constant_time_eq;
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;

use crate::config::Config;
use crate::keycloak::{KeycloakValidator, ValidatedToken};
use crate::state::AppState;

pub type TokenValidationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<ValidatedToken>>> + Send + 'a>>;

pub trait TokenValidator: Send + Sync {
    /// Resolves to `Ok(Some(ValidatedToken))` (carrying the token's expiry and
    /// subject) when the token is accepted, `Ok(None)` when it is rejected.
    fn validate_token<'a>(&'a self, token: &'a str) -> TokenValidationFuture<'a>;
}

impl TokenValidator for KeycloakValidator {
    fn validate_token<'a>(&'a self, token: &'a str) -> TokenValidationFuture<'a> {
        Box::pin(async move { KeycloakValidator::validate_token(self, token).await })
    }
}

/// Coerces the optional shared `KeycloakValidator` into the `TokenValidator`
/// trait object expected by [`authenticate_client`]. When `None`, the caller
/// falls back to static-token auth.
pub(crate) fn as_token_validator(
    keycloak: Option<&Arc<KeycloakValidator>>,
) -> Option<&dyn TokenValidator> {
    keycloak.map(|kc| kc.as_ref() as &dyn TokenValidator)
}

/// On success returns the assigned IP pair and, for Keycloak auth, the validated
/// token (its expiry and subject). Static-token sessions carry no expiry and no
/// subject (`None`).
pub async fn authenticate_client(
    token: &str,
    state: &Arc<AppState>,
    config: &Config,
    keycloak: Option<&dyn TokenValidator>,
) -> Result<(Ipv4Addr, Ipv6Addr, Option<ValidatedToken>)> {
    let session_auth = if let Some(kc) = keycloak {
        let Some(validated) = kc.validate_token(token).await? else {
            anyhow::bail!("Access Denied: Invalid Keycloak Token");
        };
        Some(validated)
    } else {
        let Some(auth_token) = config.auth_token.as_deref().filter(|t| !t.is_empty()) else {
            anyhow::bail!("Static auth is enabled but VPN_AUTH_TOKEN is not configured");
        };
        if !constant_time_eq(token.as_bytes(), auth_token.as_bytes()) {
            anyhow::bail!("Access Denied: Invalid Token");
        }
        None
    };

    let (ip4, ip6) = state.assign_ip_pair()?;
    Ok((ip4, ip6, session_auth))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn test_config() -> Config {
        Config::parse_from(["mavi-vpn", "--auth-token", "correct-token"])
    }

    #[tokio::test]
    async fn valid_token_authenticates() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let result = authenticate_client("correct-token", &state, &config, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn invalid_token_rejects() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let result = authenticate_client("wrong-token", &state, &config, None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid Token"));
    }

    #[tokio::test]
    async fn empty_token_rejects() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let result = authenticate_client("", &state, &config, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn valid_token_returns_ip_pair() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let (ip4, ip6, session_auth) = authenticate_client("correct-token", &state, &config, None)
            .await
            .unwrap();
        assert_eq!(ip4, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(ip6, Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2));
        assert!(session_auth.is_none());
    }

    #[tokio::test]
    async fn pool_exhaustion_returns_error() {
        let state = Arc::new(AppState::new("10.0.0.0/30").unwrap());
        let config = test_config();
        let _ = authenticate_client("correct-token", &state, &config, None)
            .await
            .unwrap();
        let result = authenticate_client("correct-token", &state, &config, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn case_sensitive_token() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let result = authenticate_client("CORRECT-TOKEN", &state, &config, None).await;
        assert!(result.is_err());
    }

    #[derive(Debug)]
    struct MockValidator {
        result: Result<Option<i64>, &'static str>,
        calls: AtomicUsize,
    }

    impl TokenValidator for MockValidator {
        fn validate_token<'a>(&'a self, token: &'a str) -> TokenValidationFuture<'a> {
            Box::pin(async move {
                assert_eq!(token, "kc-token");
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.result
                    .map(|opt| {
                        opt.map(|exp| ValidatedToken {
                            exp,
                            sub: "user-1".to_string(),
                        })
                    })
                    .map_err(anyhow::Error::msg)
            })
        }
    }

    #[tokio::test]
    async fn keycloak_validator_success_authenticates() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let validator = MockValidator {
            result: Ok(Some(4_102_444_800)),
            calls: AtomicUsize::new(0),
        };

        let (ip4, ip6, session_auth) =
            authenticate_client("kc-token", &state, &config, Some(&validator))
                .await
                .unwrap();

        assert_eq!(validator.calls.load(Ordering::SeqCst), 1);
        assert_eq!(ip4, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(ip6, Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2));
        assert_eq!(session_auth.map(|v| v.exp), Some(4_102_444_800));
    }

    #[tokio::test]
    async fn keycloak_validator_false_rejects() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let validator = MockValidator {
            result: Ok(None),
            calls: AtomicUsize::new(0),
        };

        let result = authenticate_client("kc-token", &state, &config, Some(&validator)).await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid Keycloak Token"));
        assert_eq!(validator.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn keycloak_validator_error_rejects() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let validator = MockValidator {
            result: Err("validator unavailable"),
            calls: AtomicUsize::new(0),
        };

        let result = authenticate_client("kc-token", &state, &config, Some(&validator)).await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("validator unavailable"));
        assert_eq!(validator.calls.load(Ordering::SeqCst), 1);
    }
}
