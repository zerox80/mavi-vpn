use anyhow::Result;
use constant_time_eq::constant_time_eq;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use tracing::warn;

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
///
/// `remote_addr` is checked against the server's per-IP failed-authentication
/// rate limiter *before* any real validation work (token comparison, Keycloak
/// call) runs, so a blocked IP never reaches the validator. A blocked IP fails
/// with the exact same error text as a normal invalid-token rejection — the
/// caller must never be able to distinguish "rate limited" from "wrong token"
/// on the wire, preserving the server's anti-probing design.
pub async fn authenticate_client(
    token: &str,
    remote_addr: IpAddr,
    state: &Arc<AppState>,
    config: &Config,
    keycloak: Option<&dyn TokenValidator>,
) -> Result<(Ipv4Addr, Ipv6Addr, Option<ValidatedToken>)> {
    if state.auth_rate_limiter.is_blocked(remote_addr) {
        warn!(
            "Rejecting {} due to auth rate limit (repeated failed attempts)",
            remote_addr
        );
        anyhow::bail!("Access Denied: Invalid Token");
    }

    let session_auth = if let Some(kc) = keycloak {
        match kc.validate_token(token).await {
            Ok(Some(validated)) => Some(validated),
            Ok(None) => {
                state.auth_rate_limiter.record_failure(remote_addr);
                anyhow::bail!("Access Denied: Invalid Keycloak Token");
            }
            Err(e) => {
                warn!("Keycloak token validation error for {}: {}", remote_addr, e);
                state.auth_rate_limiter.record_failure(remote_addr);
                anyhow::bail!("Access Denied: Invalid Keycloak Token");
            }
        }
    } else {
        let Some(auth_token) = config.auth_token.as_deref().filter(|t| !t.is_empty()) else {
            anyhow::bail!("Static auth is enabled but VPN_AUTH_TOKEN is not configured");
        };
        if !constant_time_eq(token.as_bytes(), auth_token.as_bytes()) {
            state.auth_rate_limiter.record_failure(remote_addr);
            anyhow::bail!("Access Denied: Invalid Token");
        }
        None
    };

    let (ip4, ip6) = state.assign_ip_pair()?;
    state.auth_rate_limiter.record_success(remote_addr);
    Ok((ip4, ip6, session_auth))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::net::Ipv4Addr as StdIpv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn test_config() -> Config {
        Config::parse_from(["mavi-vpn", "--auth-token", "correct-token"])
    }

    /// Distinct per-test loopback address so no two tests can ever share
    /// rate-limiter state, even though each test already builds its own
    /// fresh `AppState` (defense against future test-sharing refactors).
    fn test_ip(last_octet: u8) -> IpAddr {
        IpAddr::V4(StdIpv4Addr::new(127, 0, 0, last_octet))
    }

    #[tokio::test]
    async fn valid_token_authenticates() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let result = authenticate_client("correct-token", test_ip(1), &state, &config, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn invalid_token_rejects() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let result = authenticate_client("wrong-token", test_ip(2), &state, &config, None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid Token"));
    }

    #[tokio::test]
    async fn empty_token_rejects() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let result = authenticate_client("", test_ip(3), &state, &config, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn valid_token_returns_ip_pair() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let (ip4, ip6, session_auth) =
            authenticate_client("correct-token", test_ip(4), &state, &config, None)
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
        let _ = authenticate_client("correct-token", test_ip(5), &state, &config, None)
            .await
            .unwrap();
        let result = authenticate_client("correct-token", test_ip(6), &state, &config, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn case_sensitive_token() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let result = authenticate_client("CORRECT-TOKEN", test_ip(7), &state, &config, None).await;
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
            authenticate_client("kc-token", test_ip(8), &state, &config, Some(&validator))
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

        let result =
            authenticate_client("kc-token", test_ip(9), &state, &config, Some(&validator)).await;

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

        let result =
            authenticate_client("kc-token", test_ip(10), &state, &config, Some(&validator)).await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid Keycloak Token"));
        assert_eq!(validator.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn repeated_keycloak_validator_errors_eventually_block() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let ip = test_ip(16);

        for _ in 0..10 {
            let validator = MockValidator {
                result: Err("invalid jwt header"),
                calls: AtomicUsize::new(0),
            };
            let result =
                authenticate_client("kc-token", ip, &state, &config, Some(&validator)).await;
            assert!(result.is_err());
            assert_eq!(validator.calls.load(Ordering::SeqCst), 1);
        }
        assert!(state.auth_rate_limiter.is_blocked(ip));

        let validator = MockValidator {
            result: Err("invalid jwt header"),
            calls: AtomicUsize::new(0),
        };
        let result = authenticate_client("kc-token", ip, &state, &config, Some(&validator)).await;

        assert!(result.is_err());
        assert!(state.auth_rate_limiter.is_blocked(ip));
        assert_eq!(validator.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn blocked_ip_rejects_before_reaching_validator() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let ip = test_ip(11);

        // Exhaust the default limit (10 failures/60s) with a static-token
        // config so the IP becomes blocked, then switch to a Keycloak
        // validator and prove it is never even invoked.
        for _ in 0..10 {
            let _ = authenticate_client("wrong-token", ip, &state, &config, None).await;
        }
        assert!(state.auth_rate_limiter.is_blocked(ip));

        let validator = MockValidator {
            result: Ok(Some(4_102_444_800)),
            calls: AtomicUsize::new(0),
        };
        let result = authenticate_client("kc-token", ip, &state, &config, Some(&validator)).await;

        assert!(result.is_err());
        assert_eq!(
            validator.calls.load(Ordering::SeqCst),
            0,
            "a blocked IP must never reach the validator"
        );
    }

    #[tokio::test]
    async fn repeated_wrong_tokens_from_same_ip_eventually_block() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let ip = test_ip(12);

        for _ in 0..9 {
            let result = authenticate_client("wrong-token", ip, &state, &config, None).await;
            assert!(result.is_err());
        }
        assert!(
            !state.auth_rate_limiter.is_blocked(ip),
            "below the threshold should not block yet"
        );

        let _ = authenticate_client("wrong-token", ip, &state, &config, None).await;
        assert!(
            state.auth_rate_limiter.is_blocked(ip),
            "exactly the threshold should block"
        );
    }

    #[tokio::test]
    async fn successful_auth_does_not_count_as_failure() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let ip = test_ip(13);

        for _ in 0..5 {
            let _ = authenticate_client("wrong-token", ip, &state, &config, None).await;
            let _ = authenticate_client("correct-token", ip, &state, &config, None).await;
        }
        for _ in 0..9 {
            let _ = authenticate_client("wrong-token", ip, &state, &config, None).await;
        }
        assert!(
            !state.auth_rate_limiter.is_blocked(ip),
            "successes interleaved with failures must reset the failure count each time"
        );
        let _ = authenticate_client("wrong-token", ip, &state, &config, None).await;
        assert!(
            state.auth_rate_limiter.is_blocked(ip),
            "exactly the threshold after a success should block"
        );
    }

    #[tokio::test]
    async fn rate_limit_is_per_ip_not_global() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let ip_a = test_ip(14);
        let ip_b = test_ip(15);

        for _ in 0..10 {
            let _ = authenticate_client("wrong-token", ip_a, &state, &config, None).await;
        }
        assert!(state.auth_rate_limiter.is_blocked(ip_a));

        let result = authenticate_client("correct-token", ip_b, &state, &config, None).await;
        assert!(result.is_ok(), "a different IP must not be affected");
    }
}
