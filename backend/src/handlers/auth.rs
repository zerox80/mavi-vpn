use anyhow::Result;
use constant_time_eq::constant_time_eq;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use crate::config::Config;
use crate::keycloak::KeycloakValidator;
use crate::state::AppState;

pub async fn authenticate_client(
    token: &str,
    state: &Arc<AppState>,
    config: &Config,
    keycloak: &Option<Arc<KeycloakValidator>>,
) -> Result<(Ipv4Addr, Ipv6Addr)> {
    if let Some(kc) = keycloak {
        if !kc.validate_token(token).await? {
            anyhow::bail!("Access Denied: Invalid Keycloak Token");
        }
    } else if !constant_time_eq(token.as_bytes(), config.auth_token.as_bytes()) {
        anyhow::bail!("Access Denied: Invalid Token");
    }

    state.assign_ip_pair()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn test_config() -> Config {
        Config::parse_from(["mavi-vpn", "--auth-token", "correct-token"])
    }

    #[tokio::test]
    async fn valid_token_authenticates() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let result = authenticate_client("correct-token", &state, &config, &None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn invalid_token_rejects() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let result = authenticate_client("wrong-token", &state, &config, &None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid Token"));
    }

    #[tokio::test]
    async fn empty_token_rejects() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let result = authenticate_client("", &state, &config, &None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn valid_token_returns_ip_pair() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let (ip4, ip6) = authenticate_client("correct-token", &state, &config, &None)
            .await
            .unwrap();
        assert_eq!(ip4, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(ip6, Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2));
    }

    #[tokio::test]
    async fn pool_exhaustion_returns_error() {
        let state = Arc::new(AppState::new("10.0.0.0/30").unwrap());
        let config = test_config();
        let _ = authenticate_client("correct-token", &state, &config, &None)
            .await
            .unwrap();
        let result = authenticate_client("correct-token", &state, &config, &None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn case_sensitive_token() {
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = test_config();
        let result = authenticate_client("CORRECT-TOKEN", &state, &config, &None).await;
        assert!(result.is_err());
    }
}
