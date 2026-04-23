use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use anyhow::Result;
use constant_time_eq::constant_time_eq;

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
