use anyhow::{Context, Result};
use constant_time_eq::constant_time_eq;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn};

pub struct KeycloakValidator {
    url: String,
    realm: String,
    pub client_id: String,
    // Combined lock: JWKS and its fetch timestamp are always updated atomically.
    // Keeping them in a single RwLock prevents a TOCTOU race where `last_refresh`
    // could be written by a different task between the two separate writes.
    jwks_cache: RwLock<Option<(JwkSet, Instant)>>,
}

const JWKS_REFRESH_COOLDOWN: Duration = Duration::from_secs(10);

impl KeycloakValidator {
    pub fn new(url: String, realm: String, client_id: String) -> Self {
        Self {
            url,
            realm,
            client_id,
            jwks_cache: RwLock::new(None),
        }
    }

    pub async fn init_and_fetch(&self) -> Result<()> {
        let jwks = self.fetch_jwks_from_server().await?;
        *self.jwks_cache.write().await = Some((jwks, Instant::now()));
        info!("Successfully loaded Keycloak JWKS configuration");
        Ok(())
    }

    /// Fetches a fresh JWKS from Keycloak. Called on startup and when an unknown kid is seen.
    async fn fetch_jwks_from_server(&self) -> Result<JwkSet> {
        let jwks_url = format!(
            "{}/realms/{}/protocol/openid-connect/certs",
            self.url.trim_end_matches('/'),
            self.realm
        );
        info!("Fetching Keycloak JWKS from: {}", jwks_url);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?;

        let res = client
            .get(&jwks_url)
            .send()
            .await
            .context("Failed to fetch JWKS")?;
        let jwks: JwkSet = res.json().await.context("Failed to parse JWKS JSON")?;
        Ok(jwks)
    }

    #[allow(clippy::too_many_lines)]
    pub async fn validate_token(&self, token: &str) -> Result<bool> {
        let header = decode_header(token).context("Invalid JWT header")?;
        let kid = header
            .kid
            .ok_or_else(|| anyhow::anyhow!("JWT header without 'kid' block"))?;

        // First attempt: look up kid in cached JWKS.
        // If not found, Keycloak may have rotated keys — refresh once and retry.
        let kid_found = self
            .jwks_cache
            .read()
            .await
            .as_ref()
            .is_some_and(|(j, _)| j.find(&kid).is_some());

        if !kid_found {
            let should_refresh = self
                .jwks_cache
                .read()
                .await
                .as_ref()
                .is_none_or(|(_, t)| t.elapsed() >= JWKS_REFRESH_COOLDOWN);

            if should_refresh {
                warn!(
                    "Token kid '{}' not found in cached JWKS — refreshing keys from Keycloak",
                    kid
                );
                match self.fetch_jwks_from_server().await {
                    Ok(fresh) => {
                        // Atomic update: JWKS and timestamp written together under a single lock.
                        *self.jwks_cache.write().await = Some((fresh, Instant::now()));
                    }
                    Err(e) => warn!("JWKS refresh failed: {}. Proceeding with cached keys.", e),
                }
            } else {
                warn!(
                    "Token kid '{}' not found but JWKS refresh is on cooldown. Rejecting token.",
                    kid
                );
            }
        }

        let cache_guard = self.jwks_cache.read().await;
        let (jwks, _) = cache_guard
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("JWKS not yet loaded from Keycloak Server"))?;

        let jwk = jwks.find(&kid).ok_or_else(|| {
            warn!(
                "Token kid '{}' not found even after JWKS refresh. Available kids: {:?}",
                kid,
                jwks.keys
                    .iter()
                    .filter_map(|k| k.common.key_id.as_ref())
                    .collect::<Vec<_>>()
            );
            anyhow::anyhow!("JWK not found for kid: {kid}")
        })?;
        let decoding_key =
            DecodingKey::from_jwk(jwk).context("Failed to create decoding key from JWK")?;
        drop(cache_guard);

        let mut validation = Validation::new(Algorithm::RS256);

        // Keycloak access tokens have aud:"account" by default, NOT the client_id.
        // The client_id is in the "azp" (authorized party) claim.
        // So we disable built-in audience validation and check azp manually below.
        validation.validate_aud = false;

        // Small leeway to compensate for clock drift between server and Keycloak.
        validation.leeway = 30;

        // Validate the issuer (the Keycloak realm URL)
        let issuer = format!("{}/realms/{}", self.url.trim_end_matches('/'), self.realm);
        validation.set_issuer(&[&issuer]);

        match decode::<serde_json::Value>(token, &decoding_key, &validation) {
            Ok(token_data) => {
                let claims = &token_data.claims;
                #[allow(clippy::cast_possible_wrap)]
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .context("System clock is before Unix epoch")?
                    .as_secs() as i64;
                #[allow(clippy::cast_possible_wrap)]
                let leeway = validation.leeway as i64;

                if !Self::validate_claims(claims, &self.client_id, now, leeway) {
                    return Ok(false);
                }

                info!(
                    "Keycloak JWT validated successfully (sub: {}, azp: {})",
                    claims.get("sub").and_then(|v| v.as_str()).unwrap_or("?"),
                    claims.get("azp").and_then(|v| v.as_str()).unwrap_or("?")
                );
                Ok(true)
            }
            Err(e) => {
                warn!("JWT validation failed: {}", e);
                // Return Err so callers can distinguish "token is invalid" (Ok(false))
                // from "an error occurred during validation" (Err). Both reject the
                // connection, but Err propagates the underlying reason up the call stack.
                Err(anyhow::anyhow!("JWT decode error: {e}"))
            }
        }
    }

    fn validate_claims(claims: &serde_json::Value, client_id: &str, now: i64, leeway: i64) -> bool {
        let Some(exp) = claims.get("exp").and_then(json_number_as_i64) else {
            warn!("JWT missing 'exp' claim - rejecting token");
            return false;
        };

        if now > exp + leeway {
            warn!("JWT expired: exp={}, now={}", exp, now);
            return false;
        }

        if let Some(nbf) = claims.get("nbf").and_then(json_number_as_i64) {
            if now + leeway < nbf {
                warn!("JWT not yet valid: nbf={}, now={}", nbf, now);
                return false;
            }
        }

        let Some(azp) = claims.get("azp").and_then(|v| v.as_str()) else {
            warn!("JWT missing 'azp' claim — rejecting token");
            return false;
        };

        // Strict check: Only accept tokens that were explicitly issued to THIS client ID.
        if !constant_time_eq(azp.as_bytes(), client_id.as_bytes()) {
            warn!(
                "JWT azp mismatch: expected '{}', got '{}'. Rejecting token for security.",
                client_id, azp
            );
            return false;
        }

        true
    }
}

fn json_number_as_i64(value: &serde_json::Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|v| i64::try_from(v).ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_number_as_i64_positive() {
        assert_eq!(json_number_as_i64(&serde_json::json!(42)), Some(42));
        assert_eq!(json_number_as_i64(&serde_json::json!(0)), Some(0));
        assert_eq!(
            json_number_as_i64(&serde_json::json!(i64::MAX)),
            Some(i64::MAX)
        );
    }

    #[test]
    fn json_number_as_i64_negative() {
        assert_eq!(json_number_as_i64(&serde_json::json!(-1)), Some(-1));
        assert_eq!(json_number_as_i64(&serde_json::json!(-100)), Some(-100));
    }

    #[test]
    fn json_number_as_i64_float_returns_none() {
        assert_eq!(json_number_as_i64(&serde_json::json!(42.5)), None);
        assert_eq!(json_number_as_i64(&serde_json::json!(-2.5)), None);
    }

    #[test]
    fn json_number_as_i64_string_returns_none() {
        assert_eq!(json_number_as_i64(&serde_json::json!("42")), None);
        assert_eq!(json_number_as_i64(&serde_json::json!("")), None);
    }

    #[test]
    fn json_number_as_i64_bool_returns_none() {
        assert_eq!(json_number_as_i64(&serde_json::json!(true)), None);
        assert_eq!(json_number_as_i64(&serde_json::json!(false)), None);
    }

    #[test]
    fn json_number_as_i64_null_returns_none() {
        assert_eq!(json_number_as_i64(&serde_json::json!(null)), None);
    }

    #[test]
    fn json_number_as_i64_u64_max_overflows() {
        // u64::MAX > i64::MAX, should return None
        assert_eq!(json_number_as_i64(&serde_json::json!(u64::MAX)), None);
    }

    #[test]
    fn json_number_as_i64_u64_within_range() {
        assert_eq!(
            json_number_as_i64(&serde_json::json!(i64::MAX as u64)),
            Some(i64::MAX)
        );
    }

    #[test]
    fn validator_new_sets_fields() {
        let v = KeycloakValidator::new(
            "https://auth.example.com".to_string(),
            "my-realm".to_string(),
            "my-client".to_string(),
        );
        assert_eq!(v.client_id, "my-client");
    }

    #[test]
    fn validator_new_stores_url_and_realm() {
        let v = KeycloakValidator::new(
            "https://kc.test.com/".to_string(),
            "test-realm".to_string(),
            "client-1".to_string(),
        );
        assert_eq!(v.client_id, "client-1");
    }

    #[test]
    fn test_validate_claims() {
        let client_id = "my-client";
        let now = 1000;
        let leeway = 30;

        // Valid token
        let claims = serde_json::json!({
            "exp": 1100,
            "azp": "my-client",
            "sub": "user1"
        });
        assert!(KeycloakValidator::validate_claims(&claims, client_id, now, leeway));

        // Missing exp
        let claims = serde_json::json!({
            "azp": "my-client"
        });
        assert!(!KeycloakValidator::validate_claims(&claims, client_id, now, leeway));

        // Expired
        let claims = serde_json::json!({
            "exp": 900,
            "azp": "my-client"
        });
        assert!(!KeycloakValidator::validate_claims(&claims, client_id, now, leeway));

        // Expired but within leeway
        let claims = serde_json::json!({
            "exp": 980,
            "azp": "my-client"
        });
        assert!(KeycloakValidator::validate_claims(&claims, client_id, now, leeway));

        // nbf in the future
        let claims = serde_json::json!({
            "exp": 1100,
            "nbf": 1050,
            "azp": "my-client"
        });
        assert!(!KeycloakValidator::validate_claims(&claims, client_id, now, leeway));

        // nbf in the future but within leeway
        let claims = serde_json::json!({
            "exp": 1100,
            "nbf": 1020,
            "azp": "my-client"
        });
        assert!(KeycloakValidator::validate_claims(&claims, client_id, now, leeway));

        // Missing azp
        let claims = serde_json::json!({
            "exp": 1100
        });
        assert!(!KeycloakValidator::validate_claims(&claims, client_id, now, leeway));

        // azp mismatch
        let claims = serde_json::json!({
            "exp": 1100,
            "azp": "wrong-client"
        });
        assert!(!KeycloakValidator::validate_claims(&claims, client_id, now, leeway));
    }
}
