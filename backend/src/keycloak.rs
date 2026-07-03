use anyhow::{Context, Result};
use constant_time_eq::constant_time_eq;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn};

pub type JwksFetchFuture<'a> = Pin<Box<dyn Future<Output = Result<JwkSet>> + Send + 'a>>;

pub trait JwksFetcher: Send + Sync + std::fmt::Debug {
    fn fetch_jwks<'a>(&'a self, url: &'a str) -> JwksFetchFuture<'a>;
}

#[derive(Debug)]
struct DefaultJwksFetcher;

impl JwksFetcher for DefaultJwksFetcher {
    fn fetch_jwks<'a>(&'a self, url: &'a str) -> JwksFetchFuture<'a> {
        Box::pin(async move {
            info!("Fetching Keycloak JWKS from: {}", url);
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()?;

            let res = client
                .get(url)
                .send()
                .await
                .context("Failed to fetch JWKS")?;
            let jwks: JwkSet = res.json().await.context("Failed to parse JWKS JSON")?;
            Ok(jwks)
        })
    }
}

/// A successfully validated Keycloak access token. Carries the token's expiry
/// (`exp`, Unix seconds) and the subject (`sub`) it was issued for, so that an
/// in-band re-authentication can be bound to the same user that opened the
/// session rather than extending it on any otherwise-valid token.
#[derive(Debug, Clone)]
pub struct ValidatedToken {
    pub exp: i64,
    pub sub: String,
}

pub struct KeycloakValidator {
    url: String,
    realm: String,
    pub client_id: String,
    required_role: Option<String>,
    required_scope: Option<String>,
    // Combined lock: JWKS and its fetch timestamp are always updated atomically.
    // Keeping them in a single RwLock prevents a TOCTOU race where `last_refresh`
    // could be written by a different task between the two separate writes.
    jwks_cache: RwLock<Option<(JwkSet, Instant)>>,
    fetcher: Arc<dyn JwksFetcher>,
}

const JWKS_REFRESH_COOLDOWN: Duration = Duration::from_secs(10);

/// Upper bound on how long a cache hit on `kid` is trusted without a refresh.
/// Normally a matching `kid` means the cached key is still current, but if
/// Keycloak ever reused a `kid` across a genuine rotation (a JWKS spec
/// violation, but cheap to defend against), a kid-found cache hit would
/// otherwise never expire. Forcing a periodic refresh bounds how long a
/// stale key could stay trusted in that scenario.
const JWKS_MAX_CACHE_AGE: Duration = Duration::from_secs(60 * 60);

impl KeycloakValidator {
    pub fn new(
        url: String,
        realm: String,
        client_id: String,
        required_role: Option<String>,
        required_scope: Option<String>,
    ) -> Self {
        Self {
            url,
            realm,
            client_id,
            required_role,
            required_scope,
            jwks_cache: RwLock::new(None),
            fetcher: Arc::new(DefaultJwksFetcher),
        }
    }

    #[cfg(test)]
    pub fn with_fetcher(
        url: String,
        realm: String,
        client_id: String,
        fetcher: Arc<dyn JwksFetcher>,
    ) -> Self {
        Self {
            url,
            realm,
            client_id,
            required_role: None,
            required_scope: None,
            jwks_cache: RwLock::new(None),
            fetcher,
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
        self.fetcher.fetch_jwks(&jwks_url).await
    }

    /// Validates the token. Returns `Ok(Some(ValidatedToken))` (carrying the
    /// token's expiry and subject) when the token is accepted, `Ok(None)` when it
    /// fails a policy check, and `Err` when validation could not be performed.
    #[allow(clippy::too_many_lines)]
    pub async fn validate_token(&self, token: &str) -> Result<Option<ValidatedToken>> {
        let header = decode_header(token).context("Invalid JWT header")?;
        let kid = header
            .kid
            .ok_or_else(|| anyhow::anyhow!("JWT header without 'kid' block"))?;

        // First attempt: look up kid in cached JWKS.
        // If not found, Keycloak may have rotated keys — refresh once and retry.
        let (kid_found, cache_age) = {
            let cache = self.jwks_cache.read().await;
            let kid_found = cache.as_ref().is_some_and(|(j, _)| j.find(&kid).is_some());
            let cache_age = cache.as_ref().map(|(_, t)| t.elapsed());
            (kid_found, cache_age)
        };
        // A kid-found cache hit is normally trusted without a refresh, but a
        // cache older than JWKS_MAX_CACHE_AGE is refreshed anyway (see its
        // doc comment) so a reused kid can't pin a stale key indefinitely.
        let cache_is_stale = cache_age.is_none_or(|age| age >= JWKS_MAX_CACHE_AGE);

        if !kid_found || cache_is_stale {
            let should_refresh = self
                .jwks_cache
                .read()
                .await
                .as_ref()
                .is_none_or(|(_, t)| t.elapsed() >= JWKS_REFRESH_COOLDOWN);

            if should_refresh {
                if kid_found {
                    info!(
                        "Periodic JWKS refresh (cache age exceeded {:?})",
                        JWKS_MAX_CACHE_AGE
                    );
                } else {
                    warn!(
                        "Token kid '{}' not found in cached JWKS — refreshing keys from Keycloak",
                        kid
                    );
                }
                match self.fetch_jwks_from_server().await {
                    Ok(fresh) => {
                        // Atomic update: JWKS and timestamp written together under a single lock.
                        *self.jwks_cache.write().await = Some((fresh, Instant::now()));
                    }
                    Err(e) => warn!("JWKS refresh failed: {}. Proceeding with cached keys.", e),
                }
            } else if !kid_found {
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

                let Some(exp) = Self::validate_claims_with_policy(
                    claims,
                    &self.client_id,
                    now,
                    leeway,
                    self.required_role.as_deref(),
                    self.required_scope.as_deref(),
                ) else {
                    return Ok(None);
                };

                // The subject binds the session to a specific user. Without it an
                // in-band reauth could not verify that a refreshed token belongs to
                // the same principal, so a missing/empty `sub` is rejected.
                let Some(sub) = claims
                    .get("sub")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                else {
                    warn!("JWT missing 'sub' claim - rejecting token");
                    return Ok(None);
                };

                info!(
                    "Keycloak JWT validated successfully (sub: {}, azp: {})",
                    sub,
                    claims.get("azp").and_then(|v| v.as_str()).unwrap_or("?")
                );
                Ok(Some(ValidatedToken {
                    exp,
                    sub: sub.to_string(),
                }))
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

    #[cfg(test)]
    fn validate_claims(claims: &serde_json::Value, client_id: &str, now: i64, leeway: i64) -> bool {
        Self::validate_claims_with_policy(claims, client_id, now, leeway, None, None).is_some()
    }

    /// Returns the token's `exp` claim when all policy checks pass, `None` otherwise.
    fn validate_claims_with_policy(
        claims: &serde_json::Value,
        client_id: &str,
        now: i64,
        leeway: i64,
        required_role: Option<&str>,
        required_scope: Option<&str>,
    ) -> Option<i64> {
        // Keycloak marks access tokens with typ:"Bearer". ID tokens (typ:"ID")
        // share issuer, signature keys and azp, so without this check they
        // would be accepted as VPN credentials.
        let Some(typ) = claims.get("typ").and_then(|v| v.as_str()) else {
            warn!("JWT missing 'typ' claim - rejecting token");
            return None;
        };
        if typ != "Bearer" {
            warn!(
                "JWT 'typ' is '{}', expected 'Bearer' - rejecting token",
                typ
            );
            return None;
        }

        let Some(exp) = claims.get("exp").and_then(json_number_as_i64) else {
            warn!("JWT missing 'exp' claim - rejecting token");
            return None;
        };

        if now > exp + leeway {
            warn!("JWT expired: exp={}, now={}", exp, now);
            return None;
        }

        if let Some(nbf) = claims.get("nbf").and_then(json_number_as_i64) {
            if now + leeway < nbf {
                warn!("JWT not yet valid: nbf={}, now={}", nbf, now);
                return None;
            }
        }

        let Some(azp) = claims.get("azp").and_then(|v| v.as_str()) else {
            warn!("JWT missing 'azp' claim — rejecting token");
            return None;
        };

        // Strict check: Only accept tokens that were explicitly issued to THIS client ID.
        if !constant_time_eq(azp.as_bytes(), client_id.as_bytes()) {
            warn!(
                "JWT azp mismatch: expected '{}', got '{}'. Rejecting token for security.",
                client_id, azp
            );
            return None;
        }

        if let Some(role) = required_role {
            if !claim_has_role(claims, client_id, role) {
                warn!("JWT missing required Keycloak role '{}'", role);
                return None;
            }
        }

        if let Some(scope) = required_scope {
            if !claim_has_scope(claims, scope) {
                warn!("JWT missing required OAuth scope '{}'", scope);
                return None;
            }
        }

        Some(exp)
    }
}

fn claim_has_role(claims: &serde_json::Value, client_id: &str, required_role: &str) -> bool {
    let realm_roles = claims
        .get("realm_access")
        .and_then(|v| v.get("roles"))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten();

    let client_roles = claims
        .get("resource_access")
        .and_then(|v| v.get(client_id))
        .and_then(|v| v.get("roles"))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten();

    realm_roles
        .chain(client_roles)
        .filter_map(serde_json::Value::as_str)
        .any(|role| constant_time_eq(role.as_bytes(), required_role.as_bytes()))
}

fn claim_has_scope(claims: &serde_json::Value, required_scope: &str) -> bool {
    claims
        .get("scope")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .split_ascii_whitespace()
        .any(|scope| constant_time_eq(scope.as_bytes(), required_scope.as_bytes()))
}

fn json_number_as_i64(value: &serde_json::Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|v| i64::try_from(v).ok()))
}

#[cfg(test)]
mod test_keys;
#[cfg(test)]
mod tests;
