use anyhow::{Context, Result};
use constant_time_eq::constant_time_eq;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn};

#[async_trait::async_trait]
pub trait JwksFetcher: Send + Sync + std::fmt::Debug {
    async fn fetch_jwks(&self, url: &str) -> Result<JwkSet>;
}

#[derive(Debug)]
struct DefaultJwksFetcher;

#[async_trait::async_trait]
impl JwksFetcher for DefaultJwksFetcher {
    async fn fetch_jwks(&self, url: &str) -> Result<JwkSet> {
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
    }
}

pub struct KeycloakValidator {
    url: String,
    realm: String,
    pub client_id: String,
    // Combined lock: JWKS and its fetch timestamp are always updated atomically.
    // Keeping them in a single RwLock prevents a TOCTOU race where `last_refresh`
    // could be written by a different task between the two separate writes.
    jwks_cache: RwLock<Option<(JwkSet, Instant)>>,
    fetcher: Arc<dyn JwksFetcher>,
}

const JWKS_REFRESH_COOLDOWN: Duration = Duration::from_secs(10);

impl KeycloakValidator {
    pub fn new(url: String, realm: String, client_id: String) -> Self {
        Self {
            url,
            realm,
            client_id,
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
    use jsonwebtoken::jwk::{Jwk, JwkSet, KeyAlgorithm, RSAKeyParameters, RSAKeyType};
    use jsonwebtoken::Header;

    #[derive(Debug, Default)]
    struct MockFetcher {
        jwks: RwLock<Option<JwkSet>>,
        fetch_count: Arc<std::sync::atomic::AtomicUsize>,
        should_fail: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl JwksFetcher for MockFetcher {
        async fn fetch_jwks(&self, _url: &str) -> Result<JwkSet> {
            self.fetch_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.should_fail.load(std::sync::atomic::Ordering::SeqCst) {
                anyhow::bail!("Mock fetcher failure");
            }
            Ok(self
                .jwks
                .read()
                .await
                .clone()
                .unwrap_or_else(|| JwkSet { keys: vec![] }))
        }
    }

    fn create_mock_jwks(kid: &str) -> JwkSet {
        let rsa = RSAKeyParameters {
            n: "n".to_string(),
            e: "e".to_string(),
            key_type: RSAKeyType::RSA,
        };
        let mut jwk = Jwk {
            common: jsonwebtoken::jwk::CommonParameters {
                key_id: Some(kid.to_string()),
                ..Default::default()
            },
            algorithm: jsonwebtoken::jwk::AlgorithmParameters::RSA(rsa),
        };
        jwk.common.key_algorithm = Some(KeyAlgorithm::RS256);

        JwkSet { keys: vec![jwk] }
    }

    fn signed_token_and_jwks(
        kid: &str,
        issuer: &str,
        client_id: &str,
        expires_at: u64,
    ) -> (String, JwkSet) {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use rcgen::{PublicKeyData, SigningKey};

        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
        let (n, e) = rsa_components_from_der(key_pair.der_bytes()).unwrap();

        let mut jwk = Jwk {
            common: jsonwebtoken::jwk::CommonParameters {
                key_id: Some(kid.to_string()),
                key_algorithm: Some(KeyAlgorithm::RS256),
                ..Default::default()
            },
            algorithm: jsonwebtoken::jwk::AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: RSAKeyType::RSA,
                n: URL_SAFE_NO_PAD.encode(strip_leading_zeroes(n)),
                e: URL_SAFE_NO_PAD.encode(strip_leading_zeroes(e)),
            }),
        };
        jwk.common.key_algorithm = Some(KeyAlgorithm::RS256);

        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(kid.to_string());

        let claims = serde_json::json!({
            "iss": issuer,
            "sub": "user-1",
            "azp": client_id,
            "exp": expires_at,
        });

        let message = [
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap()),
        ]
        .join(".");
        let signature = key_pair.sign(message.as_bytes()).unwrap();
        let token = format!("{}.{}", message, URL_SAFE_NO_PAD.encode(signature));
        (token, JwkSet { keys: vec![jwk] })
    }

    fn strip_leading_zeroes(bytes: &[u8]) -> &[u8] {
        let first_non_zero = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len().saturating_sub(1));
        &bytes[first_non_zero..]
    }

    fn rsa_components_from_der(der: &[u8]) -> Option<(&[u8], &[u8])> {
        let (tag, body, rest) = der_read_tlv(der)?;
        if tag != 0x30 || !rest.is_empty() {
            return None;
        }

        if let Some(components) = rsa_components_from_sequence(body) {
            return Some(components);
        }

        // SubjectPublicKeyInfo: SEQUENCE { algorithm, BIT STRING public_key }
        let (_, _, after_algorithm) = der_read_tlv(body)?;
        let (bit_string_tag, bit_string, _) = der_read_tlv(after_algorithm)?;
        if bit_string_tag != 0x03 || bit_string.first().copied()? != 0 {
            return None;
        }
        let (inner_tag, inner_body, inner_rest) = der_read_tlv(&bit_string[1..])?;
        if inner_tag != 0x30 || !inner_rest.is_empty() {
            return None;
        }
        rsa_components_from_sequence(inner_body)
    }

    fn rsa_components_from_sequence(sequence: &[u8]) -> Option<(&[u8], &[u8])> {
        let (n_tag, n, after_n) = der_read_tlv(sequence)?;
        let (e_tag, e, after_e) = der_read_tlv(after_n)?;
        if n_tag == 0x02 && e_tag == 0x02 && after_e.is_empty() {
            Some((n, e))
        } else {
            None
        }
    }

    fn der_read_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
        let (&tag, input) = input.split_first()?;
        let (&length_byte, input) = input.split_first()?;
        let (length, input) = if length_byte & 0x80 == 0 {
            (usize::from(length_byte), input)
        } else {
            let length_octets = usize::from(length_byte & 0x7f);
            if length_octets == 0 || length_octets > std::mem::size_of::<usize>() {
                return None;
            }
            let (length_bytes, input) = input.split_at_checked(length_octets)?;
            let length = length_bytes
                .iter()
                .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
            (length, input)
        };
        let (body, rest) = input.split_at_checked(length)?;
        Some((tag, body, rest))
    }

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

    #[tokio::test]
    async fn test_init_and_fetch() {
        let fetcher = Arc::new(MockFetcher::default());
        let jwks = create_mock_jwks("kid1");
        *fetcher.jwks.write().await = Some(jwks);

        let v = KeycloakValidator::with_fetcher(
            "url".to_string(),
            "realm".to_string(),
            "client".to_string(),
            fetcher.clone(),
        );

        v.init_and_fetch().await.unwrap();
        assert_eq!(
            fetcher
                .fetch_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );

        let cache = v.jwks_cache.read().await;
        assert!(cache.is_some());
        assert_eq!(cache.as_ref().unwrap().0.keys.len(), 1);
    }

    #[tokio::test]
    async fn test_validate_token_success_with_cached_keys() {
        let fetcher = Arc::new(MockFetcher::default());
        let issuer = "http://kc/realms/realm";
        let (token, jwks) = signed_token_and_jwks(
            "kid1",
            issuer,
            "client",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 600,
        );
        *fetcher.jwks.write().await = Some(jwks);

        let v = KeycloakValidator::with_fetcher(
            "http://kc".to_string(),
            "realm".to_string(),
            "client".to_string(),
            fetcher.clone(),
        );

        v.init_and_fetch().await.unwrap();

        assert!(v.validate_token(&token).await.unwrap());
        assert_eq!(
            fetcher
                .fetch_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn test_refresh_on_unknown_kid() {
        let fetcher = Arc::new(MockFetcher::default());
        let v = KeycloakValidator::with_fetcher(
            "url".to_string(),
            "realm".to_string(),
            "client".to_string(),
            fetcher.clone(),
        );

        // Initial fetch
        let jwks1 = create_mock_jwks("kid1");
        *fetcher.jwks.write().await = Some(jwks1);
        v.init_and_fetch().await.unwrap();

        // Simulate token with unknown kid
        let token_with_kid2 =
            "eyJraWQiOiJraWQyIiwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ.eyJhIjoibiJ9.c"; // kid2 in header

        // This should trigger a refresh
        let jwks2 = create_mock_jwks("kid2");
        *fetcher.jwks.write().await = Some(jwks2);

        // Bypass cooldown: set the last fetch time to far in the past
        {
            let mut cache = v.jwks_cache.write().await;
            if let Some((_, t)) = cache.as_mut() {
                *t = Instant::now() - Duration::from_secs(3600);
            }
        }

        let _ = v.validate_token(token_with_kid2).await;
        assert_eq!(
            fetcher
                .fetch_count
                .load(std::sync::atomic::Ordering::SeqCst),
            2
        );
    }

    #[tokio::test]
    async fn test_refresh_cooldown() {
        let fetcher = Arc::new(MockFetcher::default());
        let v = KeycloakValidator::with_fetcher(
            "url".to_string(),
            "realm".to_string(),
            "client".to_string(),
            fetcher.clone(),
        );

        // Initial fetch
        let jwks1 = create_mock_jwks("kid1");
        *fetcher.jwks.write().await = Some(jwks1);
        v.init_and_fetch().await.unwrap();

        // Unknown kid immediately after
        let token_with_kid2 = "eyJraWQiOiJraWQyIn0.eyJhInoiOiJiIn0.c";
        let _ = v.validate_token(token_with_kid2).await;

        // Should NOT have refreshed because of cooldown
        assert_eq!(
            fetcher
                .fetch_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn test_fetch_failure_uses_cache() {
        let fetcher = Arc::new(MockFetcher::default());
        let v = KeycloakValidator::with_fetcher(
            "url".to_string(),
            "realm".to_string(),
            "client".to_string(),
            fetcher.clone(),
        );

        // Initial fetch success
        let jwks1 = create_mock_jwks("kid1");
        *fetcher.jwks.write().await = Some(jwks1);
        v.init_and_fetch().await.unwrap();

        // Bypass cooldown: set the last fetch time to far in the past
        {
            let mut cache = v.jwks_cache.write().await;
            if let Some((_, t)) = cache.as_mut() {
                *t = Instant::now() - Duration::from_secs(3600);
            }
        }

        // Make it fail for next fetch
        fetcher
            .should_fail
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let token_with_kid2 =
            "eyJraWQiOiJraWQyIiwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ.eyJhIjoibiJ9.c";
        let result = v.validate_token(token_with_kid2).await;

        // Should have attempted refresh
        assert_eq!(
            fetcher
                .fetch_count
                .load(std::sync::atomic::Ordering::SeqCst),
            2
        );

        // But since refresh failed, it should have used the old cache (which doesn't have kid2)
        // and ultimately failed to find the key.
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("JWK not found"));
    }

    #[tokio::test]
    async fn test_init_and_fetch_propagates_malformed_jwks_error() {
        let fetcher = Arc::new(MockFetcher::default());
        fetcher
            .should_fail
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let v = KeycloakValidator::with_fetcher(
            "url".to_string(),
            "realm".to_string(),
            "client".to_string(),
            fetcher,
        );

        let result = v.init_and_fetch().await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Mock fetcher failure"));
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
        assert!(KeycloakValidator::validate_claims(
            &claims, client_id, now, leeway
        ));

        // Missing exp
        let claims = serde_json::json!({
            "azp": "my-client"
        });
        assert!(!KeycloakValidator::validate_claims(
            &claims, client_id, now, leeway
        ));

        // Expired
        let claims = serde_json::json!({
            "exp": 900,
            "azp": "my-client"
        });
        assert!(!KeycloakValidator::validate_claims(
            &claims, client_id, now, leeway
        ));

        // Expired but within leeway
        let claims = serde_json::json!({
            "exp": 980,
            "azp": "my-client"
        });
        assert!(KeycloakValidator::validate_claims(
            &claims, client_id, now, leeway
        ));

        // nbf in the future
        let claims = serde_json::json!({
            "exp": 1100,
            "nbf": 1050,
            "azp": "my-client"
        });
        assert!(!KeycloakValidator::validate_claims(
            &claims, client_id, now, leeway
        ));

        // nbf in the future but within leeway
        let claims = serde_json::json!({
            "exp": 1100,
            "nbf": 1020,
            "azp": "my-client"
        });
        assert!(KeycloakValidator::validate_claims(
            &claims, client_id, now, leeway
        ));

        // Missing azp
        let claims = serde_json::json!({
            "exp": 1100
        });
        assert!(!KeycloakValidator::validate_claims(
            &claims, client_id, now, leeway
        ));

        // azp mismatch
        let claims = serde_json::json!({
            "exp": 1100,
            "azp": "wrong-client"
        });
        assert!(!KeycloakValidator::validate_claims(
            &claims, client_id, now, leeway
        ));
    }
}
