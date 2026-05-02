use super::test_keys;
use super::*;
use jsonwebtoken::jwk::{Jwk, JwkSet, KeyAlgorithm, RSAKeyParameters, RSAKeyType};

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
    let (token, jwks) = test_keys::signed_token_and_jwks(
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
    let token_with_kid2 = "eyJraWQiOiJraWQyIiwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ.eyJhIjoibiJ9.c"; // kid2 in header

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

    let token_with_kid2 = "eyJraWQiOiJraWQyIiwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ.eyJhIjoibiJ9.c";
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
