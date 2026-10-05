use super::*;
use std::sync::atomic::Ordering;

#[tokio::test]
async fn expired_known_key_is_rejected_on_fetch_failure_and_cooldown_then_recovers() {
    let fetcher = Arc::new(MockFetcher::default());
    let (token, jwks) = test_keys::signed_token_and_jwks(
        "kid1",
        "http://kc/realms/realm",
        "client",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600,
    );
    *fetcher.jwks.write().await = Some(jwks);
    let v = KeycloakValidator::with_fetcher(
        "http://kc".into(),
        "realm".into(),
        "client".into(),
        fetcher.clone(),
    );
    v.init_and_fetch().await.unwrap();
    fetcher.should_fail.store(true, Ordering::SeqCst);
    // Fresh cached keys remain usable during a brief outage.
    assert!(v.validate_token(&token).await.unwrap().is_some());
    v.jwks_cache.write().await.as_mut().unwrap().1 = Instant::now() - JWKS_MAX_CACHE_AGE;
    for _ in 0..3 {
        assert!(v
            .validate_token(&token)
            .await
            .unwrap_err()
            .to_string()
            .contains("cache expired"));
    }
    assert_eq!(fetcher.fetch_count.load(Ordering::SeqCst), 2);
    // A successful fetch, unlike a failed attempt, starts a new trust lifetime.
    fetcher.should_fail.store(false, Ordering::SeqCst);
    *v.jwks_refresh.lock().await = None;
    assert!(v.validate_token(&token).await.unwrap().is_some());
    // Removing the key at the next refresh revokes acceptance of its tokens.
    fetcher.jwks.write().await.as_mut().unwrap().keys.clear();
    v.jwks_cache.write().await.as_mut().unwrap().1 = Instant::now() - JWKS_MAX_CACHE_AGE;
    *v.jwks_refresh.lock().await = None;
    assert!(v.validate_token(&token).await.is_err());
}
