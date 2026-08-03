use super::create_mock_jwks;
use crate::keycloak::{JwksFetchFuture, JwksFetcher, KeycloakValidator, JWKS_REFRESH_COOLDOWN};
use jsonwebtoken::jwk::JwkSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Barrier;

const CONCURRENT_VALIDATORS: usize = 8;
const UNKNOWN_KID_TOKEN: &str =
    "eyJraWQiOiJraWQyIiwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ.eyJhIjoibiJ9.c";

#[derive(Debug)]
struct SlowFetcher {
    jwks: JwkSet,
    should_fail: bool,
    fetch_count: AtomicUsize,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
}

impl SlowFetcher {
    fn new(jwks: JwkSet, should_fail: bool) -> Self {
        Self {
            jwks,
            should_fail,
            fetch_count: AtomicUsize::new(0),
            in_flight: AtomicUsize::new(0),
            max_in_flight: AtomicUsize::new(0),
        }
    }
}

impl JwksFetcher for SlowFetcher {
    fn fetch_jwks<'a>(&'a self, _url: &'a str) -> JwksFetchFuture<'a> {
        Box::pin(async move {
            self.fetch_count.fetch_add(1, Ordering::SeqCst);
            let active = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(active, Ordering::SeqCst);

            // Keep the first request in flight long enough for every validator
            // to reach the vulnerable refresh decision.
            tokio::time::sleep(Duration::from_millis(25)).await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);

            if self.should_fail {
                anyhow::bail!("simulated JWKS failure");
            }
            Ok(self.jwks.clone())
        })
    }
}

async fn run_unknown_kid_burst(should_fail: bool) -> (Arc<SlowFetcher>, Arc<KeycloakValidator>) {
    let fetcher = Arc::new(SlowFetcher::new(create_mock_jwks("kid2"), should_fail));
    let validator = Arc::new(KeycloakValidator::with_fetcher(
        "url".to_string(),
        "realm".to_string(),
        "client".to_string(),
        fetcher.clone(),
    ));
    let old_fetch = Instant::now()
        .checked_sub(JWKS_REFRESH_COOLDOWN + Duration::from_secs(1))
        .unwrap_or_else(Instant::now);
    *validator.jwks_cache.write().await = Some((create_mock_jwks("kid1"), old_fetch));

    let start = Arc::new(Barrier::new(CONCURRENT_VALIDATORS + 1));
    let mut tasks = Vec::with_capacity(CONCURRENT_VALIDATORS);
    for _ in 0..CONCURRENT_VALIDATORS {
        let validator = validator.clone();
        let start = start.clone();
        tasks.push(tokio::spawn(async move {
            start.wait().await;
            let _ = validator.validate_token(UNKNOWN_KID_TOKEN).await;
        }));
    }
    start.wait().await;
    for task in tasks {
        task.await.unwrap();
    }

    (fetcher, validator)
}

#[tokio::test]
async fn concurrent_unknown_kids_share_successful_refresh() {
    let (fetcher, validator) = run_unknown_kid_burst(false).await;

    assert_eq!(fetcher.fetch_count.load(Ordering::SeqCst), 1);
    assert_eq!(fetcher.max_in_flight.load(Ordering::SeqCst), 1);
    assert!(validator
        .jwks_cache
        .read()
        .await
        .as_ref()
        .is_some_and(|(jwks, _)| jwks.find("kid2").is_some()));
}

#[tokio::test]
async fn concurrent_unknown_kids_cool_down_failed_refresh() {
    let (fetcher, validator) = run_unknown_kid_burst(true).await;

    assert_eq!(fetcher.fetch_count.load(Ordering::SeqCst), 1);
    assert_eq!(fetcher.max_in_flight.load(Ordering::SeqCst), 1);
    assert!(validator
        .jwks_cache
        .read()
        .await
        .as_ref()
        .is_some_and(|(jwks, _)| jwks.find("kid1").is_some()));
}
