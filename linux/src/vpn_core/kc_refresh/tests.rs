use super::*;
use base64::Engine;
use shared::kc_oauth::OAuthTokens;
use std::sync::atomic::AtomicUsize;

fn fresh_token() -> String {
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let payload =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{{\"exp\":{exp}}}"));
    format!("header.{payload}.signature")
}

fn refresher() -> TokenRefresher {
    TokenRefresher {
        current_token: Arc::new(StdMutex::new("expired".into())),
        refresh_token: Arc::new(StdMutex::new(Some("refresh-before-outage".into()))),
        refresh_lock: tokio::sync::Mutex::new(()),
        kc_url: String::new(),
        realm: String::new(),
        client_id: String::new(),
    }
}

#[tokio::test]
async fn expired_token_recovers_after_network_outage_without_an_active_session() {
    let refresher = refresher();
    let failure = refresher
        .refresh_with(30, |_| async {
            RefreshOutcome::NetworkError("offline".into())
        })
        .await;
    assert!(matches!(failure, Err(RefreshError::Temporary(_))));
    assert_eq!(refresher.current_token.lock().unwrap().as_str(), "expired");
    let access_token = fresh_token();
    let refreshed_token = access_token.clone();
    refresher
        .refresh_with(30, |refresh| async move {
            assert_eq!(refresh, "refresh-before-outage");
            RefreshOutcome::Success(OAuthTokens {
                access_token: refreshed_token,
                refresh_token: Some("rotated".into()),
            })
        })
        .await
        .unwrap();
    assert_eq!(*refresher.current_token.lock().unwrap(), access_token);
    assert_eq!(
        refresher.refresh_token.lock().unwrap().as_deref(),
        Some("rotated")
    );
}

#[tokio::test]
async fn reconnect_and_background_refresh_do_not_reuse_a_rotating_token() {
    let refresher = refresher();
    let requests = AtomicUsize::new(0);
    let exchange = |refresh: String| {
        requests.fetch_add(1, Ordering::SeqCst);
        async move {
            assert_eq!(refresh, "refresh-before-outage");
            tokio::task::yield_now().await;
            RefreshOutcome::Success(OAuthTokens {
                access_token: fresh_token(),
                refresh_token: Some("rotated".into()),
            })
        }
    };
    let (first, second) = tokio::join!(
        refresher.refresh_with(30, exchange),
        refresher.refresh_with(300, exchange),
    );
    first.unwrap();
    second.unwrap();
    assert_eq!(requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn revoked_refresh_requires_login_and_keeps_credentials_for_error_reporting() {
    let refresher = refresher();
    let result = refresher
        .refresh_with(30, |_| async {
            RefreshOutcome::NeedsLogin("invalid_grant".into())
        })
        .await;
    assert!(matches!(result, Err(RefreshError::NeedsLogin(_))));
    assert_eq!(
        refresher.refresh_token.lock().unwrap().as_deref(),
        Some("refresh-before-outage")
    );
}
