//! Keycloak refresh lives for the whole VPN run, including reconnect backoff.

use shared::kc_oauth::{self, RefreshOutcome};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tracing::{info, warn};

pub(super) struct TokenRefresher {
    current_token: Arc<StdMutex<String>>,
    refresh_token: Arc<StdMutex<Option<String>>>,
    refresh_lock: tokio::sync::Mutex<()>,
    kc_url: String,
    realm: String,
    client_id: String,
}

#[derive(Debug)]
pub(super) enum RefreshError {
    Temporary(String),
    NeedsLogin(String),
}

impl RefreshError {
    pub(super) fn message(&self) -> String {
        match self {
            Self::Temporary(message) => format!("Keycloak refresh temporarily failed: {message}"),
            Self::NeedsLogin(message) => {
                format!("{} {message}", shared::ipc::KEYCLOAK_LOGIN_REQUIRED_PREFIX)
            }
        }
    }
}

impl TokenRefresher {
    pub(super) fn new(
        config: &shared::ipc::Config,
        current_token: Arc<StdMutex<String>>,
        refresh_token: Arc<StdMutex<Option<String>>>,
    ) -> Option<Arc<Self>> {
        config.kc_auth.unwrap_or(false).then(|| {
            Arc::new(Self {
                current_token,
                refresh_token,
                refresh_lock: tokio::sync::Mutex::new(()),
                kc_url: config.kc_url.clone().unwrap_or_default(),
                realm: config.kc_realm.clone().unwrap_or_else(|| "mavi-vpn".into()),
                client_id: config
                    .kc_client_id
                    .clone()
                    .unwrap_or_else(|| "mavi-client".into()),
            })
        })
    }

    /// Serialize reconnect and background refreshes so a rotated refresh token
    /// cannot be submitted twice. Recheck the access token after taking the lock.
    pub(super) async fn refresh_if_needed(&self, skew_secs: u64) -> Result<(), RefreshError> {
        self.refresh_with(skew_secs, |refresh| async move {
            kc_oauth::refresh_access_token(&self.kc_url, &self.realm, &self.client_id, &refresh)
                .await
        })
        .await
    }

    async fn refresh_with<F, Fut>(&self, skew_secs: u64, exchange: F) -> Result<(), RefreshError>
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = RefreshOutcome>,
    {
        let _lock = self.refresh_lock.lock().await;
        let token = self
            .current_token
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if kc_oauth::is_access_token_usable(&token, skew_secs) {
            return Ok(());
        }
        let refresh = self
            .refresh_token
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .filter(|r| !r.is_empty());
        let Some(refresh) = refresh else {
            // A login without a refresh token remains usable until expiry.
            return if kc_oauth::is_access_token_usable(&token, 0) {
                Ok(())
            } else {
                Err(RefreshError::NeedsLogin(
                    "No refresh token available".into(),
                ))
            };
        };
        match exchange(refresh).await {
            RefreshOutcome::Success(tokens) => {
                *self
                    .current_token
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = tokens.access_token;
                if let Some(refresh) = tokens.refresh_token {
                    *self
                        .refresh_token
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(refresh);
                }
                info!("Keycloak access token refreshed");
                Ok(())
            }
            RefreshOutcome::NetworkError(message) => Err(RefreshError::Temporary(message)),
            RefreshOutcome::NeedsLogin(message) => Err(RefreshError::NeedsLogin(message)),
        }
    }

    pub(super) fn spawn(
        self: &Arc<Self>,
        running: Arc<AtomicBool>,
        last_error: Arc<StdMutex<Option<String>>>,
    ) -> tokio::task::JoinHandle<()> {
        let refresher = self.clone();
        tokio::spawn(async move {
            while running.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(30)).await;
                if !running.load(Ordering::Relaxed) {
                    break;
                }
                if let Err(error) = refresher.refresh_if_needed(300).await {
                    warn!("{}", error.message());
                    if matches!(error, RefreshError::NeedsLogin(_)) {
                        *last_error
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) =
                            Some(error.message());
                        running.store(false, Ordering::SeqCst);
                        break;
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests;
