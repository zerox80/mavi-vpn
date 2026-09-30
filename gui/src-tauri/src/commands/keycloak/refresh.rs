use super::{persist_refresh_token, REFRESH_SKEW_SECS};
use crate::secret_store::SecretStore;
use shared::ipc::IpcResponse;
use shared::kc_oauth::{self, RefreshOutcome};
use std::future::Future;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum TickOutcome {
    Skipped,
    Delivered,
}

#[derive(Debug)]
pub(super) enum TickError {
    Delivery(String),
    Network(String),
    NeedsLogin(String),
    Persistence(String),
}

/// Keep a refreshed token pending until IPC acknowledges it. A failed delivery
/// retries the same token without another OAuth exchange or refresh-token rotation.
pub(super) async fn refresh_tick<R, RFut, S, SFut>(
    access_token: &mut String,
    pending_token: &mut Option<String>,
    store: &impl SecretStore,
    refresh_account: &str,
    refresh: R,
    send: S,
) -> Result<TickOutcome, TickError>
where
    R: FnOnce(String) -> RFut,
    RFut: Future<Output = RefreshOutcome>,
    S: FnOnce(String) -> SFut,
    SFut: Future<Output = Result<IpcResponse, String>>,
{
    if pending_token
        .as_deref()
        .is_some_and(|token| !kc_oauth::is_access_token_usable(token, 0))
    {
        *pending_token = None;
    }

    if pending_token.is_none() {
        if kc_oauth::is_access_token_usable(access_token, REFRESH_SKEW_SECS) {
            return Ok(TickOutcome::Skipped);
        }
        let refresh_token = store
            .get_secret(refresh_account)
            .ok()
            .flatten()
            .filter(|token| !token.is_empty())
            .ok_or_else(|| TickError::NeedsLogin("Session expired; please log in again.".into()))?;
        let tokens = match refresh(refresh_token).await {
            RefreshOutcome::Success(tokens) => tokens,
            RefreshOutcome::NetworkError(error) => return Err(TickError::Network(error)),
            RefreshOutcome::NeedsLogin(error) => return Err(TickError::NeedsLogin(error)),
        };
        persist_refresh_token(store, refresh_account, tokens.refresh_token.as_deref())
            .map_err(TickError::Persistence)?;
        *pending_token = Some(tokens.access_token);
    }

    let Some(token) = pending_token.clone() else {
        return Ok(TickOutcome::Skipped);
    };
    match send(token.clone()).await {
        Ok(IpcResponse::Ok) => {
            *access_token = token;
            *pending_token = None;
            Ok(TickOutcome::Delivered)
        }
        Ok(IpcResponse::Error(error)) => Err(TickError::Delivery(error)),
        Ok(response) => Err(TickError::Delivery(format!(
            "Unexpected response: {response:?}"
        ))),
        Err(error) => Err(TickError::Delivery(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_store::tests::MemorySecretStore;
    use base64::Engine;
    use shared::kc_oauth::OAuthTokens;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn token_with_lifetime(seconds: u64) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!("{{\"exp\":{}}}", now + seconds));
        format!("e30.{payload}.signature")
    }

    #[tokio::test]
    async fn failed_ipc_delivery_retries_without_another_oauth_exchange() {
        let store = MemorySecretStore::default();
        store.set_secret("refresh", "old-refresh").unwrap();
        let old_token = token_with_lifetime(240);
        let new_token = token_with_lifetime(900);
        let mut access_token = old_token.clone();
        let mut pending = None;
        let mut exchanges = 0;
        let mut delivered = Vec::new();

        for reply in [
            Err("temporary IPC failure".into()),
            Ok(IpcResponse::Error("busy".into())),
            Ok(IpcResponse::Ok),
        ] {
            let outcome = refresh_tick(
                &mut access_token,
                &mut pending,
                &store,
                "refresh",
                |refresh| {
                    exchanges += 1;
                    assert_eq!(refresh, "old-refresh");
                    let token = new_token.clone();
                    async move {
                        RefreshOutcome::Success(OAuthTokens {
                            access_token: token,
                            refresh_token: Some("rotated-refresh".into()),
                        })
                    }
                },
                |token| {
                    delivered.push(token);
                    async move { reply }
                },
            )
            .await;
            match outcome {
                Err(_) => {
                    assert_eq!(access_token, old_token);
                    assert_eq!(pending.as_deref(), Some(new_token.as_str()));
                }
                Ok(outcome) => {
                    assert_eq!(outcome, TickOutcome::Delivered);
                    assert_eq!(access_token, new_token);
                    assert!(pending.is_none());
                }
            }
        }
        assert_eq!(exchanges, 1);
        assert_eq!(delivered, vec![new_token.clone(); 3]);
        assert_eq!(store.secret("refresh").as_deref(), Some("rotated-refresh"));

        let outcome = refresh_tick(
            &mut access_token,
            &mut pending,
            &store,
            "refresh",
            |_| async { panic!("acknowledged fresh token should not be refreshed") },
            |_| async { panic!("acknowledged fresh token should not be sent again") },
        )
        .await
        .unwrap();
        assert_eq!(outcome, TickOutcome::Skipped);
    }

    #[tokio::test]
    async fn expired_pending_token_is_replaced_before_delivery() {
        let store = MemorySecretStore::default();
        store.set_secret("refresh", "rotated-refresh").unwrap();
        let mut access_token = token_with_lifetime(0);
        let mut pending = Some(access_token.clone());
        let new_token = token_with_lifetime(900);
        refresh_tick(
            &mut access_token,
            &mut pending,
            &store,
            "refresh",
            |refresh| {
                assert_eq!(refresh, "rotated-refresh");
                let token = new_token.clone();
                async move {
                    RefreshOutcome::Success(OAuthTokens {
                        access_token: token,
                        refresh_token: None,
                    })
                }
            },
            |token| {
                assert_eq!(token, new_token);
                async { Ok(IpcResponse::Ok) }
            },
        )
        .await
        .unwrap();
        assert_eq!(access_token, new_token);
        assert!(pending.is_none());
    }

    #[tokio::test]
    async fn network_failure_keeps_the_current_token_and_refresh_token() {
        let store = MemorySecretStore::default();
        store.set_secret("refresh", "valid-refresh").unwrap();
        let old_token = token_with_lifetime(240);
        let mut access_token = old_token.clone();
        let mut pending = None;
        let outcome = refresh_tick(
            &mut access_token,
            &mut pending,
            &store,
            "refresh",
            |_| async { RefreshOutcome::NetworkError("offline".into()) },
            |_| async { panic!("no token to deliver") },
        )
        .await;
        assert!(matches!(outcome, Err(TickError::Network(_))));
        assert_eq!(access_token, old_token);
        assert!(pending.is_none());
        assert_eq!(store.secret("refresh").as_deref(), Some("valid-refresh"));
    }
}
