use super::*;
use crate::secret_store::tests::MemorySecretStore;
use std::cell::RefCell;

fn update() -> IpcResponse {
    IpcResponse::RefreshTokenUpdate {
        connection_id: Some("profile".into()),
        refresh_token: Some("rotated-secret".into()),
    }
}

#[tokio::test]
async fn acknowledges_only_after_keyring_storage_and_retries_lost_acknowledgements() {
    let store = MemorySecretStore::default();
    let account = connection_refresh_token_account("profile");
    let requests = RefCell::new(Vec::new());

    for acknowledgement_delivered in [false, true] {
        let result = sync_refresh_token_update(&store, |request| {
            let response = match &request {
                IpcRequest::TakeRefreshTokenUpdate => Ok(update()),
                IpcRequest::AcknowledgeRefreshTokenUpdate {
                    connection_id,
                    refresh_token,
                } => {
                    assert_eq!(connection_id, "profile");
                    assert_eq!(refresh_token, "rotated-secret");
                    assert_eq!(store.secret(&account).as_deref(), Some("rotated-secret"));
                    if acknowledgement_delivered {
                        Ok(IpcResponse::Ok)
                    } else {
                        Err("pipe disconnected".into())
                    }
                }
                other => panic!("Unexpected request {other:?}"),
            };
            requests.borrow_mut().push(request);
            std::future::ready(response)
        })
        .await;
        assert_eq!(result.is_ok(), acknowledgement_delivered);
    }
    assert_eq!(requests.borrow().len(), 4);
}

struct FailingStore;

impl SecretStore for FailingStore {
    fn set_secret(&self, _: &str, _: &str) -> Result<(), String> {
        Err("keyring unavailable".into())
    }

    fn get_secret(&self, _: &str) -> Result<Option<String>, String> {
        unreachable!()
    }

    fn delete_secret(&self, _: &str) -> Result<(), String> {
        unreachable!()
    }
}

#[tokio::test]
async fn keyring_failure_leaves_the_update_unacknowledged() {
    let result = sync_refresh_token_update(&FailingStore, |request| {
        assert_eq!(request, IpcRequest::TakeRefreshTokenUpdate);
        std::future::ready(Ok(update()))
    })
    .await;
    assert_eq!(result.unwrap_err(), "keyring unavailable");
}

#[tokio::test]
async fn no_pending_update_does_not_write_or_acknowledge() {
    let result = sync_refresh_token_update(&FailingStore, |request| {
        assert_eq!(request, IpcRequest::TakeRefreshTokenUpdate);
        std::future::ready(Ok(IpcResponse::RefreshTokenUpdate {
            connection_id: None,
            refresh_token: None,
        }))
    })
    .await;
    assert!(!result.unwrap());
}

#[tokio::test]
async fn rejected_acknowledgement_is_retryable() {
    let store = MemorySecretStore::default();
    let result = sync_refresh_token_update(&store, |request| {
        std::future::ready(Ok(match request {
            IpcRequest::TakeRefreshTokenUpdate => update(),
            IpcRequest::AcknowledgeRefreshTokenUpdate { .. } => IpcResponse::Error("retry".into()),
            other => panic!("Unexpected request {other:?}"),
        }))
    })
    .await;
    assert_eq!(result.unwrap_err(), "retry");
}
