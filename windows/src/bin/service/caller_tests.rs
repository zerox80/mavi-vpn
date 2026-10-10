use super::*;
use crate::caller::SessionOwner;
use crate::state::PendingKeycloakRefreshToken;

fn user(sid: &str, session_id: u32) -> Caller {
    Caller {
        owner: SessionOwner {
            sid: sid.into(),
            session_id,
            logon_id: (session_id, 0),
        },
        privileged: false,
    }
}

#[tokio::test]
async fn refreshed_token_is_only_delivered_to_its_logon_owner() {
    let state = Arc::new(Mutex::new(VpnServiceState::new()));
    let alice = user("S-1-5-21-1", 1);
    let bob = user("S-1-5-21-2", 2);
    {
        let mut guard = state.lock().await;
        guard.session_owner = Some(alice.owner.clone());
        guard
            .runtime_handles()
            .publish_keycloak_refresh_token(PendingKeycloakRefreshToken {
                connection_id: "same-profile-id".into(),
                refresh_token: "alice-secret".into(),
            });
    }
    for caller in [&bob, &Caller::test_admin()] {
        let response = dispatch_as(
            ipc::IpcRequest::TakeRefreshTokenUpdate,
            &state,
            caller,
            || Some((bob.owner.sid.clone(), 2)),
        )
        .await;
        assert!(matches!(response, ipc::IpcResponse::Error(_)));
    }
    let mut new_logon = user(&alice.owner.sid, 1);
    new_logon.owner.logon_id = (9999, 0);
    assert!(matches!(
        dispatch_as(
            ipc::IpcRequest::TakeRefreshTokenUpdate,
            &state,
            &new_logon,
            || Some((alice.owner.sid.clone(), 1))
        )
        .await,
        ipc::IpcResponse::Error(_)
    ));
    // Unauthorized reads did not consume the owner's pending secret.
    assert!(
        matches!(dispatch_as(ipc::IpcRequest::TakeRefreshTokenUpdate, &state, &alice, || Some((alice.owner.sid.clone(), 1))).await, ipc::IpcResponse::RefreshTokenUpdate { refresh_token: Some(token), .. } if token == "alice-secret")
    );
}

#[tokio::test]
async fn queued_request_rechecks_console_after_acquiring_state_lock() {
    let state = Arc::new(Mutex::new(VpnServiceState::new()));
    let guard = state.lock().await;
    let console = Arc::new(std::sync::Mutex::new(Some(("S-1-5-21-1".into(), 1))));
    let task_state = state.clone();
    let task_console = console.clone();
    let task = tokio::spawn(async move {
        dispatch_as(
            ipc::IpcRequest::UpdateToken {
                token: "old-user-token".into(),
            },
            &task_state,
            &user("S-1-5-21-1", 1),
            || task_console.lock().unwrap().clone(),
        )
        .await
    });
    tokio::task::yield_now().await;
    *console.lock().unwrap() = Some(("S-1-5-21-2".into(), 2));
    drop(guard);
    assert!(matches!(task.await.unwrap(), ipc::IpcResponse::Error(_)));
    assert!(state.lock().await.current_token.lock().unwrap().is_empty());
}
