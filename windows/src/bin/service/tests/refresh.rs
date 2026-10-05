use super::*;
use crate::state::PendingKeycloakRefreshToken;

fn keycloak_auth() -> ipc::KeycloakRuntimeAuth {
    ipc::KeycloakRuntimeAuth {
        connection_id: "profile".into(),
        kc_url: "https://auth.example.com".into(),
        realm: "mavi-vpn".into(),
        client_id: "mavi-client".into(),
        refresh_token: "new-login-refresh".into(),
    }
}

#[tokio::test]
async fn keycloak_start_does_not_deliver_previous_sessions_rotation() {
    let mut state = VpnServiceState::new();
    state.mark_session_starting(TEST_USER_SID, test_config(), Some("profile"));
    let previous = state.runtime_handles();
    state.stop_session();
    previous.publish_keycloak_refresh_token(PendingKeycloakRefreshToken {
        connection_id: "profile".into(),
        refresh_token: "old-session-rotation".into(),
    });

    let keycloak = keycloak_auth();
    let response = handle_start_request(test_config(), Some(keycloak), &mut state);
    assert!(matches!(response, ipc::IpcResponse::Ok));

    if let Some(task) = state.take_task() {
        task.abort();
    }
    state.stop_session();
    previous.publish_keycloak_refresh_token(PendingKeycloakRefreshToken {
        connection_id: "profile".into(),
        refresh_token: "late-old-session-rotation".into(),
    });
    let state = Arc::new(Mutex::new(state));
    assert!(matches!(
        dispatch_request(ipc::IpcRequest::TakeRefreshTokenUpdate, &state).await,
        ipc::IpcResponse::RefreshTokenUpdate {
            connection_id: None,
            refresh_token: None,
        }
    ));
}

#[tokio::test]
async fn refresh_dispatch_restricts_fetch_and_ack_to_the_starting_user() {
    let state = Arc::new(Mutex::new(VpnServiceState::new()));
    assert!(matches!(
        dispatch_for_caller(
            ipc::IpcRequest::StartWithKeycloak {
                config: test_config(),
                keycloak: keycloak_auth(),
            },
            &state,
            TEST_USER_SID
        )
        .await,
        ipc::IpcResponse::Ok
    ));
    {
        let mut guard = state.lock().await;
        guard
            .runtime_handles()
            .publish_keycloak_refresh_token(PendingKeycloakRefreshToken {
                connection_id: "profile".into(),
                refresh_token: "owner-secret".into(),
            });
        if let Some(task) = guard.take_task() {
            task.abort();
        }
    }
    assert!(matches!(
        dispatch_for_caller(ipc::IpcRequest::Stop, &state, "").await,
        ipc::IpcResponse::Ok
    ));
    let other_user = "S-1-5-21-2000";
    assert!(matches!(
        dispatch_for_caller(ipc::IpcRequest::TakeRefreshTokenUpdate, &state, other_user).await,
        ipc::IpcResponse::RefreshTokenUpdate {
            connection_id: None,
            refresh_token: None
        }
    ));
    let ack = || ipc::IpcRequest::AcknowledgeRefreshTokenUpdate {
        connection_id: "profile".into(),
        refresh_token: "owner-secret".into(),
    };
    assert!(matches!(
        dispatch_for_caller(ack(), &state, other_user).await,
        ipc::IpcResponse::Ok
    ));
    match dispatch_for_caller(
        ipc::IpcRequest::TakeRefreshTokenUpdate,
        &state,
        TEST_USER_SID,
    )
    .await
    {
        ipc::IpcResponse::RefreshTokenUpdate {
            connection_id,
            refresh_token,
        } => {
            assert_eq!(connection_id.as_deref(), Some("profile"));
            assert_eq!(refresh_token.as_deref(), Some("owner-secret"));
        }
        response => panic!("Unexpected response: {response:?}"),
    }
    assert!(matches!(
        dispatch_for_caller(ack(), &state, TEST_USER_SID).await,
        ipc::IpcResponse::Ok
    ));
    assert!(state
        .lock()
        .await
        .pending_keycloak_refresh_token(TEST_USER_SID)
        .is_none());
}

#[tokio::test]
async fn sensitive_requests_require_identity_but_status_and_stop_remain_available() {
    let state = Arc::new(Mutex::new(VpnServiceState::new()));
    let requests = [
        ipc::IpcRequest::StartWithKeycloak {
            config: test_config(),
            keycloak: keycloak_auth(),
        },
        ipc::IpcRequest::TakeRefreshTokenUpdate,
        ipc::IpcRequest::AcknowledgeRefreshTokenUpdate {
            connection_id: "profile".into(),
            refresh_token: "secret".into(),
        },
    ];
    for request in requests {
        assert!(matches!(
            dispatch_for_caller(request, &state, "").await,
            ipc::IpcResponse::Error(_)
        ));
    }
    assert!(!state.lock().await.is_running());
    assert!(matches!(
        dispatch_for_caller(ipc::IpcRequest::Status, &state, "").await,
        ipc::IpcResponse::Status { .. }
    ));
    assert!(matches!(
        dispatch_for_caller(ipc::IpcRequest::Stop, &state, "").await,
        ipc::IpcResponse::Ok
    ));
}
