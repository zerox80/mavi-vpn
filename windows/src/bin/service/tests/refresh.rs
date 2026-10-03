use super::*;
use crate::state::PendingKeycloakRefreshToken;

#[tokio::test]
async fn keycloak_start_does_not_deliver_previous_sessions_rotation() {
    let mut state = VpnServiceState::new();
    state.mark_session_starting(test_config(), Some("profile"));
    let previous = state.runtime_handles();
    state.stop_session();
    previous.publish_keycloak_refresh_token(PendingKeycloakRefreshToken {
        connection_id: "profile".into(),
        refresh_token: "old-session-rotation".into(),
    });

    let keycloak = ipc::KeycloakRuntimeAuth {
        connection_id: "profile".into(),
        kc_url: "https://auth.example.com".into(),
        realm: "mavi-vpn".into(),
        client_id: "mavi-client".into(),
        refresh_token: "new-login-refresh".into(),
    };
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
