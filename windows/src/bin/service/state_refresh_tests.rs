use super::{tests::test_config, PendingKeycloakRefreshToken, VpnServiceState};

fn update(connection_id: &str, refresh_token: &str) -> PendingKeycloakRefreshToken {
    PendingKeycloakRefreshToken {
        connection_id: connection_id.into(),
        refresh_token: refresh_token.into(),
    }
}

#[test]
fn fetching_and_stopping_preserve_rotations_until_exact_storage_confirmation() {
    let mut state = VpnServiceState::new();
    state.mark_session_starting(test_config());
    let runtime = state.runtime_handles();
    let rotated = update("profile", "rotated-secret");
    runtime.publish_keycloak_refresh_token(rotated.clone());

    for _ in 0..2 {
        assert_eq!(
            state.pending_keycloak_refresh_token(),
            Some(rotated.clone())
        );
    }
    state.stop_session();
    assert_eq!(
        state.pending_keycloak_refresh_token(),
        Some(rotated.clone())
    );

    state.acknowledge_keycloak_refresh_token("other-profile", "rotated-secret");
    state.acknowledge_keycloak_refresh_token("profile", "old-secret");
    assert_eq!(
        state.pending_keycloak_refresh_token(),
        Some(rotated.clone())
    );
    state.acknowledge_keycloak_refresh_token("profile", "rotated-secret");
    assert!(state.pending_keycloak_refresh_token().is_none());
    state.acknowledge_keycloak_refresh_token("profile", "rotated-secret");
    assert!(state.pending_keycloak_refresh_token().is_none());
}

#[test]
fn stale_acknowledgements_cannot_discard_a_newer_rotation() {
    let mut state = VpnServiceState::new();
    state.mark_session_starting(test_config());
    let runtime = state.runtime_handles();
    runtime.publish_keycloak_refresh_token(update("profile", "rotation-1"));
    let fetched = state.pending_keycloak_refresh_token().unwrap();
    runtime.publish_keycloak_refresh_token(update("profile", "rotation-2"));

    state.acknowledge_keycloak_refresh_token(&fetched.connection_id, &fetched.refresh_token);
    assert_eq!(
        state.pending_keycloak_refresh_token(),
        Some(update("profile", "rotation-2"))
    );
}

#[test]
fn switching_sessions_keeps_unsaved_rotations_for_each_profile() {
    let mut state = VpnServiceState::new();
    state.mark_session_starting(test_config());
    let previous = state.runtime_handles();
    previous.publish_keycloak_refresh_token(update("profile-1", "rotation-1"));
    state.stop_session();
    state.mark_session_starting(test_config());
    state
        .runtime_handles()
        .publish_keycloak_refresh_token(update("profile-2", "rotation-2"));

    // A cancelled old refresh must not overwrite tokens in the new session.
    previous.publish_keycloak_refresh_token(update("profile-1", "late-old-rotation"));
    assert_eq!(
        state.pending_keycloak_refresh_token(),
        Some(update("profile-1", "rotation-1"))
    );
    state.acknowledge_keycloak_refresh_token("profile-1", "rotation-1");
    assert_eq!(
        state.pending_keycloak_refresh_token(),
        Some(update("profile-2", "rotation-2"))
    );
}

#[test]
fn inflight_rotation_published_after_stop_is_still_available_for_storage() {
    let mut state = VpnServiceState::new();
    state.mark_session_starting(test_config());
    let runtime = state.runtime_handles();
    state.stop_session();
    runtime.publish_keycloak_refresh_token(update("profile", "rotation-after-stop"));
    assert_eq!(
        state.pending_keycloak_refresh_token(),
        Some(update("profile", "rotation-after-stop"))
    );
}
