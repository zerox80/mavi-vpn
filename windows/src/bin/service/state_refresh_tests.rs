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
    state.mark_session_starting(test_config(), Some("profile"));
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
    state.mark_session_starting(test_config(), Some("profile"));
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
    state.mark_session_starting(test_config(), Some("profile-1"));
    let previous = state.runtime_handles();
    previous.publish_keycloak_refresh_token(update("profile-1", "rotation-1"));
    state.stop_session();
    state.mark_session_starting(test_config(), Some("profile-2"));
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
    state.mark_session_starting(test_config(), Some("profile"));
    let runtime = state.runtime_handles();
    state.stop_session();
    runtime.publish_keycloak_refresh_token(update("profile", "rotation-after-stop"));
    assert_eq!(
        state.pending_keycloak_refresh_token(),
        Some(update("profile", "rotation-after-stop"))
    );
}

#[test]
fn restarting_same_profile_retires_old_rotations_without_losing_other_profiles() {
    let mut state = VpnServiceState::new();
    state.mark_session_starting(test_config(), Some("other-profile"));
    state
        .runtime_handles()
        .publish_keycloak_refresh_token(update("other-profile", "unsaved-other-rotation"));
    state.stop_session();

    state.mark_session_starting(test_config(), Some("profile"));
    let previous = state.runtime_handles();
    state.stop_session();
    // The old response finishes after the GUI's pre-login drain, while new
    // login credentials are being saved under the operation lock.
    previous.publish_keycloak_refresh_token(update("profile", "old-session-rotation"));
    state.mark_session_starting(test_config(), Some("profile"));
    previous.publish_keycloak_refresh_token(update("profile", "late-old-session-rotation"));

    assert_eq!(
        state.pending_keycloak_refresh_token(),
        Some(update("other-profile", "unsaved-other-rotation"))
    );
    state.acknowledge_keycloak_refresh_token("other-profile", "unsaved-other-rotation");
    assert!(state.pending_keycloak_refresh_token().is_none());

    state
        .runtime_handles()
        .publish_keycloak_refresh_token(update("profile", "new-session-rotation"));
    state.acknowledge_keycloak_refresh_token("profile", "old-session-rotation");
    assert_eq!(
        state.pending_keycloak_refresh_token(),
        Some(update("profile", "new-session-rotation"))
    );
}

#[test]
fn starting_without_keycloak_preserves_all_unsaved_rotations() {
    let mut state = VpnServiceState::new();
    state.mark_session_starting(test_config(), Some("profile"));
    state
        .runtime_handles()
        .publish_keycloak_refresh_token(update("profile", "unsaved-rotation"));
    state.stop_session();
    state.mark_session_starting(test_config(), None);

    assert_eq!(
        state.pending_keycloak_refresh_token(),
        Some(update("profile", "unsaved-rotation"))
    );
}
