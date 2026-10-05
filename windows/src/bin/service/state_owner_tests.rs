use super::tests::test_config;
use super::{PendingKeycloakRefreshToken, VpnServiceState};

const ALICE: &str = "S-1-5-21-1000";
const BOB: &str = "S-1-5-21-2000";

fn rotation(token: &str) -> PendingKeycloakRefreshToken {
    PendingKeycloakRefreshToken {
        connection_id: "shared-profile-id".into(),
        refresh_token: token.into(),
    }
}

#[test]
fn another_user_cannot_fetch_or_acknowledge_a_stopped_sessions_rotation() {
    let mut state = VpnServiceState::new();
    state.mark_session_starting(ALICE, test_config(), Some("shared-profile-id"));
    state
        .runtime_handles()
        .publish_keycloak_refresh_token(rotation("alice-secret"));
    state.stop_session();

    assert!(state.pending_keycloak_refresh_token(BOB).is_none());
    assert!(state.pending_keycloak_refresh_token("").is_none());
    state.acknowledge_keycloak_refresh_token(BOB, "shared-profile-id", "alice-secret");
    state.acknowledge_keycloak_refresh_token("", "shared-profile-id", "alice-secret");
    assert_eq!(
        state.pending_keycloak_refresh_token(ALICE),
        Some(rotation("alice-secret"))
    );
    state.acknowledge_keycloak_refresh_token(ALICE, "shared-profile-id", "alice-secret");
    assert!(state.pending_keycloak_refresh_token(ALICE).is_none());
}

#[test]
fn same_profile_id_in_another_account_neither_retires_nor_supersedes_owner_tokens() {
    let mut state = VpnServiceState::new();
    state.mark_session_starting(ALICE, test_config(), Some("shared-profile-id"));
    let alice = state.runtime_handles();
    alice.publish_keycloak_refresh_token(rotation("alice-secret"));
    state.stop_session();
    state.mark_session_starting(BOB, test_config(), Some("shared-profile-id"));
    assert_eq!(
        state.pending_keycloak_refresh_token(ALICE),
        Some(rotation("alice-secret"))
    );
    let bob = state.runtime_handles();
    bob.publish_keycloak_refresh_token(rotation("bob-old-secret"));
    bob.publish_keycloak_refresh_token(rotation("bob-new-secret"));
    // A late response must not publish into Bob's session or replace Alice's queue.
    alice.publish_keycloak_refresh_token(rotation("alice-late-secret"));
    state.stop_session();

    assert_eq!(
        state.pending_keycloak_refresh_token(BOB),
        Some(rotation("bob-new-secret"))
    );
    state.acknowledge_keycloak_refresh_token(BOB, "shared-profile-id", "bob-old-secret");
    assert_eq!(
        state.pending_keycloak_refresh_token(BOB),
        Some(rotation("bob-new-secret"))
    );
    state.acknowledge_keycloak_refresh_token(BOB, "shared-profile-id", "bob-new-secret");
    assert!(state.pending_keycloak_refresh_token(BOB).is_none());
    assert_eq!(
        state.pending_keycloak_refresh_token(ALICE),
        Some(rotation("alice-secret"))
    );
}

#[test]
fn identical_profile_and_token_still_require_the_original_owner() {
    let mut state = VpnServiceState::new();
    for owner in [ALICE, BOB] {
        state.mark_session_starting(owner, test_config(), Some("shared-profile-id"));
        state
            .runtime_handles()
            .publish_keycloak_refresh_token(rotation("same-secret"));
        state.stop_session();
    }
    state.acknowledge_keycloak_refresh_token(BOB, "shared-profile-id", "same-secret");
    assert!(state.pending_keycloak_refresh_token(BOB).is_none());
    assert_eq!(
        state.pending_keycloak_refresh_token(ALICE),
        Some(rotation("same-secret"))
    );
}

#[test]
fn runtime_without_an_owner_cannot_publish_credentials() {
    let mut state = VpnServiceState::new();
    state.mark_session_starting("", test_config(), None);
    state
        .runtime_handles()
        .publish_keycloak_refresh_token(rotation("ownerless-secret"));
    for owner in ["", ALICE, BOB] {
        assert!(state.pending_keycloak_refresh_token(owner).is_none());
    }
}
