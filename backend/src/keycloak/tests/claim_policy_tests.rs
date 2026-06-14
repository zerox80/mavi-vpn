use super::*;

#[test]
fn validate_claims_returns_exp_on_success() {
    let claims = serde_json::json!({
        "typ": "Bearer",
        "exp": 1100,
        "azp": "my-client"
    });
    assert_eq!(
        KeycloakValidator::validate_claims_with_policy(&claims, "my-client", 1000, 30, None, None),
        Some(1100)
    );
}

#[test]
fn validate_claims_rejects_missing_typ() {
    let claims = serde_json::json!({
        "exp": 1100,
        "azp": "my-client"
    });
    assert!(!KeycloakValidator::validate_claims(
        &claims,
        "my-client",
        1000,
        30
    ));
}

#[test]
fn validate_claims_rejects_id_token_typ() {
    let claims = serde_json::json!({
        "typ": "ID",
        "exp": 1100,
        "azp": "my-client"
    });
    assert!(!KeycloakValidator::validate_claims(
        &claims,
        "my-client",
        1000,
        30
    ));
}

#[test]
fn validate_claims_accepts_required_realm_role() {
    let claims = serde_json::json!({
        "typ": "Bearer",
        "exp": 1100,
        "azp": "my-client",
        "realm_access": {
            "roles": ["vpn-user"]
        }
    });

    assert!(KeycloakValidator::validate_claims_with_policy(
        &claims,
        "my-client",
        1000,
        30,
        Some("vpn-user"),
        None
    )
    .is_some());
}

#[test]
fn validate_claims_accepts_required_client_role() {
    let claims = serde_json::json!({
        "typ": "Bearer",
        "exp": 1100,
        "azp": "my-client",
        "resource_access": {
            "my-client": {
                "roles": ["vpn-user"]
            }
        }
    });

    assert!(KeycloakValidator::validate_claims_with_policy(
        &claims,
        "my-client",
        1000,
        30,
        Some("vpn-user"),
        None
    )
    .is_some());
}

#[test]
fn validate_claims_rejects_missing_required_role() {
    let claims = serde_json::json!({
        "typ": "Bearer",
        "exp": 1100,
        "azp": "my-client",
        "realm_access": {
            "roles": ["other-role"]
        }
    });

    assert!(KeycloakValidator::validate_claims_with_policy(
        &claims,
        "my-client",
        1000,
        30,
        Some("vpn-user"),
        None
    )
    .is_none());
}

#[test]
fn validate_claims_accepts_required_scope() {
    let claims = serde_json::json!({
        "typ": "Bearer",
        "exp": 1100,
        "azp": "my-client",
        "scope": "openid profile vpn:connect"
    });

    assert!(KeycloakValidator::validate_claims_with_policy(
        &claims,
        "my-client",
        1000,
        30,
        None,
        Some("vpn:connect")
    )
    .is_some());
}

#[test]
fn validate_claims_rejects_missing_required_scope() {
    let claims = serde_json::json!({
        "typ": "Bearer",
        "exp": 1100,
        "azp": "my-client",
        "scope": "openid profile"
    });

    assert!(KeycloakValidator::validate_claims_with_policy(
        &claims,
        "my-client",
        1000,
        30,
        None,
        Some("vpn:connect")
    )
    .is_none());
}
