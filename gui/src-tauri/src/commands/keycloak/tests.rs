use super::*;

fn test_config() -> Config {
    Config {
        endpoint: "vpn.example.com:443".to_string(),
        token: "token".to_string(),
        cert_pin: "pin".to_string(),
        censorship_resistant: false,
        http3_framing: false,
        http2_framing: false,
        kc_auth: None,
        kc_url: None,
        kc_realm: None,
        kc_client_id: None,
        refresh_token: None,
        ech_config: None,
        vpn_mtu: None,
    }
}

#[tokio::test]
async fn keycloak_config_requires_url() {
    let mut config = test_config();
    config.kc_auth = Some(true);
    config.kc_url = Some(String::new());

    let result = prepare_keycloak_config(&mut config, "test-conn", true).await;

    // Avoid `unwrap_err` so the success type (which holds a token) needs no
    // Debug impl; `.err()` discards the Ok value entirely.
    assert_eq!(
        result.err(),
        Some("Keycloak URL is not configured.".to_string())
    );
}

#[tokio::test]
async fn prepare_skips_when_keycloak_disabled() {
    let mut config = test_config();
    config.kc_auth = None;

    // No Keycloak, no session, token left as-is, no keyring/network touched.
    let result = prepare_keycloak_config(&mut config, "test-conn", true).await;

    assert!(result.unwrap().is_none());
    assert_eq!(config.token, "token");
}

#[test]
fn persist_refresh_token_skips_empty_values() {
    use crate::secret_store::tests::MemorySecretStore;

    let store = MemorySecretStore::default();
    persist_refresh_token(&store, "acc", None).unwrap();
    persist_refresh_token(&store, "acc", Some("")).unwrap();
    assert!(store.secret("acc").is_none());

    persist_refresh_token(&store, "acc", Some("refresh-xyz")).unwrap();
    assert_eq!(store.secret("acc").as_deref(), Some("refresh-xyz"));
}

#[test]
fn required_refresh_token_rejects_empty_values() {
    assert_eq!(
        required_refresh_token(Some(" refresh ")).unwrap(),
        "refresh"
    );
    assert!(required_refresh_token(None).is_err());
    assert!(required_refresh_token(Some("")).is_err());
    assert!(required_refresh_token(Some("   ")).is_err());
}
