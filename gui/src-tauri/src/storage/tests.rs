use super::*;
use crate::secret_store::tests::MemorySecretStore;

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

#[test]
fn prefs_accepts_valid_hex_accent() {
    let prefs: Prefs = serde_json::from_str(r##"{"accent": "#AB12ef"}"##).unwrap();
    assert_eq!(prefs.accent, "#AB12ef");
}

#[test]
fn prefs_falls_back_to_default_accent_for_invalid_values() {
    for bad in [
        "red",
        "#12345",   // too short
        "#1234567", // too long
        "#GGGGGG",  // non-hex digits
        "javascript:alert(1)",
        "\"></style><script>alert(1)</script>",
    ] {
        let json = serde_json::json!({ "accent": bad }).to_string();
        let prefs: Prefs = serde_json::from_str(&json).unwrap();
        assert_eq!(prefs.accent, default_accent(), "input was: {bad:?}");
    }
}

#[test]
fn prefs_defaults_accent_when_absent() {
    let prefs: Prefs = serde_json::from_str("{}").unwrap();
    assert_eq!(prefs.accent, default_accent());
}

#[test]
fn missing_config_returns_none() {
    let dir = tempfile::tempdir().unwrap();

    let config = load_config_from_dir(dir.path()).unwrap();

    assert!(config.is_none());
}

#[test]
fn config_roundtrip_normalizes_transport_before_save() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config();
    config.censorship_resistant = true;
    config.http3_framing = false;

    let store = MemorySecretStore::default();
    save_config_to_dir_with_store(dir.path(), &mut config, &store).unwrap();
    let loaded = load_config_from_dir_with_store(dir.path(), &store)
        .unwrap()
        .unwrap();

    assert!(loaded.http3_framing);
    assert_eq!(loaded.token, "token");
    assert!(!std::fs::read_to_string(dir.path().join("config.json"))
        .unwrap()
        .contains("\"token\": \"token\""));
}

#[test]
fn corrupt_config_json_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("config.json"), "{not-json").unwrap();

    let result = load_config_from_dir(dir.path());

    assert!(result.is_err());
}

#[test]
fn missing_prefs_returns_defaults() {
    let dir = tempfile::tempdir().unwrap();

    let prefs = load_prefs_from_dir(dir.path()).unwrap();

    assert_eq!(prefs.theme, "light");
    assert_eq!(prefs.accent, "#2B44FF");
    assert!(prefs.connections.is_empty());
}

#[test]
fn prefs_roundtrip_normalizes_connection_transport() {
    let dir = tempfile::tempdir().unwrap();
    let mut prefs = Prefs {
        connections: vec![SavedConn {
            id: "one".to_string(),
            label: "One".to_string(),
            endpoint: "vpn.example.com:443".to_string(),
            token: Some("token".to_string()),
            cert_pin: "pin".to_string(),
            censorship_resistant: true,
            http3_framing: false,
            ..SavedConn::default()
        }],
        ..Prefs::default()
    };

    let store = MemorySecretStore::default();
    save_prefs_to_dir_with_store(dir.path(), &mut prefs, &store).unwrap();
    let loaded = load_prefs_from_dir_with_store(dir.path(), &store).unwrap();

    assert!(loaded.connections[0].http3_framing);
    assert_eq!(loaded.connections[0].token.as_deref(), Some("token"));
    assert!(!std::fs::read_to_string(dir.path().join("prefs.json"))
        .unwrap()
        .contains("token"));
}

#[test]
fn load_prefs_migrates_legacy_plaintext_token() {
    let dir = tempfile::tempdir().unwrap();
    let prefs_path = dir.path().join("prefs.json");
    std::fs::write(
        &prefs_path,
        r#"{
  "connections": [{
    "id": "one",
    "label": "One",
    "endpoint": "vpn.example.com:443",
    "token": "legacy-token",
    "cert_pin": "pin"
  }]
}"#,
    )
    .unwrap();
    let store = MemorySecretStore::default();

    let loaded = load_prefs_from_dir_with_store(dir.path(), &store).unwrap();

    assert_eq!(loaded.connections[0].token.as_deref(), Some("legacy-token"));
    assert_eq!(
        store.secret(&connection_token_account("one")).as_deref(),
        Some("legacy-token")
    );
    assert!(!std::fs::read_to_string(&prefs_path)
        .unwrap()
        .contains("legacy-token"));
}

#[test]
fn save_prefs_deletes_removed_connection_secret() {
    let dir = tempfile::tempdir().unwrap();
    let mut prefs = Prefs {
        connections: vec![SavedConn {
            id: "one".to_string(),
            label: "One".to_string(),
            endpoint: "vpn.example.com:443".to_string(),
            token: Some("token".to_string()),
            cert_pin: "pin".to_string(),
            ..SavedConn::default()
        }],
        ..Prefs::default()
    };
    let store = MemorySecretStore::default();
    save_prefs_to_dir_with_store(dir.path(), &mut prefs, &store).unwrap();
    store
        .set_secret(&connection_refresh_token_account("one"), "refresh")
        .unwrap();

    prefs.connections.clear();
    save_prefs_to_dir_with_store(dir.path(), &mut prefs, &store).unwrap();

    assert!(store.deleted().contains(&connection_token_account("one")));
    assert!(store
        .deleted()
        .contains(&connection_refresh_token_account("one")));
}

#[test]
fn save_config_deletes_empty_token_secret() {
    let dir = tempfile::tempdir().unwrap();
    let store = MemorySecretStore::default();
    store
        .set_secret(legacy_config_token_account(), "stale-token")
        .unwrap();
    let mut config = test_config();
    config.token.clear();

    save_config_to_dir_with_store(dir.path(), &mut config, &store).unwrap();
    let loaded = load_config_from_dir_with_store(dir.path(), &store)
        .unwrap()
        .unwrap();

    assert!(loaded.token.is_empty());
    assert!(store
        .deleted()
        .contains(&legacy_config_token_account().to_string()));
}
