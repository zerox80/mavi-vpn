use super::*;
use crate::secrets::tests::MemorySecretStore;

fn test_config() -> Config {
    Config {
        endpoint: "vpn.example.com:443".to_string(),
        token: "token".to_string(),
        cert_pin: "pin".to_string(),
        censorship_resistant: false,
        http3_framing: false,
        kc_auth: None,
        kc_url: None,
        kc_realm: None,
        kc_client_id: None,
        ech_config: None,
        vpn_mtu: None,
    }
}

#[test]
fn save_config_redacts_token_and_load_merges_secret() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let store = MemorySecretStore::default();

    save_config_to_path(&path, &test_config(), &store).unwrap();
    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(!raw.contains("\"token\": \"token\""));
    assert_eq!(
        store.secret(config_token_account()).as_deref(),
        Some("token")
    );

    let loaded = load_config_from_path(&path, &store).unwrap().unwrap();
    assert_eq!(loaded.token, "token");
}

#[test]
fn load_config_migrates_legacy_plaintext_token() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    std::fs::write(
        &path,
        r#"{
  "endpoint": "vpn.example.com:443",
  "token": "legacy-token",
  "cert_pin": "pin",
  "censorship_resistant": false,
  "http3_framing": false,
  "kc_auth": null,
  "kc_url": null,
  "kc_realm": null,
  "kc_client_id": null,
  "ech_config": null
}"#,
    )
    .unwrap();
    let store = MemorySecretStore::default();

    let loaded = load_config_from_path(&path, &store).unwrap().unwrap();

    assert_eq!(loaded.token, "legacy-token");
    assert_eq!(
        store.secret(config_token_account()).as_deref(),
        Some("legacy-token")
    );
    assert!(!std::fs::read_to_string(&path)
        .unwrap()
        .contains("legacy-token"));
}

#[test]
fn save_config_deletes_empty_token_secret() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let store = MemorySecretStore::default();
    store
        .set_secret(config_token_account(), "stale-token")
        .unwrap();
    let mut config = test_config();
    config.token.clear();

    save_config_to_path(&path, &config, &store).unwrap();
    let loaded = load_config_from_path(&path, &store).unwrap().unwrap();

    assert!(loaded.token.is_empty());
    assert!(store
        .deleted()
        .contains(&config_token_account().to_string()));
}

#[test]
fn load_config_returns_none_when_file_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nonexistent.json");
    let store = MemorySecretStore::default();

    let result = load_config_from_path(&path, &store).unwrap();
    assert!(result.is_none());
}

#[test]
fn save_and_load_config_preserves_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let store = MemorySecretStore::default();
    let config = test_config();

    save_config_to_path(&path, &config, &store).unwrap();
    let loaded = load_config_from_path(&path, &store).unwrap().unwrap();

    assert_eq!(loaded.endpoint, "vpn.example.com:443");
    assert_eq!(loaded.cert_pin, "pin");
}

#[test]
fn save_and_load_config_preserves_boolean_flags() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let store = MemorySecretStore::default();
    let mut config = test_config();
    config.censorship_resistant = true;
    config.http3_framing = true;

    save_config_to_path(&path, &config, &store).unwrap();
    let loaded = load_config_from_path(&path, &store).unwrap().unwrap();

    assert!(loaded.censorship_resistant);
    assert!(loaded.http3_framing);
}

#[test]
fn save_and_load_config_preserves_keycloak_fields() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let store = MemorySecretStore::default();
    let mut config = test_config();
    config.kc_auth = Some(true);
    config.kc_url = Some("https://auth.example.com".to_string());
    config.kc_realm = Some("test-realm".to_string());
    config.kc_client_id = Some("test-client".to_string());

    save_config_to_path(&path, &config, &store).unwrap();
    let loaded = load_config_from_path(&path, &store).unwrap().unwrap();

    assert_eq!(loaded.kc_auth, Some(true));
    assert_eq!(loaded.kc_url.as_deref(), Some("https://auth.example.com"));
    assert_eq!(loaded.kc_realm.as_deref(), Some("test-realm"));
    assert_eq!(loaded.kc_client_id.as_deref(), Some("test-client"));
}

#[test]
fn save_and_load_config_preserves_vpn_mtu() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let store = MemorySecretStore::default();
    let mut config = test_config();
    config.vpn_mtu = Some(1340);

    save_config_to_path(&path, &config, &store).unwrap();
    let loaded = load_config_from_path(&path, &store).unwrap().unwrap();

    assert_eq!(loaded.vpn_mtu, Some(1340));
}

#[test]
fn save_and_load_config_preserves_ech_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let store = MemorySecretStore::default();
    let mut config = test_config();
    config.ech_config = Some("deadbeef".to_string());

    save_config_to_path(&path, &config, &store).unwrap();
    let loaded = load_config_from_path(&path, &store).unwrap().unwrap();

    assert_eq!(loaded.ech_config.as_deref(), Some("deadbeef"));
}

#[test]
fn config_path_contains_mavi_vpn_directory() {
    let path = config_path();
    let path_str = path.to_string_lossy();
    assert!(path_str.contains("MaviVPN"));
}

#[test]
fn config_path_ends_with_config_json() {
    let path = config_path();
    assert_eq!(path.file_name().unwrap(), "config.json");
}

#[test]
fn load_config_handles_invalid_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    std::fs::write(&path, "not valid json {{{").unwrap();
    let store = MemorySecretStore::default();

    let result = load_config_from_path(&path, &store);
    assert!(result.is_err());
}

#[test]
fn load_config_empty_token_without_secret_returns_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    std::fs::write(
        &path,
        r#"{
  "endpoint": "vpn.example.com:443",
  "token": "",
  "cert_pin": "pin",
  "censorship_resistant": false,
  "http3_framing": false,
  "kc_auth": null,
  "kc_url": null,
  "kc_realm": null,
  "kc_client_id": null,
  "ech_config": null
}"#,
    )
    .unwrap();
    let store = MemorySecretStore::default();

    let loaded = load_config_from_path(&path, &store).unwrap().unwrap();
    assert!(loaded.token.is_empty());
}

#[test]
fn save_and_load_config_preserves_vpn_mtu_boundary_values() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let store = MemorySecretStore::default();

    let mut config = test_config();
    config.vpn_mtu = Some(1280);
    save_config_to_path(&path, &config, &store).unwrap();
    let loaded = load_config_from_path(&path, &store).unwrap().unwrap();
    assert_eq!(loaded.vpn_mtu, Some(1280));

    config.vpn_mtu = Some(1360);
    save_config_to_path(&path, &config, &store).unwrap();
    let loaded = load_config_from_path(&path, &store).unwrap().unwrap();
    assert_eq!(loaded.vpn_mtu, Some(1360));
}

#[test]
fn save_config_normalizes_transport_before_writing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let store = MemorySecretStore::default();
    let mut config = test_config();
    config.censorship_resistant = true;
    config.http3_framing = false;

    save_config_to_path(&path, &config, &store).unwrap();
    let loaded = load_config_from_path(&path, &store).unwrap().unwrap();

    assert!(loaded.censorship_resistant);
    assert!(loaded.http3_framing);
}

#[test]
fn load_config_normalizes_transport_on_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    std::fs::write(
        &path,
        r#"{
  "endpoint": "vpn.example.com:443",
  "token": "token",
  "cert_pin": "pin",
  "censorship_resistant": true,
  "http3_framing": false,
  "kc_auth": null,
  "kc_url": null,
  "kc_realm": null,
  "kc_client_id": null,
  "ech_config": null
}"#,
    )
    .unwrap();
    let store = MemorySecretStore::default();

    let loaded = load_config_from_path(&path, &store).unwrap().unwrap();
    assert!(loaded.censorship_resistant);
    assert!(loaded.http3_framing);
}
