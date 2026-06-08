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
