use crate::secret_store::{
    connection_token_account, legacy_config_token_account, KeyringSecretStore, SecretStore,
};
use shared::ipc::Config;
use std::path::Path;

#[derive(serde::Serialize, serde::Deserialize, Clone, Default)]
struct SavedConn {
    id: String,
    label: String,
    endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    /// SHA-256 fingerprint(s) of the server's TLS cert, hex-encoded. Normally
    /// a single 64-char value; during a manual server cert rotation this may
    /// be a comma-separated list ("<old_pin>,<new_pin>") so already-saved
    /// connections keep working until every client has picked up the new pin.
    cert_pin: String,
    #[serde(default)]
    ech_config: Option<String>,
    #[serde(default)]
    http3_framing: bool,
    #[serde(default)]
    censorship_resistant: bool,
    #[serde(default)]
    kc_auth: Option<bool>,
    #[serde(default)]
    kc_url: Option<String>,
    #[serde(default)]
    kc_realm: Option<String>,
    #[serde(default)]
    kc_client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vpn_mtu: Option<u16>,
}

impl SavedConn {
    const fn normalize_transport(&mut self) -> bool {
        let old_http3_framing = self.http3_framing;
        if self.censorship_resistant {
            self.http3_framing = true;
        }
        self.http3_framing != old_http3_framing
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub(crate) struct Prefs {
    #[serde(default = "default_theme")]
    theme: String,
    #[serde(default = "default_accent")]
    accent: String,
    #[serde(default)]
    connections: Vec<SavedConn>,
    #[serde(default)]
    active_id: Option<String>,
    #[serde(default)]
    legacy_config_migrated: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            theme: default_theme(),
            accent: default_accent(),
            connections: vec![],
            active_id: None,
            legacy_config_migrated: false,
        }
    }
}

impl Prefs {
    fn normalize_transport(&mut self) -> bool {
        let mut changed = false;
        for conn in &mut self.connections {
            changed |= conn.normalize_transport();
        }
        changed
    }
}

fn default_theme() -> String {
    "light".into()
}

fn default_accent() -> String {
    "#2B44FF".into()
}

pub(crate) fn save_config_to_dir(config_dir: &Path, config: &mut Config) -> Result<(), String> {
    save_config_to_dir_with_store(config_dir, config, &KeyringSecretStore)
}

fn save_config_to_dir_with_store(
    config_dir: &Path,
    config: &mut Config,
    store: &dyn SecretStore,
) -> Result<(), String> {
    std::fs::create_dir_all(config_dir).map_err(|e| e.to_string())?;
    let config_path = config_dir.join("config.json");
    config.normalize_transport();
    let mut redacted = config.clone();
    if !redacted.token.is_empty() {
        store.set_secret(legacy_config_token_account(), &redacted.token)?;
        redacted.token.clear();
    } else {
        store.delete_secret(legacy_config_token_account())?;
    }
    let content = serde_json::to_string_pretty(&redacted).map_err(|e| e.to_string())?;
    std::fs::write(&config_path, content).map_err(|e| e.to_string())?;
    Ok(())
}

pub(crate) fn load_config_from_dir(config_dir: &Path) -> Result<Option<Config>, String> {
    load_config_from_dir_with_store(config_dir, &KeyringSecretStore)
}

fn load_config_from_dir_with_store(
    config_dir: &Path,
    store: &dyn SecretStore,
) -> Result<Option<Config>, String> {
    let config_path = config_dir.join("config.json");
    if !config_path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(config_path).map_err(|e| e.to_string())?;
    let mut config: Config = serde_json::from_str(&content).map_err(|e| e.to_string())?;
    config.normalize_transport();
    if config.token.is_empty() {
        if let Some(secret) = store.get_secret(legacy_config_token_account())? {
            config.token = secret;
        }
    } else {
        save_config_to_dir_with_store(config_dir, &mut config, store)?;
    }
    Ok(Some(config))
}

pub(crate) fn load_prefs_from_dir(config_dir: &Path) -> Result<Prefs, String> {
    load_prefs_from_dir_with_store(config_dir, &KeyringSecretStore)
}

fn load_prefs_from_dir_with_store(
    config_dir: &Path,
    store: &dyn SecretStore,
) -> Result<Prefs, String> {
    let prefs_path = config_dir.join("prefs.json");
    if !prefs_path.exists() {
        return Ok(Prefs::default());
    }
    let content = std::fs::read_to_string(prefs_path).map_err(|e| e.to_string())?;
    let mut prefs: Prefs = serde_json::from_str(&content).map_err(|e| e.to_string())?;
    prefs.normalize_transport();
    let mut migrated_plaintext = false;
    for conn in &mut prefs.connections {
        if conn.token.as_deref().is_none_or(str::is_empty) {
            conn.token = store.get_secret(&connection_token_account(&conn.id))?;
        } else if let Some(token) = conn.token.clone() {
            store.set_secret(&connection_token_account(&conn.id), &token)?;
            conn.token = Some(token);
            migrated_plaintext = true;
        }
    }
    if migrated_plaintext {
        let mut redacted = prefs.clone();
        save_prefs_to_dir_with_store(config_dir, &mut redacted, store)?;
    }
    Ok(prefs)
}

pub(crate) fn save_prefs_to_dir(config_dir: &Path, prefs: &mut Prefs) -> Result<(), String> {
    save_prefs_to_dir_with_store(config_dir, prefs, &KeyringSecretStore)
}

fn save_prefs_to_dir_with_store(
    config_dir: &Path,
    prefs: &mut Prefs,
    store: &dyn SecretStore,
) -> Result<(), String> {
    std::fs::create_dir_all(config_dir).map_err(|e| e.to_string())?;
    let prefs_path = config_dir.join("prefs.json");
    let previous = if prefs_path.exists() {
        std::fs::read_to_string(&prefs_path)
            .ok()
            .and_then(|content| serde_json::from_str::<Prefs>(&content).ok())
            .unwrap_or_default()
    } else {
        Prefs::default()
    };

    prefs.normalize_transport();
    let mut redacted = prefs.clone();
    let current_ids = redacted
        .connections
        .iter()
        .map(|conn| conn.id.clone())
        .collect::<std::collections::HashSet<_>>();

    for conn in &mut redacted.connections {
        if let Some(token) = conn.token.as_deref().filter(|t| !t.is_empty()) {
            store.set_secret(&connection_token_account(&conn.id), token)?;
        }
        conn.token = None;
    }

    for old in previous.connections {
        if !current_ids.contains(&old.id) {
            store.delete_secret(&connection_token_account(&old.id))?;
        }
    }

    let content = serde_json::to_string_pretty(&redacted).map_err(|e| e.to_string())?;
    std::fs::write(&prefs_path, content).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_store::tests::MemorySecretStore;

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
            refresh_token: None,
            ech_config: None,
            vpn_mtu: None,
        }
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

        prefs.connections.clear();
        save_prefs_to_dir_with_store(dir.path(), &mut prefs, &store).unwrap();

        assert!(store.deleted().contains(&connection_token_account("one")));
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
}
