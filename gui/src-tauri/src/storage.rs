use shared::ipc::Config;
use std::path::Path;

#[derive(serde::Serialize, serde::Deserialize, Clone, Default)]
struct SavedConn {
    id: String,
    label: String,
    endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
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
    std::fs::create_dir_all(config_dir).map_err(|e| e.to_string())?;
    let config_path = config_dir.join("config.json");
    config.normalize_transport();
    let content = serde_json::to_string_pretty(config).map_err(|e| e.to_string())?;
    std::fs::write(&config_path, content).map_err(|e| e.to_string())?;
    Ok(())
}

pub(crate) fn load_config_from_dir(config_dir: &Path) -> Result<Option<Config>, String> {
    let config_path = config_dir.join("config.json");
    if !config_path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(config_path).map_err(|e| e.to_string())?;
    let mut config: Config = serde_json::from_str(&content).map_err(|e| e.to_string())?;
    config.normalize_transport();
    Ok(Some(config))
}

pub(crate) fn load_prefs_from_dir(config_dir: &Path) -> Result<Prefs, String> {
    let prefs_path = config_dir.join("prefs.json");
    if !prefs_path.exists() {
        return Ok(Prefs::default());
    }
    let content = std::fs::read_to_string(prefs_path).map_err(|e| e.to_string())?;
    let mut prefs: Prefs = serde_json::from_str(&content).map_err(|e| e.to_string())?;
    prefs.normalize_transport();
    Ok(prefs)
}

pub(crate) fn save_prefs_to_dir(config_dir: &Path, prefs: &mut Prefs) -> Result<(), String> {
    std::fs::create_dir_all(config_dir).map_err(|e| e.to_string())?;
    let prefs_path = config_dir.join("prefs.json");
    prefs.normalize_transport();
    let content = serde_json::to_string_pretty(prefs).map_err(|e| e.to_string())?;
    std::fs::write(&prefs_path, content).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

        save_config_to_dir(dir.path(), &mut config).unwrap();
        let loaded = load_config_from_dir(dir.path()).unwrap().unwrap();

        assert!(loaded.http3_framing);
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

        save_prefs_to_dir(dir.path(), &mut prefs).unwrap();
        let loaded = load_prefs_from_dir(dir.path()).unwrap();

        assert!(loaded.connections[0].http3_framing);
    }
}
