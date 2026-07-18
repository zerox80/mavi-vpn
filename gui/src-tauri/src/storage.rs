use crate::secret_store::{
    connection_refresh_token_account, connection_token_account, legacy_config_token_account,
    KeyringSecretStore, SecretStore,
};
use serde::Deserialize;
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
    http2_framing: bool,
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
    fn normalize_transport(&mut self) -> bool {
        let old = (
            self.http2_framing,
            self.http3_framing,
            self.censorship_resistant,
        );
        if self.http2_framing {
            self.http3_framing = false;
            self.censorship_resistant = false;
        } else if self.censorship_resistant {
            self.http3_framing = true;
        }
        old != (
            self.http2_framing,
            self.http3_framing,
            self.censorship_resistant,
        )
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub(crate) struct Prefs {
    #[serde(default = "default_theme")]
    theme: String,
    /// Validated on the way in (from disk *and* from the frontend's
    /// `save_prefs` IPC call, since both deserialize through this struct):
    /// it is later interpolated into an SVG `innerHTML` template on the
    /// frontend, so a malformed value must never reach the UI layer.
    #[serde(default = "default_accent", deserialize_with = "deserialize_accent")]
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

/// Accepts only `#RRGGBB`; falls back to [`default_accent`] otherwise rather
/// than erroring, so a corrupted/hand-edited prefs file doesn't block the GUI
/// from starting.
fn deserialize_accent<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(if is_valid_hex_color(&s) {
        s
    } else {
        default_accent()
    })
}

fn is_valid_hex_color(s: &str) -> bool {
    s.len() == 7 && s.starts_with('#') && s.as_bytes()[1..].iter().all(u8::is_ascii_hexdigit)
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
            store.delete_secret(&connection_refresh_token_account(&old.id))?;
        }
    }

    let content = serde_json::to_string_pretty(&redacted).map_err(|e| e.to_string())?;
    std::fs::write(&prefs_path, content).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests;
