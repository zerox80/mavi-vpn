use anyhow::Result;
use std::path::PathBuf;

use crate::ipc::Config;
use crate::secrets::{
    config_refresh_token_account, config_token_account, KeyringSecretStore, SecretStore,
};

const CONFIG_FILE: &str = "config.json";

pub(crate) fn config_path() -> PathBuf {
    let dir = std::env::var("APPDATA")
        .map_or_else(|_| PathBuf::from("."), PathBuf::from)
        .join("MaviVPN");
    let _ = std::fs::create_dir_all(&dir);
    dir.join(CONFIG_FILE)
}

pub(crate) fn load_config() -> Result<Option<Config>> {
    load_config_from_path(&config_path(), &KeyringSecretStore)
}

pub(crate) fn load_config_from_path(
    path: &std::path::Path,
    store: &dyn SecretStore,
) -> Result<Option<Config>> {
    if path.exists() {
        let content = std::fs::read_to_string(path)?;
        let mut config: Config = serde_json::from_str(&content)?;
        config.normalize_transport();
        let has_plaintext_token = !config.token.is_empty();
        let has_plaintext_refresh = config
            .refresh_token
            .as_deref()
            .is_some_and(|r| !r.is_empty());
        if has_plaintext_token || has_plaintext_refresh {
            // Restore any existing keyring secrets before rewriting the file so
            // the migration does not accidentally delete them.
            if config.token.is_empty() {
                if let Some(secret) = store.get_secret(config_token_account())? {
                    config.token = secret;
                }
            }
            if config.refresh_token.as_deref().unwrap_or("").is_empty() {
                if let Some(secret) = store.get_secret(config_refresh_token_account())? {
                    config.refresh_token = Some(secret);
                }
            }
            save_config_to_path(path, &config, store)?;
        }
        if config.token.is_empty() {
            if let Some(secret) = store.get_secret(config_token_account())? {
                config.token = secret;
            }
        }
        if config.refresh_token.as_deref().unwrap_or("").is_empty() {
            if let Some(secret) = store.get_secret(config_refresh_token_account())? {
                config.refresh_token = Some(secret);
            }
        }
        Ok(Some(config))
    } else {
        Ok(None)
    }
}

pub(crate) fn save_config(config: &Config) -> Result<()> {
    save_config_to_path(&config_path(), config, &KeyringSecretStore)
}

pub(crate) fn save_config_to_path(
    path: &std::path::Path,
    config: &Config,
    store: &dyn SecretStore,
) -> Result<()> {
    let mut config = config.clone();
    config.normalize_transport();
    if !config.token.is_empty() {
        store.set_secret(config_token_account(), &config.token)?;
        config.token.clear();
    } else {
        store.delete_secret(config_token_account())?;
    }
    if let Some(ref refresh) = config.refresh_token {
        if !refresh.is_empty() {
            store.set_secret(config_refresh_token_account(), refresh)?;
            config.refresh_token = None;
        } else {
            store.delete_secret(config_refresh_token_account())?;
            config.refresh_token = None;
        }
    } else {
        store.delete_secret(config_refresh_token_account())?;
    }
    let content = serde_json::to_string_pretty(&config)?;
    std::fs::write(path, content)?;
    println!("Config saved to {}", path.display());
    Ok(())
}
