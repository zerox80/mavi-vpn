//! OS keyring storage for the CLI config's credentials.
//!
//! `mavi-vpn.json` only holds non-secret settings. The access/preshared token and
//! the Keycloak refresh token live in the Secret Service keyring, keyed by the
//! config file's absolute path so separate config files never share credentials.
//!
//! When no keyring is reachable (for example `sudo mavi-vpn` without a user
//! session bus) a preshared key falls back to the 0600 config file, because a
//! headless connect has nowhere else to keep it. Keycloak tokens are never
//! written to disk; without a keyring they only live in memory for the current
//! run and the next run logs in again.

use anyhow::Result;
use keyring::Entry;
use shared::ipc::Config;
use std::path::Path;

const SERVICE: &str = "com.mavi.vpn";

pub(super) trait SecretStore {
    fn set_secret(&self, account: &str, secret: &str) -> Result<()>;
    fn get_secret(&self, account: &str) -> Result<Option<String>>;
    fn delete_secret(&self, account: &str) -> Result<()>;
}

pub(super) struct KeyringSecretStore;

impl SecretStore for KeyringSecretStore {
    fn set_secret(&self, account: &str, secret: &str) -> Result<()> {
        Entry::new(SERVICE, account)?.set_password(secret)?;
        Ok(())
    }

    fn get_secret(&self, account: &str) -> Result<Option<String>> {
        match Entry::new(SERVICE, account)?.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn delete_secret(&self, account: &str) -> Result<()> {
        match Entry::new(SERVICE, account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// Keyring account names for the secrets belonging to one config file.
pub(super) struct SecretAccounts {
    token: String,
    refresh_token: String,
}

impl SecretAccounts {
    pub(super) fn for_config(path: &Path) -> Self {
        let path = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        let id = path.display();
        Self {
            token: format!("linux-cli:{id}:token"),
            refresh_token: format!("linux-cli:{id}:refresh-token"),
        }
    }
}

/// Returns true when a config read from disk still carries plaintext secrets.
pub(super) fn has_plaintext_secrets(config: &Config) -> bool {
    !config.token.is_empty()
        || config
            .refresh_token
            .as_deref()
            .is_some_and(|r| !r.is_empty())
}

/// Moves the secrets of `config` into `store` and returns the copy that is safe
/// to write to the config file.
pub(super) fn strip_secrets(
    config: &Config,
    accounts: &SecretAccounts,
    store: &dyn SecretStore,
) -> Config {
    let keycloak = config.kc_auth.unwrap_or(false);
    let mut on_disk = config.clone();
    on_disk.token.clear();
    on_disk.refresh_token = None;
    let mut keyring_error = None;

    match config.refresh_token.as_deref().filter(|r| !r.is_empty()) {
        Some(refresh) => {
            if let Err(e) = store.set_secret(&accounts.refresh_token, refresh) {
                keyring_error = Some(e);
            }
        }
        None => {
            let _ = store.delete_secret(&accounts.refresh_token);
        }
    }

    if config.token.is_empty() {
        let _ = store.delete_secret(&accounts.token);
    } else if let Err(e) = store.set_secret(&accounts.token, &config.token) {
        if !keycloak {
            on_disk.token = config.token.clone();
        }
        keyring_error.get_or_insert(e);
    }

    if let Some(e) = keyring_error {
        if keycloak {
            eprintln!(
                "Warning: OS keyring unavailable ({e:#}); Keycloak tokens are kept in memory \
                 only and you will need to log in again next time."
            );
        } else {
            eprintln!(
                "Warning: OS keyring unavailable ({e:#}); the preshared key stays in the \
                 config file (mode 0600)."
            );
        }
    }
    on_disk
}

/// Fills the secret fields that are empty in a config loaded from disk with the
/// values held in `store`.
pub(super) fn restore_secrets(
    config: &mut Config,
    accounts: &SecretAccounts,
    store: &dyn SecretStore,
) {
    let mut keyring_error = None;
    if config.token.is_empty() {
        match store.get_secret(&accounts.token) {
            Ok(secret) => config.token = secret.unwrap_or_default(),
            Err(e) => keyring_error = Some(e),
        }
    }
    let keycloak = config.kc_auth.unwrap_or(false);
    if keycloak && config.refresh_token.as_deref().is_none_or(str::is_empty) {
        match store.get_secret(&accounts.refresh_token) {
            Ok(secret) => config.refresh_token = secret,
            Err(e) => {
                keyring_error.get_or_insert(e);
            }
        }
    }
    if let Some(e) = keyring_error {
        eprintln!("Warning: could not read credentials from the OS keyring: {e:#}");
    }
}

#[cfg(test)]
pub(super) mod tests;
