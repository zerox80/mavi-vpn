use keyring::Entry;

const SERVICE: &str = "com.mavi.vpn";

pub(crate) trait SecretStore {
    fn set_secret(&self, account: &str, secret: &str) -> Result<(), String>;
    fn get_secret(&self, account: &str) -> Result<Option<String>, String>;
    fn delete_secret(&self, account: &str) -> Result<(), String>;
}

pub(crate) struct KeyringSecretStore;

impl SecretStore for KeyringSecretStore {
    fn set_secret(&self, account: &str, secret: &str) -> Result<(), String> {
        Entry::new(SERVICE, account)
            .map_err(|e| e.to_string())?
            .set_password(secret)
            .map_err(|e| e.to_string())
    }

    fn get_secret(&self, account: &str) -> Result<Option<String>, String> {
        match Entry::new(SERVICE, account)
            .map_err(|e| e.to_string())?
            .get_password()
        {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    fn delete_secret(&self, account: &str) -> Result<(), String> {
        match Entry::new(SERVICE, account)
            .map_err(|e| e.to_string())?
            .delete_credential()
        {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
}

pub(crate) fn legacy_config_token_account() -> &'static str {
    "legacy-config-token"
}

pub(crate) fn connection_token_account(id: &str) -> String {
    format!("connection:{id}:token")
}

/// Keyring account for a connection's Keycloak **refresh** token. Kept separate
/// from the access/PSK token (`connection_token_account`) and never written to
/// `prefs.json`/`config.json` or sent over IPC — it stays in the user-session
/// OS keyring so the GUI can renew access tokens silently.
pub(crate) fn connection_refresh_token_account(id: &str) -> String {
    format!("connection:{id}:refresh_token")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::SecretStore;
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[derive(Default)]
    pub(crate) struct MemorySecretStore {
        secrets: RefCell<HashMap<String, String>>,
        deleted: RefCell<Vec<String>>,
    }

    impl MemorySecretStore {
        pub(crate) fn secret(&self, account: &str) -> Option<String> {
            self.secrets.borrow().get(account).cloned()
        }

        pub(crate) fn deleted(&self) -> Vec<String> {
            self.deleted.borrow().clone()
        }
    }

    impl SecretStore for MemorySecretStore {
        fn set_secret(&self, account: &str, secret: &str) -> Result<(), String> {
            self.secrets
                .borrow_mut()
                .insert(account.to_string(), secret.to_string());
            Ok(())
        }

        fn get_secret(&self, account: &str) -> Result<Option<String>, String> {
            Ok(self.secret(account))
        }

        fn delete_secret(&self, account: &str) -> Result<(), String> {
            self.secrets.borrow_mut().remove(account);
            self.deleted.borrow_mut().push(account.to_string());
            Ok(())
        }
    }
}
