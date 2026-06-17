use anyhow::Result;
use keyring::Entry;

const SERVICE: &str = "com.mavi.vpn";

pub trait SecretStore {
    fn set_secret(&self, account: &str, secret: &str) -> Result<()>;
    fn get_secret(&self, account: &str) -> Result<Option<String>>;
    fn delete_secret(&self, account: &str) -> Result<()>;
}

pub struct KeyringSecretStore;

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

pub const fn config_token_account() -> &'static str {
    "windows-cli-config-token"
}

pub const fn config_refresh_token_account() -> &'static str {
    "windows-cli-config-refresh-token"
}

#[cfg(test)]
pub mod tests {
    use super::SecretStore;
    use anyhow::Result;
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[derive(Default)]
    pub struct MemorySecretStore {
        secrets: RefCell<HashMap<String, String>>,
        deleted: RefCell<Vec<String>>,
    }

    impl MemorySecretStore {
        pub fn secret(&self, account: &str) -> Option<String> {
            self.secrets.borrow().get(account).cloned()
        }

        pub fn deleted(&self) -> Vec<String> {
            self.deleted.borrow().clone()
        }
    }

    impl SecretStore for MemorySecretStore {
        fn set_secret(&self, account: &str, secret: &str) -> Result<()> {
            self.secrets
                .borrow_mut()
                .insert(account.to_string(), secret.to_string());
            Ok(())
        }

        fn get_secret(&self, account: &str) -> Result<Option<String>> {
            Ok(self.secret(account))
        }

        fn delete_secret(&self, account: &str) -> Result<()> {
            if self.secrets.borrow_mut().remove(account).is_some() {
                self.deleted.borrow_mut().push(account.to_string());
            }
            Ok(())
        }
    }

    #[test]
    fn memory_store_basic_operations() {
        let store = MemorySecretStore::default();
        assert_eq!(store.get_secret("missing").unwrap(), None);

        store.set_secret("acc", "val").unwrap();
        assert_eq!(store.secret("acc"), Some("val".to_string()));
        assert_eq!(store.get_secret("acc").unwrap(), Some("val".to_string()));

        store.delete_secret("acc").unwrap();
        assert_eq!(store.secret("acc"), None);
        assert!(store.deleted().contains(&"acc".to_string()));
    }

    #[test]
    fn memory_store_overwrite() {
        let store = MemorySecretStore::default();
        store.set_secret("acc", "first").unwrap();
        store.set_secret("acc", "second").unwrap();
        assert_eq!(store.secret("acc"), Some("second".to_string()));
    }

    #[test]
    fn memory_store_delete_nonexistent() {
        let store = MemorySecretStore::default();
        assert!(store.delete_secret("nope").is_ok());
        assert!(!store.deleted().contains(&"nope".to_string()));
    }
}
