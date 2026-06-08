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
            self.secrets.borrow_mut().remove(account);
            self.deleted.borrow_mut().push(account.to_string());
            Ok(())
        }
    }
}
