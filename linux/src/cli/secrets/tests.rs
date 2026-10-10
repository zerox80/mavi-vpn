use super::*;
use std::cell::RefCell;
use std::collections::HashMap;

#[derive(Default)]
pub(in crate::cli) struct MemorySecretStore {
    secrets: RefCell<HashMap<String, String>>,
}

impl MemorySecretStore {
    pub(in crate::cli) fn len(&self) -> usize {
        self.secrets.borrow().len()
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
        Ok(self.secrets.borrow().get(account).cloned())
    }

    fn delete_secret(&self, account: &str) -> Result<()> {
        self.secrets.borrow_mut().remove(account);
        Ok(())
    }
}

/// Behaves like a missing Secret Service, e.g. under `sudo` without a session bus.
pub(in crate::cli) struct UnavailableSecretStore;

impl SecretStore for UnavailableSecretStore {
    fn set_secret(&self, _: &str, _: &str) -> Result<()> {
        anyhow::bail!("no secret service")
    }

    fn get_secret(&self, _: &str) -> Result<Option<String>> {
        anyhow::bail!("no secret service")
    }

    fn delete_secret(&self, _: &str) -> Result<()> {
        anyhow::bail!("no secret service")
    }
}

pub(in crate::cli) fn sample_config(keycloak: bool) -> Config {
    Config {
        endpoint: "vpn.example.com:443".to_string(),
        token: "access-token".to_string(),
        cert_pin: "pin".to_string(),
        censorship_resistant: false,
        http3_framing: false,
        kc_auth: Some(keycloak),
        kc_url: Some("https://auth.example.com".to_string()),
        kc_realm: Some("mavi-vpn".to_string()),
        kc_client_id: Some("mavi-client".to_string()),
        refresh_token: keycloak.then(|| "refresh-token".to_string()),
        ech_config: None,
        vpn_mtu: None,
        http2_framing: false,
    }
}

#[test]
fn strip_moves_keycloak_tokens_into_the_store() {
    let store = MemorySecretStore::default();
    let accounts = SecretAccounts::for_config(Path::new("/etc/mavi-vpn/mavi-vpn.json"));

    let on_disk = strip_secrets(&sample_config(true), &accounts, &store);

    assert!(on_disk.token.is_empty());
    assert_eq!(on_disk.refresh_token, None);
    let mut restored = on_disk;
    restore_secrets(&mut restored, &accounts, &store);
    assert_eq!(restored.token, "access-token");
    assert_eq!(restored.refresh_token.as_deref(), Some("refresh-token"));
}

#[test]
fn keycloak_tokens_never_reach_disk_without_a_keyring() {
    let accounts = SecretAccounts::for_config(Path::new("mavi-vpn.json"));

    let on_disk = strip_secrets(&sample_config(true), &accounts, &UnavailableSecretStore);

    assert!(on_disk.token.is_empty());
    assert_eq!(on_disk.refresh_token, None);
}

#[test]
fn preshared_key_falls_back_to_the_file_without_a_keyring() {
    let accounts = SecretAccounts::for_config(Path::new("mavi-vpn.json"));

    let on_disk = strip_secrets(&sample_config(false), &accounts, &UnavailableSecretStore);

    assert_eq!(on_disk.token, "access-token");
    assert_eq!(on_disk.refresh_token, None);
}

#[test]
fn accounts_are_scoped_to_the_config_path() {
    let store = MemorySecretStore::default();
    let first = SecretAccounts::for_config(Path::new("/tmp/a/mavi-vpn.json"));
    let second = SecretAccounts::for_config(Path::new("/tmp/b/mavi-vpn.json"));
    let mut other = sample_config(false);
    other.token = "other-psk".to_string();

    let mut first_disk = strip_secrets(&sample_config(false), &first, &store);
    let mut second_disk = strip_secrets(&other, &second, &store);
    restore_secrets(&mut first_disk, &first, &store);
    restore_secrets(&mut second_disk, &second, &store);

    assert_eq!(first_disk.token, "access-token");
    assert_eq!(second_disk.token, "other-psk");
}

#[test]
fn clearing_secrets_deletes_stale_keyring_entries() {
    let store = MemorySecretStore::default();
    let accounts = SecretAccounts::for_config(Path::new("mavi-vpn.json"));
    strip_secrets(&sample_config(true), &accounts, &store);
    assert_eq!(store.len(), 2);

    let mut cleared = sample_config(true);
    cleared.token.clear();
    cleared.refresh_token = None;
    strip_secrets(&cleared, &accounts, &store);

    assert_eq!(store.len(), 0);
}
