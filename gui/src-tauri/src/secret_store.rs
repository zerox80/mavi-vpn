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
/// `prefs.json`/`config.json`. On Windows it is sent over local authenticated
/// IPC only to seed the service's RAM-only refresh task for the active session.
pub(crate) fn connection_refresh_token_account(id: &str) -> String {
    format!("connection:{id}:refresh_token")
}

/// Use the same normalized base for credential identity and actual requests.
pub(crate) fn keycloak_base_url(kc_url: &str) -> Result<String, String> {
    let base = kc_url.trim().trim_end_matches('/');
    shared::validate_keycloak_url(base)?;
    let url = url::Url::parse(base).map_err(|e| format!("Invalid Keycloak URL: {e}"))?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "Keycloak URL must name a server path without credentials, query or fragment".into(),
        );
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

/// An immutable credential identity, also carried through Windows service
/// refresh replies. A delayed reply/ticker can only update its original issuer.
pub(crate) fn keycloak_credential_id(
    connection_id: &str,
    kc_url: &str,
    realm: &str,
    client_id: &str,
) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    let normalized = keycloak_base_url(kc_url)?;
    let identity = serde_json::to_vec(&(connection_id, normalized, realm, client_id))
        .map_err(|e| e.to_string())?;
    let mut id = String::from("oauth-v2:");
    for byte in Sha256::digest(identity) {
        let _ = write!(id, "{byte:02x}");
    }
    Ok(id)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{
        connection_refresh_token_account, keycloak_base_url, keycloak_credential_id, SecretStore,
    };
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[test]
    fn requests_use_the_same_base_url_as_credential_lookup() {
        for configured in [
            " https://AUTH.example.com:443/auth/ ",
            "https://auth.example.com/auth\\",
        ] {
            let base = keycloak_base_url(configured).unwrap();
            assert_eq!(base, "https://auth.example.com/auth");
            let endpoint = url::Url::parse(&format!(
                "{base}/realms/realm/protocol/openid-connect/token"
            ))
            .unwrap();
            assert_eq!(
                endpoint.path(),
                "/auth/realms/realm/protocol/openid-connect/token"
            );
            assert_eq!(
                keycloak_credential_id("profile", configured, "realm", "client").unwrap(),
                keycloak_credential_id("profile", &base, "realm", "client").unwrap(),
            );
        }
    }

    #[test]
    fn credential_identity_is_bound_to_profile_and_complete_authority() {
        let id = |profile, url, realm, client| {
            keycloak_credential_id(profile, url, realm, client).unwrap()
        };
        let original = id(
            "profile",
            "https://auth.example.com/auth",
            "realm",
            "client",
        );
        assert_eq!(
            original,
            id(
                "profile",
                " https://AUTH.example.com:443/auth/ ",
                "realm",
                "client"
            )
        );
        for different in [
            id("other", "https://auth.example.com/auth", "realm", "client"),
            id(
                "profile",
                "https://other.example.com/auth",
                "realm",
                "client",
            ),
            id(
                "profile",
                "https://auth.example.com/other",
                "realm",
                "client",
            ),
            id(
                "profile",
                "https://auth.example.com:8443/auth",
                "realm",
                "client",
            ),
            id(
                "profile",
                "https://auth.example.com/auth",
                "other",
                "client",
            ),
            id("profile", "https://auth.example.com/auth", "realm", "other"),
        ] {
            assert_ne!(original, different);
        }
        assert_ne!(
            id("profile", "https://auth.example.com/auth", "a:b", "c"),
            id("profile", "https://auth.example.com/auth", "a", "b:c"),
        );
        assert_ne!(
            connection_refresh_token_account("profile"),
            connection_refresh_token_account(&original)
        );
    }

    #[test]
    fn late_service_reply_or_ticker_only_updates_its_original_authority() {
        let store = MemorySecretStore::default();
        let account = |url| {
            connection_refresh_token_account(
                &keycloak_credential_id("profile", url, "realm", "client").unwrap(),
            )
        };
        let first = account("https://first.example.com");
        let second = account("https://second.example.com");
        store.set_secret(&second, "second-session").unwrap();
        store.set_secret(&first, "late-first-session").unwrap();
        assert_eq!(
            store.get_secret(&second).unwrap().as_deref(),
            Some("second-session")
        );
        assert_eq!(
            store.get_secret(&first).unwrap().as_deref(),
            Some("late-first-session")
        );
    }

    #[test]
    fn credential_identity_rejects_url_credentials_queries_and_fragments() {
        for url in [
            "https://user@auth.example.com",
            "https://auth.example.com?x=1",
            "https://auth.example.com#other",
        ] {
            assert!(keycloak_credential_id("profile", url, "realm", "client").is_err());
        }
    }

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
