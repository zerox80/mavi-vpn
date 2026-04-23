//! Encrypted Client Hello (ECH) support for mavi-vpn server.
//!
//! This module generates and persists HPKE keys and ECHConfigList bytes used
//! for ECH. The ECHConfigList is distributed out-of-band to clients (next to
//! `cert_pin.txt`). Clients use it to:
//!
//!   1. Read the `public_name` (the "cover" SNI sent on the wire), and
//!   2. Obtain an HPKE public key + suite for building an ECH GREASE extension.
//!
//! Server-side ECH acceptance (decrypting the inner ClientHello) is not
//! implemented in rustls 0.23.x. Clients therefore use `EchMode::Grease` plus
//! SNI spoofing to the `public_name`. This still hides the real server name
//! from on-path observers because the server does not rely on SNI (it uses
//! SHA-256 cert pinning) — any SNI works.
//!
//! When rustls gains server-side ECH, the infrastructure here (key + config
//! persistence, out-of-band distribution) can be reused to switch clients to
//! `EchMode::Enable` for full ECH without a protocol change.

use anyhow::{Context, Result};
use rustls::crypto::aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128;
use rustls::crypto::hpke::{Hpke, HpkePrivateKey};
use rustls::internal::msgs::base::PayloadU16;
use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::internal::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
use rustls::internal::msgs::handshake::{
    EchConfigContents, EchConfigPayload, HpkeKeyConfig, HpkeSymmetricCipherSuite,
};
use rustls::pki_types::DnsName;
use std::fs;
use std::path::Path;

/// An ECH key pair + its corresponding `EchConfigList` bytes.
pub struct ServerEch {
    #[allow(dead_code)]
    pub private_key: HpkePrivateKey,
    pub config_list_bytes: Vec<u8>,
    pub public_name: String,
}

/// Load the ECH key + config from disk, or generate a new pair if missing.
///
/// Generated files:
///   - `ech_key_path`   — raw HPKE private key bytes
///   - `ech_config_path` — raw `ECHConfigList` bytes for clients
///   - `<cfg_dir>/ech_config_hex.txt` — hex-encoded `ECHConfigList` for admin
///     distribution (next to `cert_pin.txt`)
///
/// `public_name` is baked into the generated `ECHConfig`. It is the SNI that
/// clients will send on the wire. Once generated it is fixed; change it by
/// deleting the files and restarting the server.
pub fn load_or_generate(
    ech_config_path: &Path,
    ech_key_path: &Path,
    public_name: &str,
) -> Result<ServerEch> {
    if ech_config_path.exists() && ech_key_path.exists() {
        tracing::info!(
            "Loading existing ECH config from {:?} and key from {:?}",
            ech_config_path,
            ech_key_path
        );
        let config_list_bytes =
            fs::read(ech_config_path).context("failed to read ECH config list")?;
        let key_bytes = fs::read(ech_key_path).context("failed to read ECH private key")?;
        let private_key = HpkePrivateKey::from(key_bytes);
        let name = parse_ech_public_name(&config_list_bytes)
            .context("failed to parse stored ECH config list")?;
        return Ok(ServerEch {
            private_key,
            config_list_bytes,
            public_name: name,
        });
    }

    tracing::info!(
        "Generating new ECH config with public_name={:?}",
        public_name
    );
    let hpke: &'static dyn Hpke = DH_KEM_X25519_HKDF_SHA256_AES_128;
    let (public_key, private_key) = hpke
        .generate_key_pair()
        .context("failed to generate HPKE key pair")?;

    let public_name_dns: DnsName<'static> = DnsName::try_from(public_name)
        .map_err(|_| anyhow::anyhow!("invalid ECH public_name"))?
        .to_owned();

    let contents = EchConfigContents {
        key_config: HpkeKeyConfig {
            // A stable identifier for this config. Randomizing isn't necessary
            // because we only publish one config.
            config_id: 0,
            kem_id: HpkeKem::DHKEM_X25519_HKDF_SHA256,
            public_key: PayloadU16::new(public_key.0.clone()),
            symmetric_cipher_suites: vec![HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::HKDF_SHA256,
                aead_id: HpkeAead::AES_128_GCM,
            }],
        },
        // Upper bound on the length of any inner SNI. 64 comfortably covers
        // common domain lengths; clients may pad beyond this.
        maximum_name_length: 64,
        public_name: public_name_dns,
        extensions: Vec::new(),
    };
    let payload = EchConfigPayload::V18(contents);

    // ECHConfigList is a TLS vector (Vec<EchConfigPayload>) with a U16 length
    // prefix — `TlsListElement` on `EchConfigPayload` takes care of framing.
    let mut config_list_bytes = Vec::new();
    vec![payload].encode(&mut config_list_bytes);

    // Persist the key + config.
    if let Some(parent) = ech_key_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Some(parent) = ech_config_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(ech_key_path, private_key.secret_bytes())
        .context("failed to write ECH private key")?;
    fs::write(ech_config_path, &config_list_bytes).context("failed to write ECH config list")?;

    // Write a hex-encoded copy next to cert_pin.txt for easy client
    // distribution.
    let pin_hex = hex::encode(&config_list_bytes);
    if let Some(parent) = ech_config_path.parent() {
        let hex_path = parent.join("ech_config_hex.txt");
        if let Err(e) = fs::write(&hex_path, &pin_hex) {
            tracing::warn!("Failed to write ech_config_hex.txt: {}", e);
        } else {
            tracing::info!("Wrote ECHConfigList (hex) to {:?}", hex_path);
        }
    }
    tracing::info!("ECHConfigList (hex) for clients: {}", pin_hex);

    Ok(ServerEch {
        private_key,
        config_list_bytes,
        public_name: public_name.to_string(),
    })
}

/// Parse an ECHConfigList and return the first V18 entry's `public_name`.
fn parse_ech_public_name(bytes: &[u8]) -> Result<String> {
    let mut reader = Reader::init(bytes);
    let payloads: Vec<EchConfigPayload> = Vec::read(&mut reader)
        .map_err(|e| anyhow::anyhow!("failed to decode ECHConfigList: {:?}", e))?;

    for payload in payloads {
        if let EchConfigPayload::V18(contents) = payload {
            return Ok(contents.public_name.as_ref().to_string());
        }
    }
    anyhow::bail!("no supported V18 ECH config in list")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn load_or_generate_creates_new_ech() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("ech_config.bin");
        let key_path = dir.path().join("ech_key.bin");

        let ech = load_or_generate(&config_path, &key_path, "cover.example.com").unwrap();
        assert_eq!(ech.public_name, "cover.example.com");
        assert!(!ech.config_list_bytes.is_empty());
        assert!(!ech.private_key.secret_bytes().is_empty());
        assert!(config_path.exists());
        assert!(key_path.exists());
    }

    #[test]
    fn load_or_generate_loads_existing() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("ech_config.bin");
        let key_path = dir.path().join("ech_key.bin");

        let ech1 = load_or_generate(&config_path, &key_path, "cover.example.com").unwrap();
        let ech2 = load_or_generate(&config_path, &key_path, "cover.example.com").unwrap();

        assert_eq!(ech1.config_list_bytes, ech2.config_list_bytes);
        assert_eq!(ech1.public_name, ech2.public_name);
        assert_eq!(
            ech1.private_key.secret_bytes(),
            ech2.private_key.secret_bytes()
        );
    }

    #[test]
    fn ech_config_hex_file_written() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("ech_config.bin");
        let key_path = dir.path().join("ech_key.bin");

        let _ = load_or_generate(&config_path, &key_path, "cover.example.com").unwrap();

        let hex_path = dir.path().join("ech_config_hex.txt");
        assert!(hex_path.exists());
        let hex_content = std::fs::read_to_string(&hex_path).unwrap();
        assert!(hex_content.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn parse_ech_public_name_from_generated() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("ech_config.bin");
        let key_path = dir.path().join("ech_key.bin");

        let ech = load_or_generate(&config_path, &key_path, "my-cover.com").unwrap();
        let name = parse_ech_public_name(&ech.config_list_bytes).unwrap();
        assert_eq!(name, "my-cover.com");
    }

    #[test]
    fn parse_ech_public_name_invalid_bytes() {
        let result = parse_ech_public_name(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_ech_public_name_empty() {
        let result = parse_ech_public_name(&[]);
        assert!(result.is_err());
    }
}
