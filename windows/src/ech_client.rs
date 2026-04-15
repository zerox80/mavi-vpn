//! Client-side Encrypted Client Hello (ECH) helper.
//!
//! Parses a server-provided `ECHConfigList` to derive:
//!   - the `public_name` (used as the outer SNI on the wire), and
//!   - an [`rustls::client::EchGreaseConfig`] matching the server's advertised
//!     HPKE suite + public key.
//!
//! `EchMode::Grease` is used (not `EchMode::Enable`) because rustls 0.23.x
//! lacks server-side ECH acceptance. Clients still spoof the SNI to the
//! `public_name`, which is safe because the server authenticates via
//! SHA-256 cert pinning and does not care about the SNI.

use anyhow::{bail, Context, Result};
use rustls::client::EchGreaseConfig;
use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
use rustls::crypto::hpke::{Hpke, HpkePublicKey, HpkeSuite};
use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::handshake::EchConfigPayload;

/// Information extracted from a server `ECHConfigList` for client use.
pub struct ClientEch {
    /// DNS name to send as the outer SNI in the QUIC ClientHello.
    pub outer_sni: String,
    /// An `EchMode::Grease`-capable configuration that mimics the server's
    /// advertised HPKE suite + public key.
    pub grease: EchGreaseConfig,
}

/// Parse the first V18 entry of an `ECHConfigList` and build an
/// [`EchGreaseConfig`] for it. Returns `Ok(None)` if no entry is compatible
/// with the local HPKE provider (in which case callers should proceed without
/// ECH).
pub fn parse(ech_config_list: &[u8]) -> Result<Option<ClientEch>> {
    let mut reader = Reader::init(ech_config_list);
    let payloads: Vec<EchConfigPayload> = <Vec<EchConfigPayload> as rustls::internal::msgs::codec::Codec>::read(&mut reader)
        .map_err(|e| anyhow::anyhow!("failed to decode ECHConfigList: {:?}", e))?;

    for payload in payloads {
        let contents = match payload {
            EchConfigPayload::V18(c) => c,
            _ => continue,
        };
        let outer_sni = contents.public_name.as_ref().to_string();
        let kem = contents.key_config.kem_id;
        let public_key_bytes = encoded_public_key(&contents.key_config)?;

        // Pick the first symmetric suite that our HPKE provider supports.
        for sym in &contents.key_config.symmetric_cipher_suites {
            let suite = HpkeSuite { kem, sym: *sym };
            if let Some(hpke) = ALL_SUPPORTED_SUITES
                .iter()
                .find(|h| h.suite() == suite)
            {
                let grease =
                    EchGreaseConfig::new(*hpke as &'static dyn Hpke, HpkePublicKey(public_key_bytes));
                return Ok(Some(ClientEch { outer_sni, grease }));
            }
        }
    }

    Ok(None)
}

/// Extract the raw HPKE public-key bytes from an `HpkeKeyConfig` by
/// re-encoding it and decoding just the `opaque<1..2^16-1>` field. We can't
/// read `PayloadU16::<NonEmpty>` fields directly because its inner `Vec<u8>`
/// is `pub(crate)` in rustls.
fn encoded_public_key(
    key_config: &rustls::internal::msgs::handshake::HpkeKeyConfig,
) -> Result<Vec<u8>> {
    use rustls::internal::msgs::codec::Codec;

    let mut buf = Vec::new();
    key_config.encode(&mut buf);

    // `HpkeKeyConfig` wire layout:
    //   u8  config_id
    //   u16 kem_id
    //   u16 pk_len | pk_bytes
    //   u16 suites_len | suites...
    if buf.len() < 1 + 2 + 2 {
        bail!("HpkeKeyConfig too short");
    }
    let pk_len = u16::from_be_bytes(
        buf[3..5]
            .try_into()
            .context("reading pk_len failed")?,
    ) as usize;
    let start = 5usize;
    let end = start
        .checked_add(pk_len)
        .context("pk_len overflow")?;
    if end > buf.len() {
        bail!("HpkeKeyConfig pk_len out of range");
    }
    Ok(buf[start..end].to_vec())
}

/// Decode a hex string into bytes. Returns `None` on any parse error.
pub use shared::hex::decode_hex;

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::internal::msgs::base::PayloadU16;
    use rustls::internal::msgs::codec::Codec;
    use rustls::internal::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
    use rustls::internal::msgs::handshake::{HpkeKeyConfig, HpkeSymmetricCipherSuite};

    /// Verify that `encoded_public_key` correctly extracts the HPKE public-key
    /// bytes from an `HpkeKeyConfig` encoded using the rustls wire format.
    ///
    /// This test guards against silent breakage if rustls ever changes the
    /// `HpkeKeyConfig` wire layout (which lives in `rustls::internal` and
    /// carries no stability guarantee).
    #[test]
    fn encoded_public_key_extracts_correct_bytes() {
        let pk_bytes: Vec<u8> = (0u8..32).collect(); // 32 distinct fake bytes
        let key_config = HpkeKeyConfig {
            config_id: 0,
            kem_id: HpkeKem::DHKEM_X25519_HKDF_SHA256,
            public_key: PayloadU16::new(pk_bytes.clone()),
            symmetric_cipher_suites: vec![HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::HKDF_SHA256,
                aead_id: HpkeAead::AES_128_GCM,
            }],
        };

        // Sanity-check the encoded layout we rely on.
        let mut buf = Vec::new();
        key_config.encode(&mut buf);
        // Wire: u8 config_id(0) | u16 kem_id | u16 pk_len(32) | 32 pk_bytes | ...
        assert!(buf.len() >= 5 + 32, "encoded buffer shorter than expected");
        assert_eq!(u16::from_be_bytes([buf[3], buf[4]]) as usize, 32, "pk_len field mismatch");

        let extracted = encoded_public_key(&key_config).expect("extraction must not fail");
        assert_eq!(extracted, pk_bytes, "extracted bytes must equal the original public key");
    }
}
