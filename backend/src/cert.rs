use rcgen::generate_simple_self_signed;
use std::{fs, path::PathBuf};
use anyhow::{Result, Context};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};

pub fn load_or_generate_certs(cert_path: PathBuf, key_path: PathBuf) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    if cert_path.exists() && key_path.exists() {
        tracing::info!("Loading existing certificates...");
        let cert_chain = fs::read(&cert_path).context("failed to read certificate chain")?;
        let key = fs::read(&key_path).context("failed to read private key")?;

        let certs = rustls_pemfile::certs(&mut &cert_chain[..])
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let keys: Vec<PrivateKeyDer> = rustls_pemfile::pkcs8_private_keys(&mut &key[..])
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .map(PrivateKeyDer::Pkcs8)
            .collect();
            
        let key = keys.into_iter().next().ok_or_else(|| anyhow::anyhow!("no private key found"))?;

        if let Some(cert) = certs.first() {
            let mut hasher = Sha256::new();
            hasher.update(cert.as_ref());
            let hash = hasher.finalize();
            let pin_hex = hex::encode(hash);
            tracing::info!("Server Certificate PIN (SHA256 Hex): {}", pin_hex);
            
            if let Some(parent) = cert_path.parent() {
                let pin_path = parent.join("cert_pin.txt");
                if let Err(e) = std::fs::write(&pin_path, &pin_hex) {
                    tracing::warn!("Failed to write cert_pin.txt: {}", e);
                } else {
                    tracing::info!("Wrote Certificate PIN to {:?}", pin_path);
                }
            }
        }

        Ok((certs, key))
    } else {
        tracing::info!("Generating new self-signed certificates...");
        let subject_alt_names = vec!["localhost".to_string(), "vpn-server".to_string()];
        let cert = generate_simple_self_signed(subject_alt_names).unwrap();
        
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        fs::write(&cert_path, &cert_pem).context("failed to write cert file")?;
        fs::write(&key_path, &key_pem).context("failed to write key file")?;

        // Parse them back to return rustls types
        let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let keys: Vec<PrivateKeyDer> = rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .map(PrivateKeyDer::Pkcs8)
            .collect();
        let key = keys.into_iter().next().unwrap();

        if let Some(cert) = certs.first() {
            let mut hasher = Sha256::new();
            hasher.update(cert.as_ref());
            let hash = hasher.finalize();
            let pin_hex = hex::encode(hash);
            tracing::info!("Server Certificate PIN (SHA256 Hex): {}", pin_hex);
            
            if let Some(parent) = cert_path.parent() {
                let pin_path = parent.join("cert_pin.txt");
                if let Err(e) = std::fs::write(&pin_path, &pin_hex) {
                    tracing::warn!("Failed to write cert_pin.txt: {}", e);
                } else {
                    tracing::info!("Wrote Certificate PIN to {:?}", pin_path);
                }
            }
        }

        Ok((certs, key))
    }
}
