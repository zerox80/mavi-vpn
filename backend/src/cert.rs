use rcgen::generate_simple_self_signed;
use std::{fs, path::PathBuf};
use anyhow::{Result, Context};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};

/// Loads existing TLS certificates from disk or generates a new self-signed pair if missing.
///
/// This function also extracts and logs the SHA-256 "pin" (the certificate's fingerprint).
/// This pin is meant to be shared with clients to prevent Man-in-the-Middle attacks,
/// as they will trust only the certificate matching this specific hash.
///
/// # Arguments
/// - `cert_path` - Location of the `.pem` certificate.
/// - `key_path` - Location of the `.pem` private key.
///
/// # Returns
/// A tuple containing the certificate chain and the private key in `rustls` compatible formats.
pub fn load_or_generate_certs(cert_path: PathBuf, key_path: PathBuf) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    if cert_path.exists() && key_path.exists() {
        tracing::info!("Loading existing certificates from {:?}", cert_path);
        let cert_chain = fs::read(&cert_path).context("failed to read certificate chain")?;
        let key = fs::read(&key_path).context("failed to read private key")?;

        // Parse PEM formatted certificates and keys
        let certs = rustls_pemfile::certs(&mut &cert_chain[..])
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let keys: Vec<PrivateKeyDer> = rustls_pemfile::pkcs8_private_keys(&mut &key[..])
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .map(PrivateKeyDer::Pkcs8)
            .collect();
            
        let key = keys.into_iter().next().ok_or_else(|| anyhow::anyhow!("No PKCS#8 private key found in {:?}", key_path))?;

        // Calculate and log the SHA-256 fingerprint of the end-entity certificate
        if let Some(cert) = certs.first() {
            write_cert_pin(&cert_path, cert)?;
        }

        Ok((certs, key))
    } else {
        tracing::info!("Certificates not found. Generating new self-signed certificates...");
        let subject_alt_names = vec!["localhost".to_string(), "vpn-server".to_string(), "mavivpn".to_string()];
        
        // Generate a new self-signed certificate (valid for 365 days by default in rcgen)
        let cert = generate_simple_self_signed(subject_alt_names).context("Failed to generate self-signed certificate")?;
        
        let cert_pem = cert.cert.pem();
        let key_pem = cert.signing_key.serialize_pem();

        fs::write(&cert_path, &cert_pem).context("failed to write cert file")?;
        fs::write(&key_path, &key_pem).context("failed to write key file")?;

        // Re-parse the PEMs into rustls-internal DER formats
        let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let keys: Vec<PrivateKeyDer> = rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .map(PrivateKeyDer::Pkcs8)
            .collect();
        let key = keys.into_iter().next().ok_or_else(|| anyhow::anyhow!("No PKCS#8 private key found in generated certificate"))?;

        if let Some(cert) = certs.first() {
            write_cert_pin(&cert_path, cert)?;
        }

        Ok((certs, key))
    }
}

/// Computes the SHA-256 fingerprint of the certificate and writes it to `cert_pin.txt`.
fn write_cert_pin(cert_path: &std::path::Path, cert: &CertificateDer) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(cert.as_ref());
    let hash = hasher.finalize();
    let pin_hex = hex::encode(hash);
    
    tracing::info!("Server Certificate PIN (SHA256 Hex): {}", pin_hex);
    
    // Save to file alongside the cert for easy access by administrators
    if let Some(parent) = cert_path.parent() {
        let pin_path = parent.join("cert_pin.txt");
        if let Err(e) = std::fs::write(&pin_path, &pin_hex) {
            tracing::warn!("Failed to write cert_pin.txt to {:?}: {}", pin_path, e);
        } else {
            tracing::info!("Wrote Certificate PIN to {:?}", pin_path);
        }
    }
    Ok(())
}
