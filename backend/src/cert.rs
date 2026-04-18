use rcgen::generate_simple_self_signed;
use std::{fs, path::{Path, PathBuf}};
use anyhow::{Result, Context};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};

/// Write `contents` to `path` with an owner-only (0o600) permission mask from
/// the start, so the TLS private key never exists on disk with world- or
/// group-readable bits — even briefly. On Unix, we use `O_CREAT | O_EXCL`
/// with `mode(0o600)` and `O_NOFOLLOW` to avoid clobbering a symlink-attacked
/// target. On other platforms, fall back to `fs::write`.
fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    // Remove any stale file so previously-created world-readable keys from
    // older builds cannot persist with their old mode.
    let _ = fs::remove_file(path);

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .with_context(|| format!("failed to create {:?} with 0600 mode", path))?;
        f.write_all(contents)
            .with_context(|| format!("failed to write {:?}", path))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, contents)
            .with_context(|| format!("failed to write {:?}", path))?;
    }
    Ok(())
}

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

        // Defensive migration: older builds persisted the key via `fs::write`,
        // which honoured the process umask and typically left the file
        // world-readable (0o644). On upgrade, tighten the permissions to 0o600
        // so an already-generated key does not stay exposed on disk.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = fs::metadata(&key_path) {
                let mode = meta.permissions().mode() & 0o777;
                if mode != 0o600 {
                    match fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)) {
                        Ok(()) => tracing::info!(
                            "Tightened permissions on existing key file {:?} from {:o} to 0600",
                            key_path, mode
                        ),
                        Err(e) => tracing::warn!(
                            "Failed to tighten permissions on {:?} (current mode {:o}): {}",
                            key_path, mode, e
                        ),
                    }
                }
            }
        }

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
        write_private_file(&key_path, key_pem.as_bytes())?;

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
