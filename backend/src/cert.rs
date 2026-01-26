use rcgen::generate_simple_self_signed;
use std::{fs, path::PathBuf};
use anyhow::{Result, Context};

pub fn load_or_generate_certs(cert_path: PathBuf, key_path: PathBuf) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey)> {
    if cert_path.exists() && key_path.exists() {
        tracing::info!("Loading existing certificates...");
        let cert_chain = fs::read(&cert_path).context("failed to read certificate chain")?;
        let key = fs::read(&key_path).context("failed to read private key")?;

        let certs = rustls_pemfile::certs(&mut &cert_chain[..])
            .collect::<Result<Vec<_>, _>>()?;
        let keys: Vec<rustls::PrivateKey> = rustls_pemfile::pkcs8_private_keys(&mut &key[..])
            .collect::<Result<Vec<_>, _>>()?;
            
        let key = keys.into_iter().next().ok_or_else(|| anyhow::anyhow!("no private key found"))?;

        Ok((certs, key))
    } else {
        tracing::info!("Generating new self-signed certificates...");
        let subject_alt_names = vec!["localhost".to_string(), "vpn-server".to_string()];
        let cert = generate_simple_self_signed(subject_alt_names).unwrap();
        
        let cert_pem = cert.serialize_pem()?;
        let key_pem = cert.serialize_private_key_pem();

        fs::write(&cert_path, &cert_pem).context("failed to write cert file")?;
        fs::write(&key_path, &key_pem).context("failed to write key file")?;

        // Parse them back to return rustls types
        let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()?;
        let keys: Vec<rustls::PrivateKey> = rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()?;
        let key = keys.into_iter().next().unwrap();

        Ok((certs, key))
    }
}
