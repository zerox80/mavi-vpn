use rcgen::generate_simple_self_signed;
use std::{fs, path::PathBuf};
use anyhow::{Result, Context};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

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

        Ok((certs, key))
    }
}
