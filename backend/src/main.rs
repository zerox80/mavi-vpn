//! # Mavi VPN Backend
//! 
//! High-performance VPN server leveraging QUIC as the transport layer and TUN devices
//! for network integration.

use anyhow::{Context, Result};
use bytes::Bytes;
use quinn::{Endpoint, ServerConfig};
use std::sync::Arc;
use tracing::{info, warn};
use tun::AbstractDevice;

mod cert;
mod config;
mod state;
mod keycloak;
mod handler;
mod routing;
mod utils;

use crate::state::AppState;
use crate::handler::handle_connection;
use crate::routing::{spawn_tun_reader, spawn_tun_writer};
use crate::utils::cleanup_legacy_rules;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let config = config::load();
    info!("Starting Mavi VPN Server...");
    info!("Network: {}", config.network_cidr);
    info!("Bind Address: {}", config.bind_addr);

    let state = Arc::new(AppState::new(&config.network_cidr)?);

    let cert_path = config.cert_path.clone();
    let key_path = config.key_path.clone();
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create certificate directory")?;
    }
    let (certs, key) = cert::load_or_generate_certs(cert_path, key_path)?;

    let mut keycloak_validator = None;
    if config.keycloak_enabled {
        if let Some(url) = &config.keycloak_url {
            let kc = crate::keycloak::KeycloakValidator::new(
                url.clone(),
                config.keycloak_realm.clone(),
                config.keycloak_client_id.clone(),
            );
            match kc.init_and_fetch().await {
                Ok(_) => keycloak_validator = Some(Arc::new(kc)),
                Err(e) => {
                    tracing::error!("Failed to initialize Keycloak JWKS cache: {}. Ensure Keycloak is running and reachable at {}", e, url);
                    warn!("Error reading from TUN: {}", e);
                    break;
                }
            }
        }
    });

    let keycloak = if config.use_keycloak {
        Some(Arc::new(KeycloakValidator::new(&config.keycloak_url, &config.keycloak_realm, &config.keycloak_client_id)))
    } else {
        None
    };

    info!("Server Ready. Waiting for connections...");

    while let Some(conn) = endpoint.accept().await {
        let state = state.clone();
        let config = config.clone();
        let tx_tun = tx_tun.clone();
        let keycloak = keycloak.clone();
        
        tokio::spawn(async move {
            if let Err(e) = handle_connection(conn, state, config, tx_tun, keycloak, true).await {
                warn!("Connection handler exited: {}", e);
            }
        });
    }

    Ok(())
}
