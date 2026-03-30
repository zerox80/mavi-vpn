//! # Mavi VPN Backend
//! 
//! High-performance VPN server leveraging QUIC as the transport layer and TUN devices
//! for network integration.

use anyhow::{Context, Result};
use bytes::Bytes;
use std::sync::Arc;
use tracing::{info, warn};

mod cert;
mod config;
mod state;
mod keycloak;
mod routing;
mod utils;
mod network;
mod server;

use crate::state::AppState;
use crate::handlers::connection::handle_connection;
use crate::routing::{spawn_tun_reader, spawn_tun_writer};
use crate::utils::cleanup_legacy_rules;
use crate::network::tun::create_tun_device;
use crate::server::quic::create_quic_endpoint;

// Proxy module to bridge between main.rs and existing directory structure
mod handlers {
    pub mod connection;
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    
    // Install the cryptographic provider (aws-lc-rs for better performance)
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    
    let config = config::load();
    info!("Starting Mavi VPN Server...");
    info!("Network: {}", config.network_cidr);
    info!("Bind Address: {}", config.bind_addr);

    let state = Arc::new(AppState::new(&config.network_cidr)?);

    // Load or generate certificates
    let cert_path = config.cert_path.clone();
    let key_path = config.key_path.clone();
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create certificate directory")?;
    }
    let (certs, key) = cert::load_or_generate_certs(cert_path, key_path)?;

    // Keycloak Validator Setup
    let keycloak = if config.keycloak_enabled {
        if let Some(url) = &config.keycloak_url {
            let kc = crate::keycloak::KeycloakValidator::new(
                url.clone(),
                config.keycloak_realm.clone(),
                config.keycloak_client_id.clone(),
            );
            // Optionally we could call kc.init_and_fetch() here.
            Some(Arc::new(kc))
        } else {
            None
        }
    } else {
        None
    };

    // --- NETWORK SETUP ---
    // Create the global TUN message channel (Capacity 4096 to prevent backpressure)
    let (tx_tun, rx_tun) = tokio::sync::mpsc::channel::<Bytes>(4096);

    // Create the TUN device
    let tun_device = create_tun_device(&config, &state)?;
    
    // Split the TUN device for concurrent reading/writing
    let (tun_reader, tun_writer) = tokio::io::split(tun_device);
    
    // Start background routing tasks
    spawn_tun_reader(tun_reader, state.clone());
    spawn_tun_writer(tun_writer, rx_tun);

    // Cleanup legacy firewall rules (if any)
    let _ = cleanup_legacy_rules();

    // Create the QUIC endpoint
    let endpoint = create_quic_endpoint(&config, certs, key)?;

    info!("Server Ready. Waiting for connections...");

    // Accept incoming connections
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
