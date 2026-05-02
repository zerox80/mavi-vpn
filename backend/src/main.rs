//! # Mavi VPN Backend
//!
//! High-performance VPN server leveraging QUIC as the transport layer and TUN devices
//! for network integration.

#![allow(clippy::multiple_crate_versions)]
use anyhow::{Context, Result};
use bytes::Bytes;
use std::sync::Arc;
use tracing::{info, warn};

mod cert;
mod config;
mod ech;
mod keycloak;
mod network;
mod routing;
mod server;
mod state;
mod utils;

use crate::handlers::connection::handle_connection;
use crate::network::tun::create_tun_device;
use crate::routing::{spawn_tun_reader, spawn_tun_writer};
use crate::server::quic::create_quic_endpoint;
use crate::state::AppState;
use crate::utils::cleanup_legacy_rules;

mod handlers;

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Install the cryptographic provider (aws-lc-rs for better performance)
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let config = config::load();

    let quic_overhead: u16 = 80;
    let quic_payload_mtu = config.mtu + quic_overhead;
    let wire_overhead_ipv4 = 20u16 + 8; // IP + UDP
    let wire_overhead_ipv6 = 40u16 + 8;
    let mtu_source = if std::env::var("VPN_MTU").is_ok() {
        "VPN_MTU env / .env"
    } else {
        "default"
    };

    info!("Starting Mavi VPN Server...");
    info!("Network: {}", config.network_cidr);
    info!("Bind Address: {}", config.bind_addr);
    info!(
        "MSS Clamping: {}",
        if config.mss_clamping {
            "enabled"
        } else {
            "disabled"
        }
    );
    info!(
        "MTU: {} (source: {}) → QUIC Payload: {} → Wire IPv4: {} / IPv6: {}",
        config.mtu,
        mtu_source,
        quic_payload_mtu,
        quic_payload_mtu + wire_overhead_ipv4,
        quic_payload_mtu + wire_overhead_ipv6,
    );

    let state = Arc::new(AppState::new(&config.network_cidr)?);

    // Load or generate certificates
    let cert_path = config.cert_path.clone();
    let key_path = config.key_path.clone();
    if let Some(parent) = cert_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).context("Failed to create certificate directory")?;
        }
    }
    let (certs, key) = cert::load_or_generate_certs(&cert_path, &key_path)?;

    // ECH (Encrypted Client Hello) setup — generates and persists an HPKE key
    // pair + ECHConfigList when censorship-resistant mode is enabled. The
    // ECHConfigList is distributed to clients out-of-band (alongside the cert
    // pin) so they can read the cover SNI and offer ECH GREASE.
    if config.censorship_resistant {
        match ech::load_or_generate(
            &config.ech_config_path,
            &config.ech_key_path,
            &config.ech_public_name,
        ) {
            Ok(ech_state) => {
                info!(
                    "ECH ready: public_name={:?}, config_list={} bytes",
                    ech_state.public_name,
                    ech_state.config_list_bytes.len()
                );
                // The server itself does not yet decrypt ECH inner ClientHellos
                // (pending rustls server-side ECH support). Keep the state
                // loaded so tests and future wiring can reuse it.
                let _ = ech_state;
            }
            Err(e) => {
                warn!("ECH setup failed, continuing without ECH artefacts: {}", e);
            }
        }
    }

    // Keycloak Validator Setup
    let mut keycloak = None;
    if config.keycloak_enabled {
        let Some(url) = &config.keycloak_url else {
            panic!("FATAL: VPN_KEYCLOAK_ENABLED=true but VPN_KEYCLOAK_URL is not set!");
        };

        let kc = crate::keycloak::KeycloakValidator::new(
            url.clone(),
            config.keycloak_realm.clone(),
            config.keycloak_client_id.clone(),
        );

        info!("Initializing Keycloak validator for {}...", url);

        // Retry with exponential backoff — Keycloak may not be ready yet
        let max_retries = 5u32;
        let mut success = false;
        for attempt in 1..=max_retries {
            match kc.init_and_fetch().await {
                Ok(()) => {
                    info!(
                        "Keycloak JWKS loaded successfully (attempt {}/{})",
                        attempt, max_retries
                    );
                    success = true;
                    break;
                }
                Err(e) => {
                    let delay = std::time::Duration::from_secs(2u64.pow(attempt - 1));
                    warn!(
                        "Failed to fetch Keycloak JWKS (attempt {}/{}): {}. Retrying in {}s...",
                        attempt,
                        max_retries,
                        e,
                        delay.as_secs()
                    );
                    if attempt == max_retries {
                        break;
                    }
                    tokio::time::sleep(delay).await;
                }
            }
        }

        if success {
            keycloak = Some(Arc::new(kc));
        } else {
            // DO NOT silently fall back to static token — that's a security disaster.
            panic!(
                "FATAL: Could not load Keycloak JWKS after {} attempts. \
                 Refusing to start with broken auth. \
                 Ensure Keycloak is reachable at: {}/realms/{}/protocol/openid-connect/certs",
                max_retries, url, config.keycloak_realm
            );
        }
    }

    // --- NETWORK SETUP ---
    // Create the global TUN message channel (Capacity 4096 to prevent backpressure)
    let (tx_tun, rx_tun) = tokio::sync::mpsc::channel::<Bytes>(4096);

    // Create the TUN device; returns whether IPv6 was successfully configured
    let (tun_device, ipv6_enabled) = create_tun_device(&config, &state)?;

    // Split the TUN device for concurrent reading/writing
    let (tun_reader, tun_writer) = tokio::io::split(tun_device);

    // Start background routing tasks
    spawn_tun_reader(tun_reader, state.clone());
    spawn_tun_writer(tun_writer, rx_tun);

    // Cleanup legacy firewall rules (if any)
    cleanup_legacy_rules();

    // Create the QUIC endpoint
    let endpoint = create_quic_endpoint(&config, certs, key)?;

    info!("Server Ready. Waiting for connections...");

    let connection_semaphore = Arc::new(tokio::sync::Semaphore::new(1000));

    // Accept incoming connections
    while let Some(conn) = endpoint.accept().await {
        let Ok(permit) = connection_semaphore.clone().try_acquire_owned() else {
            warn!("Connection limit reached (1000), rejecting new connection");
            continue;
        };

        let state = state.clone();
        let config = config.clone();
        let tx_tun = tx_tun.clone();
        let keycloak = keycloak.clone();

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) =
                handle_connection(conn, state, config, tx_tun, keycloak, ipv6_enabled).await
            {
                warn!("Connection handler exited: {}", e);
            }
        });
    }

    Ok(())
}
