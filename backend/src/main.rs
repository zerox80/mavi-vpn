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
                    std::process::exit(1);
                }
            }
        } else {
            tracing::error!("KEYCLOAK_ENABLED is true but KEYCLOAK_URL is not set.");
            std::process::exit(1);
        }
    }

    let mut server_crypto = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into()
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
        .with_single_cert(certs, key)?;
    
    server_crypto.alpn_protocols = if config.censorship_resistant {
        vec![b"h3".to_vec()]
    } else {
        vec![b"h3".to_vec(), b"mavivpn".to_vec()]
    };
    
    if config.censorship_resistant {
        info!("Censorship Resistant Mode ENABLED. ALPN priority: h3");
    } else {
        info!("Standard Mode ENABLED. ALPN priority: h3 (Compatibility: mavivpn)");
    }
    
    let mut server_config = ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| anyhow::anyhow!("Failed to access transport config"))?;
    
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(2)));
    
    transport_config.datagram_receive_buffer_size(Some(4 * 1024 * 1024)); 
    transport_config.datagram_send_buffer_size(4 * 1024 * 1024); 
    transport_config.receive_window(quinn::VarInt::from(4u32 * 1024 * 1024)); 
    transport_config.stream_receive_window(quinn::VarInt::from(1024u32 * 1024)); 
    transport_config.send_window(4 * 1024 * 1024); 
    
    transport_config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    
    transport_config.mtu_discovery_config(None); 
    transport_config.initial_mtu(1360); 
    transport_config.min_mtu(1360);
    
    transport_config.enable_segmentation_offload(true);
    
    let socket = std::net::UdpSocket::bind(config.bind_addr)?;
    let socket2_sock = socket2::Socket::from(socket);
    let _ = socket2_sock.set_recv_buffer_size(4 * 1024 * 1024); 
    let _ = socket2_sock.set_send_buffer_size(4 * 1024 * 1024); 
    
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket2_sock.as_raw_fd();
        
        unsafe {
            let val: libc::c_int = 0; 
            let _ = libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, &val as *const _ as *const libc::c_void, std::mem::size_of_val(&val) as libc::socklen_t);
            let _ = libc::setsockopt(fd, libc::IPPROTO_IPV6, 23, &val as *const _ as *const libc::c_void, std::mem::size_of_val(&val) as libc::socklen_t);
            info!("UDP Fragmentation enabled (PMTUDISC_DONT) for IPv4/IPv6");
        }
    }

    let socket = std::net::UdpSocket::from(socket2_sock);
    let endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    
    let mut tun_config = tun::Configuration::default();
    let gateway_ip = state.gateway_ip();
    let netmask = state.network.mask();

    tun_config.address(gateway_ip)
              .netmask(netmask)
              .mtu(config.mtu as u16)
              .up();

    if let Some(dev_path) = &config.tun_device_path {
        tun_config.tun_name(dev_path);
    }

    let dev = tun::create_as_async(&tun_config).context("Failed to create TUN device. Ensure NET_ADMIN cap is set.")?;
    let tun_name = std::ops::Deref::deref(&dev).tun_name().unwrap_or_else(|_| "tun0".into());
    let (tun_reader, tun_writer) = tokio::io::split(dev);

    info!("TUN Device created: {}. IP: {}", tun_name, gateway_ip);

    let gateway_ip6 = state.gateway_ip_v6();
    let ipv6_enabled = match std::process::Command::new("ip")
        .args(&["-6", "addr", "add", &format!("{}/64", gateway_ip6), "dev", &tun_name])
        .output() {
            Ok(output) if output.status.success() => {
                 info!("IPv6 address {} successfully assigned to {}", gateway_ip6, tun_name);
                 true
            }
            Ok(output) => {
                 warn!("FAILED to assign IPv6 address to TUN: {}. IPv6 connectivity will be disabled for clients.", String::from_utf8_lossy(&output.stderr).trim());
                 false
            }
            Err(e) => {
                 warn!("FAILED to execute 'ip' command for IPv6 assignment: {}. Ensure 'iproute2' is installed. IPv6 disabled.", e);
                 false
            }
        };

    cleanup_legacy_rules();

    let (tx_tun, rx_tun) = tokio::sync::mpsc::channel::<Bytes>(2048);

    spawn_tun_writer(tun_writer, rx_tun);
    spawn_tun_reader(tun_reader, state.clone());

    while let Some(conn) = endpoint.accept().await {
        let state = state.clone();
        let config = config.clone();
        let tx_tun = tx_tun.clone();
        let keycloak = keycloak_validator.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(conn, state, config, tx_tun, keycloak, ipv6_enabled).await {
               warn!("Connection terminated: {}", e);
            }
        });
    }

    Ok(())
}
