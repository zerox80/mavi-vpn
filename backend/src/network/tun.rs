use anyhow::{Context, Result};
use tracing::{info, warn};
use tun::AbstractDevice;
use crate::config::Config;
use crate::state::AppState;

pub fn create_tun_device(config: &Config, state: &AppState) -> Result<tokio::io::DuplexStream> {
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
    
    info!("TUN Device created: {}. IP: {}", tun_name, gateway_ip);
    
    setup_ipv6(&tun_name, state);

    // This is a bit tricky, tokio::io::split returns Reader/Writer. 
    // I will return the reader/writer or just the device if I can.
    // Actually the original main.rs split it immediately.
    // I'll return the device after some logic.
    // Wait, create_as_async returns 'AsyncDevice'.
    
    Ok(dev)
}

fn setup_ipv6(tun_name: &str, state: &AppState) -> bool {
    let gateway_ip6 = state.gateway_ip_v6();
    match std::process::Command::new("ip")
        .args(&["-6", "addr", "add", &format!("{}/64", gateway_ip6), "dev", tun_name])
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
        }
}
