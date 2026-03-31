use anyhow::{Context, Result};
use tracing::{info, warn};
use tun::AbstractDevice;
use crate::config::Config;
use crate::state::AppState;

pub fn create_tun_device(config: &Config, state: &AppState) -> Result<(tun::AsyncDevice, bool)> {
    let mut tun_config = tun::Configuration::default();
    let gateway_ip = state.gateway_ip();
    let netmask = state.network.mask();

    tun_config.address(gateway_ip)
              .netmask(netmask)
              .mtu(config.mtu as u16)
              .up();

    if let Some(tun_name_override) = &config.tun_device_path {
        if tun_name_override.contains('/') || tun_name_override.contains('\\') {
            anyhow::bail!(
                "VPN_TUN_DEVICE must be a TUN interface name like 'tun0', not a filesystem path: {}",
                tun_name_override
            );
        }
        tun_config.tun_name(tun_name_override);
    }

    let dev = tun::create_as_async(&tun_config).context("Failed to create TUN device. Ensure NET_ADMIN cap is set.")?;
    let tun_name = std::ops::Deref::deref(&dev).tun_name().unwrap_or_else(|_| "tun0".into());

    info!("TUN Device created: {}. IP: {}", tun_name, gateway_ip);

    let ipv6_enabled = setup_ipv6(&tun_name, state);

    Ok((dev, ipv6_enabled))
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
