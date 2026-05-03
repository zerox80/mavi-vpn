use crate::config::Config;
use crate::state::AppState;
use anyhow::{Context, Result};
use tracing::{info, warn};
use tun::AbstractDevice;

fn validate_tun_name(name: &str) -> Result<()> {
    if name.contains('/') || name.contains('\\') {
        anyhow::bail!(
            "VPN_TUN_DEVICE must be a TUN interface name like 'tun0', not a filesystem path: {name}"
        );
    }
    Ok(())
}

fn ipv6_setup_args(tun_name: &str, gateway_ip6: std::net::Ipv6Addr) -> Vec<String> {
    vec![
        "-6".to_string(),
        "addr".to_string(),
        "add".to_string(),
        format!("{gateway_ip6}/64"),
        "dev".to_string(),
        tun_name.to_string(),
    ]
}

pub fn create_tun_device(config: &Config, state: &AppState) -> Result<(tun::AsyncDevice, bool)> {
    let mut tun_config = tun::Configuration::default();
    let gateway_ip = state.gateway_ip();
    let netmask = state.network.mask();

    tun_config
        .address(gateway_ip)
        .netmask(netmask)
        .mtu(config.mtu)
        .up();

    if let Some(tun_name_override) = &config.tun_device_path {
        validate_tun_name(tun_name_override)?;
        tun_config.tun_name(tun_name_override);
    }

    let dev = tun::create_as_async(&tun_config)
        .context("Failed to create TUN device. Ensure NET_ADMIN cap is set.")?;
    let tun_name = &*dev.tun_name().unwrap_or_else(|_| "tun0".into());

    info!(
        "TUN Device created: {}. IP: {} MTU: {}",
        tun_name, gateway_ip, config.mtu
    );

    let ipv6_enabled = setup_ipv6(tun_name, state);

    Ok((dev, ipv6_enabled))
}

fn setup_ipv6(tun_name: &str, state: &AppState) -> bool {
    let gateway_ip6 = state.gateway_ip_v6();
    let args = ipv6_setup_args(tun_name, gateway_ip6);
    match std::process::Command::new("ip")
        .args(args.iter().map(String::as_str))
        .output()
    {
        Ok(output) if output.status.success() => {
            info!(
                "IPv6 address {} successfully assigned to {}",
                gateway_ip6, tun_name
            );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_name_rejects_filesystem_paths() {
        assert!(validate_tun_name("mavi0").is_ok());
        assert!(validate_tun_name("tun-prod_1").is_ok());
        assert!(validate_tun_name("/dev/net/tun").is_err());
        assert!(validate_tun_name("..\\tun").is_err());
    }

    #[test]
    fn ipv6_setup_args_assign_gateway_to_interface() {
        let args = ipv6_setup_args(
            "mavi0",
            std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
        );

        assert_eq!(
            args,
            vec![
                "-6",
                "addr",
                "add",
                "fd00::1/64",
                "dev",
                "mavi0"
            ]
        );
    }
}
