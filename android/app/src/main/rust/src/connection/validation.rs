use shared::ControlMessage;

pub(crate) fn validate_server_mtu(
    config: &ControlMessage,
    local_tun_mtu: u16,
) -> anyhow::Result<()> {
    if let ControlMessage::Config { mtu, .. } = config {
        shared::check_server_mtu(*mtu, local_tun_mtu).map_err(|e| anyhow::anyhow!(e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn config_with_mtu(mtu: u16) -> ControlMessage {
        ControlMessage::Config {
            assigned_ip: Ipv4Addr::new(10, 8, 0, 2),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::new(10, 8, 0, 1),
            dns_server: Ipv4Addr::new(1, 1, 1, 1),
            mtu,
            assigned_ipv6: None,
            netmask_v6: None,
            gateway_v6: None,
            dns_server_v6: None,
            whitelist_domains: None,
        }
    }

    #[test]
    fn accepts_exact_match() {
        assert!(validate_server_mtu(&config_with_mtu(1280), 1280).is_ok());
        assert!(validate_server_mtu(&config_with_mtu(1340), 1340).is_ok());
    }

    #[test]
    fn rejects_mismatch_regardless_of_direction() {
        assert!(validate_server_mtu(&config_with_mtu(1340), 1280).is_err());
        assert!(validate_server_mtu(&config_with_mtu(1280), 1340).is_err());
    }

    #[test]
    fn rejects_out_of_range() {
        assert!(validate_server_mtu(&config_with_mtu(1500), 1500).is_err());
    }

    #[test]
    fn ignores_non_config_messages() {
        let auth = ControlMessage::Auth {
            token: "tok".to_string(),
        };
        assert!(validate_server_mtu(&auth, 1280).is_ok());
    }
}
