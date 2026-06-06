use shared::{ControlMessage, TunMtuSource, MAX_TUN_MTU, MIN_TUN_MTU};

pub(crate) fn validate_server_mtu(
    config: &ControlMessage,
    local_tun_mtu: u16,
    mtu_source: TunMtuSource,
) -> anyhow::Result<()> {
    if let ControlMessage::Config { mtu, .. } = config {
        if !(MIN_TUN_MTU..=MAX_TUN_MTU).contains(mtu) {
            anyhow::bail!(
                "Server pushed unsupported VPN MTU {}. Supported range is {}-{}.",
                mtu,
                MIN_TUN_MTU,
                MAX_TUN_MTU
            );
        }

        if mtu_source != TunMtuSource::Default && *mtu != local_tun_mtu {
            anyhow::bail!(
                "MTU mismatch: local/client VPN MTU is {local_tun_mtu}, but server pushed {mtu}. Configure both sides to the same VPN_MTU."
            );
        }
    }
    Ok(())
}
