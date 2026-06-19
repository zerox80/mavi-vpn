pub(super) fn is_permanent_setup_error(message: &str) -> bool {
    message.contains("AUTH_FAILED")
        || message.contains("Server rejected connection")
        || message.contains("MTU mismatch")
        || message.contains("unsupported VPN MTU")
        || message.contains("Failed to open /dev/net/tun")
        || message.contains("Failed to create TUN device")
        || message.contains("Failed to install IPv6 split route")
        || message.contains("Failed to execute: ip ")
        || message.contains("ip failed:")
}

pub(super) enum SessionEnd {
    UserStopped,
    ConnectionLost,
}
