/// Marker substrings for Linux-specific permanent setup failures: TUN device
/// creation and `ip`-command failures will fail identically on retry, so the
/// reconnect loop must stop instead of backing off forever. The cross-platform
/// markers (auth, server rejection, MTU) live in [`shared::session_errors`].
const LINUX_PERMANENT_MARKERS: &[&str] = &[
    "Failed to open /dev/net/tun",
    "Failed to create TUN device",
    "Failed to install IPv6 split route",
    "Failed to execute: ip ",
    "ip failed:",
];

pub(super) fn is_permanent_setup_error(message: &str) -> bool {
    shared::session_errors::is_permanent_session_error(message, LINUX_PERMANENT_MARKERS)
}

pub(super) enum SessionEnd {
    UserStopped,
    ConnectionLost,
}
