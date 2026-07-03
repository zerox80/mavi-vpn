//! Shared classification of permanent (non-retryable) session errors.
//!
//! Every client crate runs a reconnect loop that must decide whether a failed
//! session is worth retrying. Some failures are permanent: reconnecting cannot
//! fix bad credentials, a rejected handshake, or an MTU misconfiguration — the
//! retry would fail identically, so the loop must stop instead of backing off
//! forever.
//!
//! Historically each platform crate (Linux, Windows, Android) kept its own
//! marker list, which silently drifted: Windows, for example, did not
//! recognise the `unsupported VPN MTU` marker that [`crate::check_server_mtu`]
//! emits, so that misconfiguration retried forever there. The cross-platform
//! markers now live here — next to the code that produces them — and each
//! platform passes only its genuinely platform-specific markers on top.

/// Marker for authentication failures detected by the client (e.g. the server
/// answered with its HTTP/3 camouflage page instead of a `Config`).
pub const MARKER_AUTH_FAILED: &str = "AUTH_FAILED";

/// Marker for an explicit `ControlMessage::Error` rejection from the server.
pub const MARKER_SERVER_REJECTED: &str = "Server rejected connection";

/// Marker for a server-pushed MTU that differs from the client's pinned MTU.
/// Produced by [`crate::check_server_mtu`].
pub const MARKER_MTU_MISMATCH: &str = "MTU mismatch";

/// Marker for a server-pushed MTU outside the supported 1280–1360 range.
/// Produced by [`crate::check_server_mtu`].
pub const MARKER_UNSUPPORTED_MTU: &str = "unsupported VPN MTU";

/// Markers every platform treats as permanent, regardless of OS.
pub const COMMON_PERMANENT_MARKERS: &[&str] = &[
    MARKER_AUTH_FAILED,
    MARKER_SERVER_REJECTED,
    MARKER_MTU_MISMATCH,
    MARKER_UNSUPPORTED_MTU,
];

/// Returns `true` when `message` marks a permanent session failure that a
/// reconnect cannot fix.
///
/// Checks the cross-platform [`COMMON_PERMANENT_MARKERS`] plus any
/// `platform_markers` the caller supplies (e.g. TUN-device or adapter setup
/// failures that only exist on one OS). Matching is on exact substrings, same
/// as the per-platform lists this replaces.
#[must_use]
pub fn is_permanent_session_error(message: &str, platform_markers: &[&str]) -> bool {
    COMMON_PERMANENT_MARKERS
        .iter()
        .chain(platform_markers)
        .any(|marker| message.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_markers_are_permanent_without_platform_markers() {
        for message in [
            "AUTH_FAILED: Server returned HTML (camouflage response)",
            "Server rejected connection: bad token",
            "MTU mismatch: local/client VPN MTU is 1280, but server pushed 1360",
            "Server pushed unsupported VPN MTU 9000. Supported range is 1280-1360.",
        ] {
            assert!(is_permanent_session_error(message, &[]), "{message}");
        }
    }

    #[test]
    fn transient_errors_are_not_permanent() {
        assert!(!is_permanent_session_error("connection lost", &[]));
        assert!(!is_permanent_session_error(
            "Connection attempt timed out after 15s",
            &[]
        ));
        assert!(!is_permanent_session_error("", &[]));
    }

    #[test]
    fn platform_markers_extend_the_common_set() {
        let platform = &["Failed to open /dev/net/tun"];
        assert!(is_permanent_session_error(
            "Failed to open /dev/net/tun: permission denied",
            platform
        ));
        assert!(!is_permanent_session_error(
            "Failed to open /dev/net/tun: permission denied",
            &[]
        ));
    }

    /// Contract test: the errors [`crate::check_server_mtu`] produces must be
    /// classified as permanent on every platform, otherwise a client would
    /// retry an unfixable MTU misconfiguration forever. This pins the coupling
    /// between the message text and the classifier in one place.
    #[test]
    fn check_server_mtu_errors_are_permanent() {
        let mismatch = crate::check_server_mtu(1300, 1280).unwrap_err();
        assert!(is_permanent_session_error(&mismatch, &[]), "{mismatch}");

        let out_of_range = crate::check_server_mtu(9000, 1280).unwrap_err();
        assert!(
            is_permanent_session_error(&out_of_range, &[]),
            "{out_of_range}"
        );
    }
}
