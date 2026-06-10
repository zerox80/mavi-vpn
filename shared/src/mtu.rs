//! MTU validation and ICMP "Packet Too Big" helpers shared by server and
//! clients.
//!
//! The inner TUN MTU is the single knob operators turn; the QUIC payload MTU is
//! derived from it and pinned before the handshake (MTU discovery is disabled).
//! These helpers keep server and clients in agreement on that value and make the
//! synthesized PMTUD signal actually convergent.

use crate::{MAX_TUN_MTU, MIN_TUN_MTU};

/// Validates the MTU the server pushed against the inner TUN MTU the client
/// pinned its QUIC transport budget to.
///
/// Clients fix `initial_mtu`/`min_mtu` **before** the handshake (MTU discovery
/// is disabled), so they can never transport datagrams larger than that pinned
/// budget. The server-pushed MTU must therefore be **exactly equal** to the
/// local TUN MTU. Accepting a larger value — even when the local MTU came from
/// the compiled-in default — silently breaks every full-size packet, and the
/// synthesized ICMP "Packet Too Big" cannot recover it because the dropped
/// packet never reaches the path where PMTUD would help.
///
/// The error message embeds the marker substrings `"unsupported VPN MTU"` /
/// `"MTU mismatch"`, which every client's permanent-error classifier already
/// recognises, so a misconfiguration stops the reconnect loop instead of
/// retrying forever.
///
/// # Errors
/// Returns `Err` if `server_mtu` is out of the supported range or differs from
/// `local_tun_mtu`.
pub fn check_server_mtu(server_mtu: u16, local_tun_mtu: u16) -> Result<(), String> {
    if !(MIN_TUN_MTU..=MAX_TUN_MTU).contains(&server_mtu) {
        return Err(format!(
            "Server pushed unsupported VPN MTU {server_mtu}. Supported range is {MIN_TUN_MTU}-{MAX_TUN_MTU}."
        ));
    }
    if server_mtu != local_tun_mtu {
        return Err(format!(
            "MTU mismatch: local/client VPN MTU is {local_tun_mtu}, but server pushed {server_mtu}. \
             Configure both sides to the same VPN_MTU (the client pins its transport budget before \
             the handshake and cannot adopt a different value)."
        ));
    }
    Ok(())
}

/// Computes the MTU value to report in a synthesized ICMP "Packet Too Big".
///
/// The reported value MUST be small enough that the sender's PMTUD actually
/// shrinks its segments below the QUIC datagram limit. The true ceiling is the
/// inner IP packet that fits in a QUIC datagram — `max_datagram_size` minus any
/// H3/MASQUE datagram prefix the side adds — **not** the configured TUN MTU,
/// which can be larger than what the pinned transport can carry.
///
/// `tun_mtu` is used as an upper clamp (never advertise more than configured).
/// When `max_datagram_size` is unknown we fall back to `tun_mtu`. IPv6 is
/// floored at the RFC 8200 minimum of 1280.
#[must_use]
pub fn effective_ptb_mtu(
    tun_mtu: u16,
    max_datagram_size: Option<usize>,
    h3_prefix_len: usize,
    is_ipv6: bool,
) -> u16 {
    let mut reported = tun_mtu;
    if let Some(max) = max_datagram_size {
        let budget = u16::try_from(max.saturating_sub(h3_prefix_len)).unwrap_or(u16::MAX);
        reported = reported.min(budget);
    }
    if is_ipv6 {
        // IPv6 mandates a minimum link MTU of 1280; never advertise less.
        reported = reported.max(1280);
    }
    reported
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_server_mtu_accepts_only_exact_match() {
        assert!(check_server_mtu(1280, 1280).is_ok());
        assert!(check_server_mtu(1360, 1360).is_ok());
        // Mismatch is rejected regardless of which side is larger.
        assert!(check_server_mtu(1360, 1280).is_err());
        assert!(check_server_mtu(1280, 1360).is_err());
    }

    #[test]
    fn check_server_mtu_rejects_out_of_range() {
        let err = check_server_mtu(1279, 1279).unwrap_err();
        assert!(err.contains("unsupported VPN MTU"));
        assert!(check_server_mtu(1361, 1361).is_err());
    }

    #[test]
    fn check_server_mtu_error_contains_classifier_markers() {
        // The strings the per-platform permanent-error classifiers match on.
        assert!(check_server_mtu(1360, 1280)
            .unwrap_err()
            .contains("MTU mismatch"));
        assert!(check_server_mtu(2000, 1280)
            .unwrap_err()
            .contains("unsupported VPN MTU"));
    }

    #[test]
    fn effective_ptb_mtu_reports_transport_budget_not_tun_mtu() {
        // TUN MTU 1360 but the path only carries 1330-byte datagrams -> report
        // 1330 so the sender's PMTUD actually shrinks below the QUIC limit.
        assert_eq!(effective_ptb_mtu(1360, Some(1330), 0, false), 1330);
        // H3 prefix eats into the inner-packet budget.
        assert_eq!(effective_ptb_mtu(1360, Some(1330), 2, false), 1328);
    }

    #[test]
    fn effective_ptb_mtu_clamps_to_tun_mtu_and_falls_back() {
        // Budget larger than tun_mtu -> never advertise more than configured.
        assert_eq!(effective_ptb_mtu(1280, Some(5000), 0, false), 1280);
        // Unknown datagram size -> fall back to tun_mtu.
        assert_eq!(effective_ptb_mtu(1300, None, 0, false), 1300);
    }

    #[test]
    fn effective_ptb_mtu_floors_ipv6_at_1280() {
        // Even a tiny transport budget must report >= 1280 for IPv6.
        assert_eq!(effective_ptb_mtu(1280, Some(1000), 0, true), 1280);
        // IPv4 may go below 1280.
        assert_eq!(effective_ptb_mtu(1280, Some(1000), 0, false), 1000);
    }
}
