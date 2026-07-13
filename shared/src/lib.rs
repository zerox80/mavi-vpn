#![allow(clippy::multiple_crate_versions)]
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

pub mod cert_pin;
// Also compiled for plain `cargo test -p shared` (via the `test` cfg and the
// matching dev-dependencies) so its unit tests run without feature flags.
#[cfg(any(feature = "control-client", test))]
pub mod control;
pub mod endpoint;
pub mod hex;
pub mod http2;
pub mod icmp;
pub mod ipc;
#[cfg(feature = "oauth-client")]
pub mod kc_oauth;
pub mod masque;
pub mod mtu;
pub mod session_errors;
pub mod split_tunnel;

pub use endpoint::{
    endpoint_host, endpoint_host_is_explicit_ipv6, resolve_server_name, split_endpoint,
};
pub use mtu::{
    check_server_mtu, compute_quic_mtu_config, effective_ptb_mtu, validate_control_message_mtu,
    QuicMtuConfig,
};

#[cfg(test)]
pub mod test_helpers;

/// Fixed overhead budget (in bytes) reserved on top of the inner TUN MTU to
/// cover QUIC short-header framing + AEAD tag + connection-ID bytes.
///
/// The outer QUIC payload MTU is derived as `tun_mtu + QUIC_OVERHEAD_BYTES`, so
/// the inner MTU remains the single knob operators turn. Server and client
/// must agree on `tun_mtu`, otherwise the larger side will send packets the
/// smaller side considers out-of-spec.
pub const QUIC_OVERHEAD_BYTES: u16 = 80;

/// Default inner TUN MTU when the operator has not overridden `VPN_MTU`.
///
/// 1280 is the IPv6 minimum (RFC 8200) and is safe on every residential path
/// we have measured. It yields a QUIC payload MTU of 1360, matching the
/// pre-knob pinning.
pub const DEFAULT_TUN_MTU: u16 = 1280;

/// Minimum allowed inner TUN MTU (inclusive).
pub const MIN_TUN_MTU: u16 = 1280;

/// Maximum allowed inner TUN MTU (inclusive).
pub const MAX_TUN_MTU: u16 = 1360;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunMtuSource {
    Config,
    Env,
    Default,
}

/// Resolve the inner TUN MTU from a config value, environment, or default.
///
/// The explicit `vpn_mtu` parameter takes highest priority; it must be within
/// the 1280–1360 range. Invalid or out-of-range values are silently ignored
/// and fall through to the next source.
///
/// QUIC Payload MTU is always derived as `tun_mtu + QUIC_OVERHEAD_BYTES`
/// (i.e. +80) and must never be set independently.
#[must_use]
pub fn resolve_tun_mtu(vpn_mtu: Option<u16>) -> u16 {
    resolve_tun_mtu_with_source(vpn_mtu).0
}

/// Resolve the inner TUN MTU and return the source of the value.
///
/// The explicit `vpn_mtu` parameter takes highest priority; it must be within
/// the 1280–1360 range. Invalid or out-of-range values are silently ignored
/// and fall through to the next source.
#[must_use]
pub fn resolve_tun_mtu_with_source(vpn_mtu: Option<u16>) -> (u16, TunMtuSource) {
    // 1. Explicit config field (highest priority)
    if let Some(v) = vpn_mtu {
        if (MIN_TUN_MTU..=MAX_TUN_MTU).contains(&v) {
            return (v, TunMtuSource::Config);
        }
        // Fall through to env / default on out-of-range values
    }

    // 2. Environment variable (CLI / daemon use)
    if let Ok(s) = std::env::var("VPN_MTU") {
        if let Ok(v) = s.trim().parse::<u16>() {
            if (MIN_TUN_MTU..=MAX_TUN_MTU).contains(&v) {
                return (v, TunMtuSource::Env);
            }
        }
    }

    // 3. Compiled-in default
    (DEFAULT_TUN_MTU, TunMtuSource::Default)
}

/// Control-plane messages exchanged over the QUIC bidirectional stream during
/// connection setup (the "handshake phase").
///
/// Wire format: each message is length-prefixed with a little-endian `u32`
/// followed by the `bincode`-serialised payload.
///
/// # Flow
/// 1. Client opens a bidirectional QUIC stream.
/// 2. Client sends `Auth { token }`.
/// 3. Server responds with either `Config { … }` (success) or `Error { … }` (failure).
/// 4. The stream is then closed; all subsequent data is exchanged via datagrams.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ControlMessage {
    /// Sent by the client to authenticate against the server's pre-shared token.
    Auth { token: String },

    /// Sent by the server upon successful authentication.
    /// Contains all network configuration the client needs to bring up the tunnel.
    Config {
        /// IPv4 address assigned to the client's virtual network interface.
        assigned_ip: Ipv4Addr,
        /// IPv4 subnet mask of the VPN network (e.g. `255.255.255.0` for /24).
        netmask: Ipv4Addr,
        /// IPv4 address of the VPN gateway (server-side TUN interface), used
        /// as the next-hop for the default route.
        gateway: Ipv4Addr,
        /// IPv4 DNS server the client should use while connected.
        dns_server: Ipv4Addr,
        /// Maximum Transmission Unit for the virtual network interface in bytes.
        /// Clients should set their TUN/TAP adapter MTU to this value.
        mtu: u16,

        // --- Optional IPv6 configuration ---
        /// IPv6 address assigned to the client (dual-stack support). `None` if
        /// the server does not offer IPv6.
        assigned_ipv6: Option<Ipv6Addr>,
        /// IPv6 prefix length (e.g. `64` for a /64 network). IPv6 uses CIDR
        /// prefix lengths rather than dot-decimal netmasks.
        netmask_v6: Option<u8>,
        /// IPv6 gateway address (server-side TUN interface) for the default IPv6 route.
        gateway_v6: Option<Ipv6Addr>,
        /// IPv6 DNS server the client should use while connected.
        dns_server_v6: Option<Ipv6Addr>,
        /// Optional list of domain names that should bypass the VPN tunnel
        /// (split-tunnelling allow-list). An empty list means route all DNS through VPN.
        whitelist_domains: Option<Vec<String>>,
    },

    /// Sent by the server when it rejects the connection (e.g. bad token, no IPs available).
    /// The client should log `message` and may retry after a backoff.
    Error { message: String },

    /// Sent by an already-authenticated client over a *fresh* bidirectional QUIC
    /// stream during an active session to present a silently refreshed Keycloak
    /// access token. It lets the server extend the session deadline in place so
    /// the live tunnel survives the original token's expiry without a reconnect.
    ///
    /// Framed exactly like the handshake `Auth` message (`u32` length prefix +
    /// bincode payload). Appended after `Error` so existing variant indices stay
    /// wire-compatible with older peers.
    Reauth { token: String },

    /// Server's reply to [`ControlMessage::Reauth`]. `accepted` is `true` when the
    /// new token validated and the session deadline was extended; `false` when the
    /// token was rejected (the client should let the session lapse and re-login).
    ReauthResult { accepted: bool },
}

/// Validates that a Keycloak base URL uses HTTPS.
///
/// JWKS fetches, the OAuth authorization redirect and the token exchange all
/// derive from this URL; over plain HTTP a MITM can substitute signing keys
/// or capture tokens. Plain HTTP is only allowed for loopback hosts (dev).
///
/// # Errors
/// Returns a human-readable reason when the URL is not acceptable.
pub fn validate_keycloak_url(url: &str) -> Result<(), String> {
    if url.starts_with("https://") {
        return Ok(());
    }
    if let Some(rest) = url.strip_prefix("http://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if authority.contains('@') {
            return Err(
                "Keycloak URL must not contain userinfo; plain HTTP is only allowed for localhost"
                    .to_string(),
            );
        }
        let host = authority
            .strip_prefix('[')
            .and_then(|h| h.split(']').next())
            .unwrap_or_else(|| authority.rsplit_once(':').map_or(authority, |(h, _)| h));
        if matches!(host, "localhost" | "127.0.0.1" | "::1") {
            return Ok(());
        }
        return Err(format!(
            "Keycloak URL must use https:// (got plain http for host {host:?}); plain HTTP is only allowed for localhost"
        ));
    }
    Err("Keycloak URL must start with https://".to_string())
}

/// Checks whether a raw byte buffer looks like an HTML response.
///
/// Used by clients to detect the server's camouflage/nginx response when
/// authentication fails in censorship-resistant mode. This replaces the
/// fragile magic-number length check (`0x1901`) that was previously used
/// on Windows and Android.
#[must_use]
pub fn looks_like_html_response(buf: &[u8]) -> bool {
    let start = buf
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(buf.len());
    let trimmed = &buf[start..];
    [b"<!doctype".as_slice(), b"<html".as_slice()]
        .iter()
        .any(|prefix| {
            trimmed.len() >= prefix.len() && trimmed[..prefix.len()].eq_ignore_ascii_case(prefix)
        })
}

#[cfg(test)]
mod tests;
