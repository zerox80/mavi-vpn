use clap::{value_parser, Parser};
use std::net::SocketAddr;

/// Inclusive lower bound for the inner tunnel MTU.
/// 1280 is mandated as the minimum by RFC 8200 (IPv6). Anything lower would
/// break IPv6 entirely and is almost always a misconfiguration.
const MIN_MTU: u16 = 1280;

/// Inclusive upper bound for the inner tunnel MTU.
///
/// This is the MTU of the TUN device and the value pushed to clients; it is
/// *not* the outer UDP/QUIC path MTU. The inner MTU must stay below the
/// outer path MTU by the combined QUIC + UDP + IP overhead (~50–80 bytes).
///
/// 1360 is the hard ceiling: it is the usable inner MTU for a residential
/// PPPoE/DSL path (outer path MTU 1460) after subtracting QUIC + UDP + IP
/// overhead, and it works on both IPv4 and IPv6 outer packets. Anything
/// larger would fragment or blackhole on that very common class of last-mile
/// link and is rejected as misconfiguration.
const MAX_MTU: u16 = 1360;

/// Command-line configuration for the Mavi VPN Server.
/// All fields can be set via environment variables (prefixed with `VPN_`)
/// or direct CLI flags.
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Config {
    /// The public address and port the QUIC server will listen on.
    /// Format: `IP:PORT` (e.g., `0.0.0.0:4433`).
    #[arg(long, env = "VPN_BIND_ADDR", default_value = "0.0.0.0:4433")]
    pub bind_addr: SocketAddr,

    /// Pre-shared authentication token. Clients must provide this exact string
    /// during the handshake to gain access. Use a long, random string for security.
    #[arg(long, env = "VPN_AUTH_TOKEN")]
    pub auth_token: String,

    /// The virtual internal network range managed by the VPN.
    /// Example: `10.8.0.0/24`. All clients will receive IPs from this range.
    #[arg(long, env = "VPN_NETWORK", default_value = "10.8.0.0/24")]
    pub network_cidr: String,

    /// Optional explicit TUN interface name.
    /// If not provided, the server will create one (usually `tun0`).
    #[arg(long, env = "VPN_TUN_DEVICE")]
    pub tun_device_path: Option<String>,

    /// The DNS server IP address that will be pushed to all VPN clients.
    /// Recommended: `1.1.1.1` (Cloudflare) or `8.8.8.8` (Google).
    #[arg(long, env = "VPN_DNS", default_value = "1.1.1.1")]
    pub dns: std::net::Ipv4Addr,

    /// Path to the TLS certificate (PEM format).
    /// If it doesn't exist, a self-signed one will be generated on startup.
    #[arg(long, env = "VPN_CERT", default_value = "data/cert.pem")]
    pub cert_path: std::path::PathBuf,

    /// Path to the TLS private key (PEM format).
    #[arg(long, env = "VPN_KEY", default_value = "data/key.pem")]
    pub key_path: std::path::PathBuf,

    /// Maximum Transmission Unit for the virtual interface (inner tunnel MTU).
    ///
    /// This is **not** the outer UDP/QUIC MTU — it is the size of the inner
    /// packets handed to QUIC for encapsulation. Pick it so that
    /// `mtu + QUIC/UDP/IP overhead ≤ path MTU`, where the overhead is ~50–80
    /// bytes depending on IP family and QUIC header flavour.
    ///
    /// WHY 1280 AS DEFAULT?
    /// 1280 is the minimum MTU required for IPv6 and happens to be the path
    /// MTU floor on many mobile networks. It minimises fragmentation and the
    /// "black hole" class of bugs where larger packets are silently dropped.
    ///
    /// RECOMMENDED VALUES
    /// * 1280 — safest default, works everywhere (IPv6 minimum)
    /// * 1360 — maximum; matches a PPPoE/DSL path (outer MTU 1460) minus
    ///   QUIC + UDP + IP overhead, works on both IPv4 and IPv6 outer packets
    #[arg(
        long,
        env = "VPN_MTU",
        default_value = "1280",
        value_parser = value_parser!(u16).range(MIN_MTU as i64..=MAX_MTU as i64),
    )]
    pub mtu: u16,

    /// Enable Layer 7 Obfuscation (Probe Resistance).
    ///
    /// When enabled:
    /// 1. The server uses ALPN `h3` (pretending to be standard HTTP/3).
    /// 2. Unauthorized access attempts receive a fake `nginx` welcome page (HTTP/3 200 OK)
    ///    instead of a simple connection reset. This defeats active probing from firewalls.
    #[arg(long, env = "VPN_CENSORSHIP_RESISTANT", default_value = "false")]
    pub censorship_resistant: bool,

    /// Enable TCP MSS Clamping.
    ///
    /// Rewrites the Maximum Segment Size (MSS) in TCP headers to ensure TCP
    /// connections within the tunnel fit into the (smaller) VPN packets.
    /// Usually disabled when using a safe default MTU (1280).
    #[arg(long, env = "VPN_MSS_CLAMPING", default_value = "false")]
    pub mss_clamping: bool,

    /// The IPv6 DNS server IP address pushed to clients (only used when IPv6 is active).
    /// If not set, defaults to 2606:4700:4700::1111 (Cloudflare).
    #[arg(long, env = "VPN_DNS_V6")]
    pub dns_v6: Option<std::net::Ipv6Addr>,

    /// Split-tunnelling: domain names provided here will be whitelisted on
    /// the client side (resolved via local DNS, bypassing the VPN).
    #[arg(long, env = "VPN_WHITELIST_DOMAINS", value_delimiter = ',', num_args = 0..)]
    pub whitelist_domains: Vec<String>,

    /// Enable Keycloak JWT authentication instead of static token
    #[arg(long, env = "VPN_KEYCLOAK_ENABLED", default_value = "false")]
    pub keycloak_enabled: bool,

    /// Keycloak Server URL (e.g., https://auth.example.com)
    #[arg(long, env = "VPN_KEYCLOAK_URL")]
    pub keycloak_url: Option<String>,

    /// Keycloak Realm
    #[arg(long, env = "VPN_KEYCLOAK_REALM", default_value = "mavi-vpn")]
    pub keycloak_realm: String,

    /// Keycloak Client ID
    #[arg(long, env = "VPN_KEYCLOAK_CLIENT_ID", default_value = "mavi-client")]
    pub keycloak_client_id: String,

    /// ECH "public_name" — the cover/outer SNI that clients will send on the
    /// wire. Must be a plausible-looking domain (e.g. a CDN). Only used when
    /// `censorship_resistant` is enabled.
    #[arg(long, env = "VPN_ECH_PUBLIC_NAME", default_value = "cloudflare-ech.com")]
    pub ech_public_name: String,

    /// Path to the persisted ECHConfigList bytes (clients consume this).
    #[arg(long, env = "VPN_ECH_CONFIG", default_value = "data/ech_config.bin")]
    pub ech_config_path: std::path::PathBuf,

    /// Path to the persisted ECH HPKE private key bytes.
    #[arg(long, env = "VPN_ECH_KEY", default_value = "data/ech_key.bin")]
    pub ech_key_path: std::path::PathBuf,
}

/// Loads the server configuration from environment variables and CLI arguments.
/// Also attempts to load a `.env` file from the current working directory.
pub fn load() -> Config {
    // Load .env file if it exists
    dotenv::dotenv().ok();
    Config::parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::parse_from(&["mavi-vpn", "--auth-token", "secret123"]);
        assert_eq!(config.mtu, 1280);
        assert_eq!(config.network_cidr, "10.8.0.0/24");
        assert_eq!(config.dns, std::net::Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(config.auth_token, "secret123");
        assert!(!config.censorship_resistant);
        assert!(!config.mss_clamping);
    }

    #[test]
    fn test_mtu_valid_range() {
        let config = Config::parse_from(&["mavi-vpn", "--auth-token", "secret123", "--mtu", "1360"]);
        assert_eq!(config.mtu, 1360);
        
        let config = Config::parse_from(&["mavi-vpn", "--auth-token", "secret123", "--mtu", "1280"]);
        assert_eq!(config.mtu, 1280);
    }

    #[test]
    fn test_custom_arguments() {
        let config = Config::parse_from(&[
            "mavi-vpn",
            "--auth-token", "super_secret",
            "--network", "192.168.10.0/24",
            "--dns", "8.8.8.8",
            "--censorship-resistant",
            "--mss-clamping",
        ]);
        assert_eq!(config.auth_token, "super_secret");
        assert_eq!(config.network_cidr, "192.168.10.0/24");
        assert_eq!(config.dns, std::net::Ipv4Addr::new(8, 8, 8, 8));
        assert!(config.censorship_resistant);
        assert!(config.mss_clamping);
    }

    #[test]
    fn test_whitelist_domains() {
        let config = Config::parse_from(&[
            "mavi-vpn",
            "--auth-token", "secret",
            "--whitelist-domains", "github.com,google.com"
        ]);
        assert_eq!(config.whitelist_domains, vec!["github.com", "google.com"]);
    }
}

