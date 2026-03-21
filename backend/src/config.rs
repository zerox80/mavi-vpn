use clap::Parser;
use std::net::SocketAddr;

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

    /// Optional explicit path to the TUN device.
    /// If not provided, the server will attempt to create a new one (usually `tun0`).
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

    /// Maximum Transmission Unit for the virtual interface.
    ///
    /// WHY 1280?
    /// 1280 is the minimum MTU required for IPv6. By matching the inner MTU
    /// to the path MTU limit of many mobile networks, we minimise fragmentation
    /// overhead and "Black Hole" issues where larger packets are silently dropped.
    #[arg(long, env = "VPN_MTU", default_value = "1280")]
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

    /// Split-tunnelling: domain names provided here will be whitelisted on
    /// the client side (resolved via local DNS, bypassing the VPN).
    #[arg(long, env = "VPN_WHITELIST_DOMAINS", value_delimiter = ',', num_args = 0..)]
    pub whitelist_domains: Vec<String>,

    /// Enable Keycloak JWT authentication instead of static token
    #[arg(long, env = "KEYCLOAK_ENABLED", default_value = "false")]
    pub keycloak_enabled: bool,

    /// Keycloak Server URL (e.g., https://auth.example.com)
    #[arg(long, env = "KEYCLOAK_URL")]
    pub keycloak_url: Option<String>,

    /// Keycloak Realm
    #[arg(long, env = "KEYCLOAK_REALM", default_value = "mavi-vpn")]
    pub keycloak_realm: String,

    /// Keycloak Client ID
    #[arg(long, env = "KEYCLOAK_CLIENT_ID", default_value = "mavi-client")]
    pub keycloak_client_id: String,
}

/// Loads the server configuration from environment variables and CLI arguments.
/// Also attempts to load a `.env` file from the current working directory.
pub fn load() -> Config {
    // Load .env file if it exists
    dotenv::dotenv().ok();
    Config::parse()
}
