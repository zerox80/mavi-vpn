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

    /// Pre-shared authentication token. Required unless Keycloak authentication
    /// is enabled. Clients must provide this exact string during the handshake
    /// to gain access. Use a long, random string for security.
    #[arg(long, env = "VPN_AUTH_TOKEN")]
    pub auth_token: Option<String>,

    /// The virtual internal network range managed by the VPN.
    /// Example: `10.8.0.0/24`. All clients will receive IPs from this range.
    #[arg(long, env = "VPN_NETWORK", default_value = "10.8.0.0/24")]
    pub network_cidr: String,

    /// The virtual internal IPv6 network range managed by the VPN.
    /// Example: `fd00::/64`. All dual-stack clients receive IPv6 addresses
    /// from this range when IPv6 setup succeeds.
    #[arg(long, env = "VPN_NETWORK_V6", default_value = "fd00::/64")]
    pub network_cidr_v6: String,

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
    /// If not set, defaults to `2606:4700:4700::1111` (Cloudflare).
    #[arg(long, env = "VPN_DNS_V6")]
    pub dns_v6: Option<std::net::Ipv6Addr>,

    /// Split-tunnelling: domain names provided here will be whitelisted on
    /// the client side (resolved via local DNS, bypassing the VPN).
    #[arg(long, env = "VPN_WHITELIST_DOMAINS", value_delimiter = ',', num_args = 0..)]
    pub whitelist_domains: Vec<String>,

    /// Enable Keycloak JWT authentication instead of static token
    #[arg(long, env = "VPN_KEYCLOAK_ENABLED", default_value = "false")]
    pub keycloak_enabled: bool,

    /// Keycloak Server URL (e.g., <https://auth.example.com>)
    #[arg(long, env = "VPN_KEYCLOAK_URL")]
    pub keycloak_url: Option<String>,

    /// Keycloak Realm
    #[arg(long, env = "VPN_KEYCLOAK_REALM", default_value = "mavi-vpn")]
    pub keycloak_realm: String,

    /// Keycloak Client ID
    #[arg(long, env = "VPN_KEYCLOAK_CLIENT_ID", default_value = "mavi-client")]
    pub keycloak_client_id: String,

    /// Optional Keycloak role required on accepted JWTs. The validator checks
    /// both realm roles and roles scoped to `VPN_KEYCLOAK_CLIENT_ID`.
    #[arg(long, env = "VPN_KEYCLOAK_REQUIRED_ROLE")]
    pub keycloak_required_role: Option<String>,

    /// Optional OAuth scope required on accepted JWTs.
    #[arg(long, env = "VPN_KEYCLOAK_REQUIRED_SCOPE")]
    pub keycloak_required_scope: Option<String>,

    /// ECH "`public_name`" — the cover/outer SNI that clients will send on the
    /// wire. Must be a plausible-looking domain (e.g. a CDN). Only used when
    /// `censorship_resistant` is enabled.
    #[arg(
        long,
        env = "VPN_ECH_PUBLIC_NAME",
        default_value = "cloudflare-ech.com"
    )]
    pub ech_public_name: String,

    /// Path to the persisted `ECHConfigList` bytes (clients consume this).
    #[arg(long, env = "VPN_ECH_CONFIG", default_value = "data/ech_config.bin")]
    pub ech_config_path: std::path::PathBuf,

    /// Path to the persisted ECH HPKE private key bytes.
    #[arg(long, env = "VPN_ECH_KEY", default_value = "data/ech_key.bin")]
    pub ech_key_path: std::path::PathBuf,
}

/// Where the effective `mtu` value came from, for the startup log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtuSetting {
    Flag,
    Env,
    Default,
}

impl MtuSetting {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Flag => "--mtu flag",
            Self::Env => "VPN_MTU env / .env",
            Self::Default => "default",
        }
    }

    fn from_matches(matches: &clap::ArgMatches) -> Self {
        match matches.value_source("mtu") {
            Some(clap::parser::ValueSource::CommandLine) => Self::Flag,
            Some(clap::parser::ValueSource::EnvVariable) => Self::Env,
            _ => Self::Default,
        }
    }
}

/// Loads the server configuration from environment variables and CLI arguments.
/// Also attempts to load a `.env` file from the current working directory.
/// Returns the config together with the provenance of the MTU value, so the
/// startup log can say where the knob was turned (flag vs. env vs. default).
pub fn load() -> (Config, MtuSetting) {
    // Load .env file if it exists
    dotenvy::dotenv().ok();
    let matches = <Config as clap::CommandFactory>::command().get_matches();
    let mut config = match <Config as clap::FromArgMatches>::from_arg_matches(&matches) {
        Ok(config) => config,
        Err(err) => err.exit(),
    };
    config.normalize();
    if let Err(err) = config.validate() {
        eprintln!("{err}");
        std::process::exit(2);
    }
    (config, MtuSetting::from_matches(&matches))
}

impl Config {
    /// Docker Compose forwards unset optional variables as empty strings
    /// (`${VAR:-}`), which clap surfaces as `Some("")`. Treat empty
    /// role/scope requirements as absent, like `auth_token`/`keycloak_url`.
    fn normalize(&mut self) {
        for field in [
            &mut self.keycloak_required_role,
            &mut self.keycloak_required_scope,
        ] {
            if field.as_deref().is_some_and(str::is_empty) {
                *field = None;
            }
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.keycloak_enabled && self.auth_token.as_deref().is_none_or(str::is_empty) {
            return Err(
                "VPN_AUTH_TOKEN / --auth-token is required when Keycloak auth is disabled"
                    .to_string(),
            );
        }
        if !self.keycloak_enabled
            && (self.keycloak_required_role.is_some() || self.keycloak_required_scope.is_some())
        {
            return Err(
                "VPN_KEYCLOAK_REQUIRED_ROLE/SCOPE require VPN_KEYCLOAK_ENABLED=true".to_string(),
            );
        }
        if self
            .keycloak_required_role
            .as_deref()
            .is_some_and(str::is_empty)
            || self
                .keycloak_required_scope
                .as_deref()
                .is_some_and(str::is_empty)
        {
            return Err("Keycloak role/scope requirements must not be empty".to_string());
        }
        if self.keycloak_enabled {
            let Some(url) = self.keycloak_url.as_deref().filter(|u| !u.is_empty()) else {
                return Err(
                    "VPN_KEYCLOAK_URL is required when VPN_KEYCLOAK_ENABLED=true".to_string(),
                );
            };
            if let Err(err) = shared::validate_keycloak_url(url) {
                return Err(format!("VPN_KEYCLOAK_URL: {err}"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
