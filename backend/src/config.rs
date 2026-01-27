use clap::Parser;
use std::net::SocketAddr;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Config {
    /// The address to listen on (UDP/QUIC)
    #[arg(long, env = "VPN_BIND_ADDR", default_value = "0.0.0.0:4433")]
    pub bind_addr: SocketAddr,

    /// The authentication token clients must provide
    #[arg(long, env = "VPN_AUTH_TOKEN")]
    pub auth_token: String,

    /// The CIDR network to manage (e.g., 10.8.0.0/24)
    #[arg(long, env = "VPN_NETWORK", default_value = "10.8.0.0/24")]
    pub network_cidr: String,

    /// Path to the Tun interface (e.g., /dev/net/tun)
    // On Linux we create it, but good to have configurable for some environments
    #[arg(long, env = "VPN_TUN_DEVICE")]
    pub tun_device_path: Option<String>,

    /// The DNS server to push to clients
    #[arg(long, env = "VPN_DNS", default_value = "1.1.1.1")]
    pub dns: std::net::Ipv4Addr,

    /// Path to the SSL Certificate
    #[arg(long, env = "VPN_CERT", default_value = "data/cert.pem")]
    pub cert_path: std::path::PathBuf,

    /// Path to the SSL Private Key
    #[arg(long, env = "VPN_KEY", default_value = "data/key.pem")]
    pub key_path: std::path::PathBuf,

    /// MTU for the VPN interface
    #[arg(long, env = "VPN_MTU", default_value = "1280")]
    pub mtu: u16,
}

pub fn load() -> Config {
    // Load .env file if it exists
    dotenv::dotenv().ok();
    Config::parse()
}
