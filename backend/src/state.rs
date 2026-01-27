use dashmap::DashMap;
use ipnetwork::{Ipv4Network, Ipv6Network};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::sync::mpsc;
use anyhow::{Result, anyhow};
use std::collections::HashSet;
use std::sync::Mutex;

/// A channel to send specific IP packets to a connected client task.
pub type ClientTx = mpsc::Sender<bytes::Bytes>;

/// Manages the state of the VPN server: connected peers and IP allocation.
pub struct AppState {
    /// Map of Virtual IP -> Channel to send packets to that client
    pub peers: DashMap<Ipv4Addr, ClientTx>,
    pub peers_v6: DashMap<Ipv6Addr, ClientTx>,

    /// The network range we are managing (e.g., 10.8.0.0/24)
    pub network: Ipv4Network,
    pub network_v6: Ipv6Network,

    /// Stack of free IPs for O(1) allocation
    free_ips: Mutex<Vec<Ipv4Addr>>,
    free_ips_v6: Mutex<Vec<Ipv6Addr>>,
}

impl AppState {
    pub fn new(cidr: &str) -> Result<Self> {
        let network: Ipv4Network = cidr.parse().map_err(|_| anyhow!("Invalid CIDR"))?;
        let network_v6: Ipv6Network = "fd00::/64".parse().unwrap();
        
        // Pre-fill free IPs (excluding Network, Gateway, Broadcast)
        let mut free_ips = Vec::new();
        let gateway = network.nth(1).unwrap();
        let broadcast = network.broadcast();
        
        for ip in network.iter() {
            if ip != network.network() && ip != gateway && ip != broadcast {
                free_ips.push(ip);
            }
        }
        // Reverse so we allocate from .2 upwards (pop from end)
        free_ips.reverse();

        // IPv6 (Simpler, just take first 5000 for now to avoid massive memory usage)
        let mut free_ips_v6 = Vec::new();
        let gateway_v6 = network_v6.iter().nth(1).unwrap();
        
        // We can't iterate all IPv6 /64, just take a reasonable pool size
        for i in 2..5002 {
             if let Some(ip) = network_v6.iter().nth(i) {
                 free_ips_v6.push(ip);
             }
        }
        free_ips_v6.reverse();

        Ok(Self {
            peers: DashMap::new(),
            peers_v6: DashMap::new(),
            network,
            network_v6,
            free_ips: Mutex::new(free_ips),
            free_ips_v6: Mutex::new(free_ips_v6),
        })
    }

    /// Allocate a new free IPv4 address (O(1))
    pub fn assign_ip(&self) -> Result<Ipv4Addr> {
        let mut free = self.free_ips.lock().unwrap();
        free.pop().ok_or_else(|| anyhow!("No IPv4 addresses available"))
    }

    /// Allocate a new free IPv6 address (O(1))
    pub fn assign_ipv6(&self) -> Result<Ipv6Addr> {
        let mut free = self.free_ips_v6.lock().unwrap();
        free.pop().ok_or_else(|| anyhow!("No IPv6 addresses available"))
    }

    /// Release IP addresses (O(1))
    pub fn release_ips(&self, ip4: Ipv4Addr, ip6: Ipv6Addr) {
        {
            let mut free = self.free_ips.lock().unwrap();
            // We push back to stack. Order doesn't strictly matter for correctness.
            free.push(ip4);
        }
        {
            let mut free = self.free_ips_v6.lock().unwrap();
            free.push(ip6);
        }
        self.peers.remove(&ip4);
        self.peers_v6.remove(&ip6);
    }

    pub fn register_client(&self, ip4: Ipv4Addr, ip6: Ipv6Addr, tx: ClientTx) {
        self.peers.insert(ip4, tx.clone());
        self.peers_v6.insert(ip6, tx);
    }

    pub fn gateway_ip(&self) -> Ipv4Addr {
        self.network.nth(1).unwrap()
    }

    pub fn gateway_ip_v6(&self) -> Ipv6Addr {
        self.network_v6.iter().nth(1).unwrap()
    }
}
