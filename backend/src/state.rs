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

    /// Simple IP Allocator
    allocated_ips: Mutex<HashSet<Ipv4Addr>>,
    allocated_ips_v6: Mutex<HashSet<Ipv6Addr>>,
}

impl AppState {
    pub fn new(cidr: &str) -> Result<Self> {
        let network: Ipv4Network = cidr.parse().map_err(|_| anyhow!("Invalid CIDR"))?;
        let network_v6: Ipv6Network = "fd00::/64".parse().unwrap();
        
        let mut allocated = HashSet::new();
        allocated.insert(network.network());
        allocated.insert(network.nth(1).unwrap()); // .1 is Gateway
        allocated.insert(network.broadcast());

        let mut allocated_v6 = HashSet::new();
        allocated_v6.insert(network_v6.network());
        allocated_v6.insert(network_v6.iter().nth(1).unwrap()); // ::1 is Gateway

        Ok(Self {
            peers: DashMap::new(),
            peers_v6: DashMap::new(),
            network,
            network_v6,
            allocated_ips: Mutex::new(allocated),
            allocated_ips_v6: Mutex::new(allocated_v6),
        })
    }

    /// Allocate a new free IPv4 address
    pub fn assign_ip(&self) -> Result<Ipv4Addr> {
        let mut allocated = self.allocated_ips.lock().unwrap();
        for ip in self.network.iter() {
            if !allocated.contains(&ip) {
                allocated.insert(ip);
                return Ok(ip);
            }
        }
        Err(anyhow!("No IPv4 addresses available"))
    }

    /// Allocate a new free IPv6 address (sequential search)
    pub fn assign_ipv6(&self) -> Result<Ipv6Addr> {
        let mut allocated = self.allocated_ips_v6.lock().unwrap();
        // Just try the first 1000 addresses for now
        for i in 2..1000 {
            if let Some(ip) = self.network_v6.iter().nth(i) {
                if !allocated.contains(&ip) {
                    allocated.insert(ip);
                    return Ok(ip);
                }
            }
        }
        Err(anyhow!("No IPv6 addresses available (limit reached)"))
    }

    /// Release IP addresses
    pub fn release_ips(&self, ip4: Ipv4Addr, ip6: Ipv6Addr) {
        {
            let mut allocated = self.allocated_ips.lock().unwrap();
            allocated.remove(&ip4);
        }
        {
            let mut allocated_v6 = self.allocated_ips_v6.lock().unwrap();
            allocated_v6.remove(&ip6);
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
