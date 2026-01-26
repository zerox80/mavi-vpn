use dashmap::DashMap;
use ipnetwork::Ipv4Network;
use std::net::Ipv4Addr;
use tokio::sync::mpsc;
use anyhow::{Result, anyhow};
use std::collections::HashSet;
use std::sync::Mutex;

/// A channel to send specific IP packets to a connected client task.
pub type ClientTx = mpsc::Sender<bytes::Bytes>;

/// Manages the state of the VPN server: connected peers and IP allocation.
pub struct AppState {
    /// Map of Virtual IP -> Channel to send packets to that client
    /// Used by the TUN Reader to route packets.
    pub peers: DashMap<Ipv4Addr, ClientTx>,

    /// The network range we are managing (e.g., 10.8.0.0/24)
    pub network: Ipv4Network,

    /// Simple IP Allocator
    allocated_ips: Mutex<HashSet<Ipv4Addr>>,
}

impl AppState {
    pub fn new(cidr: &str) -> Result<Self> {
        let network: Ipv4Network = cidr.parse().map_err(|_| anyhow!("Invalid CIDR"))?;
        
        let mut allocated = HashSet::new();
        // Reserve network address and gateway (assuming gateway is .1)
        allocated.insert(network.network());
        allocated.insert(network.nth(1).unwrap()); // .1 is Gateway/Server
        allocated.insert(network.broadcast());

        Ok(Self {
            peers: DashMap::new(),
            network,
            allocated_ips: Mutex::new(allocated),
        })
    }

    /// Allocate a new free IP address
    pub fn assign_ip(&self) -> Result<Ipv4Addr> {
        let mut allocated = self.allocated_ips.lock().unwrap();
        
        for ip in self.network.iter() {
            if !allocated.contains(&ip) {
                allocated.insert(ip);
                return Ok(ip);
            }
        }
        
        Err(anyhow!("No IP addresses available"))
    }

    /// Release an IP address when a client disconnects
    pub fn release_ip(&self, ip: Ipv4Addr) {
        let mut allocated = self.allocated_ips.lock().unwrap();
        allocated.remove(&ip);
        self.peers.remove(&ip);
    }

    pub fn register_client(&self, ip: Ipv4Addr, tx: ClientTx) {
        self.peers.insert(ip, tx);
    }

    pub fn gateway_ip(&self) -> Ipv4Addr {
        // We assume the server is always the second IP (.1)
        self.network.nth(1).unwrap()
    }
}
