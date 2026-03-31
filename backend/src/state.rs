use dashmap::DashMap;
use ipnetwork::{Ipv4Network, Ipv6Network};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::sync::mpsc;
use anyhow::{Result, anyhow};
use std::sync::Mutex;

/// A channel for sending raw IP packets to the specific task handling a client connection.
pub type ClientTx = mpsc::Sender<bytes::Bytes>;

/// Global application state responsible for IP address management
/// and tracking active VPN clients (peers).
///
/// This structure is shared across many tasks via `Arc<AppState>`.
pub struct AppState {
    /// Mapping of Virtual IPv4 -> Packet Sender.
    /// Used by the TUN reader to route incoming internet traffic to the correct QUIC connection.
    pub peers: DashMap<Ipv4Addr, ClientTx>,
    
    /// Mapping of Virtual IPv6 -> Packet Sender.
    pub peers_v6: DashMap<Ipv6Addr, ClientTx>,

    /// The IPv4 subnet managed by this server (e.g. 10.8.0.0/24).
    pub network: Ipv4Network,
    
    /// The IPv6 subnet managed by this server (Unique Local Address scope, default fd00::/64).
    pub network_v6: Ipv6Network,

    /// Stack of available (unassigned) IPv4 addresses.
    /// Handled via a Mutex for atomic lease/release.
    free_ips: Mutex<Vec<Ipv4Addr>>,
    
    /// Stack of available (unassigned) IPv6 addresses.
    free_ips_v6: Mutex<Vec<Ipv6Addr>>,
}

impl AppState {
    /// Initialises the application state and pre-fills the address pools.
    ///
    /// # Arguments
    /// - `cidr` - The IPv4 network specification (e.g., "10.8.0.0/24").
    pub fn new(cidr: &str) -> Result<Self> {
        let network: Ipv4Network = cidr.parse().map_err(|_| anyhow!("Invalid CIDR format: {}", cidr))?;
        // Internal IPv6 network (ULA range)
        let network_v6: Ipv6Network = "fd00::/64".parse().expect("Invalid hardcoded IPv6 CIDR 'fd00::/64'");
        
        // --- Populate IPv4 pool ---
        if network.prefix() > 30 {
            return Err(anyhow!("CIDR '{}' network is too small (/{} prefix leaves fewer than 2 usable addresses): use /30 or larger network (i.e. a smaller prefix number)", cidr, network.prefix()));
        }
        if network.prefix() < 8 {
            return Err(anyhow!("CIDR '{}' network is too large (/{} prefix): use /8 or smaller network (i.e. a larger prefix number) to avoid exhausting system memory on IP pool allocation", cidr, network.prefix()));
        }
        let mut free_ips = Vec::new();
        let gateway = network.nth(1).ok_or_else(|| anyhow!("CIDR '{}' too small to assign a gateway address", cidr))?; // By convention, server is .1
        let broadcast = network.broadcast();
        
        for ip in network.iter() {
            // Exclude the network address, the gateway (.1), and the broadcast address (.255)
            if ip != network.network() && ip != gateway && ip != broadcast {
                free_ips.push(ip);
            }
        }
        // Reverse so we allocate from .2 upwards (pop from end is O(1))
        free_ips.reverse();

        // --- Populate IPv6 pool ---
        // For performance, we pre-allocate only the first 5000 suffix addresses
        let mut free_ips_v6: Vec<Ipv6Addr> = network_v6.iter()
            .skip(2) // Skip ::0 and ::1 (gateway)
            .take(5000)
            .collect();
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

    /// Leases a free IPv4 address from the pool.
    ///
    /// # Errors
    /// Returns an error if the pool is exhausted.
    pub fn assign_ip(&self) -> Result<Ipv4Addr> {
        let mut free = self.free_ips.lock().unwrap_or_else(|e| e.into_inner());
        free.pop().ok_or_else(|| anyhow!("VPN IPv4 pool exhausted"))
    }

    /// Leases a free IPv6 address from the pool.
    pub fn assign_ipv6(&self) -> Result<Ipv6Addr> {
        let mut free = self.free_ips_v6.lock().unwrap_or_else(|e| e.into_inner());
        free.pop().ok_or_else(|| anyhow!("VPN IPv6 pool exhausted"))
    }

    /// Returns the leasable IPs to the pool and removes the peer registration.
    ///
    /// This is typically called by the `IpGuard` when a client disconnects.
    pub fn release_ips(&self, ip4: Ipv4Addr, ip6: Ipv6Addr) {
        // Remove from peer registry FIRST to prevent race conditions
        self.peers.remove(&ip4);
        self.peers_v6.remove(&ip6);

        // Then return to pools
        {
            let mut free = self.free_ips.lock().unwrap_or_else(|e| e.into_inner());
            free.push(ip4);
        }
        {
            let mut free = self.free_ips_v6.lock().unwrap_or_else(|e| e.into_inner());
            free.push(ip6);
        }
    }

    /// Associates an IPv4/IPv6 pair with an async sender channel for a connected client.
    pub fn register_client(&self, ip4: Ipv4Addr, ip6: Ipv6Addr, tx: ClientTx) {
        self.peers.insert(ip4, tx.clone());
        self.peers_v6.insert(ip6, tx);
    }

    /// Returns the server's internal IPv4 address (the VPN Gateway).
    pub fn gateway_ip(&self) -> Ipv4Addr {
        self.network.nth(1).unwrap_or(Ipv4Addr::new(10, 8, 0, 1))
    }

    /// Returns the server's internal IPv6 address (the VPN Gateway).
    pub fn gateway_ip_v6(&self) -> Ipv6Addr {
        self.network_v6.iter().nth(1).unwrap_or(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))
    }
}
