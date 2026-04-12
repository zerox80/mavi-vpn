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

    /// Next IPv6 host suffix to lease when no recycled address is available.
    next_ipv6_host: Mutex<u64>,
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

        Ok(Self {
            peers: DashMap::new(),
            peers_v6: DashMap::new(),
            network,
            network_v6,
            free_ips: Mutex::new(free_ips),
            free_ips_v6: Mutex::new(Vec::new()),
            next_ipv6_host: Mutex::new(2),
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
        if let Some(ip) = free.pop() {
            return Ok(ip);
        }
        drop(free);

        let mut next = self.next_ipv6_host.lock().unwrap_or_else(|e| e.into_inner());
        let candidate = u128::from(self.network_v6.network())
            .checked_add(u128::from(*next))
            .ok_or_else(|| anyhow!("VPN IPv6 pool exhausted"))?;
        let ip = Ipv6Addr::from(candidate);
        if !self.network_v6.contains(ip) {
            return Err(anyhow!("VPN IPv6 pool exhausted"));
        }
        *next = next
            .checked_add(1)
            .ok_or_else(|| anyhow!("VPN IPv6 pool exhausted"))?;
        Ok(ip)
    }

    pub fn assign_ip_pair(&self) -> Result<(Ipv4Addr, Ipv6Addr)> {
        let ip4 = self.assign_ip()?;

        match self.assign_ipv6() {
            Ok(ip6) => Ok((ip4, ip6)),
            Err(err) => {
                let mut free = self.free_ips.lock().unwrap_or_else(|e| e.into_inner());
                free.push(ip4);
                Err(err)
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_valid_cidr_24() {
        let state = AppState::new("10.8.0.0/24").unwrap();
        assert_eq!(state.network.prefix(), 24);
        // /24 = 256 addresses, minus network (.0), gateway (.1), broadcast (.255) = 253
        let free = state.free_ips.lock().unwrap();
        assert_eq!(free.len(), 253);
    }

    #[test]
    fn new_valid_cidr_16() {
        let state = AppState::new("172.16.0.0/16").unwrap();
        assert_eq!(state.network.prefix(), 16);
        // /16 = 65536 addresses, minus network (.0.0), gateway (.0.1), broadcast (.255.255) = 65533
        // Note: this test intentionally allocates a large pool to verify the size formula.
        let free = state.free_ips.lock().unwrap();
        assert_eq!(free.len(), 65533);
    }

    #[test]
    fn new_valid_cidr_30() {
        let state = AppState::new("10.0.0.0/30").unwrap();
        // /30 = 4 addresses: .0 (network), .1 (gateway), .2, .3 (broadcast) → 1 usable
        let free = state.free_ips.lock().unwrap();
        assert_eq!(free.len(), 1);
        assert_eq!(free[0], Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn new_rejects_too_small_prefix() {
        assert!(AppState::new("10.0.0.0/31").is_err());
        assert!(AppState::new("10.0.0.0/32").is_err());
    }

    #[test]
    fn new_rejects_too_large_prefix() {
        assert!(AppState::new("10.0.0.0/7").is_err());
    }

    #[test]
    fn new_rejects_invalid_cidr() {
        assert!(AppState::new("not_a_cidr").is_err());
        assert!(AppState::new("").is_err());
        assert!(AppState::new("999.999.999.999/24").is_err());
    }

    #[test]
    fn gateway_ip_is_dot_one() {
        let state = AppState::new("10.8.0.0/24").unwrap();
        assert_eq!(state.gateway_ip(), Ipv4Addr::new(10, 8, 0, 1));

        let state2 = AppState::new("192.168.1.0/24").unwrap();
        assert_eq!(state2.gateway_ip(), Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn gateway_ip_v6_is_second_addr() {
        let state = AppState::new("10.8.0.0/24").unwrap();
        assert_eq!(state.gateway_ip_v6(), Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
    }

    #[test]
    fn assign_ip_returns_sequential() {
        let state = AppState::new("10.8.0.0/24").unwrap();
        let first = state.assign_ip().unwrap();
        let second = state.assign_ip().unwrap();
        let third = state.assign_ip().unwrap();
        assert_eq!(first, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(second, Ipv4Addr::new(10, 8, 0, 3));
        assert_eq!(third, Ipv4Addr::new(10, 8, 0, 4));
    }

    #[test]
    fn assign_ipv6_returns_sequential() {
        let state = AppState::new("10.8.0.0/24").unwrap();
        let first = state.assign_ipv6().unwrap();
        let second = state.assign_ipv6().unwrap();
        assert_eq!(first, Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2));
        assert_eq!(second, Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 3));
    }

    #[test]
    fn assign_ip_pair_returns_both() {
        let state = AppState::new("10.8.0.0/24").unwrap();
        let (v4, v6) = state.assign_ip_pair().unwrap();
        assert_eq!(v4, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(v6, Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2));
    }

    #[test]
    fn release_and_reassign() {
        let state = AppState::new("10.8.0.0/24").unwrap();
        let ip4 = state.assign_ip().unwrap();
        let ip6 = state.assign_ipv6().unwrap();
        assert_eq!(ip4, Ipv4Addr::new(10, 8, 0, 2));

        let second_v4 = state.assign_ip().unwrap();
        assert_eq!(second_v4, Ipv4Addr::new(10, 8, 0, 3));

        // Release first IP
        state.release_ips(ip4, ip6);

        // Next assignment should return the released IP (pushed onto stack)
        let reassigned = state.assign_ip().unwrap();
        assert_eq!(reassigned, Ipv4Addr::new(10, 8, 0, 2));
    }

    #[test]
    fn pool_exhaustion_ipv4() {
        let state = AppState::new("10.0.0.0/30").unwrap();
        // Only 1 usable IP (.2)
        assert!(state.assign_ip().is_ok());
        assert!(state.assign_ip().is_err());
    }

    #[test]
    fn register_and_lookup_client() {
        let state = AppState::new("10.8.0.0/24").unwrap();
        let (v4, v6) = state.assign_ip_pair().unwrap();
        let (tx, _rx) = mpsc::channel::<bytes::Bytes>(16);
        state.register_client(v4, v6, tx);

        assert!(state.peers.contains_key(&v4));
        assert!(state.peers_v6.contains_key(&v6));
    }

    #[test]
    fn release_removes_from_peers() {
        let state = AppState::new("10.8.0.0/24").unwrap();
        let (v4, v6) = state.assign_ip_pair().unwrap();
        let (tx, _rx) = mpsc::channel::<bytes::Bytes>(16);
        state.register_client(v4, v6, tx);

        assert!(state.peers.contains_key(&v4));
        state.release_ips(v4, v6);

        assert!(!state.peers.contains_key(&v4));
        assert!(!state.peers_v6.contains_key(&v6));
    }

    #[test]
    fn pool_does_not_contain_gateway_or_broadcast() {
        let state = AppState::new("10.8.0.0/24").unwrap();
        let free = state.free_ips.lock().unwrap();
        let gateway = Ipv4Addr::new(10, 8, 0, 1);
        let broadcast = Ipv4Addr::new(10, 8, 0, 255);
        let network = Ipv4Addr::new(10, 8, 0, 0);
        assert!(!free.contains(&gateway));
        assert!(!free.contains(&broadcast));
        assert!(!free.contains(&network));
    }

    #[test]
    fn ipv6_recycled_after_release() {
        let state = AppState::new("10.8.0.0/24").unwrap();
        let ip4 = state.assign_ip().unwrap();
        let ip6 = state.assign_ipv6().unwrap();
        assert_eq!(ip6, Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2));

        // Advance the counter so the next fresh allocation would be ::4
        let _ = state.assign_ipv6().unwrap(); // ::3
        let _ = state.assign_ipv6().unwrap(); // ::4 consumed

        // Release the first pair – the IPv6 address goes back onto the recycle stack
        state.release_ips(ip4, ip6);

        // The recycled ::2 must be handed out before any fresh address
        let recycled = state.assign_ipv6().unwrap();
        assert_eq!(recycled, Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2));
    }

    #[test]
    fn new_rejects_prefix_zero() {
        // /0 is too large (> 2^32 usable addresses, rejected by the prefix < 8 guard)
        assert!(AppState::new("0.0.0.0/0").is_err());
    }
}
