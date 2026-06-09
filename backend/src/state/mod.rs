use anyhow::{anyhow, Result};
use dashmap::DashMap;
use ipnetwork::{Ipv4Network, Ipv6Network};
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use tokio::sync::mpsc;

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

    /// The IPv6 subnet managed by this server (Unique Local Address scope, default `fd00::/64`).
    pub network_v6: Ipv6Network,

    /// Stack of available (unassigned) IPv4 addresses.
    /// Handled via a Mutex for atomic lease/release.
    free_ips: Mutex<Vec<Ipv4Addr>>,

    /// Stack of available (unassigned) IPv6 addresses.
    free_ips_v6: Mutex<Vec<Ipv6Addr>>,

    /// Next IPv6 host suffix to lease when no recycled address is available.
    next_ipv6_host: Mutex<u64>,

    /// Addresses currently leased to a connection. Reclaim is keyed on this set
    /// rather than on `peers` membership, so a lease is returned to the pool even
    /// when the connection died between assignment and `register_client` (or when
    /// the TUN reader removed the peer first). Membership also makes release
    /// idempotent: a second `release_ips` for the same address is a no-op.
    leased_ips: Mutex<HashSet<Ipv4Addr>>,
    leased_ips_v6: Mutex<HashSet<Ipv6Addr>>,
}

impl AppState {
    /// Initialises the application state and pre-fills the address pools.
    ///
    /// # Arguments
    /// - `cidr` - The IPv4 network specification (e.g., "10.8.0.0/24").
    pub fn new(cidr: &str) -> Result<Self> {
        Self::new_with_ipv6(cidr, "fd00::/64")
    }

    /// Initialises the application state with explicit IPv4 and IPv6 networks.
    ///
    /// # Arguments
    /// - `cidr` - The IPv4 network specification (e.g., "10.8.0.0/24").
    /// - `cidr_v6` - The IPv6 network specification (e.g., "fd00::/64").
    pub fn new_with_ipv6(cidr: &str, cidr_v6: &str) -> Result<Self> {
        let network: Ipv4Network = cidr
            .parse()
            .map_err(|_| anyhow!("Invalid CIDR format: {cidr}"))?;
        let network_v6: Ipv6Network = cidr_v6
            .parse()
            .map_err(|_| anyhow!("Invalid IPv6 CIDR format: {cidr_v6}"))?;
        if network_v6.prefix() > 126 {
            return Err(anyhow!(
                "IPv6 CIDR '{}' network is too small (/{} prefix leaves no client address after gateway)",
                cidr_v6,
                network_v6.prefix()
            ));
        }

        // --- Populate IPv4 pool ---
        if network.prefix() > 30 {
            return Err(anyhow!("CIDR '{}' network is too small (/{} prefix leaves fewer than 2 usable addresses): use /30 or larger network (i.e. a smaller prefix number)", cidr, network.prefix()));
        }
        if network.prefix() < 8 {
            return Err(anyhow!("CIDR '{}' network is too large (/{} prefix): use /8 or smaller network (i.e. a larger prefix number) to avoid exhausting system memory on IP pool allocation", cidr, network.prefix()));
        }
        let mut free_ips = Vec::new();
        let gateway = network
            .nth(1)
            .ok_or_else(|| anyhow!("CIDR '{cidr}' too small to assign a gateway address"))?; // By convention, server is .1
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
            leased_ips: Mutex::new(HashSet::new()),
            leased_ips_v6: Mutex::new(HashSet::new()),
        })
    }

    /// Leases a free IPv4 address from the pool.
    ///
    /// # Errors
    /// Returns an error if the pool is exhausted.
    pub fn assign_ip(&self) -> Result<Ipv4Addr> {
        let ip = {
            let mut free = self
                .free_ips
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            free.pop().ok_or_else(|| anyhow!("VPN IPv4 pool exhausted"))?
        };
        self.leased_ips
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(ip);
        Ok(ip)
    }

    /// Leases a free IPv6 address from the pool.
    pub fn assign_ipv6(&self) -> Result<Ipv6Addr> {
        let ip = self.lease_ipv6_address()?;
        self.leased_ips_v6
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(ip);
        Ok(ip)
    }

    fn lease_ipv6_address(&self) -> Result<Ipv6Addr> {
        let mut free = self
            .free_ips_v6
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(ip) = free.pop() {
            return Ok(ip);
        }
        drop(free);

        let mut next = self
            .next_ipv6_host
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        drop(next);
        Ok(ip)
    }

    pub fn assign_ip_pair(&self) -> Result<(Ipv4Addr, Ipv6Addr)> {
        let ip4 = self.assign_ip()?;

        match self.assign_ipv6() {
            Ok(ip6) => Ok((ip4, ip6)),
            Err(err) => {
                self.reclaim_ipv4(ip4);
                Err(err)
            }
        }
    }

    /// Returns a leased IPv4 address to the pool exactly once. A no-op if the
    /// address is not currently leased (already released).
    fn reclaim_ipv4(&self, ip4: Ipv4Addr) {
        let was_leased = self
            .leased_ips
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&ip4);
        if was_leased {
            self.free_ips
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(ip4);
        }
    }

    /// Returns a leased IPv6 address to the pool exactly once. A no-op if the
    /// address is not currently leased (already released).
    fn reclaim_ipv6(&self, ip6: Ipv6Addr) {
        let was_leased = self
            .leased_ips_v6
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&ip6);
        if was_leased {
            self.free_ips_v6
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(ip6);
        }
    }

    /// Returns the leased IPs to the pool and removes any peer registration.
    ///
    /// Typically called by the `IpGuard` when a client disconnects. Reclaim is
    /// keyed on the lease set, so an address assigned but never registered (the
    /// connection dropped before `register_client`, or the TUN reader removed the
    /// peer first) is still returned to the pool. Releasing the same address
    /// twice is a no-op, so this cannot corrupt the pool with duplicates.
    pub fn release_ips(&self, ip4: Ipv4Addr, ip6: Ipv6Addr) {
        // Best-effort routing cleanup; reclaim no longer depends on its result.
        self.peers.remove(&ip4);
        self.peers_v6.remove(&ip6);
        self.reclaim_ipv4(ip4);
        self.reclaim_ipv6(ip6);
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
        self.network_v6
            .iter()
            .nth(1)
            .unwrap_or(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))
    }
}

#[cfg(test)]
mod tests;
