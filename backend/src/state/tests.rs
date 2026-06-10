use super::*;

#[test]
fn new_valid_cidr_24() {
    let state = AppState::new("10.8.0.0/24").unwrap();
    assert_eq!(state.network.prefix(), 24);
    // /24 = 256 addresses, minus network (.0), gateway (.1), broadcast (.255) = 253
    assert_eq!(state.free_ips.lock().unwrap().len(), 253);
}

#[test]
fn new_valid_cidr_16() {
    let state = AppState::new("172.16.0.0/16").unwrap();
    assert_eq!(state.network.prefix(), 16);
    // /16 = 65536 addresses, minus network (.0.0), gateway (.0.1), broadcast (.255.255) = 65533
    // Note: this test intentionally allocates a large pool to verify the size formula.
    assert_eq!(state.free_ips.lock().unwrap().len(), 65533);
}

#[test]
fn new_valid_cidr_30() {
    let state = AppState::new("10.0.0.0/30").unwrap();
    // /30 = 4 addresses: .0 (network), .1 (gateway), .2, .3 (broadcast) → 1 usable
    {
        let free = state.free_ips.lock().unwrap();
        assert_eq!(free.len(), 1);
        assert_eq!(free[0], Ipv4Addr::new(10, 0, 0, 2));
        drop(free);
    }
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
    assert_eq!(
        state.gateway_ip_v6(),
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)
    );
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

    let (tx, _rx) = mpsc::channel::<bytes::Bytes>(16);
    state.register_client(ip4, ip6, tx);

    // Release first IP
    state.release_ips(ip4, ip6);

    // Next assignment should return the released IP (pushed onto stack)
    let reassigned = state.assign_ip().unwrap();
    assert_eq!(reassigned, Ipv4Addr::new(10, 8, 0, 2));
}

#[test]
fn release_reclaims_lease_even_without_registration() {
    // Reproduces the pool leak: a connection that authenticates (assigns a pair)
    // but drops before `register_client` must still return its lease to the pool.
    let state = AppState::new("10.0.0.0/30").unwrap(); // exactly one usable pair
    let (v4, v6) = state.assign_ip_pair().unwrap();
    assert!(!state.peers.contains_key(&v4)); // never registered

    // Pool is now exhausted while the lease is held.
    assert!(state.assign_ip_pair().is_err());

    // Releasing the unregistered lease must return it to the pool.
    state.release_ips(v4, v6);
    let (v4_again, _v6_again) = state.assign_ip_pair().unwrap();
    assert_eq!(v4_again, v4);
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
    let gateway = Ipv4Addr::new(10, 8, 0, 1);
    let broadcast = Ipv4Addr::new(10, 8, 0, 255);
    let network = Ipv4Addr::new(10, 8, 0, 0);
    {
        let free = state.free_ips.lock().unwrap();
        assert!(!free.contains(&gateway));
        assert!(!free.contains(&broadcast));
        assert!(!free.contains(&network));
        drop(free);
    }
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

    // Register client before release
    let (tx, _rx) = mpsc::channel::<bytes::Bytes>(16);
    state.register_client(ip4, ip6, tx);

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

#[tokio::test]
async fn test_concurrent_ip_assignment() {
    use std::sync::Arc;

    let state = Arc::new(AppState::new("10.8.0.0/16").unwrap());
    let mut handles = vec![];

    for _ in 0..100 {
        let state_clone = state.clone();
        handles.push(tokio::spawn(async move {
            let mut ips = vec![];
            for _ in 0..10 {
                if let Ok(ip) = state_clone.assign_ip() {
                    ips.push(ip);
                }
            }
            ips
        }));
    }

    let mut all_assigned = std::collections::HashSet::new();
    for handle in handles {
        let ips = handle.await.unwrap();
        for ip in ips {
            assert!(all_assigned.insert(ip), "Duplicate IP assigned: {ip}");
        }
    }

    // 100 threads * 10 IPs = 1000 unique IPs
    assert_eq!(all_assigned.len(), 1000);
}

#[test]
fn deregister_removes_peer() {
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
fn multiple_registrations_overwrite() {
    let state = AppState::new("10.8.0.0/24").unwrap();
    let (v4, v6) = state.assign_ip_pair().unwrap();
    let (tx1, _rx1) = mpsc::channel::<bytes::Bytes>(16);
    let (tx2, _rx2) = mpsc::channel::<bytes::Bytes>(16);

    state.register_client(v4, v6, tx1);
    state.register_client(v4, v6, tx2);

    assert!(state.peers.contains_key(&v4));
}

#[test]
fn gateway_ip_v6_different_networks() {
    let state = AppState::new("192.168.1.0/24").unwrap();
    assert_eq!(
        state.gateway_ip_v6(),
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)
    );
}

#[test]
fn custom_ipv6_network_is_used_for_gateway_and_assignments() {
    let state = AppState::new_with_ipv6("10.8.0.0/24", "fd12:3456::/64").unwrap();
    assert_eq!(
        state.gateway_ip_v6(),
        Ipv6Addr::new(0xfd12, 0x3456, 0, 0, 0, 0, 0, 1)
    );
    assert_eq!(
        state.assign_ipv6().unwrap(),
        Ipv6Addr::new(0xfd12, 0x3456, 0, 0, 0, 0, 0, 2)
    );
}

#[test]
fn ipv6_network_must_have_client_space() {
    assert!(AppState::new_with_ipv6("10.8.0.0/24", "fd00::/127").is_err());
    assert!(AppState::new_with_ipv6("10.8.0.0/24", "not-a-cidr").is_err());
}

#[test]
fn assign_ip_pair_release_and_reassign_cycle() {
    let state = AppState::new("10.0.0.0/30").unwrap();
    let (v4, v6) = state.assign_ip_pair().unwrap();
    let (tx, _rx) = mpsc::channel::<bytes::Bytes>(16);
    state.register_client(v4, v6, tx);
    state.release_ips(v4, v6);
    let (v4_2, v6_2) = state.assign_ip_pair().unwrap();
    assert_eq!(v4, v4_2);
    assert_eq!(v6, v6_2);
}

#[test]
fn double_release_does_not_corrupt_pool() {
    let state = AppState::new("10.0.0.0/30").unwrap();
    let pool_size_before = state.free_ips.lock().unwrap().len();

    let (v4, v6) = state.assign_ip_pair().unwrap();
    let (tx, _rx) = mpsc::channel::<bytes::Bytes>(16);
    state.register_client(v4, v6, tx);
    state.release_ips(v4, v6);

    // Second release is a no-op because the peer was already removed
    state.release_ips(v4, v6);

    let pool_size_after = state.free_ips.lock().unwrap().len();
    assert_eq!(pool_size_before, pool_size_after);
}
