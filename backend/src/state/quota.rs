//! Atomic, bounded-lifetime quotas shared across transports.
use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};

pub const MAX_PREAUTH_PER_SOURCE: usize = 4;

pub struct Quota<K> {
    counts: Mutex<HashMap<K, usize>>,
}

impl<K: Eq + Hash + Clone> Quota<K> {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            counts: Mutex::new(HashMap::new()),
        })
    }

    pub fn try_acquire(self: &Arc<Self>, key: K, limit: usize) -> Option<Permit<K>> {
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = counts.get(&key).copied().unwrap_or(0);
        if count >= limit {
            return None;
        }
        counts.insert(key.clone(), count + 1);
        Some(Permit {
            quota: self.clone(),
            key,
        })
    }
}

pub struct Permit<K: Eq + Hash> {
    quota: Arc<Quota<K>>,
    key: K,
}

impl<K: Eq + Hash> Drop for Permit<K> {
    fn drop(&mut self) {
        let mut counts = self
            .quota
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = counts.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.key);
            }
        }
    }
}

/// Group IPv6 privacy addresses by /64, and normalize IPv4-mapped addresses.
pub fn source_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or_else(|| IpAddr::V6(Ipv6Addr::from(u128::from(ip) & (u128::MAX << 64)))),
        ip => ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_releases_capacity_and_removes_idle_keys() {
        let quota = Quota::new();
        let a = quota.try_acquire("a", 1).unwrap();
        assert!(quota.try_acquire("a", 1).is_none());
        let b = quota.try_acquire("b", 1).unwrap();
        drop(a);
        assert!(quota.try_acquire("a", 1).is_some());
        drop(b);
        assert!(quota.counts.lock().unwrap().is_empty());
    }

    #[test]
    fn ipv6_address_rotation_and_mapped_ipv4_do_not_bypass_source_limit() {
        assert_eq!(
            source_key("2001:db8::1".parse().unwrap()),
            source_key("2001:db8::dead:beef".parse().unwrap())
        );
        assert_eq!(
            source_key("::ffff:192.0.2.1".parse().unwrap()),
            source_key("192.0.2.1".parse().unwrap())
        );
        assert_ne!(
            source_key("2001:db8::1".parse().unwrap()),
            source_key("2001:db8:0:1::1".parse().unwrap())
        );
    }
}
