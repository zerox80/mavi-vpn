//! Per-source-IP rate limiting for failed VPN authentication attempts.
//!
//! Protects Keycloak JWKS validation (and, for static-token auth, simple
//! brute-force attempts) from being hammered by a single misbehaving peer.
//! This is a fixed-window counter, not a strict token bucket: it is
//! deliberately simple (no new dependency) since the primary goal is
//! reducing load on the validator, not being the sole defense — a long
//! random static token or a properly configured Keycloak realm remains the
//! actual authentication boundary.
//!
//! Known limitation: keying is per source IP only. Multiple legitimate users
//! behind the same NAT/CGNAT address can be blocked together by one bad
//! actor sharing that address. This is an accepted tradeoff, not a bug.

use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Failed-auth attempt window for a single source IP.
struct FailureWindow {
    /// Count of failures observed in the current window.
    count: u32,
    /// When the current window started.
    window_start: Instant,
    /// If set, the IP is blocked until this instant. Sticky across window
    /// resets so an attacker cannot un-block by waiting out a window
    /// boundary within the block period.
    blocked_until: Option<Instant>,
}

/// Tracks failed authentication attempts per source IP and blocks an IP for
/// `block_duration` once it reaches `max_failures` within `window`.
pub struct AuthRateLimiter {
    entries: DashMap<IpAddr, FailureWindow>,
    max_failures: u32,
    window: Duration,
    block_duration: Duration,
}

impl AuthRateLimiter {
    pub fn new(max_failures: u32, window: Duration, block_duration: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            max_failures,
            window,
            block_duration,
        }
    }

    /// 10 failures within 60 seconds blocks the source IP for 5 minutes.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(10, Duration::from_secs(60), Duration::from_secs(5 * 60))
    }

    /// Returns `true` if `ip` is currently blocked. Callers must check this
    /// *before* doing any real authentication work (token comparison,
    /// Keycloak validation) so a blocked IP never reaches the validator.
    #[must_use]
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        self.entries
            .get(&ip)
            .and_then(|e| e.blocked_until)
            .is_some_and(|until| Instant::now() < until)
    }

    /// Records a failed authentication attempt for `ip`. If this pushes the
    /// IP's failure count to `max_failures` within `window`, the IP becomes
    /// blocked for `block_duration` starting now.
    pub fn record_failure(&self, ip: IpAddr) {
        let now = Instant::now();
        let mut entry = self.entries.entry(ip).or_insert_with(|| FailureWindow {
            count: 0,
            window_start: now,
            blocked_until: None,
        });

        // Fixed window: once the window has elapsed, start a fresh one. An
        // active block is left untouched even across a window reset.
        if now.duration_since(entry.window_start) >= self.window {
            entry.window_start = now;
            entry.count = 0;
        }

        entry.count += 1;
        if entry.count >= self.max_failures {
            entry.blocked_until = Some(now + self.block_duration);
        }
    }

    /// Clears any failure/block state for `ip`. Called on successful auth so
    /// a legitimate reconnect after a couple of transient failures is not
    /// penalized.
    pub fn record_success(&self, ip: IpAddr) {
        self.entries.remove(&ip);
    }

    /// Evicts entries whose window has expired and whose block (if any) has
    /// also expired. Intended to be called periodically from a background
    /// task, not per-request, to bound memory growth under sustained
    /// distributed probing.
    pub fn evict_expired(&self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| {
            let block_active = entry.blocked_until.is_some_and(|until| now < until);
            let window_active = now.duration_since(entry.window_start) < self.window;
            block_active || window_active
        });
    }

    #[cfg(test)]
    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::thread::sleep;

    fn test_ip(last_octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, last_octet))
    }

    #[test]
    fn not_blocked_initially() {
        let limiter = AuthRateLimiter::with_defaults();
        assert!(!limiter.is_blocked(test_ip(1)));
    }

    #[test]
    fn blocks_after_max_failures_within_window() {
        let limiter = AuthRateLimiter::new(3, Duration::from_secs(60), Duration::from_secs(60));
        let ip = test_ip(1);
        for _ in 0..3 {
            limiter.record_failure(ip);
        }
        assert!(limiter.is_blocked(ip), "exactly max_failures should block");
    }

    #[test]
    fn does_not_block_below_threshold() {
        let limiter = AuthRateLimiter::new(5, Duration::from_secs(60), Duration::from_secs(60));
        let ip = test_ip(1);
        for _ in 0..4 {
            limiter.record_failure(ip);
        }
        assert!(!limiter.is_blocked(ip));
    }

    #[test]
    fn block_persists_until_block_duration_elapses() {
        let limiter = AuthRateLimiter::new(1, Duration::from_secs(60), Duration::from_millis(50));
        let ip = test_ip(1);
        limiter.record_failure(ip);
        assert!(limiter.is_blocked(ip));
        sleep(Duration::from_millis(80));
        assert!(!limiter.is_blocked(ip));
    }

    #[test]
    fn record_success_clears_failure_count() {
        let limiter = AuthRateLimiter::new(3, Duration::from_secs(60), Duration::from_secs(60));
        let ip = test_ip(1);
        limiter.record_failure(ip);
        limiter.record_failure(ip);
        limiter.record_success(ip);
        // If the counter hadn't reset, this would already be blocked.
        limiter.record_failure(ip);
        limiter.record_failure(ip);
        assert!(
            !limiter.is_blocked(ip),
            "success should have reset the failure count"
        );
        limiter.record_failure(ip);
        assert!(
            limiter.is_blocked(ip),
            "exactly max_failures after the reset should block"
        );
    }

    #[test]
    fn window_reset_after_expiry_without_block() {
        let limiter = AuthRateLimiter::new(2, Duration::from_millis(30), Duration::from_secs(60));
        let ip = test_ip(1);
        limiter.record_failure(ip);
        assert!(!limiter.is_blocked(ip));
        sleep(Duration::from_millis(50));
        // Window has expired; this failure starts a fresh window and must not
        // accumulate with the earlier one.
        limiter.record_failure(ip);
        assert!(
            !limiter.is_blocked(ip),
            "failures across expired windows must not accumulate"
        );
    }

    #[test]
    fn different_ips_tracked_independently() {
        let limiter = AuthRateLimiter::new(1, Duration::from_secs(60), Duration::from_secs(60));
        let ip_a = test_ip(1);
        let ip_b = test_ip(2);
        limiter.record_failure(ip_a);
        assert!(limiter.is_blocked(ip_a));
        assert!(!limiter.is_blocked(ip_b));
    }

    #[test]
    fn evict_expired_removes_stale_unblocked_entries() {
        let limiter = AuthRateLimiter::new(10, Duration::from_millis(20), Duration::from_secs(60));
        let ip = test_ip(1);
        limiter.record_failure(ip);
        assert_eq!(limiter.entry_count(), 1);
        sleep(Duration::from_millis(40));
        limiter.evict_expired();
        assert_eq!(limiter.entry_count(), 0);
    }

    #[test]
    fn evict_expired_keeps_active_blocks() {
        let limiter = AuthRateLimiter::new(1, Duration::from_millis(20), Duration::from_secs(60));
        let ip = test_ip(1);
        limiter.record_failure(ip);
        assert!(limiter.is_blocked(ip));
        sleep(Duration::from_millis(40));
        // The window has expired but the block has not — the entry must survive.
        limiter.evict_expired();
        assert_eq!(limiter.entry_count(), 1);
        assert!(limiter.is_blocked(ip));
    }

    #[test]
    fn with_defaults_uses_documented_thresholds() {
        let limiter = AuthRateLimiter::with_defaults();
        assert_eq!(limiter.max_failures, 10);
        assert_eq!(limiter.window, Duration::from_secs(60));
        assert_eq!(limiter.block_duration, Duration::from_secs(5 * 60));
    }

    #[test]
    fn ipv6_addresses_are_tracked() {
        let limiter = AuthRateLimiter::new(1, Duration::from_secs(60), Duration::from_secs(60));
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        limiter.record_failure(ip);
        assert!(limiter.is_blocked(ip));
    }
}
