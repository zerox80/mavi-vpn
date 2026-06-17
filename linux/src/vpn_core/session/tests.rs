//! Unit tests for the Linux session reconnect/backoff helpers.

use super::{is_permanent_setup_error, sleep_unless_stopped};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[tokio::test]
async fn backoff_sleep_returns_promptly_when_stopped() {
    let running = Arc::new(AtomicBool::new(true));
    let stopper = running.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        stopper.store(false, Ordering::Relaxed);
    });

    let started = Instant::now();
    // A long backoff that must be cut short by the Stop above.
    sleep_unless_stopped(Duration::from_secs(30), &running).await;
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "Stop during backoff must return within ~1s, took {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn backoff_sleep_completes_full_delay_when_running() {
    let running = Arc::new(AtomicBool::new(true));
    let started = Instant::now();
    sleep_unless_stopped(Duration::from_millis(250), &running).await;
    assert!(started.elapsed() >= Duration::from_millis(200));
}

#[test]
fn permanent_setup_errors_stop_reconnect_loop() {
    for message in [
        "AUTH_FAILED: Server returned HTTP 401",
        "Server rejected connection: denied",
        "MTU mismatch: local/client VPN MTU is 1280, but server pushed 1360",
        "Server pushed unsupported VPN MTU 1400",
        "Failed to open /dev/net/tun: permission denied",
        "Failed to install IPv6 split route ::/1",
        "Failed to execute: ip route add 0.0.0.0/1",
        "ip failed: RTNETLINK answers: Operation not permitted",
    ] {
        assert!(is_permanent_setup_error(message), "{message}");
    }
}

#[test]
fn transient_transport_errors_keep_reconnect_loop() {
    assert!(!is_permanent_setup_error("connection lost"));
    assert!(!is_permanent_setup_error(
        "timed out while reading datagram"
    ));
}
