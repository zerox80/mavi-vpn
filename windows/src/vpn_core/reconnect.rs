use anyhow::Result;
use std::time::Duration;

// --- Default timing parameters ---
pub(crate) const RECONNECT_INITIAL_SECS: u64 = 1;
pub(crate) const RECONNECT_MAX_SECS: u64 = 30;

#[derive(Debug)]
pub(crate) enum SessionEnd {
    UserStopped,
    ConnectionLost,
}

#[derive(Debug)]
pub(crate) enum ReconnectDecision {
    Break,
    Reconnect { delay: Duration, next_backoff: Duration },
    PermanentFailure { error: String },
}

pub(crate) fn compute_reconnect_delay(
    outcome: Result<SessionEnd>,
    backoff: Duration,
) -> ReconnectDecision {
    match outcome {
        Ok(SessionEnd::UserStopped) => ReconnectDecision::Break,
        Ok(SessionEnd::ConnectionLost) => ReconnectDecision::Reconnect {
            delay: Duration::from_secs(RECONNECT_INITIAL_SECS),
            next_backoff: Duration::from_secs(RECONNECT_INITIAL_SECS),
        },
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("AUTH_FAILED")
                || err_str.contains("Server rejected connection")
                || err_str.contains("MTU mismatch")
                || err_str.contains("was not applied to adapter")
                || err_str.contains("IPV6_SETUP_FAILED")
            {
                ReconnectDecision::PermanentFailure { error: err_str }
            } else {
                ReconnectDecision::Reconnect {
                    delay: backoff,
                    next_backoff: (backoff * 2).min(Duration::from_secs(RECONNECT_MAX_SECS)),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_stopped_breaks() {
        let decision = compute_reconnect_delay(Ok(SessionEnd::UserStopped), Duration::from_secs(5));
        assert!(matches!(decision, ReconnectDecision::Break));
    }

    #[test]
    fn connection_lost_resets_backoff() {
        match compute_reconnect_delay(Ok(SessionEnd::ConnectionLost), Duration::from_secs(10)) {
            ReconnectDecision::Reconnect { delay, next_backoff } => {
                assert_eq!(delay, Duration::from_secs(1));
                assert_eq!(next_backoff, Duration::from_secs(1));
            }
            other => panic!("Expected Reconnect, got {other:?}"),
        }
    }

    #[test]
    fn transient_error_backoffs() {
        let err = anyhow::anyhow!("network timeout");
        match compute_reconnect_delay(Err(err), Duration::from_secs(2)) {
            ReconnectDecision::Reconnect { delay, next_backoff } => {
                assert_eq!(delay, Duration::from_secs(2));
                assert_eq!(next_backoff, Duration::from_secs(4));
            }
            other => panic!("Expected Reconnect, got {other:?}"),
        }
    }

    #[test]
    fn transient_error_caps_at_max() {
        let err = anyhow::anyhow!("network timeout");
        let backoff = Duration::from_secs(25);
        match compute_reconnect_delay(Err(err), backoff) {
            ReconnectDecision::Reconnect { delay, next_backoff } => {
                assert_eq!(delay, Duration::from_secs(25));
                assert_eq!(next_backoff, Duration::from_secs(30));
            }
            other => panic!("Expected Reconnect, got {other:?}"),
        }
    }

    #[test]
    fn permanent_auth_failed_stops() {
        let err = anyhow::anyhow!("AUTH_FAILED");
        match compute_reconnect_delay(Err(err), Duration::from_secs(5)) {
            ReconnectDecision::PermanentFailure { error } => {
                assert!(error.contains("AUTH_FAILED"));
            }
            other => panic!("Expected PermanentFailure, got {other:?}"),
        }
    }

    #[test]
    fn permanent_server_rejected_stops() {
        let err = anyhow::anyhow!("Server rejected connection: bad token");
        assert!(matches!(
            compute_reconnect_delay(Err(err), Duration::from_secs(5)),
            ReconnectDecision::PermanentFailure { .. }
        ));
    }

    #[test]
    fn permanent_mtu_mismatch_stops() {
        let err = anyhow::anyhow!("MTU mismatch");
        assert!(matches!(
            compute_reconnect_delay(Err(err), Duration::from_secs(5)),
            ReconnectDecision::PermanentFailure { .. }
        ));
    }

    #[test]
    fn permanent_adapter_error_stops() {
        let err = anyhow::anyhow!("IP was not applied to adapter");
        assert!(matches!(
            compute_reconnect_delay(Err(err), Duration::from_secs(5)),
            ReconnectDecision::PermanentFailure { .. }
        ));
    }

    #[test]
    fn permanent_ipv6_address_failure_stops() {
        let err = anyhow::anyhow!(
            "IPV6_SETUP_FAILED: IPv6 address fd00::2 failed verification (possibly duplicate or stack error)"
        );
        assert!(matches!(
            compute_reconnect_delay(Err(err), Duration::from_secs(5)),
            ReconnectDecision::PermanentFailure { .. }
        ));
    }

    #[test]
    fn permanent_ipv6_split_routes_failure_stops() {
        let err = anyhow::anyhow!(
            "IPV6_SETUP_FAILED: IPv6 split routes (::/1, 8000::/1) not found in routing table"
        );
        assert!(matches!(
            compute_reconnect_delay(Err(err), Duration::from_secs(5)),
            ReconnectDecision::PermanentFailure { .. }
        ));
    }

    #[test]
    fn transient_ipv6_like_error_without_marker_still_retries() {
        // A generic IPv6-mentioning transient error (no marker) must NOT be permanent.
        let err = anyhow::anyhow!("temporary IPv6 route table read glitch");
        assert!(matches!(
            compute_reconnect_delay(Err(err), Duration::from_secs(2)),
            ReconnectDecision::Reconnect { .. }
        ));
    }
}
