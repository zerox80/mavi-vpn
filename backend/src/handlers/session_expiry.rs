use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tokio::time::Instant;

// Match the leeway used by KeycloakValidator when validating the JWT.
const SESSION_EXPIRY_LEEWAY: Duration = Duration::from_secs(30);

fn session_deadline(expiry: i64) -> Instant {
    let now = Instant::now();
    let wall_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let expires_at = Duration::from_secs(u64::try_from(expiry).unwrap_or(0))
        .saturating_add(SESSION_EXPIRY_LEEWAY);
    // Apply leeway to the absolute expiry, before subtracting the current
    // time. An already-expired token must not gain another 30 seconds.
    let remaining = expires_at.saturating_sub(wall_now);
    now.checked_add(remaining).unwrap_or(now)
}

async fn wait_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// Shared expiry enforcement for raw QUIC, HTTP/3 and HTTP/2 tunnels.
/// Keep the monotonic deadline fixed until reauthentication changes the JWT
/// expiry. Losing the reauth sender must not disable an existing deadline.
pub(super) async fn wait_for_session_expiry(mut expiry_rx: watch::Receiver<Option<i64>>) {
    let mut expiry = *expiry_rx.borrow_and_update();
    let mut deadline = expiry.map(session_deadline);
    let mut updates_open = true;

    loop {
        tokio::select! {
            changed = expiry_rx.changed(), if updates_open => {
                updates_open = changed.is_ok();
            }
            () = wait_until(deadline) => {
                // An accepted reauth may race with the timer. Compare the
                // token expiry itself, not a freshly computed Instant.
                if *expiry_rx.borrow() == expiry {
                    return;
                }
            }
        }

        let latest = *expiry_rx.borrow_and_update();
        if latest != expiry {
            expiry = latest;
            deadline = expiry.map(session_deadline);
        }
    }
}

#[cfg(test)]
mod tests;
