use super::*;
use futures_util::poll;
use tokio::time::advance;

fn unix_now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

#[tokio::test(start_paused = true)]
async fn token_outside_leeway_expires_immediately() {
    let (_tx, rx) = watch::channel(Some(unix_now() - 100));
    let expiry = wait_for_session_expiry(rx);
    tokio::pin!(expiry);
    // Allow the timer driver to observe the already-due deadline.
    assert!(tokio::time::timeout(Duration::from_millis(1), &mut expiry)
        .await
        .is_ok());
}

#[tokio::test(start_paused = true)]
async fn token_inside_leeway_gets_only_the_remaining_grace() {
    let (_tx, rx) = watch::channel(Some(unix_now() - 20));
    let expiry = wait_for_session_expiry(rx);
    tokio::pin!(expiry);
    assert!(poll!(&mut expiry).is_pending());
    advance(Duration::from_secs(8)).await;
    assert!(poll!(&mut expiry).is_pending());
    advance(Duration::from_secs(3)).await;
    assert!(poll!(&mut expiry).is_ready());
}

#[tokio::test(start_paused = true)]
async fn unchanged_token_expires_without_reauth() {
    let (_tx, rx) = watch::channel(Some(unix_now() + 5));
    let expiry = wait_for_session_expiry(rx);
    tokio::pin!(expiry);
    assert!(poll!(&mut expiry).is_pending());
    advance(Duration::from_secs(33)).await;
    assert!(poll!(&mut expiry).is_pending());
    advance(Duration::from_secs(3)).await;
    assert!(poll!(&mut expiry).is_ready());
}

#[tokio::test(start_paused = true)]
async fn resending_the_same_expiry_does_not_rearm_the_timer() {
    let token_expiry = Some(unix_now() + 5);
    let (tx, rx) = watch::channel(token_expiry);
    let expiry = wait_for_session_expiry(rx);
    tokio::pin!(expiry);
    assert!(poll!(&mut expiry).is_pending());
    for _ in 0..10 {
        advance(Duration::from_secs(1)).await;
        tx.send(token_expiry).unwrap();
        assert!(poll!(&mut expiry).is_pending());
    }
    advance(Duration::from_secs(26)).await;
    assert!(poll!(&mut expiry).is_ready());
}

#[tokio::test(start_paused = true)]
async fn reauth_at_the_old_deadline_keeps_the_session_alive() {
    let now = unix_now();
    let (tx, rx) = watch::channel(Some(now + 5));
    let expiry = wait_for_session_expiry(rx);
    tokio::pin!(expiry);
    assert!(poll!(&mut expiry).is_pending());
    advance(Duration::from_secs(36)).await;
    // Both the timer and update are ready before the waiter is polled.
    tx.send(Some(now + 60)).unwrap();
    assert!(poll!(&mut expiry).is_pending());
    advance(Duration::from_secs(88)).await;
    assert!(poll!(&mut expiry).is_pending());
    advance(Duration::from_secs(3)).await;
    assert!(poll!(&mut expiry).is_ready());
}

#[tokio::test(start_paused = true)]
async fn dropped_reauth_sender_preserves_the_deadline() {
    let (tx, rx) = watch::channel(Some(unix_now() + 5));
    let expiry = wait_for_session_expiry(rx);
    tokio::pin!(expiry);
    assert!(poll!(&mut expiry).is_pending());
    drop(tx);
    assert!(poll!(&mut expiry).is_pending());
    advance(Duration::from_secs(36)).await;
    assert!(poll!(&mut expiry).is_ready());
}

#[tokio::test(start_paused = true)]
async fn final_reauth_update_is_kept_when_the_sender_closes() {
    let now = unix_now();
    let (tx, rx) = watch::channel(Some(now + 5));
    let expiry = wait_for_session_expiry(rx);
    tokio::pin!(expiry);
    assert!(poll!(&mut expiry).is_pending());
    tx.send(Some(now + 60)).unwrap();
    drop(tx);
    assert!(poll!(&mut expiry).is_pending());
    advance(Duration::from_secs(36)).await;
    assert!(poll!(&mut expiry).is_pending());
    advance(Duration::from_secs(55)).await;
    assert!(poll!(&mut expiry).is_ready());
}

#[tokio::test(start_paused = true)]
async fn static_token_session_has_no_expiry() {
    let (tx, rx) = watch::channel(None);
    let expiry = wait_for_session_expiry(rx);
    tokio::pin!(expiry);
    assert!(poll!(&mut expiry).is_pending());
    drop(tx);
    advance(Duration::from_secs(86_400)).await;
    assert!(poll!(&mut expiry).is_pending());
}
