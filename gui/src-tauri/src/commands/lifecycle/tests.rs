use super::*;
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::test]
async fn cancelling_a_login_releases_its_listener_before_the_next_attempt() {
    let lifecycle = Arc::new(ConnectionLifecycle::default());
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let task_state = lifecycle.clone();
    let task = tokio::spawn(async move {
        let mut attempt = task_state.begin("A".into()).unwrap();
        let _operation = task_state.operation.lock().await;
        attempt
            .prepare(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                ready_tx.send(listener.local_addr().unwrap()).unwrap();
                listener.accept().await.map_err(|e| e.to_string())?;
                Ok(())
            })
            .await
    });
    let address = ready_rx.await.unwrap();
    let stop = lifecycle.stop(Some("A")).unwrap().unwrap();
    let _operation = lifecycle.operation.lock().await;
    assert!(task.await.unwrap().is_err());
    assert!(!stop.needs_service_stop().unwrap());
    drop(stop);
    let _next = lifecycle.begin("B".into()).unwrap();
    let _listener = TcpListener::bind(address).await.unwrap();
}

#[test]
fn a_late_cancel_cannot_stop_a_newer_session() {
    let lifecycle = ConnectionLifecycle::default();
    lifecycle.begin("A".into()).unwrap().accept().unwrap();
    let stop = lifecycle.stop(Some("A")).unwrap().unwrap();
    assert!(stop.needs_service_stop().unwrap());
    stop.completed();
    drop(stop);
    lifecycle.begin("B".into()).unwrap().accept().unwrap();
    assert!(lifecycle.stop(Some("A")).unwrap().is_none());
    assert_eq!(
        lifecycle.state.lock().unwrap().session_id.as_deref(),
        Some("B")
    );
}

#[test]
fn a_cancelled_start_is_not_accepted_after_the_ipc_reply() {
    let lifecycle = ConnectionLifecycle::default();
    let mut attempt = lifecycle.begin("A".into()).unwrap();
    let _stop = lifecycle.stop(Some("A")).unwrap().unwrap();
    assert!(attempt.accept().is_err());
}

#[tokio::test]
async fn cancelled_start_keeps_ownership_until_stop_is_acknowledged() {
    let lifecycle = Arc::new(ConnectionLifecycle::default());
    let mut attempt = lifecycle.begin("A".into()).unwrap();
    let operation = lifecycle.operation.lock().await;
    let (cancelled_tx, cancelled_rx) = tokio::sync::oneshot::channel();
    let stopping = lifecycle.clone();
    let disconnect = tokio::spawn(async move {
        let stop = stopping.stop(Some("A")).unwrap().unwrap();
        cancelled_tx.send(()).unwrap();
        let _operation = stopping.operation.lock().await;
        // A failed compensating Stop must reach the waiting disconnect caller.
        assert!(stop.needs_service_stop().unwrap());
        // Its own Stop fails too: do not acknowledge completion.
    });
    cancelled_rx.await.unwrap();
    assert!(attempt.accept().is_err());
    drop(attempt); // Compensating Stop failed after Start was accepted.
    drop(operation);
    disconnect.await.unwrap();

    // The user can retry with the same request ID, even after both failures.
    let retry = lifecycle.stop(Some("A")).unwrap().unwrap();
    assert!(retry.needs_service_stop().unwrap());
    retry.completed();
    drop(retry);
    assert!(lifecycle.stop(Some("A")).unwrap().is_none());
    lifecycle.begin("B".into()).unwrap().accept().unwrap();
    assert!(lifecycle.stop(Some("A")).unwrap().is_none());
}

#[test]
fn successful_compensating_stop_does_not_leave_a_session_to_stop_again() {
    let lifecycle = ConnectionLifecycle::default();
    let mut attempt = lifecycle.begin("A".into()).unwrap();
    let stop = lifecycle.stop(Some("A")).unwrap().unwrap();
    assert!(attempt.accept().is_err());
    attempt.stopped();
    drop(attempt);
    assert!(!stop.needs_service_stop().unwrap());
}

#[test]
fn duplicate_logins_and_starts_during_a_stop_are_rejected() {
    let lifecycle = ConnectionLifecycle::default();
    let attempt = lifecycle.begin("A".into()).unwrap();
    assert!(lifecycle.begin("B".into()).is_err());
    let stop = lifecycle.stop(Some("A")).unwrap().unwrap();
    drop(attempt);
    assert!(lifecycle.begin("B".into()).is_err());
    drop(stop);
    assert!(lifecycle.begin("B".into()).is_ok());
}

#[test]
fn cancel_before_command_dispatch_prevents_the_later_start() {
    let lifecycle = ConnectionLifecycle::default();
    assert!(lifecycle.stop(Some("A")).unwrap().is_none());
    assert!(lifecycle.begin("A".into()).is_err());
    assert!(lifecycle.begin("B".into()).is_ok());
}

#[test]
fn a_failed_new_attempt_preserves_the_previous_session_identity() {
    let lifecycle = ConnectionLifecycle::default();
    lifecycle.begin("A".into()).unwrap().accept().unwrap();
    drop(lifecycle.begin("B".into()).unwrap());
    assert!(lifecycle.stop(Some("B")).unwrap().is_none());
    assert!(lifecycle
        .stop(Some("A"))
        .unwrap()
        .unwrap()
        .needs_service_stop()
        .unwrap());
}
