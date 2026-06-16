//! Status-query and token-update dispatch tests, split out of `tests/mod.rs`
//! to keep each file under the 500-line cap. Reuses the parent's `test_state` /
//! `test_config` helpers (accessible to this descendant module).

use super::{test_config, test_state};
use crate::handlers::dispatch_request;
use crate::ipc;
use std::sync::atomic::Ordering;

#[tokio::test]
async fn status_request_returns_current_state() {
    let state = test_state();
    {
        let mut guard = state.lock().await;
        guard.vpn_running.store(true, Ordering::SeqCst);
        guard.vpn_connected.store(true, Ordering::SeqCst);
        guard.active_config = Some(test_config());
        *guard.assigned_ip.lock().unwrap() = Some("10.8.0.2".to_string());
    }

    match dispatch_request(ipc::IpcRequest::Status, &state).await {
        ipc::IpcResponse::Status {
            running,
            assigned_ip,
            ..
        } => {
            assert!(running);
            assert_eq!(assigned_ip, Some("10.8.0.2".to_string()));
        }
        other => panic!("Expected Status, got {other:?}"),
    }
}

#[tokio::test]
async fn status_request_when_disconnected() {
    let state = test_state();

    match dispatch_request(ipc::IpcRequest::Status, &state).await {
        ipc::IpcResponse::Status {
            running,
            endpoint,
            state: vpn_state,
            last_error,
            assigned_ip,
        } => {
            assert!(!running);
            assert!(endpoint.is_none());
            assert!(matches!(vpn_state, ipc::VpnState::Stopped));
            assert!(last_error.is_none());
            assert!(assigned_ip.is_none());
        }
        other => panic!("Expected Status, got {other:?}"),
    }
}

#[tokio::test]
async fn status_request_running_with_error_is_reconnecting() {
    // running=true + last_error means the reconnect loop is retrying a transient
    // failure: Reconnecting (not the terminal Failed). This is the core fix: the
    // GUI must not flash a hard error / drop to "NOT CONNECTED" mid auto-retry.
    let state = test_state();
    {
        let guard = state.lock().await;
        guard.vpn_running.store(true, Ordering::SeqCst);
        *guard.last_error.lock().unwrap() = Some("connection failed".to_string());
    }

    match dispatch_request(ipc::IpcRequest::Status, &state).await {
        ipc::IpcResponse::Status {
            running,
            state: vpn_state,
            last_error,
            ..
        } => {
            assert!(!running);
            assert!(matches!(vpn_state, ipc::VpnState::Reconnecting));
            assert_eq!(last_error.as_deref(), Some("connection failed"));
        }
        other => panic!("Expected Status, got {other:?}"),
    }
}

#[tokio::test]
async fn status_request_failed_when_loop_gave_up() {
    // running=false + last_error: terminal Failed (the loop stopped, e.g. a
    // permanent AUTH_FAILED). Only here should the UI surface a hard error.
    let state = test_state();
    {
        let guard = state.lock().await;
        guard.vpn_running.store(false, Ordering::SeqCst);
        *guard.last_error.lock().unwrap() = Some("AUTH_FAILED".to_string());
    }

    match dispatch_request(ipc::IpcRequest::Status, &state).await {
        ipc::IpcResponse::Status {
            running,
            state: vpn_state,
            last_error,
            ..
        } => {
            assert!(!running);
            assert!(matches!(vpn_state, ipc::VpnState::Failed));
            assert_eq!(last_error.as_deref(), Some("AUTH_FAILED"));
        }
        other => panic!("Expected Status, got {other:?}"),
    }
}

#[tokio::test]
async fn update_token_replaces_current_token() {
    let state = test_state();
    {
        let guard = state.lock().await;
        *guard.current_token.lock().unwrap() = "seed".to_string();
    }

    let resp = dispatch_request(
        ipc::IpcRequest::UpdateToken {
            token: "fresh-access-token".to_string(),
        },
        &state,
    )
    .await;

    assert!(matches!(resp, ipc::IpcResponse::Ok));
    assert_eq!(
        state.lock().await.current_token.lock().unwrap().clone(),
        "fresh-access-token"
    );
}

#[tokio::test]
async fn status_request_when_stopping() {
    let state = test_state();
    {
        let guard = state.lock().await;
        guard.vpn_running.store(true, Ordering::SeqCst);
        guard.vpn_stopping.store(true, Ordering::SeqCst);
    }

    match dispatch_request(ipc::IpcRequest::Status, &state).await {
        ipc::IpcResponse::Status {
            state: vpn_state, ..
        } => {
            assert!(matches!(vpn_state, ipc::VpnState::Stopping));
        }
        other => panic!("Expected Status, got {other:?}"),
    }
}

#[tokio::test]
async fn status_request_when_starting() {
    let state = test_state();
    {
        let guard = state.lock().await;
        guard.vpn_running.store(true, Ordering::SeqCst);
        guard.vpn_connected.store(false, Ordering::SeqCst);
    }

    match dispatch_request(ipc::IpcRequest::Status, &state).await {
        ipc::IpcResponse::Status {
            state: vpn_state, ..
        } => {
            assert!(matches!(vpn_state, ipc::VpnState::Starting));
        }
        other => panic!("Expected Status, got {other:?}"),
    }
}

#[tokio::test]
async fn status_request_with_endpoint_and_assigned_ip() {
    let state = test_state();
    {
        let mut guard = state.lock().await;
        guard.vpn_running.store(true, Ordering::SeqCst);
        guard.vpn_connected.store(true, Ordering::SeqCst);
        guard.active_config = Some(test_config());
        *guard.assigned_ip.lock().unwrap() = Some("10.8.0.5".to_string());
    }

    match dispatch_request(ipc::IpcRequest::Status, &state).await {
        ipc::IpcResponse::Status {
            running,
            endpoint,
            assigned_ip,
            ..
        } => {
            assert!(running);
            assert_eq!(endpoint.as_deref(), Some("vpn.example.com:4433"));
            assert_eq!(assigned_ip.as_deref(), Some("10.8.0.5"));
        }
        other => panic!("Expected Status, got {other:?}"),
    }
}
