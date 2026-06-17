mod control;
mod status;

use crate::handlers::{dispatch_request, handle_start_request};
use crate::ipc;
use crate::state::VpnServiceState;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

fn test_config() -> ipc::Config {
    ipc::Config {
        endpoint: "vpn.example.com:4433".to_string(),
        token: "token".to_string(),
        cert_pin: "deadbeef".to_string(),
        censorship_resistant: false,
        http3_framing: false,
        kc_auth: None,
        kc_url: None,
        kc_realm: None,
        kc_client_id: None,
        refresh_token: None,
        ech_config: None,
        vpn_mtu: None,
    }
}

fn test_state() -> Arc<Mutex<VpnServiceState>> {
    Arc::new(Mutex::new(VpnServiceState::new()))
}

#[tokio::test]
async fn stop_request_marks_active_task_as_stopping() {
    let state = test_state();
    let sleeper = tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(60)).await;
    });
    {
        let mut guard = state.lock().await;
        guard.vpn_running.store(true, Ordering::SeqCst);
        guard.vpn_connected.store(true, Ordering::SeqCst);
        guard.active_config = Some(test_config());
        if let Ok(mut last) = guard.last_error.lock() {
            *last = Some("old error".to_string());
        }
        guard.vpn_task = Some(sleeper);
    }

    assert!(matches!(
        dispatch_request(ipc::IpcRequest::Stop, &state).await,
        ipc::IpcResponse::Ok
    ));

    let task = {
        let mut guard = state.lock().await;
        assert!(!guard.vpn_running.load(Ordering::SeqCst));
        assert!(!guard.vpn_connected.load(Ordering::SeqCst));
        assert!(guard.vpn_stopping.load(Ordering::SeqCst));
        assert!(guard.active_config.is_none());
        assert!(guard.last_error.lock().unwrap().is_none());
        guard.vpn_task.take()
    };
    if let Some(task) = task {
        task.abort();
    }
}

#[tokio::test]
async fn stop_request_without_task_reports_stopped() {
    let state = test_state();
    {
        let mut guard = state.lock().await;
        guard.vpn_running.store(true, Ordering::SeqCst);
        guard.vpn_connected.store(true, Ordering::SeqCst);
        guard.active_config = Some(test_config());
    }

    assert!(matches!(
        dispatch_request(ipc::IpcRequest::Stop, &state).await,
        ipc::IpcResponse::Ok
    ));

    let guard = state.lock().await;
    assert!(!guard.vpn_running.load(Ordering::SeqCst));
    assert!(!guard.vpn_connected.load(Ordering::SeqCst));
    assert!(!guard.vpn_stopping.load(Ordering::SeqCst));
    assert!(guard.active_config.is_none());
    drop(guard);
}

#[tokio::test]
async fn start_request_is_rejected_while_stopping() {
    let state = test_state();
    {
        let guard = state.lock().await;
        guard.vpn_stopping.store(true, Ordering::SeqCst);
    }

    match dispatch_request(ipc::IpcRequest::Start(test_config()), &state).await {
        ipc::IpcResponse::Error(msg) => {
            assert_eq!(msg, "VPN is stopping; retry shortly");
        }
        other => panic!("Expected Error, got {other:?}"),
    }
}

#[tokio::test]
async fn start_request_is_rejected_when_already_running() {
    let state = test_state();
    let sleeper = tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(60)).await;
    });
    {
        let mut guard = state.lock().await;
        guard.vpn_running.store(true, Ordering::SeqCst);
        guard.vpn_task = Some(sleeper);
    }

    match dispatch_request(ipc::IpcRequest::Start(test_config()), &state).await {
        ipc::IpcResponse::Error(msg) => {
            assert_eq!(msg, "VPN is already running");
        }
        other => panic!("Expected Error, got {other:?}"),
    }

    let task = {
        let mut guard = state.lock().await;
        guard.vpn_task.take()
    };
    if let Some(task) = task {
        task.abort();
    }
}

#[tokio::test]
async fn start_request_succeeds_when_idle() {
    let state = test_state();
    {
        let guard = state.lock().await;
        assert!(!guard.vpn_running.load(Ordering::SeqCst));
        assert!(guard.vpn_task.is_none());
    }

    let result = dispatch_request(ipc::IpcRequest::Start(test_config()), &state).await;
    assert!(matches!(result, ipc::IpcResponse::Ok));

    let mut guard = state.lock().await;
    assert!(guard.vpn_running.load(Ordering::SeqCst));
    assert!(guard.active_config.is_some());
    assert!(guard.vpn_task.is_some());

    let task = guard.vpn_task.take();
    if let Some(task) = task {
        task.abort();
    }
}

#[tokio::test]
async fn handle_start_request_sets_config_and_flags() {
    let mut state = VpnServiceState::new();
    let config = test_config();

    let result = handle_start_request(config.clone(), &mut state);
    assert!(matches!(result, ipc::IpcResponse::Ok));
    assert!(state.vpn_running.load(Ordering::SeqCst));
    assert!(!state.vpn_connected.load(Ordering::SeqCst));
    assert!(!state.vpn_stopping.load(Ordering::SeqCst));
    assert_eq!(
        state.active_config.as_ref().unwrap().endpoint,
        config.endpoint
    );
    assert!(state.vpn_task.is_some());

    if let Some(task) = state.vpn_task.take() {
        task.abort();
    }
}

#[tokio::test]
async fn handle_start_request_clears_last_error() {
    let mut state = VpnServiceState::new();
    *state.last_error.lock().unwrap() = Some("previous error".to_string());

    let result = handle_start_request(test_config(), &mut state);
    assert!(matches!(result, ipc::IpcResponse::Ok));
    assert!(state.last_error.lock().unwrap().is_none());

    if let Some(task) = state.vpn_task.take() {
        task.abort();
    }
}

#[tokio::test]
async fn repair_network_clears_state() {
    let state = test_state();
    let sleeper = tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(60)).await;
    });
    {
        let mut guard = state.lock().await;
        guard.vpn_running.store(true, Ordering::SeqCst);
        guard.vpn_connected.store(true, Ordering::SeqCst);
        guard.active_config = Some(test_config());
        *guard.last_error.lock().unwrap() = Some("old error".to_string());
        guard.vpn_task = Some(sleeper);
    }

    assert!(matches!(
        dispatch_request(ipc::IpcRequest::RepairNetwork, &state).await,
        ipc::IpcResponse::Ok
    ));

    let guard = state.lock().await;
    assert!(!guard.vpn_running.load(Ordering::SeqCst));
    assert!(!guard.vpn_connected.load(Ordering::SeqCst));
    assert!(guard.active_config.is_none());
    assert!(guard.last_error.lock().unwrap().is_none());
    drop(guard);
}

#[tokio::test]
async fn repair_network_without_task_reports_not_stopping() {
    let state = test_state();
    {
        let guard = state.lock().await;
        guard.vpn_running.store(true, Ordering::SeqCst);
    }

    assert!(matches!(
        dispatch_request(ipc::IpcRequest::RepairNetwork, &state).await,
        ipc::IpcResponse::Ok
    ));

    let guard = state.lock().await;
    assert!(!guard.vpn_stopping.load(Ordering::SeqCst));
    drop(guard);
}

#[tokio::test]
async fn start_request_with_finished_task_succeeds() {
    let state = test_state();
    let finished_task = tokio::spawn(async {});
    tokio::time::sleep(Duration::from_millis(10)).await;
    {
        let mut guard = state.lock().await;
        guard.vpn_running.store(false, Ordering::SeqCst);
        guard.vpn_task = Some(finished_task);
    }

    let result = dispatch_request(ipc::IpcRequest::Start(test_config()), &state).await;
    assert!(matches!(result, ipc::IpcResponse::Ok));

    let mut guard = state.lock().await;
    assert!(guard.vpn_running.load(Ordering::SeqCst));
    if let Some(task) = guard.vpn_task.take() {
        task.abort();
    }
}

#[tokio::test]
async fn update_token_replaces_current_token_without_refresh_dependency() {
    // The GUI owns the Keycloak refresh token; the service only ever receives
    // the freshly minted access token via UpdateToken. Verify that UpdateToken
    // overwrites current_token and never touches any refresh-token state.
    let state = test_state();
    {
        let guard = state.lock().await;
        guard.set_current_token("initial-access".to_string());
        assert_eq!(
            guard.current_token.lock().unwrap().clone(),
            "initial-access"
        );
    }

    let result = dispatch_request(
        ipc::IpcRequest::UpdateToken {
            token: "fresh-access-token".to_string(),
        },
        &state,
    )
    .await;
    assert!(matches!(result, ipc::IpcResponse::Ok));

    let guard = state.lock().await;
    assert_eq!(
        guard.current_token.lock().unwrap().clone(),
        "fresh-access-token"
    );
}

#[tokio::test]
async fn update_token_succeeds_even_with_no_session_active() {
    // UpdateToken must be harmless when no session is running: the next Start
    // overwrites current_token anyway, and the service must not require a
    // refresh token or an active session to accept an access-token update.
    let state = test_state();

    let result = dispatch_request(
        ipc::IpcRequest::UpdateToken {
            token: "standalone-access".to_string(),
        },
        &state,
    )
    .await;
    assert!(matches!(result, ipc::IpcResponse::Ok));

    let guard = state.lock().await;
    assert_eq!(
        guard.current_token.lock().unwrap().clone(),
        "standalone-access"
    );
    assert!(!guard.vpn_running.load(Ordering::SeqCst));
}

#[tokio::test]
async fn handle_start_request_preserves_config_fields() {
    let mut state = VpnServiceState::new();
    let mut config = test_config();
    config.censorship_resistant = true;
    config.http3_framing = true;
    config.vpn_mtu = Some(1340);
    config.kc_auth = Some(true);
    config.kc_url = Some("https://auth.example.com".to_string());

    let result = handle_start_request(config.clone(), &mut state);
    assert!(matches!(result, ipc::IpcResponse::Ok));

    let saved_config = state.active_config.as_ref().unwrap();
    assert!(saved_config.censorship_resistant);
    assert!(saved_config.http3_framing);
    assert_eq!(saved_config.vpn_mtu, Some(1340));
    assert_eq!(saved_config.kc_auth, Some(true));
    assert_eq!(
        saved_config.kc_url.as_deref(),
        Some("https://auth.example.com")
    );

    if let Some(task) = state.vpn_task.take() {
        task.abort();
    }
}

#[tokio::test]
async fn stop_request_clears_assigned_ip() {
    let state = test_state();
    {
        let guard = state.lock().await;
        guard.vpn_running.store(true, Ordering::SeqCst);
        guard.vpn_connected.store(true, Ordering::SeqCst);
        *guard.assigned_ip.lock().unwrap() = Some("10.8.0.2".to_string());
    }

    assert!(matches!(
        dispatch_request(ipc::IpcRequest::Stop, &state).await,
        ipc::IpcResponse::Ok
    ));

    let guard = state.lock().await;
    assert!(guard.assigned_ip.lock().unwrap().is_none());
}

#[tokio::test]
async fn repair_network_clears_assigned_ip() {
    let state = test_state();
    {
        let guard = state.lock().await;
        guard.vpn_running.store(true, Ordering::SeqCst);
        *guard.assigned_ip.lock().unwrap() = Some("10.8.0.2".to_string());
    }

    assert!(matches!(
        dispatch_request(ipc::IpcRequest::RepairNetwork, &state).await,
        ipc::IpcResponse::Ok
    ));

    let guard = state.lock().await;
    assert!(guard.assigned_ip.lock().unwrap().is_none());
}

#[tokio::test]
async fn sequential_stop_start_stop_cycle() {
    let state = test_state();

    assert!(matches!(
        dispatch_request(ipc::IpcRequest::Start(test_config()), &state).await,
        ipc::IpcResponse::Ok
    ));

    let mut guard = state.lock().await;
    assert!(guard.vpn_running.load(Ordering::SeqCst));
    if let Some(task) = guard.vpn_task.take() {
        task.abort();
    }
    drop(guard);

    tokio::time::sleep(Duration::from_millis(10)).await;

    assert!(matches!(
        dispatch_request(ipc::IpcRequest::Stop, &state).await,
        ipc::IpcResponse::Ok
    ));

    let guard = state.lock().await;
    assert!(!guard.vpn_running.load(Ordering::SeqCst));
    assert!(!guard.vpn_stopping.load(Ordering::SeqCst));
    drop(guard);

    assert!(matches!(
        dispatch_request(ipc::IpcRequest::Start(test_config()), &state).await,
        ipc::IpcResponse::Ok
    ));

    let mut guard = state.lock().await;
    assert!(guard.vpn_running.load(Ordering::SeqCst));
    if let Some(task) = guard.vpn_task.take() {
        task.abort();
    }
}
