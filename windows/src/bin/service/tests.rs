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
    assert_eq!(state.active_config.as_ref().unwrap().endpoint, config.endpoint);
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
        ipc::IpcResponse::Status { running, assigned_ip, .. } => {
            assert!(running);
            assert_eq!(assigned_ip, Some("10.8.0.2".to_string()));
        }
        other => panic!("Expected Status, got {other:?}"),
    }
}
