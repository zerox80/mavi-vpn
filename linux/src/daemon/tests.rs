use super::*;
use shared::ipc::VpnState;
use std::fs;
use tempfile::tempdir;

fn no_cleanup() {}

fn test_state() -> Arc<Mutex<DaemonState>> {
    Arc::new(Mutex::new(DaemonState::new()))
}

fn test_config() -> Config {
    Config {
        endpoint: "vpn.example.com:443".to_string(),
        token: "token".to_string(),
        cert_pin: "00".repeat(32),
        censorship_resistant: false,
        http3_framing: false,
        kc_auth: None,
        kc_url: None,
        kc_realm: None,
        kc_client_id: None,
        ech_config: None,
        vpn_mtu: Some(1280),
    }
}

#[test]
fn ipc_token_modes_are_not_world_readable() {
    assert_eq!(IpcTokenAccess::RootOnly.mode(), 0o600);
    assert_eq!(IpcTokenAccess::Group(Gid::from_raw(123)).mode(), 0o640);
    assert_eq!(IpcTokenAccess::RootOnly.mode() & 0o007, 0);
    assert_eq!(IpcTokenAccess::Group(Gid::from_raw(123)).mode() & 0o007, 0);
}

#[test]
fn root_only_token_file_is_created_with_0600() {
    let dir = tempdir().unwrap();
    let token_path = dir.path().join("mavi-vpn.token");

    write_ipc_token_with_access(&token_path, "secret", IpcTokenAccess::RootOnly).unwrap();

    let metadata = fs::metadata(&token_path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(fs::read_to_string(&token_path).unwrap(), "secret");
}

#[test]
fn existing_token_is_replaced_without_world_readable_bits() {
    let dir = tempdir().unwrap();
    let token_path = dir.path().join("mavi-vpn.token");
    fs::write(&token_path, "old").unwrap();
    fs::set_permissions(&token_path, fs::Permissions::from_mode(0o644)).unwrap();

    write_ipc_token_with_access(&token_path, "new", IpcTokenAccess::RootOnly).unwrap();

    let metadata = fs::metadata(&token_path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(fs::read_to_string(&token_path).unwrap(), "new");
}

#[tokio::test]
async fn dispatch_status_initially_stopped() {
    let state = test_state();

    let resp = dispatch_request_with_hooks(IpcRequest::Status, &state, false, no_cleanup).await;

    assert_eq!(
        resp,
        IpcResponse::Status {
            running: false,
            endpoint: None,
            state: VpnState::Stopped,
            last_error: None,
            assigned_ip: None,
        }
    );
}

#[tokio::test]
async fn dispatch_start_is_accepted_and_duplicate_start_rejected() {
    let state = test_state();

    assert_eq!(
        dispatch_request_with_hooks(
            IpcRequest::Start(test_config()),
            &state,
            false,
            no_cleanup
        )
        .await,
        IpcResponse::Ok
    );
    assert!(matches!(
        dispatch_request_with_hooks(
            IpcRequest::Start(test_config()),
            &state,
            false,
            no_cleanup
        )
        .await,
        IpcResponse::Error(msg) if msg.contains("already running")
    ));

    let resp = dispatch_request_with_hooks(IpcRequest::Status, &state, false, no_cleanup).await;
    assert!(matches!(
        resp,
        IpcResponse::Status {
            running: false,
            endpoint: Some(_),
            state: VpnState::Starting,
            ..
        }
    ));
}

#[tokio::test]
async fn dispatch_stop_clears_active_config_error_and_state() {
    let state = test_state();
    dispatch_request_with_hooks(IpcRequest::Start(test_config()), &state, false, no_cleanup).await;
    {
        let guard = state.lock().await;
        *guard.last_error.lock().unwrap() = Some("boom".to_string());
        *guard.assigned_ip.lock().unwrap() = Some("10.8.0.2".to_string());
    }

    assert_eq!(
        dispatch_request_with_hooks(IpcRequest::Stop, &state, false, no_cleanup).await,
        IpcResponse::Ok
    );
    assert_eq!(
        dispatch_request_with_hooks(IpcRequest::Status, &state, false, no_cleanup).await,
        IpcResponse::Status {
            running: false,
            endpoint: None,
            state: VpnState::Stopped,
            last_error: None,
            assigned_ip: None,
        }
    );
}

#[tokio::test]
async fn dispatch_repair_network_clears_state_without_real_cleanup() {
    let state = test_state();
    dispatch_request_with_hooks(IpcRequest::Start(test_config()), &state, false, no_cleanup).await;

    assert_eq!(
        dispatch_request_with_hooks(IpcRequest::RepairNetwork, &state, false, no_cleanup).await,
        IpcResponse::Ok
    );
    assert_eq!(
        dispatch_request_with_hooks(IpcRequest::Status, &state, false, no_cleanup).await,
        IpcResponse::Status {
            running: false,
            endpoint: None,
            state: VpnState::Stopped,
            last_error: None,
            assigned_ip: None,
        }
    );
}

#[tokio::test]
async fn dispatch_status_maps_failed_starting_stopping_and_connected() {
    let state = test_state();
    {
        let guard = state.lock().await;
        guard.vpn_running.store(true, Ordering::SeqCst);
    }
    assert!(matches!(
        dispatch_request_with_hooks(IpcRequest::Status, &state, false, no_cleanup).await,
        IpcResponse::Status {
            state: VpnState::Starting,
            ..
        }
    ));

    {
        let guard = state.lock().await;
        guard.vpn_connected.store(true, Ordering::SeqCst);
        *guard.assigned_ip.lock().unwrap() = Some("10.8.0.2".to_string());
    }
    assert!(matches!(
        dispatch_request_with_hooks(IpcRequest::Status, &state, false, no_cleanup).await,
        IpcResponse::Status {
            running: true,
            state: VpnState::Connected,
            assigned_ip: Some(_),
            ..
        }
    ));

    {
        let guard = state.lock().await;
        guard.vpn_connected.store(false, Ordering::SeqCst);
        guard.vpn_running.store(false, Ordering::SeqCst);
        guard.vpn_stopping.store(true, Ordering::SeqCst);
        *guard.assigned_ip.lock().unwrap() = None;
    }
    assert!(matches!(
        dispatch_request_with_hooks(IpcRequest::Status, &state, false, no_cleanup).await,
        IpcResponse::Status {
            state: VpnState::Stopping,
            ..
        }
    ));

    {
        let guard = state.lock().await;
        guard.vpn_stopping.store(false, Ordering::SeqCst);
        *guard.last_error.lock().unwrap() = Some("auth failed".to_string());
    }
    assert!(matches!(
        dispatch_request_with_hooks(IpcRequest::Status, &state, false, no_cleanup).await,
        IpcResponse::Status {
            state: VpnState::Failed,
            last_error: Some(_),
            ..
        }
    ));
}
