use super::transport::{
    bind_ipc_socket_at, handle_ipc_client, write_ipc_token_with_access, IpcTokenAccess,
};
use super::*;
use nix::unistd::Gid;
use shared::ipc::{SecureIpcRequest, VpnState};
use std::fs;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

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
        refresh_token: None,
        ech_config: None,
        vpn_mtu: Some(1280),
        http2_framing: false,
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
fn ipc_socket_modes_are_not_world_accessible() {
    assert_eq!(IpcTokenAccess::RootOnly.socket_mode(), 0o600);
    assert_eq!(
        IpcTokenAccess::Group(Gid::from_raw(123)).socket_mode(),
        0o660
    );
    assert_eq!(IpcTokenAccess::RootOnly.socket_mode() & 0o007, 0);
    assert_eq!(
        IpcTokenAccess::Group(Gid::from_raw(123)).socket_mode() & 0o007,
        0
    );
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
async fn bind_ipc_socket_creates_socket_file_with_correct_mode() {
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("mavi-vpn.sock");

    let _listener = bind_ipc_socket_at(&socket_path, IpcTokenAccess::RootOnly).unwrap();

    let metadata = fs::metadata(&socket_path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert!(metadata.file_type().is_socket());
}

#[tokio::test]
async fn bind_ipc_socket_removes_stale_socket_file() {
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("mavi-vpn.sock");

    // Simulate a stale socket file left behind by a crashed daemon.
    {
        let _first = bind_ipc_socket_at(&socket_path, IpcTokenAccess::RootOnly).unwrap();
    }
    assert!(socket_path.exists());

    // Binding again must succeed by removing the stale path first, not fail
    // with AddrInUse.
    let _second = bind_ipc_socket_at(&socket_path, IpcTokenAccess::RootOnly).unwrap();
    assert!(socket_path.exists());
}

#[tokio::test]
async fn bind_ipc_socket_root_only_mode_when_no_group() {
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("mavi-vpn.sock");

    let _listener = bind_ipc_socket_at(&socket_path, IpcTokenAccess::RootOnly).unwrap();

    let metadata = fs::metadata(&socket_path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
}

#[tokio::test]
async fn handle_ipc_client_over_unix_socket_roundtrip() {
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("mavi-vpn.sock");
    let listener = bind_ipc_socket_at(&socket_path, IpcTokenAccess::RootOnly).unwrap();

    let state = test_state();
    let auth_token = Arc::new("secret-token".to_string());

    let server_auth_token = auth_token.clone();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        handle_ipc_client(socket, state, server_auth_token)
            .await
            .unwrap();
    });

    let mut client = UnixStream::connect(&socket_path).await.unwrap();
    let req = SecureIpcRequest {
        auth_token: (*auth_token).clone(),
        request: IpcRequest::Status,
    };
    let req_buf = bincode::serde::encode_to_vec(&req, bincode::config::standard()).unwrap();
    client.write_u32_le(req_buf.len() as u32).await.unwrap();
    client.write_all(&req_buf).await.unwrap();

    let mut len_buf = [0u8; 4];
    client.read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    client.read_exact(&mut buf).await.unwrap();
    let (resp, _): (IpcResponse, usize) =
        bincode::serde::decode_from_slice(&buf, bincode::config::standard()).unwrap();

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

    server.await.unwrap();
}

#[tokio::test]
async fn handle_ipc_client_rejects_wrong_auth_token() {
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("mavi-vpn.sock");
    let listener = bind_ipc_socket_at(&socket_path, IpcTokenAccess::RootOnly).unwrap();

    let state = test_state();
    let auth_token = Arc::new("secret-token".to_string());

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        handle_ipc_client(socket, state, auth_token).await.unwrap();
    });

    let mut client = UnixStream::connect(&socket_path).await.unwrap();
    let req = SecureIpcRequest {
        auth_token: "wrong-token".to_string(),
        request: IpcRequest::Status,
    };
    let req_buf = bincode::serde::encode_to_vec(&req, bincode::config::standard()).unwrap();
    client.write_u32_le(req_buf.len() as u32).await.unwrap();
    client.write_all(&req_buf).await.unwrap();

    let mut len_buf = [0u8; 4];
    client.read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    client.read_exact(&mut buf).await.unwrap();
    let (resp, _): (IpcResponse, usize) =
        bincode::serde::decode_from_slice(&buf, bincode::config::standard()).unwrap();

    assert!(matches!(resp, IpcResponse::Error(msg) if msg.contains("Unauthorized")));

    server.await.unwrap();
}

#[tokio::test]
async fn send_request_connects_to_unix_socket() {
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("mavi-vpn.sock");
    let token_path = dir.path().join("mavi-vpn.token");
    write_ipc_token_with_access(&token_path, "secret-token", IpcTokenAccess::RootOnly).unwrap();
    let listener = bind_ipc_socket_at(&socket_path, IpcTokenAccess::RootOnly).unwrap();

    let state = test_state();
    let auth_token = Arc::new("secret-token".to_string());
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        handle_ipc_client(socket, state, auth_token).await.unwrap();
    });

    // send_request() reads the token from the real ipc_token_path() and
    // connects to the real ipc_socket_path(), neither of which are
    // overridable in tests, so this test exercises the same wire protocol
    // send_request() uses (length-prefixed bincode SecureIpcRequest/
    // IpcResponse over a Unix stream) directly against tempdir paths instead.
    let mut client = UnixStream::connect(&socket_path).await.unwrap();
    let auth_token = fs::read_to_string(&token_path).unwrap();
    let req = SecureIpcRequest {
        auth_token,
        request: IpcRequest::Status,
    };
    let req_buf = bincode::serde::encode_to_vec(&req, bincode::config::standard()).unwrap();
    client.write_u32_le(req_buf.len() as u32).await.unwrap();
    client.write_all(&req_buf).await.unwrap();

    let mut len_buf = [0u8; 4];
    client.read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    client.read_exact(&mut buf).await.unwrap();
    let (resp, _): (IpcResponse, usize) =
        bincode::serde::decode_from_slice(&buf, bincode::config::standard()).unwrap();
    assert!(matches!(resp, IpcResponse::Status { .. }));

    server.await.unwrap();
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
        dispatch_request_with_hooks(IpcRequest::Start(test_config()), &state, false, no_cleanup)
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
async fn dispatch_failed_idle_state_accepts_new_start() {
    let state = test_state();
    {
        let mut guard = state.lock().await;
        guard.vpn_running.store(false, Ordering::SeqCst);
        guard.vpn_connected.store(false, Ordering::SeqCst);
        guard.active_config = Some(test_config());
        *guard.last_error.lock().unwrap() = Some("MTU mismatch".to_string());
    }

    assert!(matches!(
        dispatch_request_with_hooks(IpcRequest::Status, &state, false, no_cleanup).await,
        IpcResponse::Status {
            running: false,
            state: VpnState::Failed,
            last_error: Some(_),
            ..
        }
    ));

    assert_eq!(
        dispatch_request_with_hooks(IpcRequest::Start(test_config()), &state, false, no_cleanup)
            .await,
        IpcResponse::Ok
    );
    let guard = state.lock().await;
    assert!(guard.vpn_running.load(Ordering::SeqCst));
    assert!(guard.last_error.lock().unwrap().is_none());
}

#[tokio::test]
async fn dispatch_repair_network_clears_state_without_real_cleanup() {
    let state = test_state();
    dispatch_request_with_hooks(IpcRequest::Start(test_config()), &state, false, no_cleanup).await;
    {
        let guard = state.lock().await;
        *guard.last_error.lock().unwrap() = Some("boom".to_string());
        *guard.assigned_ip.lock().unwrap() = Some("10.8.0.2".to_string());
    }

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

#[tokio::test]
async fn dispatch_status_maps_transient_error_while_running_to_reconnecting() {
    // Reconnect loop still active (running, not connected) with a recorded
    // transient error → Reconnecting, NOT Failed. This is what keeps the GUI on
    // "connecting" through an H3_NO_ERROR retry instead of flashing a hard error.
    let state = test_state();
    {
        let guard = state.lock().await;
        guard.vpn_running.store(true, Ordering::SeqCst);
        guard.vpn_connected.store(false, Ordering::SeqCst);
        *guard.last_error.lock().unwrap() =
            Some("H3 recv_response failed: ApplicationClose: H3_NO_ERROR".to_string());
    }
    assert!(matches!(
        dispatch_request_with_hooks(IpcRequest::Status, &state, false, no_cleanup).await,
        IpcResponse::Status {
            state: VpnState::Reconnecting,
            last_error: Some(_),
            ..
        }
    ));
}

#[tokio::test]
async fn update_token_replaces_current_token() {
    let state = test_state();
    // Start (without spawning a session) seeds the cell from config.token.
    dispatch_request_with_hooks(IpcRequest::Start(test_config()), &state, false, no_cleanup).await;
    assert_eq!(
        state.lock().await.current_token.lock().unwrap().clone(),
        "token"
    );

    let resp = dispatch_request_with_hooks(
        IpcRequest::UpdateToken {
            token: "fresh-access-token".to_string(),
        },
        &state,
        false,
        no_cleanup,
    )
    .await;

    assert_eq!(resp, IpcResponse::Ok);
    assert_eq!(
        state.lock().await.current_token.lock().unwrap().clone(),
        "fresh-access-token"
    );
}
