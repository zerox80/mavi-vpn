use constant_time_eq::constant_time_eq;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::sync::Mutex;
use tracing::{error, info};

use super::keycloak_refresh;
use super::state::VpnServiceState;
use super::utils::{classify_status, run_network_repair_cleanup};
use crate::ipc;
use crate::vpn_core;

pub const IPC_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Named pipes have no peer address; the client's process ID (from
/// `GetNamedPipeClientProcessId`) is used in logs instead — strictly more
/// useful for auditing than the anonymous `127.0.0.1:PORT` line the old TCP
/// transport logged.
#[allow(unsafe_code)]
fn client_process_id(pipe: &NamedPipeServer) -> Option<u32> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;

    let handle = pipe.as_raw_handle();
    let mut pid: u32 = 0;
    let ok = unsafe { GetNamedPipeClientProcessId(handle, &mut pid) };
    (ok != 0).then_some(pid)
}

pub async fn handle_ipc_client(
    socket: NamedPipeServer,
    state: Arc<Mutex<VpnServiceState>>,
    auth_token: Arc<String>,
) -> anyhow::Result<()> {
    let peer = client_process_id(&socket)
        .map(|pid| format!("pid={pid}"))
        .unwrap_or_else(|| "<unknown>".to_string());
    info!("Client connected to Local IPC: {}", peer);
    let (mut rx, mut tx) = tokio::io::split(socket);

    let req_msg = tokio::time::timeout(IPC_REQUEST_TIMEOUT, async {
        let mut len_buf = [0u8; 4];
        rx.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > 65536 {
            anyhow::bail!("IPC request too large: {len} bytes");
        }
        let mut buf = vec![0u8; len];
        rx.read_exact(&mut buf).await?;
        let (msg, _): (ipc::SecureIpcRequest, _) =
            bincode::serde::decode_from_slice(&buf, bincode::config::standard())
                .map_err(|e| anyhow::anyhow!("IPC decode error: {e}"))?;
        Ok::<_, anyhow::Error>(msg)
    })
    .await
    .map_err(|_| anyhow::anyhow!("IPC request timeout from {peer}"))??;

    let resp = if constant_time_eq(req_msg.auth_token.as_bytes(), auth_token.as_bytes()) {
        dispatch_request(req_msg.request, &state).await
    } else {
        error!(
            "Rejecting IPC request from {} due to invalid auth token",
            peer
        );
        ipc::IpcResponse::Error("Unauthorized: Invalid IPC Token".to_string())
    };

    let resp_buf = bincode::serde::encode_to_vec(&resp, bincode::config::standard())
        .map_err(|e| anyhow::anyhow!("Failed to serialize IPC response: {e}"))?;

    tokio::time::timeout(IPC_REQUEST_TIMEOUT, async {
        #[allow(clippy::cast_possible_truncation)]
        tx.write_u32_le(resp_buf.len() as u32).await?;
        tx.write_all(&resp_buf).await?;
        Ok::<_, std::io::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("IPC response write timeout to {peer}"))??;

    Ok(())
}

pub async fn dispatch_request(
    req: ipc::IpcRequest,
    state: &Arc<Mutex<VpnServiceState>>,
) -> ipc::IpcResponse {
    let mut guard = state.lock().await;
    match req {
        ipc::IpcRequest::Status => {
            let snapshot = guard.status_snapshot();
            let state = classify_status(
                snapshot.connected,
                snapshot.stopping,
                snapshot.starting,
                snapshot.last_error.as_deref(),
            );

            ipc::IpcResponse::Status {
                running: snapshot.connected,
                endpoint: snapshot.endpoint,
                state,
                last_error: snapshot.last_error,
                assigned_ip: snapshot.assigned_ip,
            }
        }
        ipc::IpcRequest::Stop => {
            info!("Handling Stop request from client");
            guard.stop_session();
            ipc::IpcResponse::Ok
        }
        ipc::IpcRequest::RepairNetwork => {
            info!("Handling RepairNetwork request from client");
            guard.stop_session();
            drop(guard);
            run_network_repair_cleanup();
            ipc::IpcResponse::Ok
        }
        ipc::IpcRequest::Start(config) => handle_start_request(config, None, &mut guard),
        ipc::IpcRequest::StartWithKeycloak { config, keycloak } => {
            handle_start_request(config, Some(keycloak), &mut guard)
        }
        ipc::IpcRequest::UpdateToken { token } => {
            // Non-Windows clients refresh Keycloak outside the service and push
            // only the fresh access token here. Windows service-side refresh is
            // seeded by StartWithKeycloak and keeps the refresh token in RAM for
            // the active session only.
            // Harmless when no session is active - the next Start overwrites it.
            guard.set_current_token(token);
            ipc::IpcResponse::Ok
        }
        ipc::IpcRequest::TakeRefreshTokenUpdate => {
            match guard.take_pending_keycloak_refresh_token() {
                Some(update) => ipc::IpcResponse::RefreshTokenUpdate {
                    connection_id: Some(update.connection_id),
                    refresh_token: Some(update.refresh_token),
                },
                None => ipc::IpcResponse::RefreshTokenUpdate {
                    connection_id: None,
                    refresh_token: None,
                },
            }
        }
    }
}

pub fn handle_start_request(
    config: ipc::Config,
    keycloak: Option<ipc::KeycloakRuntimeAuth>,
    guard: &mut VpnServiceState,
) -> ipc::IpcResponse {
    info!("Handling Start request for endpoint: {}", config.endpoint);
    if guard.is_stopping() {
        ipc::IpcResponse::Error("VPN is stopping; retry shortly".to_string())
    } else if guard.is_running() || guard.active_task_running() {
        ipc::IpcResponse::Error("VPN is already running".to_string())
    } else {
        guard.mark_session_starting(config.clone());
        let task_runtime = guard.runtime_handles();

        if let Some(keycloak) = keycloak {
            guard.set_keycloak_refresh_task(keycloak_refresh::spawn_keycloak_refresh_task(
                keycloak,
                config.token.clone(),
                task_runtime.clone(),
            ));
        }

        guard.set_task(tokio::spawn(async move {
            if let Err(e) = vpn_core::run_vpn(
                config,
                task_runtime.running.clone(),
                task_runtime.connected.clone(),
                task_runtime.last_error.clone(),
                task_runtime.assigned_ip.clone(),
                task_runtime.current_token.clone(),
                task_runtime.token_updated.clone(),
            )
            .await
            {
                let msg = e.to_string();
                error!("VPN task failed: {}", msg);
                task_runtime.record_task_error_if_running(msg);
            }
            let _ = tokio::task::spawn_blocking(|| {
                run_network_repair_cleanup();
            })
            .await;
            task_runtime.finish_session_flags();
        }));
        ipc::IpcResponse::Ok
    }
}
