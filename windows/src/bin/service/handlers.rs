use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::Mutex as StdMutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use constant_time_eq::constant_time_eq;

use crate::ipc;
use crate::vpn_core;
use super::state::VpnServiceState;
use super::utils::{classify_status, run_network_repair_cleanup};

pub const IPC_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub async fn handle_ipc_client(
    socket: TcpStream,
    peer: std::net::SocketAddr,
    state: Arc<Mutex<VpnServiceState>>,
    auth_token: Arc<String>,
) -> anyhow::Result<()> {
    info!("Client connected to Local IPC from {}", peer);
    let (mut rx, mut tx) = socket.into_split();

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
            let connected = guard.vpn_connected.load(Ordering::SeqCst);
            let stopping = guard.vpn_stopping.load(Ordering::SeqCst);
            let starting = guard.vpn_running.load(Ordering::SeqCst) && !connected;
            let last_error = guard.last_error.lock().ok().and_then(|e| e.clone());
            let assigned_ip = guard.assigned_ip.lock().ok().and_then(|e| e.clone());
            let state = classify_status(connected, stopping, starting, last_error.as_deref());

            ipc::IpcResponse::Status {
                running: connected,
                endpoint: guard.active_config.as_ref().map(|c| c.endpoint.clone()),
                state,
                last_error,
                assigned_ip,
            }
        }
        ipc::IpcRequest::Stop => {
            info!("Handling Stop request from client");
            let task_running = guard.vpn_task.as_ref().is_some_and(|t| !t.is_finished());
            guard.vpn_running.store(false, Ordering::SeqCst);
            guard.vpn_connected.store(false, Ordering::SeqCst);
            guard.vpn_stopping.store(task_running, Ordering::SeqCst);
            if let Ok(mut last_error) = guard.last_error.lock() {
                *last_error = None;
            }
            if let Ok(mut assigned_ip) = guard.assigned_ip.lock() {
                *assigned_ip = None;
            }
            guard.active_config = None;
            ipc::IpcResponse::Ok
        }
        ipc::IpcRequest::RepairNetwork => {
            info!("Handling RepairNetwork request from client");
            let task_running = guard.vpn_task.as_ref().is_some_and(|t| !t.is_finished());
            guard.vpn_running.store(false, Ordering::SeqCst);
            guard.vpn_connected.store(false, Ordering::SeqCst);
            guard.vpn_stopping.store(task_running, Ordering::SeqCst);
            if let Ok(mut last_error) = guard.last_error.lock() {
                *last_error = None;
            }
            guard.active_config = None;
            drop(guard);
            run_network_repair_cleanup();
            ipc::IpcResponse::Ok
        }
        ipc::IpcRequest::Start(config) => handle_start_request(config, &mut guard),
    }
}

pub fn handle_start_request(config: ipc::Config, guard: &mut VpnServiceState) -> ipc::IpcResponse {
    info!("Handling Start request for endpoint: {}", config.endpoint);
    if guard.vpn_stopping.load(Ordering::SeqCst) {
        ipc::IpcResponse::Error("VPN is stopping; retry shortly".to_string())
    } else if guard.vpn_running.load(Ordering::SeqCst)
        || guard.vpn_task.as_ref().is_some_and(|t| !t.is_finished())
    {
        ipc::IpcResponse::Error("VPN is already running".to_string())
    } else {
        guard.active_config = Some(config.clone());
        guard.vpn_running.store(true, Ordering::SeqCst);
        guard.vpn_connected.store(false, Ordering::SeqCst);
        guard.vpn_stopping.store(false, Ordering::SeqCst);
        if let Ok(mut last_error) = guard.last_error.lock() {
            *last_error = None;
        }
        let flag = guard.vpn_running.clone();
        let connected = guard.vpn_connected.clone();
        let stopping = guard.vpn_stopping.clone();
        let last_error = guard.last_error.clone();
        let assigned_ip = guard.assigned_ip.clone();

        guard.vpn_task = Some(tokio::spawn(async move {
            if let Err(e) = vpn_core::run_vpn(
                config,
                flag.clone(),
                connected.clone(),
                last_error.clone(),
                assigned_ip,
            )
            .await
            {
                let msg = e.to_string();
                error!("VPN task failed: {}", msg);
                if flag.load(Ordering::SeqCst) {
                    if let Ok(mut last) = last_error.lock() {
                        *last = Some(msg);
                    }
                } else if let Ok(mut last) = last_error.lock() {
                    *last = None;
                }
            }
            let _ = tokio::task::spawn_blocking(|| {
                run_network_repair_cleanup();
            })
            .await;
            flag.store(false, Ordering::SeqCst);
            connected.store(false, Ordering::SeqCst);
            stopping.store(false, Ordering::SeqCst);
        }));
        ipc::IpcResponse::Ok
    }
}
