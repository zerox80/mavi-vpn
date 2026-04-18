//! # Mavi VPN Daemon
//!
//! IPC server that runs as a background daemon (like the Windows service).
//! Listens on `127.0.0.1:14433` for commands from the CLI or GUI.

use anyhow::Result;
use constant_time_eq::constant_time_eq;
use shared::ipc::{self, Config, IpcRequest, IpcResponse, LOCAL_IPC_ADDR};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use base64::Engine;

/// Hard limit on how long an IPC client may take to send the length prefix and
/// the request body combined. Prevents a local process from holding the daemon
/// state lock indefinitely by opening a connection and stalling mid-read.
const IPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

struct DaemonState {
    vpn_running: Arc<AtomicBool>,
    vpn_task: Option<tokio::task::JoinHandle<()>>,
    active_config: Option<Config>,
}

/// Runs the IPC daemon loop. Accepts commands from CLI/GUI clients.
pub async fn run_daemon(running_flag: Arc<AtomicBool>) -> Result<()> {
    let state = Arc::new(Mutex::new(DaemonState {
        vpn_running: Arc::new(AtomicBool::new(false)),
        vpn_task: None,
        active_config: None,
    }));

    let listener = TcpListener::bind(LOCAL_IPC_ADDR).await?;
    
    let token_bytes: [u8; 32] = rand::random();
    let auth_token = base64::engine::general_purpose::STANDARD.encode(token_bytes);
    
    let token_path = ipc::ipc_token_path();
    if let Some(parent) = token_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Pre-emptively remove any stale file so a previous world-readable token
    // from an unpatched version cannot leak via a race between create+chmod.
    let _ = std::fs::remove_file(&token_path);
    let write_result = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&token_path)
        .and_then(|mut f| f.write_all(auth_token.as_bytes()));

    if let Err(e) = write_result {
        error!("Failed to write IPC token to {:?}: {}", token_path, e);
    } else if let Err(e) =
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))
    {
        error!("Failed to harden IPC token permissions on {:?}: {}", token_path, e);
    }
    info!("Daemon listening on {} (Auth token generated)", LOCAL_IPC_ADDR);

    let auth_token = Arc::new(auth_token);

    loop {
        if !running_flag.load(Ordering::SeqCst) {
            info!("Stop signal received, shutting down daemon...");
            let mut guard = state.lock().await;
            guard.vpn_running.store(false, Ordering::SeqCst);
            if let Some(t) = guard.vpn_task.take() {
                drop(guard);
                let _ = t.await;
            }
            break;
        }

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(500)) => continue,
            conn_res = listener.accept() => {
                let (socket, peer) = match conn_res {
                    Ok(res) => res,
                    Err(e) => {
                        error!("TCP accept error: {}", e);
                        continue;
                    }
                };

                // Hand each client off to its own task so a stalled peer cannot
                // block the accept loop (previously: inline read_exact with no
                // timeout made the daemon trivially DoS-able by any local
                // process that connected and never sent data).
                let state = state.clone();
                let auth_token = auth_token.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_ipc_client(socket, peer, state, auth_token).await {
                        warn!("IPC client {} handler exited: {}", peer, e);
                    }
                });
            }
        }
    }

    Ok(())
}

async fn handle_ipc_client(
    socket: TcpStream,
    peer: std::net::SocketAddr,
    state: Arc<Mutex<DaemonState>>,
    auth_token: Arc<String>,
) -> Result<()> {
    info!("IPC client connected from {}", peer);
    let (mut rx, mut tx) = socket.into_split();

    // Bound the entire header+body read with a single timeout so a client that
    // opens a socket and then goes silent cannot hold resources indefinitely.
    let req_msg = tokio::time::timeout(IPC_REQUEST_TIMEOUT, async {
        let mut len_buf = [0u8; 4];
        rx.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > 65536 {
            anyhow::bail!("IPC request too large: {} bytes", len);
        }
        let mut buf = vec![0u8; len];
        rx.read_exact(&mut buf).await?;
        let (msg, _): (ipc::SecureIpcRequest, _) =
            bincode::serde::decode_from_slice(&buf, bincode::config::standard())
                .map_err(|e| anyhow::anyhow!("IPC decode error: {}", e))?;
        Ok::<_, anyhow::Error>(msg)
    })
    .await
    .map_err(|_| anyhow::anyhow!("IPC request timeout from {}", peer))??;

    let resp = if !constant_time_eq(req_msg.auth_token.as_bytes(), auth_token.as_bytes()) {
        error!("Rejecting IPC request from {} due to invalid auth token", peer);
        IpcResponse::Error("Unauthorized: Invalid IPC Token".to_string())
    } else {
        dispatch_request(req_msg.request, &state).await
    };

    let resp_buf = bincode::serde::encode_to_vec(&resp, bincode::config::standard())
        .map_err(|e| anyhow::anyhow!("Failed to serialize IPC response: {}", e))?;

    tokio::time::timeout(IPC_REQUEST_TIMEOUT, async {
        tx.write_u32_le(resp_buf.len() as u32).await?;
        tx.write_all(&resp_buf).await?;
        Ok::<_, std::io::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("IPC response write timeout to {}", peer))??;

    Ok(())
}

async fn dispatch_request(req: IpcRequest, state: &Arc<Mutex<DaemonState>>) -> IpcResponse {
    let mut guard = state.lock().await;
    match req {
        IpcRequest::Status => IpcResponse::Status {
            running: guard.vpn_running.load(Ordering::SeqCst),
            endpoint: guard.active_config.as_ref().map(|c| c.endpoint.clone()),
        },
        IpcRequest::Stop => {
            info!("Handling Stop request");
            guard.vpn_running.store(false, Ordering::SeqCst);
            guard.active_config = None;
            IpcResponse::Ok
        }
        IpcRequest::Start(config) => {
            info!("Handling Start request for endpoint: {}", config.endpoint);
            let still_running = guard.vpn_running.load(Ordering::SeqCst)
                || guard.vpn_task.as_ref().map_or(false, |t| !t.is_finished());
            if still_running {
                IpcResponse::Error("VPN is already running".to_string())
            } else {
                guard.active_config = Some(config.clone());
                guard.vpn_running.store(true, Ordering::SeqCst);
                let flag = guard.vpn_running.clone();

                guard.vpn_task = Some(tokio::spawn(async move {
                    if let Err(e) = crate::vpn_core::run_vpn(config, flag.clone()).await {
                        error!("VPN task failed: {}", e);
                    }
                    flag.store(false, Ordering::SeqCst);
                }));
                IpcResponse::Ok
            }
        }
    }
}

/// Sends a single IPC request to the running daemon and returns the response.
pub async fn send_request(req: IpcRequest) -> Result<IpcResponse> {
    let token_path = ipc::ipc_token_path();
    let auth_token = std::fs::read_to_string(&token_path)
        .map_err(|e| anyhow::anyhow!("Failed to read IPC token from {:?}: {}", token_path, e))?
        .trim()
        .to_string();

    let req_msg = ipc::SecureIpcRequest {
        auth_token,
        request: req,
    };

    let mut stream = TcpStream::connect(LOCAL_IPC_ADDR).await?;

    let req_buf = bincode::serde::encode_to_vec(&req_msg, bincode::config::standard())?;
    stream.write_u32_le(req_buf.len() as u32).await?;
    stream.write_all(&req_buf).await?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 65536 {
        return Err(anyhow::anyhow!("Response too large"));
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;

    let (resp, _) = bincode::serde::decode_from_slice(&buf, bincode::config::standard())
        .map_err(|e| anyhow::anyhow!("Decode error: {}", e))?;

    Ok(resp)
}
