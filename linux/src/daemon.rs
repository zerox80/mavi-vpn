//! # Mavi VPN Daemon
//!
//! IPC server that runs as a background daemon (like the Windows service).
//! Listens on `127.0.0.1:14433` for commands from the CLI or GUI.

use anyhow::Result;
use shared::ipc::{self, Config, IpcRequest, IpcResponse, LOCAL_IPC_ADDR};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};
use rand::RngCore;
use base64::Engine;

/// Runs the IPC daemon loop. Accepts commands from CLI/GUI clients.
pub async fn run_daemon(running_flag: Arc<AtomicBool>) -> Result<()> {
    let vpn_running = Arc::new(AtomicBool::new(false));
    let mut vpn_task: Option<tokio::task::JoinHandle<()>> = None;
    let mut active_config: Option<Config> = None;

    let listener = TcpListener::bind(LOCAL_IPC_ADDR).await?;
    
    let mut token_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut token_bytes);
    let auth_token = base64::engine::general_purpose::STANDARD.encode(token_bytes);
    
    let token_path = ipc::ipc_token_path();
    if let Some(parent) = token_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&token_path, &auth_token) {
        error!("Failed to write IPC token to {:?}: {}", token_path, e);
    }
    info!("Daemon listening on {} (Auth token generated)", LOCAL_IPC_ADDR);

    loop {
        if !running_flag.load(Ordering::SeqCst) {
            info!("Stop signal received, shutting down daemon...");
            vpn_running.store(false, Ordering::SeqCst);
            if let Some(t) = vpn_task {
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

                info!("IPC client connected from {}", peer);
                let (mut rx, mut tx) = socket.into_split();

                // Read request
                let mut len_buf = [0u8; 4];
                if rx.read_exact(&mut len_buf).await.is_err() { continue; }
                let len = u32::from_le_bytes(len_buf) as usize;
                if len > 65536 { continue; }

                let mut buf = vec![0u8; len];
                if rx.read_exact(&mut buf).await.is_err() { continue; }

                let req_msg: ipc::SecureIpcRequest = match bincode::serde::decode_from_slice(&buf, bincode::config::standard()) {
                    Ok((r, _)) => r,
                    Err(_) => continue,
                };

                // Handle request
                let resp = if req_msg.auth_token != auth_token {
                    error!("Rejecting IPC request due to invalid auth token");
                    IpcResponse::Error("Unauthorized: Invalid IPC Token".to_string())
                } else {
                    match req_msg.request {
                    IpcRequest::Status => {
                        IpcResponse::Status {
                            running: vpn_running.load(Ordering::SeqCst),
                            endpoint: active_config.as_ref().map(|c| c.endpoint.clone()),
                        }
                    }
                    IpcRequest::Stop => {
                        info!("Handling Stop request");
                        vpn_running.store(false, Ordering::SeqCst);
                        active_config = None;
                        IpcResponse::Ok
                    }
                    IpcRequest::Start(config) => {
                        info!("Handling Start request for endpoint: {}", config.endpoint);
                        let still_running = vpn_running.load(Ordering::SeqCst)
                            || vpn_task.as_ref().map_or(false, |t| !t.is_finished());
                        if still_running {
                            IpcResponse::Error("VPN is already running".to_string())
                        } else {
                            active_config = Some(config.clone());
                            vpn_running.store(true, Ordering::SeqCst);
                            let flag = vpn_running.clone();

                            vpn_task = Some(tokio::spawn(async move {
                                if let Err(e) = crate::vpn_core::run_vpn(config, flag.clone()).await {
                                    error!("VPN task failed: {}", e);
                                }
                                flag.store(false, Ordering::SeqCst);
                            }));
                            IpcResponse::Ok
                        }
                    }
                    }
                };

                // Send response
                match bincode::serde::encode_to_vec(&resp, bincode::config::standard()) {
                    Ok(resp_buf) => {
                        let _ = tx.write_u32_le(resp_buf.len() as u32).await;
                        let _ = tx.write_all(&resp_buf).await;
                    }
                    Err(e) => error!("Failed to serialize IPC response: {}", e),
                }
            }
        }
    }

    Ok(())
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
