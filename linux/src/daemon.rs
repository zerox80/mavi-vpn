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

/// Runs the IPC daemon loop. Accepts commands from CLI/GUI clients.
pub async fn run_daemon(stop_signal: Arc<AtomicBool>) -> Result<()> {
    let vpn_running = Arc::new(AtomicBool::new(false));
    let mut vpn_task: Option<tokio::task::JoinHandle<()>> = None;
    let mut active_config: Option<Config> = None;

    let listener = TcpListener::bind(LOCAL_IPC_ADDR).await?;
    info!("Daemon listening on {}", LOCAL_IPC_ADDR);

    loop {
        if !stop_signal.load(Ordering::SeqCst) {
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

                let req: IpcRequest = match bincode::serde::decode_from_slice(&buf, bincode::config::standard()) {
                    Ok((r, _)) => r,
                    Err(_) => continue,
                };

                // Handle request
                let resp = match req {
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
                        if vpn_running.load(Ordering::SeqCst) {
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
                };

                // Send response
                let resp_buf = bincode::serde::encode_to_vec(&resp, bincode::config::standard()).unwrap();
                let _ = tx.write_u32_le(resp_buf.len() as u32).await;
                let _ = tx.write_all(&resp_buf).await;
            }
        }
    }

    Ok(())
}

/// Sends a single IPC request to the running daemon and returns the response.
pub async fn send_request(req: IpcRequest) -> Result<IpcResponse> {
    let mut stream = TcpStream::connect(LOCAL_IPC_ADDR).await?;

    let req_buf = bincode::serde::encode_to_vec(&req, bincode::config::standard())?;
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
