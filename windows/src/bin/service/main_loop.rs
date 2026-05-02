use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use base64::Engine;

use crate::ipc;
use super::state::VpnServiceState;
use super::utils::{harden_ipc_token_permissions, run_network_repair_cleanup};
use super::handlers::handle_ipc_client;

pub async fn run_service_loop(
    stop_signal: Arc<AtomicBool>,
    reharden_signal: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let state = Arc::new(Mutex::new(VpnServiceState::new()));

    run_network_repair_cleanup();

    // Generate secure token for IPC and save to file BEFORE binding listener
    let token_bytes: [u8; 32] = rand::random();
    let auth_token = base64::engine::general_purpose::STANDARD.encode(token_bytes);

    let token_path = ipc::ipc_token_path();
    if let Some(parent) = token_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&token_path, &auth_token) {
        error!("Failed to write IPC token to {:?}: {}", token_path, e);
    } else {
        harden_ipc_token_permissions(&token_path);
    }
    info!("Auth token generated and saved");

    let listener = match TcpListener::bind(ipc::LOCAL_IPC_ADDR).await {
        Ok(l) => l,
        Err(e) => {
            error!(
                "Failed to bind TCP IPC listener on {}: {}",
                ipc::LOCAL_IPC_ADDR,
                e
            );
            return Err(e.into());
        }
    };
    info!("Service listening for IPC on {}", ipc::LOCAL_IPC_ADDR);

    let auth_token = Arc::new(auth_token);

    loop {
        if stop_signal.load(Ordering::SeqCst) {
            info!("Stop signal flag is true, terminating service loop.");
            let mut guard = state.lock().await;
            guard.vpn_running.store(false, Ordering::SeqCst);
            guard.vpn_connected.store(false, Ordering::SeqCst);
            if let Some(t) = guard.vpn_task.take() {
                guard.vpn_stopping.store(true, Ordering::SeqCst);
                drop(guard);
                let _ = t.await;
            } else {
                guard.vpn_stopping.store(false, Ordering::SeqCst);
                drop(guard);
            }
            break;
        }

        if reharden_signal.swap(false, Ordering::SeqCst) {
            info!("Re-hardening IPC token ACL after session change");
            harden_ipc_token_permissions(&token_path);
        }

        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(500)) => {
                // Periodically wake up to check stop_signal
            }
            conn_res = listener.accept() => {
                let (socket, peer) = match conn_res {
                    Ok(res) => res,
                    Err(e) => {
                        error!("TCP accept error: {}", e);
                        continue;
                    }
                };

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
