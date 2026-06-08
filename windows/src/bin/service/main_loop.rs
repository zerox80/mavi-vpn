use base64::Engine;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore};
use tracing::{error, info, warn};

use super::handlers::handle_ipc_client;
use super::state::VpnServiceState;
use super::utils::{
    prepare_ipc_auth_token, reharden_ipc_token_permissions, run_network_repair_cleanup,
};
use crate::ipc;

pub const MAX_CONCURRENT_IPC_CLIENTS: usize = 32;

pub fn build_auth_token() -> (String, [u8; 32]) {
    let token_bytes: [u8; 32] = rand::random();
    let auth_token = base64::engine::general_purpose::STANDARD.encode(token_bytes);
    (auth_token, token_bytes)
}

pub async fn run_service_loop(
    stop_signal: Arc<AtomicBool>,
    reharden_signal: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let state = Arc::new(Mutex::new(VpnServiceState::new()));

    run_network_repair_cleanup();

    // Generate secure token for IPC and save it securely BEFORE binding listener.
    let (auth_token, _token_bytes) = build_auth_token();

    let token_path = ipc::ipc_token_path();
    prepare_ipc_auth_token(&token_path, &auth_token)?;
    info!("Auth token generated, saved, and hardened");

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
    let ipc_slots = Arc::new(Semaphore::new(MAX_CONCURRENT_IPC_CLIENTS));

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
            if let Err(e) = reharden_ipc_token_permissions(&token_path) {
                warn!("Failed to re-harden IPC token ACL after session change: {e:#}");
            }
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
                let permit = match ipc_slots.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!(
                            "Rejecting IPC client {} because the connection limit ({}) is reached",
                            peer, MAX_CONCURRENT_IPC_CLIENTS
                        );
                        continue;
                    }
                };
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_ipc_client(socket, peer, state, auth_token).await {
                        warn!("IPC client {} handler exited: {}", peer, e);
                    }
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_concurrent_ipc_clients_is_reasonable() {
        assert!(MAX_CONCURRENT_IPC_CLIENTS > 0);
        assert!(MAX_CONCURRENT_IPC_CLIENTS <= 1000);
    }

    #[test]
    fn max_concurrent_ipc_clients_is_at_least_10() {
        assert!(MAX_CONCURRENT_IPC_CLIENTS >= 10);
    }

    #[test]
    fn max_concurrent_ipc_clients_is_power_of_two() {
        assert!(MAX_CONCURRENT_IPC_CLIENTS.is_power_of_two());
    }

    #[test]
    fn build_auth_token_returns_non_empty_base64() {
        let (token, raw_bytes) = build_auth_token();
        assert!(!token.is_empty());
        assert_eq!(raw_bytes.len(), 32);
    }

    #[test]
    fn build_auth_token_is_valid_base64() {
        let (token, _) = build_auth_token();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&token)
            .expect("token should be valid base64");
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn build_auth_token_produces_unique_tokens() {
        let (token1, _) = build_auth_token();
        let (token2, _) = build_auth_token();
        assert_ne!(token1, token2);
    }

    #[test]
    fn build_auth_token_raw_bytes_differ_across_calls() {
        let (_, bytes1) = build_auth_token();
        let (_, bytes2) = build_auth_token();
        assert_ne!(bytes1, bytes2);
    }
}
