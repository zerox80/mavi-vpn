use base64::Engine;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use tracing::{info, warn};

use super::named_pipe;
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

    // Generate secure token for IPC and save it securely BEFORE serving the
    // named pipe.
    let (auth_token, _token_bytes) = build_auth_token();

    let token_path = ipc::ipc_token_path();
    prepare_ipc_auth_token(&token_path, &auth_token)?;
    info!("Auth token generated, saved, and hardened");

    info!("Service listening for IPC on {}", ipc::ipc_pipe_name());

    let auth_token = Arc::new(auth_token);
    let ipc_slots = Arc::new(Semaphore::new(MAX_CONCURRENT_IPC_CLIENTS));

    // The named-pipe re-harden signal (fast-user-switching) is a no-op for
    // the pipe itself: each recycled instance computes its ACL fresh from
    // the current console user (see `named_pipe::create_pipe_instance`). The
    // token file's ACL still needs the explicit re-harden below.
    let reharden_task = {
        let stop_signal = stop_signal.clone();
        let reharden_signal = reharden_signal.clone();
        let token_path = token_path.clone();
        tokio::spawn(async move {
            loop {
                if stop_signal.load(Ordering::SeqCst) {
                    break;
                }
                if reharden_signal.swap(false, Ordering::SeqCst) {
                    info!("Re-hardening IPC token ACL after session change");
                    if let Err(e) = reharden_ipc_token_permissions(&token_path) {
                        warn!("Failed to re-harden IPC token ACL after session change: {e:#}");
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        })
    };

    let result =
        named_pipe::accept_loop(state.clone(), auth_token, ipc_slots, stop_signal.clone()).await;

    reharden_task.abort();

    info!("Stop signal flag is true, terminating service loop.");
    let task = {
        let mut guard = state.lock().await;
        guard.stop_session();
        guard.take_task()
    };
    if let Some(task) = task {
        let _ = task.await;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn max_concurrent_ipc_clients_is_reasonable() {
        assert!(MAX_CONCURRENT_IPC_CLIENTS > 0);
        assert!(MAX_CONCURRENT_IPC_CLIENTS <= 1000);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
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
