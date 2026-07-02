//! # Mavi VPN Daemon
//!
//! IPC server that runs as a background daemon (like the Windows service).
//! Listens on a Unix domain socket (see `shared::ipc::ipc_socket_path`) for
//! commands from the CLI or GUI.

use anyhow::Result;
use base64::Engine;
use shared::ipc::{self, Config, IpcRequest, IpcResponse};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use tracing::{error, info, warn};

mod transport;
pub use transport::send_request;
use transport::{bind_ipc_socket, handle_ipc_client, resolve_ipc_token_access};

pub(super) const MAX_CONCURRENT_IPC_CLIENTS: usize = 32;

fn try_acquire_ipc_slot(ipc_slots: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    ipc_slots.clone().try_acquire_owned().ok()
}

struct DaemonState {
    vpn_running: Arc<AtomicBool>,
    vpn_connected: Arc<AtomicBool>,
    vpn_stopping: Arc<AtomicBool>,
    last_error: Arc<StdMutex<Option<String>>>,
    assigned_ip: Arc<StdMutex<Option<String>>>,
    /// Access token for the next (re)handshake. Seeded from `Start` and
    /// overwritten by `UpdateToken` so the reconnect loop uses the freshest
    /// GUI-refreshed token instead of the one captured at session start.
    current_token: Arc<StdMutex<String>>,
    vpn_task: Option<tokio::task::JoinHandle<()>>,
    active_config: Option<Config>,
}

impl DaemonState {
    fn new() -> Self {
        Self {
            vpn_running: Arc::new(AtomicBool::new(false)),
            vpn_connected: Arc::new(AtomicBool::new(false)),
            vpn_stopping: Arc::new(AtomicBool::new(false)),
            last_error: Arc::new(StdMutex::new(None)),
            assigned_ip: Arc::new(StdMutex::new(None)),
            current_token: Arc::new(StdMutex::new(String::new())),
            vpn_task: None,
            active_config: None,
        }
    }
}

/// Runs the IPC daemon loop. Accepts commands from CLI/GUI clients.
pub async fn run_daemon(running_flag: Arc<AtomicBool>) -> Result<()> {
    let state = Arc::new(Mutex::new(DaemonState::new()));

    let token_bytes: [u8; 32] = rand::random();
    let auth_token = base64::engine::general_purpose::STANDARD.encode(token_bytes);
    // Resolved once and shared by the token file and the socket so both land
    // on the same root-only-vs-group access model.
    let access = resolve_ipc_token_access()?;
    transport::write_ipc_token_with_access(&ipc::ipc_token_path(), &auth_token, access)?;

    let listener = bind_ipc_socket(access)?;
    info!(
        "Daemon listening on {:?} (Auth token generated)",
        ipc::ipc_socket_path()
    );

    let auth_token = Arc::new(auth_token);
    let ipc_slots = Arc::new(Semaphore::new(MAX_CONCURRENT_IPC_CLIENTS));

    loop {
        if !running_flag.load(Ordering::SeqCst) {
            info!("Stop signal received, shutting down daemon...");
            let mut guard = state.lock().await;
            guard.vpn_running.store(false, Ordering::SeqCst);
            guard.vpn_connected.store(false, Ordering::SeqCst);
            if let Some(t) = guard.vpn_task.take() {
                guard.vpn_stopping.store(true, Ordering::SeqCst);
                drop(guard);
                let _ = t.await;
            } else {
                guard.vpn_stopping.store(false, Ordering::SeqCst);
            }
            break;
        }

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(500)) => continue,
            conn_res = listener.accept() => {
                let (socket, _peer_addr) = match conn_res {
                    Ok(res) => res,
                    Err(e) => {
                        error!("IPC accept error: {}", e);
                        continue;
                    }
                };

                let permit = match try_acquire_ipc_slot(&ipc_slots) {
                    Some(permit) => permit,
                    None => {
                        warn!(
                            "Rejecting IPC client because the connection limit ({}) is reached",
                            MAX_CONCURRENT_IPC_CLIENTS
                        );
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
                    let _permit = permit;
                    if let Err(e) = handle_ipc_client(socket, state, auth_token).await {
                        warn!("IPC client handler exited: {}", e);
                    }
                });
            }
        }
    }

    // Clean up the IPC auth token and socket files on shutdown.
    let _ = std::fs::remove_file(ipc::ipc_token_path());
    let _ = std::fs::remove_file(ipc::ipc_socket_path());

    Ok(())
}

async fn dispatch_request(req: IpcRequest, state: &Arc<Mutex<DaemonState>>) -> IpcResponse {
    dispatch_request_with_hooks(
        req,
        state,
        true,
        crate::network::cleanup_stale_network_state,
    )
    .await
}

async fn dispatch_request_with_hooks(
    req: IpcRequest,
    state: &Arc<Mutex<DaemonState>>,
    spawn_vpn_session: bool,
    cleanup_stale_network_state: fn(),
) -> IpcResponse {
    let mut guard = state.lock().await;
    match req {
        IpcRequest::Status => {
            let running = guard.vpn_running.load(Ordering::SeqCst);
            let connected = guard.vpn_connected.load(Ordering::SeqCst);
            let stopping = guard.vpn_stopping.load(Ordering::SeqCst);
            let starting = running && !connected;

            let last_error = guard.last_error.lock().ok().and_then(|e| e.clone());
            let assigned_ip = guard.assigned_ip.lock().ok().and_then(|e| e.clone());

            // A recorded error while the loop is still running (`starting`) means
            // a transient failure is being retried → Reconnecting, not Failed.
            // Failed is reserved for the terminal case (loop gave up). Otherwise
            // the UI flips to "NOT CONNECTED" mid auto-reconnect.
            let vpn_state = if connected {
                ipc::VpnState::Connected
            } else if stopping {
                ipc::VpnState::Stopping
            } else if starting {
                if last_error.is_some() {
                    ipc::VpnState::Reconnecting
                } else {
                    ipc::VpnState::Starting
                }
            } else if last_error.is_some() {
                ipc::VpnState::Failed
            } else {
                ipc::VpnState::Stopped
            };

            IpcResponse::Status {
                running: connected,
                endpoint: guard.active_config.as_ref().map(|c| c.endpoint.clone()),
                state: vpn_state,
                last_error,
                assigned_ip,
            }
        }
        IpcRequest::Stop => {
            info!("Handling Stop request");
            let task_running = guard.vpn_task.as_ref().is_some_and(|t| !t.is_finished());
            guard.vpn_running.store(false, Ordering::SeqCst);
            guard.vpn_connected.store(false, Ordering::SeqCst);
            guard.vpn_stopping.store(task_running, Ordering::SeqCst);
            if let Ok(mut last) = guard.last_error.lock() {
                *last = None;
            }
            if let Ok(mut ip) = guard.assigned_ip.lock() {
                *ip = None;
            }
            guard.active_config = None;
            IpcResponse::Ok
        }
        IpcRequest::RepairNetwork => {
            info!("Handling RepairNetwork request");
            let task_running = guard.vpn_task.as_ref().is_some_and(|t| !t.is_finished());
            guard.vpn_running.store(false, Ordering::SeqCst);
            guard.vpn_connected.store(false, Ordering::SeqCst);
            guard.vpn_stopping.store(task_running, Ordering::SeqCst);
            if let Ok(mut last) = guard.last_error.lock() {
                *last = None;
            }
            if let Ok(mut ip) = guard.assigned_ip.lock() {
                *ip = None;
            }
            guard.active_config = None;
            drop(guard);
            cleanup_stale_network_state();
            IpcResponse::Ok
        }
        IpcRequest::Start(config) => {
            info!("Handling Start request for endpoint: {}", config.endpoint);
            if guard.vpn_stopping.load(Ordering::SeqCst) {
                IpcResponse::Error("VPN is stopping; retry shortly".to_string())
            } else if guard.vpn_running.load(Ordering::SeqCst)
                || guard.vpn_task.as_ref().is_some_and(|t| !t.is_finished())
            {
                IpcResponse::Error("VPN is already running".to_string())
            } else {
                guard.active_config = Some(config.clone());
                guard.vpn_running.store(true, Ordering::SeqCst);
                guard.vpn_connected.store(false, Ordering::SeqCst);
                guard.vpn_stopping.store(false, Ordering::SeqCst);
                if let Ok(mut last) = guard.last_error.lock() {
                    *last = None;
                }
                // Seed the live token cell; the reconnect loop reads it (not
                // config.token) so GUI-pushed UpdateToken refreshes apply.
                if let Ok(mut token) = guard.current_token.lock() {
                    *token = config.token.clone();
                }
                if spawn_vpn_session {
                    let flag = guard.vpn_running.clone();
                    let connected = guard.vpn_connected.clone();
                    let stopping = guard.vpn_stopping.clone();
                    let last_error = guard.last_error.clone();
                    let assigned_ip = guard.assigned_ip.clone();
                    let current_token = guard.current_token.clone();
                    let refresh_token = Arc::new(StdMutex::new(config.refresh_token.clone()));

                    guard.vpn_task = Some(tokio::spawn(async move {
                        if let Err(e) = crate::vpn_core::run_vpn(
                            config,
                            flag.clone(),
                            connected.clone(),
                            last_error.clone(),
                            assigned_ip.clone(),
                            current_token,
                            refresh_token,
                        )
                        .await
                        {
                            let msg = e.to_string();
                            error!("VPN task failed: {}", msg);
                            if flag.load(Ordering::SeqCst) {
                                if let Ok(mut last) = last_error.lock() {
                                    *last = Some(msg);
                                }
                            }
                        }
                        cleanup_stale_network_state();
                        flag.store(false, Ordering::SeqCst);
                        connected.store(false, Ordering::SeqCst);
                        stopping.store(false, Ordering::SeqCst);
                    }));
                }
                IpcResponse::Ok
            }
        }
        IpcRequest::UpdateToken { token } => {
            // The GUI silently refreshed the Keycloak access token; store it so
            // the next (re)handshake authenticates with a valid token. Harmless
            // when no session is active — the next Start overwrites it anyway.
            if let Ok(mut current) = guard.current_token.lock() {
                *current = token;
            }
            IpcResponse::Ok
        }
        IpcRequest::StartWithKeycloak { .. } => IpcResponse::Error(
            "Service-side Keycloak refresh is only supported on Windows".to_string(),
        ),
        IpcRequest::TakeRefreshTokenUpdate => IpcResponse::RefreshTokenUpdate {
            connection_id: None,
            refresh_token: None,
        },
    }
}

#[cfg(test)]
mod ipc_limit_tests;
#[cfg(test)]
mod tests;
