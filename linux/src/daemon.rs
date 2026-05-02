//! # Mavi VPN Daemon
//!
//! IPC server that runs as a background daemon (like the Windows service).
//! Listens on `127.0.0.1:14433` for commands from the CLI or GUI.

use anyhow::Result;
use base64::Engine;
use constant_time_eq::constant_time_eq;
use nix::unistd::{chown, Gid, Group};
use shared::ipc::{self, Config, IpcRequest, IpcResponse, LOCAL_IPC_ADDR};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use tracing::{error, info, warn};

/// Hard limit on how long an IPC client may take to send the length prefix and
/// the request body combined. Prevents a local process from holding the daemon
/// state lock indefinitely by opening a connection and stalling mid-read.
const IPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const IPC_CONTROL_GROUP: &str = "mavivpn";
const IPC_TOKEN_ROOT_ONLY_MODE: u32 = 0o600;
const IPC_TOKEN_GROUP_MODE: u32 = 0o640;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IpcTokenAccess {
    RootOnly,
    Group(Gid),
}

impl IpcTokenAccess {
    const fn mode(self) -> u32 {
        match self {
            Self::RootOnly => IPC_TOKEN_ROOT_ONLY_MODE,
            Self::Group(_) => IPC_TOKEN_GROUP_MODE,
        }
    }
}

struct DaemonState {
    vpn_running: Arc<AtomicBool>,
    vpn_connected: Arc<AtomicBool>,
    vpn_stopping: Arc<AtomicBool>,
    last_error: Arc<StdMutex<Option<String>>>,
    assigned_ip: Arc<StdMutex<Option<String>>>,
    vpn_task: Option<tokio::task::JoinHandle<()>>,
    active_config: Option<Config>,
}

/// Runs the IPC daemon loop. Accepts commands from CLI/GUI clients.
pub async fn run_daemon(running_flag: Arc<AtomicBool>) -> Result<()> {
    let state = Arc::new(Mutex::new(DaemonState {
        vpn_running: Arc::new(AtomicBool::new(false)),
        vpn_connected: Arc::new(AtomicBool::new(false)),
        vpn_stopping: Arc::new(AtomicBool::new(false)),
        last_error: Arc::new(StdMutex::new(None)),
        assigned_ip: Arc::new(StdMutex::new(None)),
        vpn_task: None,
        active_config: None,
    }));

    let token_bytes: [u8; 32] = rand::random();
    let auth_token = base64::engine::general_purpose::STANDARD.encode(token_bytes);
    write_ipc_token(&ipc::ipc_token_path(), &auth_token)?;

    let listener = TcpListener::bind(LOCAL_IPC_ADDR).await?;
    info!(
        "Daemon listening on {} (Auth token generated)",
        LOCAL_IPC_ADDR
    );

    let auth_token = Arc::new(auth_token);

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

fn resolve_ipc_token_access() -> Result<IpcTokenAccess> {
    match Group::from_name(IPC_CONTROL_GROUP)? {
        Some(group) => Ok(IpcTokenAccess::Group(group.gid)),
        None => {
            warn!(
                "Unix group '{}' does not exist; IPC token will be root-only. \
                 Run the Linux installer or create the group and add trusted users.",
                IPC_CONTROL_GROUP
            );
            Ok(IpcTokenAccess::RootOnly)
        }
    }
}

fn write_ipc_token(token_path: &Path, auth_token: &str) -> Result<()> {
    let access = resolve_ipc_token_access()?;
    write_ipc_token_with_access(token_path, auth_token, access)
}

fn write_ipc_token_with_access(
    token_path: &Path,
    auth_token: &str,
    access: IpcTokenAccess,
) -> Result<()> {
    if let Some(parent) = token_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Remove stale world-readable files left by older versions, then create the
    // new token as root-only. Permissions are widened only after chown succeeds.
    match std::fs::remove_file(token_path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }

    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(IPC_TOKEN_ROOT_ONLY_MODE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(token_path)
        .and_then(|mut f| f.write_all(auth_token.as_bytes()))?;

    if let IpcTokenAccess::Group(gid) = access {
        chown(token_path, None, Some(gid))?;
    }

    std::fs::set_permissions(token_path, std::fs::Permissions::from_mode(access.mode()))?;

    match access {
        IpcTokenAccess::RootOnly => warn!(
            "IPC token at {:?} is root-only. Non-root CLI/GUI users must be added to '{}' \
             after running the installer, then log out and back in.",
            token_path, IPC_CONTROL_GROUP
        ),
        IpcTokenAccess::Group(gid) => info!(
            "IPC token permissions hardened at {:?}: mode {:o}, group {}",
            token_path,
            access.mode(),
            gid.as_raw()
        ),
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
        error!(
            "Rejecting IPC request from {} due to invalid auth token",
            peer
        );
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
        IpcRequest::Status => {
            let running = guard.vpn_running.load(Ordering::SeqCst);
            let connected = guard.vpn_connected.load(Ordering::SeqCst);
            let stopping = guard.vpn_stopping.load(Ordering::SeqCst);
            let starting = running && !connected;

            let last_error = guard.last_error.lock().ok().and_then(|e| e.clone());
            let assigned_ip = guard.assigned_ip.lock().ok().and_then(|e| e.clone());

            let vpn_state = if connected {
                ipc::VpnState::Connected
            } else if last_error.is_some() {
                ipc::VpnState::Failed
            } else if stopping {
                ipc::VpnState::Stopping
            } else if starting {
                ipc::VpnState::Starting
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
            guard.active_config = None;
            drop(guard);
            crate::network::cleanup_stale_network_state();
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
                let flag = guard.vpn_running.clone();
                let connected = guard.vpn_connected.clone();
                let stopping = guard.vpn_stopping.clone();
                let last_error = guard.last_error.clone();
                let assigned_ip = guard.assigned_ip.clone();

                guard.vpn_task = Some(tokio::spawn(async move {
                    if let Err(e) = crate::vpn_core::run_vpn(
                        config,
                        flag.clone(),
                        connected.clone(),
                        last_error.clone(),
                        assigned_ip.clone(),
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
                    crate::network::cleanup_stale_network_state();
                    flag.store(false, Ordering::SeqCst);
                    connected.store(false, Ordering::SeqCst);
                    stopping.store(false, Ordering::SeqCst);
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
        .map_err(|e| ipc_token_read_error(&token_path, e))?
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

fn ipc_token_read_error(token_path: &Path, error: io::Error) -> anyhow::Error {
    if error.kind() == io::ErrorKind::PermissionDenied {
        anyhow::anyhow!(
            "Failed to read IPC token from {:?}: permission denied. \
             Your user must be in the '{}' group to control the daemon. \
             Run `sudo usermod -aG {} $USER`, log out and back in, then retry.",
            token_path,
            IPC_CONTROL_GROUP,
            IPC_CONTROL_GROUP
        )
    } else {
        anyhow::anyhow!("Failed to read IPC token from {:?}: {}", token_path, error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn ipc_token_modes_are_not_world_readable() {
        assert_eq!(IpcTokenAccess::RootOnly.mode(), 0o600);
        assert_eq!(IpcTokenAccess::Group(Gid::from_raw(123)).mode(), 0o640);
        assert_eq!(IpcTokenAccess::RootOnly.mode() & 0o007, 0);
        assert_eq!(IpcTokenAccess::Group(Gid::from_raw(123)).mode() & 0o007, 0);
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
}
