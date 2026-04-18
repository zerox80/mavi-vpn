use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, SessionChangeReason, ServiceState,
        ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

use std::{ffi::OsString, path::Path, sync::Arc, sync::atomic::{AtomicBool, Ordering}, time::Duration};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, sync::Mutex};
use tracing::{error, info, warn};
use tracing_subscriber;
use base64::Engine;
use constant_time_eq::constant_time_eq;

#[path = "../ipc.rs"]
mod ipc;
#[path = "../ech_client.rs"]
mod ech_client;
#[path = "../vpn_core.rs"]
mod vpn_core;

const SERVICE_NAME: &str = "MaviVPNService";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// Hard limit on how long an IPC client may take to send the length prefix and
/// the request body combined. Prevents a local process from holding the service
/// state lock indefinitely by opening a connection and stalling mid-read.
const IPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

struct VpnServiceState {
    vpn_running: Arc<AtomicBool>,
    vpn_task: Option<tokio::task::JoinHandle<()>>,
    active_config: Option<ipc::Config>,
}

define_windows_service!(ffi_service_main, my_service_main);

pub fn main() -> Result<(), windows_service::Error> {
    let env_filter = tracing_subscriber::EnvFilter::from_default_env()
        .add_directive("mavi_vpn=info".parse().unwrap());
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .init();

    info!("Starting service dispatcher for {}", SERVICE_NAME);
    let args: Vec<OsString> = std::env::args_os().collect();
    
    // Support non-service local running for debugging
    if args.iter().any(|arg| arg == "--console") {
        info!("Running in console mode");
        run_standalone();
        return Ok(());
    }
    
    // Support installation via CLI
    if args.iter().any(|arg| arg == "install") {
        let exe_path = std::env::current_exe().unwrap();
        let quoted_exe_path = format!("\"{}\"", exe_path.display());
        info!("Installing MaviVPNService...");
        let status = std::process::Command::new("sc")
            .args([
                "create",
                SERVICE_NAME,
                "binPath=",
                &quoted_exe_path,
                "start=",
                "auto",
            ])
            .status();
        
        match status {
            Ok(s) if s.success() => {
                info!("Service installed successfully.");
                info!("You can now start it with: net start MaviVPNService");
            }
            Ok(s) => error!("Failed to install service. Did you run as Administrator? (Exit code: {:?})", s.code()),
            Err(e) => error!("Failed to execute sc command: {}", e),
        }
        return Ok(());
    }

    // Support uninstallation via CLI
    if args.iter().any(|arg| arg == "uninstall") {
        info!("Uninstalling MaviVPNService...");

        // 1. Stop the service first (ignore errors if already stopped)
        let _ = std::process::Command::new("sc")
            .args(["stop", SERVICE_NAME])
            .status();
        
        // Brief wait for the service to stop
        std::thread::sleep(Duration::from_secs(2));

        // 2. Delete the service
        let status = std::process::Command::new("sc")
            .args(["delete", SERVICE_NAME])
            .status();
        
        match status {
            Ok(s) if s.success() => {
                info!("Service uninstalled successfully.");
            }
            Ok(s) => error!("Failed to uninstall service. Did you run as Administrator? (Exit code: {:?})", s.code()),
            Err(e) => error!("Failed to execute sc command: {}", e),
        }
        return Ok(());
    }

    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn run_standalone() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let stop_signal = Arc::new(AtomicBool::new(false));
    let reharden_signal = Arc::new(AtomicBool::new(false));

    rt.block_on(async {
        match run_service_loop(stop_signal.clone(), reharden_signal.clone()).await {
            Ok(_) => info!("Service loop exited gracefully"),
            Err(e) => error!("Service loop error: {:?}", e),
        }
    });
}

fn my_service_main(arguments: Vec<OsString>) {
    if let Err(e) = run_service(arguments) {
        error!("Service run failed: {:?}", e);
    }
}

fn run_service(_arguments: Vec<OsString>) -> anyhow::Result<()> {
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stop_signal_handler = stop_signal.clone();
    let reharden_signal = Arc::new(AtomicBool::new(false));
    let reharden_signal_handler = reharden_signal.clone();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                info!("Received Stop signal from Service Control Manager");
                stop_signal_handler.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::SessionChange(param) => {
                // When a user logs on (console or RDP) or unlocks, re-apply the
                // IPC token ACL so the now-active interactive user can read it.
                // Without this, a service that started at boot locks the token
                // to SYSTEM+Admins only and GUI clients in the user session fail
                // with "Failed to read IPC token".
                if matches!(
                    param.reason,
                    SessionChangeReason::SessionLogon
                        | SessionChangeReason::ConsoleConnect
                        | SessionChangeReason::RemoteConnect
                        | SessionChangeReason::SessionUnlock
                ) {
                    info!(
                        "Session change ({:?}) for session {} — queuing IPC token ACL re-harden",
                        param.reason, param.notification.session_id
                    );
                    reharden_signal_handler.store(true, Ordering::SeqCst);
                }
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SESSION_CHANGE,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime");

    info!("Service is now running");

    let res = rt.block_on(run_service_loop(stop_signal.clone(), reharden_signal.clone()));
    if let Err(e) = res {
        error!("Service loop failed: {}", e);
    }

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

async fn run_service_loop(
    stop_signal: Arc<AtomicBool>,
    reharden_signal: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let state = Arc::new(Mutex::new(VpnServiceState {
        vpn_running: Arc::new(AtomicBool::new(false)),
        vpn_task: None,
        active_config: None,
    }));

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
            error!("Failed to bind TCP IPC listener on {}: {}", ipc::LOCAL_IPC_ADDR, e);
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
            if let Some(t) = guard.vpn_task.take() {
                drop(guard);
                let _ = t.await;
            }
            break;
        }

        if reharden_signal.swap(false, Ordering::SeqCst) {
            info!("Re-hardening IPC token ACL after session change");
            harden_ipc_token_permissions(&token_path);
        }

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                // Periodically wake up to check stop_signal
                continue;
            }
            conn_res = listener.accept() => {
                let (socket, peer) = match conn_res {
                    Ok(res) => res,
                    Err(e) => {
                        error!("TCP accept error: {}", e);
                        continue;
                    }
                };

                // Hand each client off to its own task so a stalled peer cannot
                // block the accept loop or the service control handler.
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
    state: Arc<Mutex<VpnServiceState>>,
    auth_token: Arc<String>,
) -> anyhow::Result<()> {
    info!("Client connected to Local IPC from {}", peer);
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
        ipc::IpcResponse::Error("Unauthorized: Invalid IPC Token".to_string())
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

async fn dispatch_request(
    req: ipc::IpcRequest,
    state: &Arc<Mutex<VpnServiceState>>,
) -> ipc::IpcResponse {
    let mut guard = state.lock().await;
    match req {
        ipc::IpcRequest::Status => ipc::IpcResponse::Status {
            running: guard.vpn_running.load(Ordering::SeqCst),
            endpoint: guard.active_config.as_ref().map(|c| c.endpoint.clone()),
        },
        ipc::IpcRequest::Stop => {
            info!("Handling Stop request from client");
            guard.vpn_running.store(false, Ordering::SeqCst);
            guard.active_config = None;
            ipc::IpcResponse::Ok
        }
        ipc::IpcRequest::Start(config) => {
            info!("Handling Start request for endpoint: {}", config.endpoint);
            let still_running = guard.vpn_running.load(Ordering::SeqCst)
                || guard.vpn_task.as_ref().map_or(false, |t| !t.is_finished());
            if still_running {
                ipc::IpcResponse::Error("VPN is already running".to_string())
            } else {
                guard.active_config = Some(config.clone());
                guard.vpn_running.store(true, Ordering::SeqCst);
                let flag = guard.vpn_running.clone();

                guard.vpn_task = Some(tokio::spawn(async move {
                    if let Err(e) = vpn_core::run_vpn(config, flag.clone()).await {
                        error!("VPN task failed: {}", e);
                    }
                    flag.store(false, Ordering::SeqCst);
                }));
                ipc::IpcResponse::Ok
            }
        }
    }
}

fn harden_ipc_token_permissions(token_path: &Path) {
    let mut args = vec![
        token_path.to_string_lossy().to_string(),
        "/inheritance:r".to_string(),
        "/grant:r".to_string(),
        "*S-1-5-18:(F)".to_string(),
        "*S-1-5-32-544:(F)".to_string(),
    ];

    if let Some(user_sid) = active_console_user_sid() {
        args.push(format!("*{}:(R)", user_sid));
    } else {
        warn!("No interactive user detected while hardening the IPC token ACL; local clients may need to run elevated until the service is restarted after login");
    }

    match std::process::Command::new("icacls").args(&args).output() {
        Ok(out) if out.status.success() => {
            info!("Locked down IPC token permissions at {:?}", token_path);
        }
        Ok(out) => {
            warn!(
                "Failed to harden IPC token permissions: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Err(e) => {
            warn!("Failed to execute icacls for IPC token hardening: {}", e);
        }
    }
}

fn active_console_user_sid() -> Option<String> {
    let ps = "$user = (Get-CimInstance Win32_ComputerSystem).UserName; if ($user) { try { (New-Object System.Security.Principal.NTAccount($user)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { '' } }";
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", ps])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let sid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if sid.is_empty() { None } else { Some(sid) }
}
