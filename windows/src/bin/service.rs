use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType, SessionChangeReason,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

use base64::Engine;
use constant_time_eq::constant_time_eq;
use std::{
    ffi::OsString,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tracing::{error, info, warn};

#[path = "../ech_client.rs"]
mod ech_client;
#[path = "../ipc.rs"]
mod ipc;
#[path = "../vpn_core/mod.rs"]
mod vpn_core;

const SERVICE_NAME: &str = "MaviVPNService";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// Hard limit on how long an IPC client may take to send the length prefix and
/// the request body combined. Prevents a local process from holding the service
/// state lock indefinitely by opening a connection and stalling mid-read.
const IPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(test)]
static REPAIR_CLEANUP_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

struct VpnServiceState {
    vpn_running: Arc<AtomicBool>,
    vpn_connected: Arc<AtomicBool>,
    vpn_stopping: Arc<AtomicBool>,
    last_error: Arc<StdMutex<Option<String>>>,
    assigned_ip: Arc<StdMutex<Option<String>>>,
    vpn_task: Option<tokio::task::JoinHandle<()>>,
    active_config: Option<ipc::Config>,
}

define_windows_service!(ffi_service_main, my_service_main);

pub fn main() -> Result<(), windows_service::Error> {
    let env_filter = tracing_subscriber::EnvFilter::from_default_env()
        .add_directive("mavi_vpn=info".parse().unwrap())
        .add_directive("wintun=off".parse().unwrap());
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

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
            Ok(s) => error!(
                "Failed to install service. Did you run as Administrator? (Exit code: {:?})",
                s.code()
            ),
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

        run_network_repair_cleanup();

        // 2. Delete the service
        let status = std::process::Command::new("sc")
            .args(["delete", SERVICE_NAME])
            .status();

        match status {
            Ok(s) if s.success() => {
                info!("Service uninstalled successfully.");
            }
            Ok(s) => error!(
                "Failed to uninstall service. Did you run as Administrator? (Exit code: {:?})",
                s.code()
            ),
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

    let stop_signal_handler = stop_signal.clone();
    rt.spawn(async move {
        use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close};
        let mut s_c = ctrl_c().expect("Failed to listen for Ctrl+C");
        let mut s_close = ctrl_close().expect("Failed to listen for Ctrl+Close");
        let mut s_break = ctrl_break().expect("Failed to listen for Ctrl+Break");

        tokio::select! {
            _ = s_c.recv() => info!("Received Ctrl+C signal"),
            _ = s_close.recv() => info!("Received Ctrl+Close signal (Alt+F4 or Window Close)"),
            _ = s_break.recv() => info!("Received Ctrl+Break signal"),
        }

        info!("Termination signal received, stopping service gracefully...");
        stop_signal_handler.store(true, Ordering::SeqCst);
    });

    rt.block_on(async {
        match run_service_loop(stop_signal.clone(), reharden_signal.clone()).await {
            Ok(_) => {
                info!("Service loop exited gracefully");
                run_network_repair_cleanup();
            }
            Err(e) => {
                error!("Service loop error: {:?}", e);
                run_network_repair_cleanup();
            }
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
            event @ (ServiceControl::Stop
            | ServiceControl::Preshutdown
            | ServiceControl::Shutdown) => {
                info!("Received {:?} signal from Service Control Manager", event);
                stop_signal_handler.store(true, Ordering::SeqCst);
                run_network_repair_cleanup();
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
        controls_accepted: ServiceControlAccept::STOP
            | ServiceControlAccept::PRESHUTDOWN
            | ServiceControlAccept::SESSION_CHANGE,
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

    let res = rt.block_on(run_service_loop(
        stop_signal.clone(),
        reharden_signal.clone(),
    ));
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
        vpn_connected: Arc::new(AtomicBool::new(false)),
        vpn_stopping: Arc::new(AtomicBool::new(false)),
        last_error: Arc::new(StdMutex::new(None)),
        assigned_ip: Arc::new(StdMutex::new(None)),
        vpn_task: None,
        active_config: None,
    }));

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
        error!(
            "Rejecting IPC request from {} due to invalid auth token",
            peer
        );
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
        ipc::IpcRequest::Start(config) => {
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
                            // Stop-requested failures are part of teardown, not user-visible connection errors.
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
    }
}

#[cfg(not(test))]
fn run_network_repair_cleanup() {
    vpn_core::cleanup_stale_network_state();
}

#[cfg(test)]
fn run_network_repair_cleanup() {
    REPAIR_CLEANUP_CALLS.fetch_add(1, Ordering::SeqCst);
}

fn classify_status(
    connected: bool,
    stopping: bool,
    starting: bool,
    last_error: Option<&str>,
) -> ipc::VpnState {
    if connected {
        ipc::VpnState::Connected
    } else if last_error.is_some() {
        ipc::VpnState::Failed
    } else if stopping {
        ipc::VpnState::Stopping
    } else if starting {
        ipc::VpnState::Starting
    } else {
        ipc::VpnState::Stopped
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
    if sid.is_empty() {
        None
    } else {
        Some(sid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_status_prefers_connected() {
        assert_eq!(
            classify_status(true, true, true, Some("previous error")),
            ipc::VpnState::Connected
        );
    }

    #[test]
    fn classify_status_reports_failed_before_stopping_or_starting() {
        assert_eq!(
            classify_status(false, true, true, Some("MTU mismatch")),
            ipc::VpnState::Failed
        );
    }

    #[test]
    fn classify_status_reports_stopping_starting_and_stopped() {
        assert_eq!(
            classify_status(false, true, true, None),
            ipc::VpnState::Stopping
        );
        assert_eq!(
            classify_status(false, false, true, None),
            ipc::VpnState::Starting
        );
        assert_eq!(
            classify_status(false, false, false, None),
            ipc::VpnState::Stopped
        );
    }

    fn test_config() -> ipc::Config {
        ipc::Config {
            endpoint: "vpn.example.com:4433".to_string(),
            token: "token".to_string(),
            cert_pin: "deadbeef".to_string(),
            censorship_resistant: false,
            http3_framing: false,
            kc_auth: None,
            kc_url: None,
            kc_realm: None,
            kc_client_id: None,
            ech_config: None,
            vpn_mtu: None,
        }
    }

    fn test_state() -> Arc<Mutex<VpnServiceState>> {
        Arc::new(Mutex::new(VpnServiceState {
            vpn_running: Arc::new(AtomicBool::new(false)),
            vpn_connected: Arc::new(AtomicBool::new(false)),
            vpn_stopping: Arc::new(AtomicBool::new(false)),
            last_error: Arc::new(StdMutex::new(None)),
            assigned_ip: Arc::new(StdMutex::new(None)),
            vpn_task: None,
            active_config: None,
        }))
    }

    #[tokio::test]
    async fn stop_request_marks_active_task_as_stopping() {
        let state = test_state();
        let sleeper = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        {
            let mut guard = state.lock().await;
            guard.vpn_running.store(true, Ordering::SeqCst);
            guard.vpn_connected.store(true, Ordering::SeqCst);
            guard.active_config = Some(test_config());
            if let Ok(mut last) = guard.last_error.lock() {
                *last = Some("old error".to_string());
            }
            guard.vpn_task = Some(sleeper);
        }

        assert!(matches!(
            dispatch_request(ipc::IpcRequest::Stop, &state).await,
            ipc::IpcResponse::Ok
        ));

        let task = {
            let mut guard = state.lock().await;
            assert!(!guard.vpn_running.load(Ordering::SeqCst));
            assert!(!guard.vpn_connected.load(Ordering::SeqCst));
            assert!(guard.vpn_stopping.load(Ordering::SeqCst));
            assert!(guard.active_config.is_none());
            assert!(guard.last_error.lock().unwrap().is_none());
            guard.vpn_task.take()
        };
        if let Some(task) = task {
            task.abort();
        }
    }

    #[tokio::test]
    async fn stop_request_without_task_reports_stopped() {
        let state = test_state();
        {
            let mut guard = state.lock().await;
            guard.vpn_running.store(true, Ordering::SeqCst);
            guard.vpn_connected.store(true, Ordering::SeqCst);
            guard.active_config = Some(test_config());
        }

        assert!(matches!(
            dispatch_request(ipc::IpcRequest::Stop, &state).await,
            ipc::IpcResponse::Ok
        ));

        let guard = state.lock().await;
        assert!(!guard.vpn_running.load(Ordering::SeqCst));
        assert!(!guard.vpn_connected.load(Ordering::SeqCst));
        assert!(!guard.vpn_stopping.load(Ordering::SeqCst));
        assert!(guard.active_config.is_none());
    }

    #[tokio::test]
    async fn repair_network_stops_active_task_and_runs_cleanup() {
        REPAIR_CLEANUP_CALLS.store(0, Ordering::SeqCst);
        let state = test_state();
        let sleeper = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        {
            let mut guard = state.lock().await;
            guard.vpn_running.store(true, Ordering::SeqCst);
            guard.vpn_connected.store(true, Ordering::SeqCst);
            guard.active_config = Some(test_config());
            guard.vpn_task = Some(sleeper);
        }

        assert!(matches!(
            dispatch_request(ipc::IpcRequest::RepairNetwork, &state).await,
            ipc::IpcResponse::Ok
        ));

        let task = {
            let mut guard = state.lock().await;
            assert!(!guard.vpn_running.load(Ordering::SeqCst));
            assert!(!guard.vpn_connected.load(Ordering::SeqCst));
            assert!(guard.vpn_stopping.load(Ordering::SeqCst));
            assert!(guard.active_config.is_none());
            guard.vpn_task.take()
        };
        assert_eq!(REPAIR_CLEANUP_CALLS.load(Ordering::SeqCst), 1);
        if let Some(task) = task {
            task.abort();
        }
    }

    #[tokio::test]
    async fn start_request_is_rejected_while_stopping() {
        let state = test_state();
        {
            let guard = state.lock().await;
            guard.vpn_stopping.store(true, Ordering::SeqCst);
        }

        match dispatch_request(ipc::IpcRequest::Start(test_config()), &state).await {
            ipc::IpcResponse::Error(msg) => {
                assert_eq!(msg, "VPN is stopping; retry shortly");
            }
            other => panic!("Expected Error, got {:?}", other),
        }
    }
}
