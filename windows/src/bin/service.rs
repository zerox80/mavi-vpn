use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

use std::{ffi::OsString, path::Path, sync::Arc, sync::atomic::{AtomicBool, Ordering}, time::Duration};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener};
use tracing::{error, info, warn};
use tracing_subscriber;
use rand::RngCore;
use base64::Engine;

#[path = "../ipc.rs"]
mod ipc;
#[path = "../vpn_core.rs"]
mod vpn_core;

const SERVICE_NAME: &str = "MaviVPNService";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

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

    rt.block_on(async {
        match run_service_loop(stop_signal.clone()).await {
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

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                info!("Received Stop signal from Service Control Manager");
                stop_signal_handler.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
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

    let res = rt.block_on(run_service_loop(stop_signal.clone()));
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

async fn run_service_loop(stop_signal: Arc<AtomicBool>) -> anyhow::Result<()> {
    // Current active VPN tracking
    let vpn_running = Arc::new(AtomicBool::new(false));
    let mut vpn_task: Option<tokio::task::JoinHandle<()>> = None;
    let mut active_config: Option<ipc::Config> = None;

    // Generate secure token for IPC and save to file BEFORE binding listener
    let mut token_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut token_bytes);
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

    loop {
        if stop_signal.load(Ordering::SeqCst) {
            info!("Stop signal flag is true, terminating service loop.");
            vpn_running.store(false, Ordering::SeqCst);
            if let Some(t) = vpn_task {
                let _ = t.await;
            }
            break;
        }

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                // Periodically wake up to check stop_signal
                continue;
            }
            conn_res = listener.accept() => {
                let (mut socket, peer) = match conn_res {
                    Ok(res) => res,
                    Err(e) => {
                        error!("TCP accept error: {}", e);
                        continue;
                    }
                };
                
                info!("Client connected to Local IPC from {}", peer);
                let (mut rx, mut tx) = socket.split();
                
                // Read next message lengths and payloads
                let mut len_buf = [0u8; 4];
                if rx.read_exact(&mut len_buf).await.is_err() {
                    continue;
                }
                
                let len = u32::from_le_bytes(len_buf) as usize;
                if len > 65536 {
                    continue;
                }
                
                let mut buf = vec![0u8; len];
                if rx.read_exact(&mut buf).await.is_err() {
                    continue;
                }
                
                let req_msg: ipc::SecureIpcRequest = match bincode::serde::decode_from_slice(&buf, bincode::config::standard()) {
                    Ok((r, _)) => r,
                    Err(_) => continue,
                };
                
                let resp = if req_msg.auth_token != auth_token {
                    error!("Rejecting IPC request due to invalid auth token");
                    ipc::IpcResponse::Error("Unauthorized: Invalid IPC Token".to_string())
                } else {
                    match req_msg.request {
                    ipc::IpcRequest::Status => {
                        ipc::IpcResponse::Status {
                            running: vpn_running.load(Ordering::SeqCst),
                            endpoint: active_config.as_ref().map(|c| c.endpoint.clone()),
                        }
                    }
                    ipc::IpcRequest::Stop => {
                        info!("Handling Stop request from client");
                        vpn_running.store(false, Ordering::SeqCst);
                        active_config = None;
                        ipc::IpcResponse::Ok
                    }
                    ipc::IpcRequest::Start(config) => {
                        info!("Handling Start request for endpoint: {}", config.endpoint);
                        let still_running = vpn_running.load(Ordering::SeqCst)
                            || vpn_task.as_ref().map_or(false, |t| !t.is_finished());
                        if still_running {
                            ipc::IpcResponse::Error("VPN is already running".to_string())
                        } else {
                            active_config = Some(config.clone());
                            vpn_running.store(true, Ordering::SeqCst);
                            let flag = vpn_running.clone();
                            
                            vpn_task = Some(tokio::spawn(async move {
                                if let Err(e) = vpn_core::run_vpn(config, flag.clone()).await {
                                    error!("VPN task failed: {}", e);
                                }
                                flag.store(false, Ordering::SeqCst);
                            }));
                            ipc::IpcResponse::Ok
                        }
                    }
                    }
                };
                
                let resp_buf = bincode::serde::encode_to_vec(&resp, bincode::config::standard()).unwrap();
                let _ = tx.write_u32_le(resp_buf.len() as u32).await;
                let _ = tx.write_all(&resp_buf).await;
            }
        }
    }

    Ok(())
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
