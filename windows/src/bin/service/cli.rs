use std::ffi::OsString;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::{error, info};
use super::utils::run_network_repair_cleanup;
use super::main_loop::run_service_loop;

pub const SERVICE_NAME: &str = "MaviVPNService";

pub fn run_standalone() {
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
            Ok(()) => {
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

pub fn install_service() {
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
}

pub fn uninstall_service() {
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
}
