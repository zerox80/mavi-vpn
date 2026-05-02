mod config;

use crate::{daemon, vpn_core};
use anyhow::Result;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use tracing::info;

pub fn run() {
    // Print banner
    println!();
    println!("\x1b[1;36m");
    println!("  ╔══════════════════════════════════════╗");
    println!("  ║          Mavi VPN - Linux             ║");
    println!("  ╚══════════════════════════════════════╝");
    println!("\x1b[0m");

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();

    let result = match args.first().map(|s| s.as_str()) {
        // --- Direct CLI mode (no daemon needed) ---
        Some("connect") | Some("up") | None => {
            if !is_root() {
                eprintln!("\x1b[1;31mError: This program requires root privileges.\x1b[0m");
                eprintln!("Please run with: sudo mavi-vpn");
                std::process::exit(1);
            }

            let config_path = args
                .iter()
                .position(|a| a == "-c" || a == "--config")
                .and_then(|i| args.get(i + 1))
                .map(PathBuf::from);

            run_connect(config_path)
        }

        // --- Daemon mode (IPC server for GUI) ---
        Some("daemon") => {
            if !is_root() {
                eprintln!("\x1b[1;31mError: Daemon requires root privileges.\x1b[0m");
                eprintln!("Please run with: sudo mavi-vpn daemon");
                std::process::exit(1);
            }
            run_daemon()
        }

        // --- IPC client commands (talk to running daemon) ---
        Some("start") => {
            let config_path = args
                .iter()
                .position(|a| a == "-c" || a == "--config")
                .and_then(|i| args.get(i + 1))
                .map(PathBuf::from);
            run_ipc_start(config_path)
        }
        Some("stop") => run_ipc_stop(),
        Some("repair") => run_ipc_repair(),

        Some("status") => {
            run_status();
            Ok(())
        }

        Some("help") | Some("--help") | Some("-h") => {
            print_help();
            Ok(())
        }
        Some(cmd) => {
            eprintln!("Unknown command: {}", cmd);
            print_help();
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("\n\x1b[1;31mError: {:#}\x1b[0m", e);
        std::process::exit(1);
    }
}

// =============================================================================
// Direct CLI mode (standalone, no daemon)
// =============================================================================

fn run_connect(config_path: Option<PathBuf>) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(async {
        let config = config::load_or_prompt_config(config_path).await?;

        let running = Arc::new(AtomicBool::new(true));
        let connected = Arc::new(AtomicBool::new(false));
        let last_error = Arc::new(StdMutex::new(None));
        let assigned_ip = Arc::new(StdMutex::new(None));
        let running_signal = running.clone();

        tokio::spawn(async move {
            let mut sigint =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                    .expect("Failed to register SIGINT handler");
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("Failed to register SIGTERM handler");

            tokio::select! {
                _ = sigint.recv() => info!("Received SIGINT"),
                _ = sigterm.recv() => info!("Received SIGTERM"),
            }

            println!("\n\x1b[33mShutting down VPN...\x1b[0m");
            running_signal.store(false, Ordering::SeqCst);
        });

        println!("\x1b[1;32mConnecting...\x1b[0m");
        println!("Press Ctrl+C to disconnect.\n");

        vpn_core::run_vpn(config, running, connected, last_error, assigned_ip).await?;

        println!("\x1b[1;32mDisconnected. Goodbye!\x1b[0m");
        Ok(())
    })
}

// =============================================================================
// Daemon mode (IPC server, like the Windows service)
// =============================================================================

fn run_daemon() -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(async {
        let running = Arc::new(AtomicBool::new(true));
        let running_signal = running.clone();

        tokio::spawn(async move {
            let mut sigint =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                    .expect("Failed to register SIGINT handler");
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("Failed to register SIGTERM handler");

            tokio::select! {
                _ = sigint.recv() => info!("Received SIGINT"),
                _ = sigterm.recv() => info!("Received SIGTERM"),
            }

            println!("\n\x1b[33mShutting down daemon...\x1b[0m");
            running_signal.store(false, Ordering::SeqCst);
        });

        daemon::run_daemon(running).await
    })
}

// =============================================================================
// IPC client commands (send to running daemon)
// =============================================================================

fn run_ipc_start(config_path: Option<PathBuf>) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
    let config = config::load_or_prompt_config(config_path).await?;
    match daemon::send_request(shared::ipc::IpcRequest::Start(config)).await {
        Ok(shared::ipc::IpcResponse::Ok) => println!("\x1b[1;32mVPN started.\x1b[0m"),
        Ok(shared::ipc::IpcResponse::Error(e)) => eprintln!("Error: {}", e),
        Ok(shared::ipc::IpcResponse::Status { .. }) => eprintln!("Unexpected response"),
        Err(e) => eprintln!("Failed to communicate with daemon: {}\nIs the daemon running? (sudo mavi-vpn daemon)", e),
    }
    Ok(())
})
}

fn run_ipc_stop() -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        match daemon::send_request(shared::ipc::IpcRequest::Stop).await {
            Ok(shared::ipc::IpcResponse::Ok) => println!("\x1b[1;32mVPN stopped.\x1b[0m"),
            Ok(shared::ipc::IpcResponse::Error(e)) => eprintln!("Error: {}", e),
            Ok(_) => eprintln!("Unexpected response"),
            Err(e) => eprintln!(
                "Failed to communicate with daemon: {}\nIs the daemon running?",
                e
            ),
        }
        Ok(())
    })
}

fn run_ipc_repair() -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        match daemon::send_request(shared::ipc::IpcRequest::RepairNetwork).await {
            Ok(shared::ipc::IpcResponse::Ok) => {
                println!("\x1b[1;32mNetwork repair cleanup completed.\x1b[0m")
            }
            Ok(shared::ipc::IpcResponse::Error(e)) => eprintln!("Error: {}", e),
            Ok(_) => eprintln!("Unexpected response"),
            Err(e) => eprintln!(
                "Failed to communicate with daemon: {}\nIs the daemon running?",
                e
            ),
        }
        Ok(())
    })
}

fn run_status() {
    // First try IPC daemon
    let rt = tokio::runtime::Runtime::new().unwrap();
    let ipc_result =
        rt.block_on(async { daemon::send_request(shared::ipc::IpcRequest::Status).await });

    if let Ok(shared::ipc::IpcResponse::Status {
        running, endpoint, ..
    }) = ipc_result
    {
        if running {
            println!("\x1b[1;32mVPN Status: CONNECTED\x1b[0m");
            if let Some(ep) = endpoint {
                println!("  Endpoint: {}", ep);
            }
        } else {
            println!("\x1b[1;33mVPN Status: DISCONNECTED (daemon running)\x1b[0m");
        }
        // Also show TUN info if available
        show_tun_info();
        return;
    }

    if let Err(e) = ipc_result {
        let msg = e.to_string();
        if msg.contains("mavivpn") || msg.contains("permission denied") {
            eprintln!("{msg}");
            return;
        }
    }

    // Fallback: check TUN device directly (for direct CLI mode)
    let tun_exists = std::path::Path::new("/sys/class/net/mavi0").exists();
    if tun_exists {
        println!("\x1b[1;32mVPN Status: CONNECTED (direct mode)\x1b[0m");
        show_tun_info();
    } else {
        println!("\x1b[1;31mVPN Status: DISCONNECTED\x1b[0m");
    }
}

fn show_tun_info() {
    if let Ok(output) = std::process::Command::new("ip")
        .args(["addr", "show", "mavi0"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("inet ") || trimmed.starts_with("inet6 ") {
                println!("  {}", trimmed);
            }
        }
    }
}

fn print_help() {
    println!("Usage: mavi-vpn [COMMAND] [OPTIONS]");
    println!();
    println!("Direct mode (standalone, no daemon):");
    println!("  connect, up           Connect to VPN directly (requires root)");
    println!();
    println!("Daemon mode (for GUI integration):");
    println!("  daemon                Start IPC daemon (requires root)");
    println!("  start                 Send connect to running daemon");
    println!("  stop                  Send disconnect to running daemon");
    println!("  repair                Repair stale routes/DNS via daemon");
    println!();
    println!("Other:");
    println!("  status                Check VPN status");
    println!("  help                  Show this help message");
    println!();
    println!("Options:");
    println!("  -c, --config <FILE>   Path to config file (default: mavi-vpn.json)");
    println!();
    println!("Environment:");
    println!("  RUST_LOG=debug        Enable debug logging");
    println!();
    println!("Examples:");
    println!("  sudo mavi-vpn                      # Interactive connect");
    println!("  sudo mavi-vpn daemon &             # Start daemon in background");
    println!("  mavi-vpn start -c my-config.json   # Connect via daemon");
    println!("  mavi-vpn stop                      # Disconnect via daemon");
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
