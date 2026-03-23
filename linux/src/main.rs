//! # Mavi VPN - Linux CLI Client
//!
//! A full-featured VPN client for Linux that uses QUIC transport.
//! Supports both direct CLI mode and daemon mode (for GUI integration).
//!
//! Usage:
//!   sudo mavi-vpn                            # Interactive connect (direct)
//!   sudo mavi-vpn connect -c config.json     # Connect with config file
//!   sudo mavi-vpn daemon                     # Start as IPC daemon (for GUI)
//!   mavi-vpn start                           # Send start to running daemon
//!   mavi-vpn stop                            # Send stop to running daemon
//!   mavi-vpn status                          # Check VPN status

mod daemon;
mod network;
mod oauth;
mod tun;
mod vpn_core;

use anyhow::Result;
use shared::ipc::Config;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::info;

const CONFIG_FILE: &str = "mavi-vpn.json";

fn main() {
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
        let config = load_or_prompt_config(config_path).await?;

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

            println!("\n\x1b[33mShutting down VPN...\x1b[0m");
            running_signal.store(false, Ordering::SeqCst);
        });

        println!("\x1b[1;32mConnecting...\x1b[0m");
        println!("Press Ctrl+C to disconnect.\n");

        vpn_core::run_vpn(config, running).await?;

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
        let config = load_or_prompt_config(config_path).await?;
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
            Err(e) => eprintln!("Failed to communicate with daemon: {}\nIs the daemon running?", e),
        }
        Ok(())
    })
}

fn run_status() {
    // First try IPC daemon
    let rt = tokio::runtime::Runtime::new().unwrap();
    let ipc_result = rt.block_on(async {
        daemon::send_request(shared::ipc::IpcRequest::Status).await
    });

    match ipc_result {
        Ok(shared::ipc::IpcResponse::Status { running, endpoint }) => {
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
        _ => {}
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

// =============================================================================
// Config loading and interactive prompting
// =============================================================================

fn default_config_path() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        let path = PathBuf::from(xdg).join("mavi-vpn").join(CONFIG_FILE);
        if path.exists() {
            return path;
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let path = PathBuf::from(home)
            .join(".config")
            .join("mavi-vpn")
            .join(CONFIG_FILE);
        if path.exists() {
            return path;
        }
    }
    let etc_path = PathBuf::from("/etc/mavi-vpn").join(CONFIG_FILE);
    if etc_path.exists() {
        return etc_path;
    }
    PathBuf::from(CONFIG_FILE)
}

fn load_config(path: &PathBuf) -> Option<Config> {
    if path.exists() {
        let content = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    } else {
        None
    }
}

fn save_config(config: &Config, path: &PathBuf) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(config)?;
    std::fs::write(path, content)?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    println!("Config saved to {}", path.display());
    Ok(())
}

async fn load_or_prompt_config(explicit_path: Option<PathBuf>) -> Result<Config> {
    let config_path = explicit_path.unwrap_or_else(default_config_path);

    if let Some(mut saved) = load_config(&config_path) {
        println!("Found saved configuration:");
        println!("  Endpoint: {}", saved.endpoint);
        if saved.kc_auth.unwrap_or(false) {
            println!("  Auth: Keycloak (SSO)");
        } else {
            println!(
                "  Token: {}...",
                &saved.token.chars().take(8).collect::<String>()
            );
        }
        println!(
            "  CR Mode: {}",
            if saved.censorship_resistant { "Yes" } else { "No" }
        );
        println!();

        print!("Use this configuration? [Y/n]: ");
        io::stdout().flush()?;
        let input = read_line()?.to_lowercase();

        if input.is_empty() || input == "y" || input == "yes" {
            if saved.kc_auth.unwrap_or(false) {
                let kc_url = saved.kc_url.as_deref().unwrap_or("");
                let realm = saved.kc_realm.as_deref().unwrap_or("mavi-vpn");
                let client_id = saved.kc_client_id.as_deref().unwrap_or("mavi-client");

                println!("Refreshing Keycloak session...");
                let fresh_token = oauth::start_oauth_flow(kc_url, realm, client_id).await?;
                println!("Session refreshed!");
                saved.token = fresh_token;
                save_config(&saved, &config_path)?;
            }

            return Ok(saved);
        }
        println!();
    }

    let config = prompt_new_config().await?;
    save_config(&config, &config_path)?;
    Ok(config)
}

async fn prompt_new_config() -> Result<Config> {
    let mut stdout = io::stdout();

    print!("Server endpoint (e.g. vpn.example.com:443): ");
    stdout.flush()?;
    let endpoint = read_line()?;

    print!("Use Keycloak authentication? [y/N]: ");
    stdout.flush()?;
    let is_keycloak = read_line()?.to_lowercase();

    let mut kc_auth = Some(false);
    let mut saved_kc_url = None;
    let mut saved_kc_realm = None;
    let mut saved_kc_client_id = None;

    let token;
    if is_keycloak == "y" || is_keycloak == "yes" {
        kc_auth = Some(true);
        print!("Keycloak server URL (e.g. https://auth.example.com): ");
        stdout.flush()?;
        let kc_url = read_line()?;

        print!("Realm (default: mavi-vpn): ");
        stdout.flush()?;
        let mut realm = read_line()?;
        if realm.is_empty() {
            realm = "mavi-vpn".to_string();
        }

        print!("Client ID (default: mavi-client): ");
        stdout.flush()?;
        let mut client_id = read_line()?;
        if client_id.is_empty() {
            client_id = "mavi-client".to_string();
        }

        token = oauth::start_oauth_flow(&kc_url, &realm, &client_id).await?;
        println!("Keycloak login successful!");

        saved_kc_url = Some(kc_url);
        saved_kc_realm = Some(realm);
        saved_kc_client_id = Some(client_id);
    } else {
        print!("Auth token: ");
        stdout.flush()?;
        token = read_line()?;
    }

    print!("Certificate PIN (SHA256 hex): ");
    stdout.flush()?;
    let cert_pin = read_line()?;

    print!("Censorship resistant mode? [y/N]: ");
    stdout.flush()?;
    let cr_input = read_line()?.to_lowercase();
    let censorship_resistant = cr_input == "y" || cr_input == "yes";

    println!();

    Ok(Config {
        endpoint,
        token,
        cert_pin,
        censorship_resistant,
        kc_auth,
        kc_url: saved_kc_url,
        kc_realm: saved_kc_realm,
        kc_client_id: saved_kc_client_id,
    })
}

fn read_line() -> Result<String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}
