use anyhow::Result;
use std::io::{self, Write};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

mod ipc;
mod oauth;
use ipc::{Config, IpcRequest, IpcResponse};

const CONFIG_FILE: &str = "config.json";

#[tokio::main]
async fn main() {
    println!();
    println!("╔══════════════════════════════════════╗");
    println!("║         Mavi VPN - Windows           ║");
    println!("╚══════════════════════════════════════╝");
    println!();

    let args: Vec<String> = std::env::args().skip(1).collect();

    let result = if args.is_empty() {
        interactive_mode().await
    } else {
        let cmd = args[0].to_lowercase();
        match cmd.as_str() {
            "start" => match load_or_prompt_config().await {
                Ok(config) => send_request(IpcRequest::Start(config)).await,
                Err(e) => Err(e),
            },
            "stop" => send_request(IpcRequest::Stop).await,
            "status" => send_request(IpcRequest::Status).await,
            _ => {
                println!("Unknown command: {}", cmd);
                println!("Usage: mavi-vpn-client [start|stop|status]");
                Ok(())
            }
        }
    };

    if let Err(e) = result {
        println!("\n❌ Error: {}", e);
    }

    // Keep window open when launched via double-click
    println!("\nPress Enter to exit...");
    let _ = read_line();
}

async fn interactive_mode() -> Result<()> {
    // First, check status
    let status_res = send_request_internal(IpcRequest::Status).await;

    match status_res {
        Ok(IpcResponse::Status {
            running: true,
            endpoint,
            ..
        }) => {
            println!(
                "VPN is currently RUNNING (Endpoint: {}).",
                endpoint.as_deref().unwrap_or("Unknown")
            );
            print!("Do you want to stop it? [y/N]: ");
            io::stdout().flush()?;
            let input = read_line()?.to_lowercase();
            if input == "y" || input == "yes" {
                send_request(IpcRequest::Stop).await?;
            } else {
                println!("Leaving VPN running in background. Goodbye!");
            }
        }
        Ok(IpcResponse::Status { running: false, .. }) => {
            println!("VPN is disconnected.");
            let config = load_or_prompt_config().await?;
            send_request(IpcRequest::Start(config)).await?;

            println!("\n✅ VPN is now CONNECTED!");
            println!("To safely DISCONNECT and exit, press Enter...");
            let _ = read_line();

            println!("Disconnecting...");
            send_request(IpcRequest::Stop).await?;
            println!("✅ Disconnected. Goodbye!");
        }
        Err(e) if e.to_string().contains("Connection refused") => {
            println!("Error: The Mavi VPN Service is not running.");
            println!("Please ensure the service is installed and started via Administrator:");
            println!("  mavi-vpn-service.exe install");
            println!("  net start MaviVPNService");
        }
        Err(e) => {
            println!("Failed to communicate with service: {}", e);
        }
        _ => {}
    }

    Ok(())
}

async fn send_request_internal(req: IpcRequest) -> Result<IpcResponse> {
    let token_path = ipc::ipc_token_path();
    let auth_token = std::fs::read_to_string(&token_path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                anyhow::anyhow!(
                    "Failed to read IPC token from {:?}: access denied. Run the client as Administrator or restart the service after logging in.",
                    token_path
                )
            } else {
                anyhow::anyhow!("Failed to read IPC token from {:?}. Is the service running? {}", token_path, e)
            }
        })?
        .trim()
        .to_string();

    let req_msg = ipc::SecureIpcRequest {
        auth_token,
        request: req,
    };

    let mut client = TcpStream::connect(ipc::LOCAL_IPC_ADDR).await?;

    let req_buf = bincode::serde::encode_to_vec(&req_msg, bincode::config::standard())?;
    client.write_u32_le(req_buf.len() as u32).await?;
    client.write_all(&req_buf).await?;

    let mut len_buf = [0u8; 4];
    client.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 65536 {
        return Err(anyhow::anyhow!("Response too large"));
    }

    let mut buf = vec![0u8; len];
    client.read_exact(&mut buf).await?;

    let (resp, _) = bincode::serde::decode_from_slice(&buf, bincode::config::standard())
        .map_err(|e| anyhow::anyhow!("Decode error: {}", e))?;

    Ok(resp)
}

async fn send_request(req: IpcRequest) -> Result<()> {
    let is_start = matches!(req, IpcRequest::Start(_));
    match send_request_internal(req).await {
        Ok(IpcResponse::Ok) => {
            if is_start {
                wait_for_connected().await?;
            } else {
                println!("Action executed successfully.");
            }
        }
        Ok(IpcResponse::Error(msg)) => {
            println!("Service returned an error: {}", msg);
        }
        Ok(IpcResponse::Status {
            running,
            endpoint,
            state,
            last_error,
        }) => {
            println!("Status: {}", if running { "RUNNING" } else { "STOPPED" });
            println!("State: {:?}", state);
            if let Some(ep) = endpoint {
                println!("Endpoint: {}", ep);
            }
            if let Some(err) = last_error {
                println!("Last error: {}", err);
            }
        }
        Err(e) => {
            println!("Failed to communicate with service: {}", e);
        }
    }
    Ok(())
}

async fn wait_for_connected() -> Result<()> {
    println!("Start accepted. Waiting for tunnel readiness...");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        match send_request_internal(IpcRequest::Status).await {
            Ok(IpcResponse::Status {
                running: true,
                endpoint,
                ..
            }) => {
                println!("VPN is now CONNECTED.");
                if let Some(ep) = endpoint {
                    println!("Endpoint: {}", ep);
                }
                return Ok(());
            }
            Ok(IpcResponse::Status {
                state: ipc::VpnState::Failed,
                last_error,
                ..
            }) => {
                anyhow::bail!(
                    "VPN failed to connect: {}",
                    last_error.as_deref().unwrap_or("unknown error")
                );
            }
            Ok(_) => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
            Err(e) => {
                anyhow::bail!("Failed to read status after start: {}", e);
            }
        }
    }
    anyhow::bail!("VPN is still starting. Run status to check progress.")
}

// Config loading and prompting functions

fn config_path() -> PathBuf {
    // Use %APPDATA%\MaviVPN\ so normal users can read/write without admin.
    let dir = std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("MaviVPN");
    let _ = std::fs::create_dir_all(&dir);
    dir.join(CONFIG_FILE)
}

fn load_config() -> Option<Config> {
    let path = config_path();
    if path.exists() {
        let content = std::fs::read_to_string(&path).ok()?;
        serde_json::from_str(&content).ok()
    } else {
        None
    }
}

fn save_config(config: &Config) -> Result<()> {
    let path = config_path();
    let content = serde_json::to_string_pretty(config)?;
    std::fs::write(&path, content)?;
    println!("Config saved to {}", path.display());
    Ok(())
}

async fn load_or_prompt_config() -> Result<Config> {
    if let Some(mut saved) = load_config() {
        println!("Gespeicherte Konfiguration gefunden:");
        println!("  Endpoint: {}", saved.endpoint);
        if saved.kc_auth.unwrap_or(false) {
            println!("  Auth Mode: Keycloak (SSO)");
        } else {
            println!(
                "  Token: {}...",
                &saved.token.chars().take(8).collect::<String>()
            );
        }
        println!(
            "  CR Mode: {}",
            if saved.censorship_resistant {
                "Ja"
            } else {
                "Nein"
            }
        );
        println!(
            "  HTTP/3 Framing: {}",
            if saved.http3_framing { "Ja" } else { "Nein" }
        );
        if let Some(mtu) = saved.vpn_mtu {
            println!("  VPN MTU: {}", mtu);
        }
        println!();

        print!("Diese Konfiguration verwenden? [J/n]: ");
        io::stdout().flush()?;
        let input = read_line()?.to_lowercase();

        if input.is_empty() || input == "j" || input == "ja" || input == "y" || input == "yes" {
            println!();

            // If Keycloak was used, we MUST fetch a fresh token because JWTs expire quickly!
            if saved.kc_auth.unwrap_or(false) {
                let kc_url = saved.kc_url.as_deref().unwrap_or("");
                let realm = saved.kc_realm.as_deref().unwrap_or("mavi-vpn");
                let client_id = saved.kc_client_id.as_deref().unwrap_or("mavi-client");

                println!("Erneuere Keycloak-Sitzung...");
                let fresh_token = oauth::start_oauth_flow(kc_url, realm, client_id).await?;
                println!("Sitzung erfolgreich erneuert!");
                saved.token = fresh_token;

                // Save the fresh token to disk as well (though it expires again soon)
                save_config(&saved)?;
            }

            return Ok(saved);
        }
        println!();
    }

    let config = prompt_new_config().await?;
    save_config(&config)?;
    Ok(config)
}

// fetch_keycloak_token removed, now using browser-based oauth::start_oauth_flow

async fn prompt_new_config() -> Result<Config> {
    let mut stdout = io::stdout();

    print!("Server Endpoint (z.B. vpn.example.com:443): ");
    stdout.flush()?;
    let endpoint = read_line()?;

    print!("Nutze Keycloak Authentifizierung? [j/N]: ");
    stdout.flush()?;
    let is_keycloak = read_line()?.to_lowercase();

    let mut kc_auth = Some(false);
    let mut saved_kc_url = None;
    let mut saved_kc_realm = None;
    let mut saved_kc_client_id = None;

    let token;
    if is_keycloak == "j" || is_keycloak == "ja" || is_keycloak == "y" || is_keycloak == "yes" {
        kc_auth = Some(true);
        print!("Keycloak Server URL (z.B. https://auth.example.com): ");
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
        println!("Keycloak Login abgeschlossen! Speichere Konfiguration...");

        saved_kc_url = Some(kc_url);
        saved_kc_realm = Some(realm);
        saved_kc_client_id = Some(client_id);
    } else {
        print!("Preshared Key: ");
        stdout.flush()?;
        token = read_line()?;
    }

    print!("Certificate PIN (SHA256 hex): ");
    stdout.flush()?;
    let cert_pin = read_line()?;

    print!("Censorship Resistant Mode? [j/N]: ");
    stdout.flush()?;
    let cr_input = read_line()?.to_lowercase();
    let censorship_resistant =
        cr_input == "j" || cr_input == "ja" || cr_input == "y" || cr_input == "yes";

    print!("HTTP/3 Datagram Framing? (Nur nützlich mit CR Mode) [j/N]: ");
    stdout.flush()?;
    let h3_input = read_line()?.to_lowercase();
    let http3_framing = h3_input == "j" || h3_input == "ja" || h3_input == "y" || h3_input == "yes";

    // Prefer $VPN_ECH_CONFIG (for headless/scripted use). Fall back to an
    // interactive prompt when censorship_resistant mode is on.
    let ech_config = match std::env::var("VPN_ECH_CONFIG") {
        Ok(s) if !s.is_empty() => Some(s),
        _ if censorship_resistant => {
            print!("ECHConfigList (hex, optional – Enter zum Überspringen): ");
            stdout.flush()?;
            let input = read_line()?;
            if input.is_empty() {
                None
            } else if shared::hex::decode_hex(&input).is_none() {
                eprintln!("Warnung: ECHConfigList-Hex ist ungültig (ungerade Länge oder kein gültiges Hex) – ECH wird deaktiviert");
                None
            } else {
                Some(input)
            }
        }
        _ => None,
    };

    print!("VPN MTU (1280–1360, optional – Enter für Standard 1280): ");
    stdout.flush()?;
    let vpn_mtu_input = read_line()?;
    let vpn_mtu = if vpn_mtu_input.is_empty() {
        None
    } else {
        match vpn_mtu_input.parse::<u16>() {
            Ok(v) if v >= 1280 && v <= 1360 => Some(v),
            _ => {
                eprintln!("Warnung: Ungültiger MTU-Wert – Standard (1280) wird verwendet");
                None
            }
        }
    };

    println!();

    Ok(Config {
        endpoint,
        token,
        cert_pin,
        censorship_resistant,
        http3_framing,
        kc_auth,
        kc_url: saved_kc_url,
        kc_realm: saved_kc_realm,
        kc_client_id: saved_kc_client_id,
        ech_config,
        vpn_mtu,
    })
}

fn read_line() -> Result<String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}
