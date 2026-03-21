use anyhow::{Context, Result};
use std::io::{self, Write};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

mod ipc;
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
            "start" => {
                match load_or_prompt_config().await {
                    Ok(config) => send_request(IpcRequest::Start(config)).await,
                    Err(e) => Err(e),
                }
            }
            "stop" => {
                send_request(IpcRequest::Stop).await
            }
            "status" => {
                send_request(IpcRequest::Status).await
            }
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
        Ok(IpcResponse::Status { running: true, endpoint }) => {
            println!("VPN is currently RUNNING (Endpoint: {}).", endpoint.as_deref().unwrap_or("Unknown"));
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
    let mut client = TcpStream::connect(ipc::LOCAL_IPC_ADDR).await?;
    
    let req_buf = bincode::serde::encode_to_vec(&req, bincode::config::standard())?;
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
    match send_request_internal(req).await {
        Ok(IpcResponse::Ok) => {
            println!("Action executed successfully.");
        }
        Ok(IpcResponse::Error(msg)) => {
            println!("Service returned an error: {}", msg);
        }
        Ok(IpcResponse::Status { running, endpoint }) => {
            println!("Status: {}", if running { "RUNNING" } else { "STOPPED" });
            if let Some(ep) = endpoint {
                println!("Endpoint: {}", ep);
            }
        }
        Err(e) => {
            println!("Failed to communicate with service: {}", e);
        }
    }
    Ok(())
}

// Config loading and prompting functions

fn config_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
        .join(CONFIG_FILE)
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
    if let Some(saved) = load_config() {
        println!("Gespeicherte Konfiguration gefunden:");
        println!("  Endpoint: {}", saved.endpoint);
        println!("  Token: {}...", &saved.token.chars().take(8).collect::<String>());
        println!("  CR Mode: {}", if saved.censorship_resistant { "Ja" } else { "Nein" });
        println!();
        
        print!("Diese Konfiguration verwenden? [J/n]: ");
        io::stdout().flush()?;
        let input = read_line()?.to_lowercase();
        
        if input.is_empty() || input == "j" || input == "ja" || input == "y" || input == "yes" {
            println!();
            return Ok(saved);
        }
        println!();
    }
    
    let config = prompt_new_config().await?;
    save_config(&config)?;
    Ok(config)
}

async fn fetch_keycloak_token(url: &str, realm: &str, client_id: &str, user: &str, pass: &str) -> Result<String> {
    let endpoint = format!("{}/realms/{}/protocol/openid-connect/token", url.trim_end_matches('/'), realm);
    
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
        
    let params = [
        ("client_id", client_id),
        ("grant_type", "password"),
        ("username", user),
        ("password", pass),
    ];
    
    let res = client.post(&endpoint)
        .form(&params)
        .send().await
        .context("Verbindung zu Keycloak fehlgeschlagen")?;
        
    if !res.status().is_success() {
        let error_text = res.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Keycloak Authentifizierung fehlgeschlagen: {}", error_text));
    }
    
    let json: serde_json::Value = res.json().await?;
    let access_token = json["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Kein access_token in Keycloak Antwort gefunden"))?;
        
    Ok(access_token.to_string())
}

async fn prompt_new_config() -> Result<Config> {
    let mut stdout = io::stdout();

    print!("Server Endpoint (z.B. vpn.example.com:443): ");
    stdout.flush()?;
    let endpoint = read_line()?;

    print!("Nutze Keycloak Authentifizierung? [j/N]: ");
    stdout.flush()?;
    let is_keycloak = read_line()?.to_lowercase();
    
    let token;
    if is_keycloak == "j" || is_keycloak == "ja" || is_keycloak == "y" || is_keycloak == "yes" {
        print!("Keycloak Server URL (z.B. https://auth.example.com): ");
        stdout.flush()?;
        let kc_url = read_line()?;
        
        print!("Realm (default: mavi-vpn): ");
        stdout.flush()?;
        let mut realm = read_line()?;
        if realm.is_empty() { realm = "mavi-vpn".to_string(); }
        
        print!("Client ID (default: mavi-client): ");
        stdout.flush()?;
        let mut client_id = read_line()?;
        if client_id.is_empty() { client_id = "mavi-client".to_string(); }
        
        print!("Username: ");
        stdout.flush()?;
        let username = read_line()?;
        
        print!("Password: ");
        stdout.flush()?;
        let password = read_line()?;
        
        println!("Authentifiziere mit Keycloak...");
        token = fetch_keycloak_token(&kc_url, &realm, &client_id, &username, &password).await?;
        println!("Keycloak Authentifizierung erfolgreich! JWT Token bezogen.");
    } else {
        print!("Auth Token: ");
        stdout.flush()?;
        token = read_line()?;
    }

    print!("Certificate PIN (SHA256 hex): ");
    stdout.flush()?;
    let cert_pin = read_line()?;

    print!("Censorship Resistant Mode? [j/N]: ");
    stdout.flush()?;
    let cr_input = read_line()?.to_lowercase();
    let censorship_resistant = cr_input == "j" || cr_input == "ja" || cr_input == "y" || cr_input == "yes";

    println!();

    Ok(Config {
        endpoint,
        token,
        cert_pin,
        censorship_resistant,
    })
}

fn read_line() -> Result<String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}
