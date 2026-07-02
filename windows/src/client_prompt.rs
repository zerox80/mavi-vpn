use anyhow::Result;
use std::io::{self, Write};

use crate::client_config::{load_config, save_config};
use crate::client_ipc::{send_request, send_request_internal};
use crate::ipc::{Config, IpcRequest, IpcResponse};
use crate::oauth;
use shared::kc_oauth::RefreshOutcome;

pub(crate) async fn interactive_mode() -> Result<()> {
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
            println!("\nVPN is now CONNECTED!");
            println!("To safely DISCONNECT and exit, press Enter...");
            let _ = read_line();
            println!("Disconnecting...");
            send_request(IpcRequest::Stop).await?;
            println!("Disconnected. Goodbye!");
        }
        Err(e) if e.to_string().contains("Connection refused") => {
            println!("Error: The Mavi VPN Service is not running.");
            println!("Please ensure the service is installed and started via Administrator:");
            println!("  mavi-vpn-service.exe install");
            println!("  net start MaviVPNService");
        }
        Err(e) => {
            println!("Failed to communicate with service: {e}");
        }
        _ => {}
    }
    Ok(())
}

pub(crate) async fn load_or_prompt_config() -> Result<Config> {
    if let Some(mut saved) = load_config()? {
        println!("Saved configuration found:");
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
                "Yes"
            } else {
                "No"
            }
        );
        println!(
            "  HTTP/3 Framing: {}",
            if saved.http3_framing { "Yes" } else { "No" }
        );
        if let Some(mtu) = saved.vpn_mtu {
            println!("  VPN MTU: {mtu}");
        }
        println!();
        print!("Use this configuration? [Y/n]: ");
        io::stdout().flush()?;
        let input = read_line()?.to_lowercase();
        if input.is_empty() || is_affirmative(&input) {
            println!();
            if saved.kc_auth.unwrap_or(false) {
                saved = refresh_keycloak_or_login(saved).await?;
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

#[allow(clippy::too_many_lines)]
async fn prompt_new_config() -> Result<Config> {
    let mut stdout = io::stdout();
    print!("Server Endpoint (e.g. vpn.example.com:443): ");
    stdout.flush()?;
    let endpoint = read_line()?;
    print!("Use Keycloak authentication? [y/N]: ");
    stdout.flush()?;
    let is_keycloak = read_line()?.to_lowercase();
    let mut kc_auth = Some(false);
    let (token, refresh_token, saved_kc_url, saved_kc_realm, saved_kc_client_id) =
        if is_affirmative(&is_keycloak) {
            kc_auth = Some(true);
            let tokens = prompt_keycloak_config().await?;
            (
                tokens.access_token,
                tokens.refresh_token,
                Some(tokens.url),
                Some(tokens.realm),
                Some(tokens.client_id),
            )
        } else {
            print!("Preshared Key: ");
            stdout.flush()?;
            (read_line()?, None, None, None, None)
        };
    print!("Certificate PIN (SHA256 hex): ");
    stdout.flush()?;
    let cert_pin = read_line()?;
    print!("Censorship Resistant Mode? [y/N]: ");
    stdout.flush()?;
    let cr_input = read_line()?.to_lowercase();
    let censorship_resistant = is_affirmative(&cr_input);
    let http3_framing = if censorship_resistant {
        println!("HTTP/3 Datagram Framing is automatically enabled in CR Mode.");
        true
    } else {
        print!("HTTP/3 Datagram Framing? (Only useful in CR Mode) [y/N]: ");
        stdout.flush()?;
        let h3_input = read_line()?.to_lowercase();
        is_affirmative(&h3_input)
    };
    let ech_config = match std::env::var("VPN_ECH_CONFIG") {
        Ok(s) if !s.is_empty() => Some(s),
        _ if censorship_resistant => {
            print!("ECHConfigList (hex, optional - Enter to skip): ");
            stdout.flush()?;
            let input = read_line()?;
            if input.is_empty() {
                None
            } else if shared::hex::decode_hex(&input).is_none() {
                eprintln!("Warning: ECHConfigList hex is invalid - ECH will be disabled");
                None
            } else {
                Some(input)
            }
        }
        _ => None,
    };
    print!("VPN MTU (1280-1360, optional - Enter for default 1280): ");
    stdout.flush()?;
    let vpn_mtu_input = read_line()?;
    let vpn_mtu = if vpn_mtu_input.is_empty() {
        None
    } else {
        match vpn_mtu_input.parse::<u16>() {
            Ok(v) if (1280..=1360).contains(&v) => Some(v),
            _ => {
                eprintln!("Warning: Invalid MTU value - using default (1280)");
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
        refresh_token,
        ech_config,
        vpn_mtu,
    })
}

struct KcPromptResult {
    access_token: String,
    refresh_token: Option<String>,
    url: String,
    realm: String,
    client_id: String,
}

async fn prompt_keycloak_config() -> Result<KcPromptResult> {
    let mut stdout = io::stdout();
    print!("Keycloak Server URL (e.g. https://auth.example.com): ");
    stdout.flush()?;
    let url = read_line()?;
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
    let tokens = oauth::start_oauth_flow(&url, &realm, &client_id).await?;
    println!("Keycloak login complete! Saving configuration...");
    Ok(KcPromptResult {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        url,
        realm,
        client_id,
    })
}

/// Tries to renew the Keycloak access token silently using the stored refresh
/// token. Falls back to an interactive browser login when there is no refresh
/// token or it has been rejected.
async fn refresh_keycloak_or_login(mut config: Config) -> Result<Config> {
    let kc_url = config.kc_url.as_deref().unwrap_or("");
    let realm = config.kc_realm.clone().unwrap_or_else(|| "mavi-vpn".into());
    let client_id = config
        .kc_client_id
        .clone()
        .unwrap_or_else(|| "mavi-client".into());

    if let Some(refresh) = config.refresh_token.as_deref().filter(|r| !r.is_empty()) {
        println!("Refreshing Keycloak session...");
        match shared::kc_oauth::refresh_access_token(kc_url, &realm, &client_id, refresh).await {
            RefreshOutcome::Success(tokens) => {
                println!("Session successfully refreshed!");
                config.token = tokens.access_token;
                config.refresh_token = tokens.refresh_token;
                return Ok(config);
            }
            RefreshOutcome::NetworkError(e) => {
                eprintln!("Could not reach Keycloak to refresh session: {e}");
                // Keep the existing tokens; the VPN core will retry.
                return Ok(config);
            }
            RefreshOutcome::NeedsLogin(_) => {
                println!("Stored Keycloak session expired; logging in again...");
                config.refresh_token = None;
            }
        }
    }

    let tokens = oauth::start_oauth_flow(kc_url, &realm, &client_id).await?;
    println!("Keycloak login complete!");
    config.token = tokens.access_token;
    config.refresh_token = tokens.refresh_token;
    Ok(config)
}

pub(crate) fn read_line() -> Result<String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

/// Returns `true` if `input` (already lowercased) is an affirmative answer in
/// English or German (`y`/`yes`/`j`/`ja`).
fn is_affirmative(input: &str) -> bool {
    matches!(input, "y" | "yes" | "j" | "ja")
}
