use anyhow::Result;
use shared::ipc::Config;
use std::io::{self, Write};
use std::path::PathBuf;

const CONFIG_FILE: &str = "mavi-vpn.json";

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
        let mut config: Config = serde_json::from_str(&content).ok()?;
        config.normalize_transport();
        Some(config)
    } else {
        None
    }
}

fn save_config(config: &Config, path: &PathBuf) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut config = config.clone();
    config.normalize_transport();
    let content = serde_json::to_string_pretty(&config)?;
    std::fs::write(path, content)?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    println!("Config saved to {}", path.display());
    Ok(())
}

pub async fn load_or_prompt_config(explicit_path: Option<PathBuf>) -> Result<Config> {
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
            println!("  VPN MTU: {}", mtu);
        }
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
                let fresh_token = crate::oauth::start_oauth_flow(kc_url, realm, client_id).await?;
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

        token = crate::oauth::start_oauth_flow(&kc_url, &realm, &client_id).await?;
        println!("Keycloak login successful!");

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

    print!("Censorship resistant mode? [y/N]: ");
    stdout.flush()?;
    let cr_input = read_line()?.to_lowercase();
    let censorship_resistant = cr_input == "y" || cr_input == "yes";

    let http3_framing = if censorship_resistant {
        println!("HTTP/3 Framing is required for CR mode and was enabled automatically.");
        true
    } else {
        print!("HTTP/3 Framing (RFC 9297)? [y/N]: ");
        stdout.flush()?;
        let h3_input = read_line()?.to_lowercase();
        h3_input == "y" || h3_input == "yes"
    };

    // Optional hex-encoded ECHConfigList. Prefer $VPN_ECH_CONFIG, fall back to
    // an interactive prompt when CR mode is on.
    let ech_config = match std::env::var("VPN_ECH_CONFIG") {
        Ok(s) if !s.is_empty() => Some(s),
        _ if censorship_resistant => {
            print!("ECHConfigList (hex, optional – press Enter to skip): ");
            stdout.flush()?;
            let input = read_line()?;
            if input.is_empty() {
                None
            } else if shared::hex::decode_hex(&input).is_none() {
                eprintln!("Warning: ECHConfigList hex is invalid (odd length or non-hex chars) — ECH will be disabled");
                None
            } else {
                Some(input)
            }
        }
        _ => None,
    };

    print!("VPN MTU (1280–1360, optional – press Enter for default 1280): ");
    stdout.flush()?;
    let vpn_mtu_input = read_line()?;
    let vpn_mtu = if vpn_mtu_input.is_empty() {
        None
    } else {
        match vpn_mtu_input.parse::<u16>() {
            Ok(v) if (1280..=1360).contains(&v) => Some(v),
            _ => {
                eprintln!("Warning: Invalid MTU value — using default (1280)");
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
