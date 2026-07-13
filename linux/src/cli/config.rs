use anyhow::Result;
use shared::ipc::Config;
use shared::split_tunnel::SplitTunnelMode;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

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

fn load_config(path: &Path) -> Option<Config> {
    if path.exists() {
        let content = std::fs::read_to_string(path).ok()?;
        let mut config: Config = serde_json::from_str(&content).ok()?;
        config.normalize_transport();
        Some(config)
    } else {
        None
    }
}

fn save_config(config: &Config, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut config = config.clone();
    config.normalize_transport();
    let content = serde_json::to_string_pretty(&config)?;
    write_config_file(path, content.as_bytes())?;
    println!("Config saved to {}", path.display());
    Ok(())
}

#[cfg(unix)]
fn write_config_file(path: &Path, content: &[u8]) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    const CONFIG_MODE: u32 = 0o600;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(CONFIG_FILE);
    let pid = std::process::id();

    let mut last_error = None;
    for attempt in 0..100 {
        let tmp_path = parent.join(format!(".{file_name}.{pid}.{attempt}.tmp"));
        let file_result = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(CONFIG_MODE)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp_path);

        let mut file = match file_result {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                last_error = Some(e);
                continue;
            }
            Err(e) => return Err(e.into()),
        };

        let write_result = file
            .write_all(content)
            .and_then(|()| file.sync_all())
            .and_then(|()| {
                std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(CONFIG_MODE))
            })
            .and_then(|()| std::fs::rename(&tmp_path, path));

        if let Err(e) = write_result {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e.into());
        }

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(CONFIG_MODE))?;
        return Ok(());
    }

    Err(last_error
        .unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::AlreadyExists, "could not create temp config")
        })
        .into())
}

#[cfg(not(unix))]
fn write_config_file(path: &Path, content: &[u8]) -> Result<()> {
    std::fs::write(path, content)?;
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
                saved.token.chars().take(8).collect::<String>()
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
        println!(
            "  HTTP/2 CONNECT-IP: {}",
            if saved.http2_framing { "Yes" } else { "No" }
        );
        if let Some(mtu) = saved.vpn_mtu {
            println!("  VPN MTU: {}", mtu);
        }
        println!("  Split tunnel: {:?}", saved.split_tunnel_mode);
        println!();

        print!("Use this configuration? [Y/n]: ");
        io::stdout().flush()?;
        let input = read_line()?.to_lowercase();

        if input.is_empty() || input == "y" || input == "yes" {
            if saved.kc_auth.unwrap_or(false) {
                saved = refresh_keycloak_or_login(saved).await?;
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
            shared::kc_oauth::RefreshOutcome::Success(tokens) => {
                println!("Session refreshed!");
                config.token = tokens.access_token;
                config.refresh_token = tokens.refresh_token;
                return Ok(config);
            }
            shared::kc_oauth::RefreshOutcome::NetworkError(e) => {
                eprintln!("Could not reach Keycloak to refresh session: {e}");
                // Keep the existing token and refresh token; the VPN core will retry.
                return Ok(config);
            }
            shared::kc_oauth::RefreshOutcome::NeedsLogin(_) => {
                println!("Stored Keycloak session expired; logging in again...");
                config.refresh_token = None;
            }
        }
    }

    let tokens = crate::oauth::start_oauth_flow(kc_url, &realm, &client_id).await?;
    println!("Keycloak login successful!");
    config.token = tokens.access_token;
    config.refresh_token = tokens.refresh_token;
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
    let refresh_token;
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

        let tokens = crate::oauth::start_oauth_flow(&kc_url, &realm, &client_id).await?;
        println!("Keycloak login successful!");
        token = tokens.access_token;
        refresh_token = tokens.refresh_token;

        saved_kc_url = Some(kc_url);
        saved_kc_realm = Some(realm);
        saved_kc_client_id = Some(client_id);
    } else {
        print!("Preshared Key: ");
        stdout.flush()?;
        token = read_line()?;
        refresh_token = None;
    }

    print!("Certificate PIN (SHA256 hex): ");
    stdout.flush()?;
    let cert_pin = read_line()?;

    print!("Use HTTP/2 CONNECT-IP over TCP (beta)? [y/N]: ");
    stdout.flush()?;
    let http2_input = read_line()?.to_lowercase();
    let http2_framing = http2_input == "y" || http2_input == "yes";
    let (censorship_resistant, http3_framing) = if http2_framing {
        println!("HTTP/2 uses reliable TCP capsules; HTTP/3 framing and CR mode are disabled.");
        (false, false)
    } else {
        print!("Censorship resistant mode? [y/N]: ");
        stdout.flush()?;
        let cr_input = read_line()?.to_lowercase();
        let censorship_resistant = cr_input == "y" || cr_input == "yes";
        let http3_framing = if censorship_resistant {
            println!("HTTP/3 Framing is required for CR mode and was enabled automatically.");
            true
        } else {
            print!("HTTP/3 Framing (CONNECT-IP/H3)? [y/N]: ");
            stdout.flush()?;
            let h3_input = read_line()?.to_lowercase();
            h3_input == "y" || h3_input == "yes"
        };
        (censorship_resistant, http3_framing)
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

    let (split_tunnel_mode, split_tunnel_targets) = prompt_split_tunnel(&mut stdout)?;

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
        http2_framing,
        split_tunnel_mode,
        split_tunnel_targets,
    })
}

fn prompt_split_tunnel(stdout: &mut impl Write) -> Result<(SplitTunnelMode, Vec<String>)> {
    print!("Desktop split tunnel [off/include/exclude] (default: off): ");
    stdout.flush()?;
    let mode = match read_line()?.to_lowercase().as_str() {
        "include" | "in" => SplitTunnelMode::Include,
        "exclude" | "ex" => SplitTunnelMode::Exclude,
        _ => SplitTunnelMode::Disabled,
    };
    if mode == SplitTunnelMode::Disabled {
        return Ok((mode, Vec::new()));
    }

    print!("Domains, IPs, or CIDRs (comma-separated): ");
    stdout.flush()?;
    let targets = read_line()?
        .split(',')
        .map(str::trim)
        .filter(|target| !target.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if targets.is_empty() {
        anyhow::bail!("Split tunneling requires at least one domain, IP, or CIDR");
    }
    Ok((mode, targets))
}

fn read_line() -> Result<String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn save_config_replaces_symlink_without_touching_target() -> Result<()> {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp = tempfile::tempdir()?;
        let config_path = temp.path().join("mavi-vpn.json");
        let symlink_target = temp.path().join("target.json");
        std::fs::write(&symlink_target, "do-not-overwrite")?;
        symlink(&symlink_target, &config_path)?;

        save_config(&sample_config(), &config_path)?;

        assert!(!std::fs::symlink_metadata(&config_path)?
            .file_type()
            .is_symlink());
        assert_eq!(
            std::fs::read_to_string(&symlink_target)?,
            "do-not-overwrite"
        );
        let mode = std::fs::metadata(&config_path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        Ok(())
    }

    fn sample_config() -> Config {
        Config {
            endpoint: "vpn.example.com:443".to_string(),
            token: "access-token".to_string(),
            cert_pin: "pin".to_string(),
            censorship_resistant: false,
            http3_framing: false,
            kc_auth: Some(true),
            kc_url: Some("https://auth.example.com".to_string()),
            kc_realm: Some("mavi-vpn".to_string()),
            kc_client_id: Some("mavi-client".to_string()),
            refresh_token: Some("refresh-token".to_string()),
            ech_config: None,
            vpn_mtu: None,
            http2_framing: false,
            split_tunnel_mode: SplitTunnelMode::Disabled,
            split_tunnel_targets: Vec::new(),
        }
    }
}
