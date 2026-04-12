//! # Keycloak OAuth2 PKCE Flow
//!
//! Implements the Authorization Code flow with PKCE for Keycloak SSO login.
//! Opens the user's browser, waits for the callback, and exchanges the code
//! for an access token.

use anyhow::{Context, Result};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Fixed callback port — register `http://127.0.0.1:18923/callback` in Keycloak.
const OAUTH_CALLBACK_PORT: u16 = 18923;

pub async fn start_oauth_flow(kc_url: &str, realm: &str, client_id: &str) -> Result<String> {
    // 1. Generate PKCE verifier and challenge
    let verifier_bytes: [u8; 32] = rand::random();
    let code_verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&verifier_bytes);

    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let code_challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());

    let state_bytes: [u8; 16] = rand::random();
    let oauth_state = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&state_bytes);

    // 2. Start local TCP listener on fixed port
    let listener = TcpListener::bind(format!("127.0.0.1:{}", OAUTH_CALLBACK_PORT))
        .await
        .context(format!("Could not bind callback port {}. Is another instance running?", OAUTH_CALLBACK_PORT))?;
    let redirect_uri = format!("http://127.0.0.1:{}/callback", OAUTH_CALLBACK_PORT);

    // 3. Construct Authorization URL
    let auth_endpoint = format!(
        "{}/realms/{}/protocol/openid-connect/auth",
        kc_url.trim_end_matches('/'),
        realm
    );
    let mut auth_url = url::Url::parse(&auth_endpoint)?;
    auth_url
        .query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", "openid")
        .append_pair("code_challenge", &code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", &oauth_state);

    // 4. Open browser
    //    Under `sudo` the desktop-session env vars (WAYLAND_DISPLAY,
    //    XDG_RUNTIME_DIR, DBUS_SESSION_BUS_ADDRESS) are stripped, so plain
    //    `xdg-open` silently fails on Wayland/GNOME.  We detect sudo and
    //    re-launch xdg-open as the original user with the session env
    //    reconstructed.
    let url_str = auth_url.as_str();
    println!("\nOpening web browser for login...");
    let browser_opened = open_browser_for_user(url_str);

    // Always show the URL — xdg-open can silently fail even when spawn()
    // returns Ok (e.g. missing portal, wrong session).
    println!(
        "\n  Login URL: \x1b[4m{}\x1b[0m\n",
        url_str
    );
    if !browser_opened {
        println!("\x1b[33mCould not launch browser. Please open the URL above manually.\x1b[0m\n");
    }
    println!("Waiting for login in browser (timeout: 5 minutes)...");

    // 5. Wait for callback
    let auth_code = tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            let (mut socket, _) = listener.accept().await?;
            let mut buf = [0u8; 4096];
            let read_bytes = socket.read(&mut buf).await?;
            if read_bytes == 0 {
                continue;
            }

            let request = String::from_utf8_lossy(&buf[..read_bytes]);
            let first_line = request.lines().next().unwrap_or("");
            if !first_line.starts_with("GET ") {
                continue;
            }

            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let path_and_query = parts[1];

            let parsed_url = url::Url::parse(&format!("http://localhost{}", path_and_query)).ok();
            if let Some(u) = parsed_url {
                let returned_state = u.query_pairs().find(|(k, _)| k == "state").map(|(_, v)| v.into_owned());
                if returned_state.as_deref() != Some(oauth_state.as_str()) {
                    continue;
                }
                if let Some(code) = u
                    .query_pairs()
                    .find(|(k, _)| k == "code")
                    .map(|(_, v)| v.into_owned())
                {
                    let html = "<html><head><title>Login Successful</title></head>\
                        <body style=\"font-family: sans-serif; text-align: center; padding-top: 50px;\">\
                        <h1 style=\"color: green;\">Login successful!</h1>\
                        <p>You can close this window and return to your terminal.</p>\
                        <script>setTimeout(function(){window.close();}, 3000);</script>\
                        </body></html>";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n{}",
                        html
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    return Ok::<String, anyhow::Error>(code);
                }

                if let Some(err) = u
                    .query_pairs()
                    .find(|(k, _)| k == "error")
                    .map(|(_, v)| v.into_owned())
                {
                    let html = format!(
                        "<html><body><h1 style=\"color: red;\">Login failed!</h1><p>Error: {}</p></body></html>",
                        html_escape(&err)
                    );
                    let response = format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n{}",
                        html
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    return Err(anyhow::anyhow!("Keycloak error: {}", err));
                }
            }

            let html =
                "<html><body><h1>Error</h1><p>Invalid callback.</p></body></html>";
            let response = format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n{}",
                html
            );
            let _ = socket.write_all(response.as_bytes()).await;
        }
    })
    .await
    .context("Login timeout (5 minutes)")??;

    println!("Login callback received! Fetching access token...");

    // 6. Exchange code for token
    let token_endpoint = format!(
        "{}/realms/{}/protocol/openid-connect/token",
        kc_url.trim_end_matches('/'),
        realm
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let params = [
        ("client_id", client_id),
        ("grant_type", "authorization_code"),
        ("code", &auth_code),
        ("redirect_uri", &redirect_uri),
        ("code_verifier", &code_verifier),
    ];

    let res = client
        .post(&token_endpoint)
        .form(&params)
        .send()
        .await
        .context("Failed to connect to Keycloak")?;
    if !res.status().is_success() {
        let error_text = res.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Token exchange failed: {}", error_text));
    }

    let json: serde_json::Value = res.json().await?;
    let access_token = json["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No access_token in response"))?;

    Ok(access_token.to_string())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Open a URL in the user's default browser.
///
/// When running under `sudo`, desktop-session env vars are stripped, so plain
/// `xdg-open` silently fails on Wayland (GNOME, KDE, etc.).  We detect this
/// via `SUDO_USER` / `SUDO_UID` and re-run xdg-open as the original user
/// with the session environment reconstructed.
fn open_browser_for_user(url: &str) -> bool {
    if let (Ok(sudo_user), Ok(sudo_uid)) = (
        std::env::var("SUDO_USER"),
        std::env::var("SUDO_UID"),
    ) {
        let runtime_dir = format!("/run/user/{}", sudo_uid);

        // Reconstruct vars that sudo strips but xdg-open/portal needs.
        let wayland_display = std::env::var("WAYLAND_DISPLAY")
            .unwrap_or_else(|_| "wayland-0".to_string());
        let display = std::env::var("DISPLAY")
            .unwrap_or_else(|_| ":0".to_string());
        let dbus_addr = std::env::var("DBUS_SESSION_BUS_ADDRESS")
            .unwrap_or_else(|_| format!("unix:path={}/bus", runtime_dir));

        // runuser (util-linux) switches to the target user without a full
        // login session — we supply the env vars explicitly via `env`.
        if std::process::Command::new("runuser")
            .args(["-u", &sudo_user, "--"])
            .arg("env")
            .arg(format!("XDG_RUNTIME_DIR={}", runtime_dir))
            .arg(format!("WAYLAND_DISPLAY={}", wayland_display))
            .arg(format!("DISPLAY={}", display))
            .arg(format!("DBUS_SESSION_BUS_ADDRESS={}", dbus_addr))
            .arg("xdg-open")
            .arg(url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .is_ok()
        {
            return true;
        }
    }

    // Not under sudo, or runuser failed — try plain xdg-open.
    std::process::Command::new("xdg-open")
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
}
