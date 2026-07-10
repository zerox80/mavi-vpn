//! # Keycloak OAuth2 PKCE Flow
//!
//! Implements the Authorization Code flow with PKCE for Keycloak SSO login.
//! Opens the user's browser, waits for the callback, and exchanges the code
//! for an access token and refresh token.

use anyhow::{Context, Result};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::net::TcpListener;

/// Fixed callback port — register `http://127.0.0.1:18923/callback` in Keycloak.
const OAUTH_CALLBACK_PORT: u16 = 18923;

pub async fn start_oauth_flow(
    kc_url: &str,
    realm: &str,
    client_id: &str,
) -> Result<shared::kc_oauth::OAuthTokens> {
    // Plain-HTTP Keycloak would expose the authorization code and tokens to a
    // MITM; only loopback is exempt (dev setups).
    shared::validate_keycloak_url(kc_url).map_err(|e| anyhow::anyhow!(e))?;

    // 1. Generate PKCE verifier and challenge
    let verifier_bytes: [u8; 32] = rand::random();
    let code_verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifier_bytes);

    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let code_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());

    let state_bytes: [u8; 16] = rand::random();
    let oauth_state = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(state_bytes);

    // 2. Start local TCP listener on fixed port
    let listener = TcpListener::bind(format!("127.0.0.1:{}", OAUTH_CALLBACK_PORT))
        .await
        .context(format!(
            "Could not bind callback port {}. Is another instance running?",
            OAUTH_CALLBACK_PORT
        ))?;
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
        .append_pair("state", &oauth_state)
        // Force Keycloak to ignore an existing SSO cookie and always present the
        // login form. Without this, reconnecting while a previous browser session
        // is still alive makes Keycloak show its "You are already logged in" info
        // page instead of redirecting back to the loopback callback — so no fresh
        // authorization code ever reaches the listener and the reconnect hangs.
        .append_pair("prompt", "login");

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
    println!("\n  Login URL: \x1b[4m{}\x1b[0m\n", url_str);
    if !browser_opened {
        println!("\x1b[33mCould not launch browser. Please open the URL above manually.\x1b[0m\n");
    }
    println!("Waiting for login in browser (timeout: 5 minutes)...");

    // 5. Wait for the redirect callback. The shared listener serves connections
    //    concurrently, so a stray or stalled local probe cannot delay the real
    //    browser callback, and validates `state` in constant time.
    let auth_code = tokio::time::timeout(
        Duration::from_secs(300),
        shared::kc_oauth::recv_oauth_callback(&listener, &oauth_state),
    )
    .await
    .context("Login timeout (5 minutes)")??;

    println!("Login callback received! Fetching access token...");

    // 6. Exchange code for token
    let token_endpoint = format!(
        "{}/realms/{}/protocol/openid-connect/token",
        kc_url.trim_end_matches('/'),
        realm
    );
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
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
        let error_text =
            shared::kc_oauth::read_capped_text(res, shared::kc_oauth::MAX_TOKEN_RESPONSE_BYTES)
                .await
                .unwrap_or_default();
        return Err(anyhow::anyhow!("Token exchange failed: {}", error_text));
    }

    let body = shared::kc_oauth::read_capped_text(res, shared::kc_oauth::MAX_TOKEN_RESPONSE_BYTES)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    shared::kc_oauth::parse_token_response(&body, None)
        .ok_or_else(|| anyhow::anyhow!("Token response missing access_token or refresh_token"))
}

/// Open a URL in the user's default browser.
///
/// When running under `sudo`, desktop-session env vars are stripped, so plain
/// `xdg-open` silently fails on Wayland (GNOME, KDE, etc.).  We detect this
/// via `SUDO_USER` / `SUDO_UID` and re-run xdg-open as the original user
/// with the session environment reconstructed.
fn open_browser_for_user(url: &str) -> bool {
    if let (Ok(sudo_user), Ok(sudo_uid)) = (std::env::var("SUDO_USER"), std::env::var("SUDO_UID")) {
        let runtime_dir = format!("/run/user/{}", sudo_uid);

        // Reconstruct vars that sudo strips but xdg-open/portal needs.
        let wayland_display =
            std::env::var("WAYLAND_DISPLAY").unwrap_or_else(|_| "wayland-0".to_string());
        let display = std::env::var("DISPLAY").unwrap_or_else(|_| ":0".to_string());
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
