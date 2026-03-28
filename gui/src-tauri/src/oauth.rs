use anyhow::{Context, Result};
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::sync::oneshot;

/// Fixed callback port so the redirect URI is predictable and can be registered
/// once in Keycloak: `http://127.0.0.1:18923/callback`
const OAUTH_CALLBACK_PORT: u16 = 18923;

static CANCEL_TX: Mutex<Option<oneshot::Sender<()>>> = Mutex::const_new(None);

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: Option<String>,
}

/// Run the Keycloak PKCE OAuth2 flow in the user's browser session.
///
/// This must be called from the GUI process (not the service) because it needs
/// to open a browser window in the user's desktop session.
/// Returns the TokenPair on success.
pub async fn start_oauth_flow(kc_url: &str, realm: &str, client_id: &str) -> Result<TokenPair> {
    // 0. Setup cancellation of any previous flow
    let (tx, mut cancel_rx) = oneshot::channel::<()>();
    {
        let mut tx_lock = CANCEL_TX.lock().await;
        if let Some(old_tx) = tx_lock.replace(tx) {
            let _ = old_tx.send(());
        }
    }

    // 1. Generate PKCE verifier and challenge
    let mut verifier_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut verifier_bytes);
    let code_verifier =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&verifier_bytes);

    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let code_challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());

    // 2. Bind the fixed callback port, retrying if necessary (in case the old one closing takes a moment)
    let mut listener = None;
    for _ in 0..15 {
        if let Ok(socket) = tokio::net::TcpSocket::new_v4() {
            let _ = socket.set_reuseaddr(true);
            let addr = format!("127.0.0.1:{}", OAUTH_CALLBACK_PORT).parse().unwrap();
            
            if let Ok(_) = socket.bind(addr) {
                if let Ok(l) = socket.listen(1024) {
                    listener = Some(l);
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let listener = listener.context(format!(
        "Could not bind callback port {}. Is another instance running?",
        OAUTH_CALLBACK_PORT
    ))?;

    let redirect_uri = format!("http://127.0.0.1:{}/callback", OAUTH_CALLBACK_PORT);

    // 3. Build the Keycloak authorization URL
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
        .append_pair("scope", "openid offline_access")
        .append_pair("code_challenge", &code_challenge)
        .append_pair("code_challenge_method", "S256");

    // 4. Open the browser (works on Windows and Linux/Wayland via xdg-open)
    let url_str = auth_url.as_str().to_string();
    open_browser(&url_str);

    // 5. Wait for the redirect callback (5 minute timeout)
    let auth_code = tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            tokio::select! {
                _ = &mut cancel_rx => {
                    return Err(anyhow::anyhow!("Cancelled by new login attempt"));
                }
                accept_res = listener.accept() => {
                    let (mut socket, _) = accept_res?;
                    let mut buf = [0u8; 4096];
                    let n = socket.read(&mut buf).await?;
                    if n == 0 {
                        continue;
                    }

                    let request = String::from_utf8_lossy(&buf[..n]);
                    let first_line = request.lines().next().unwrap_or("");
                    if !first_line.starts_with("GET ") {
                        continue;
                    }

                    let path = first_line.split_whitespace().nth(1).unwrap_or("/");
                    let parsed =
                        url::Url::parse(&format!("http://localhost{}", path)).ok();

                    if let Some(u) = parsed {
                        if let Some(code) = u
                            .query_pairs()
                            .find(|(k, _)| k == "code")
                            .map(|(_, v)| v.into_owned())
                        {
                            let html = "<html><head><title>Login successful</title></head>\
                                <body style='font-family:sans-serif;text-align:center;padding-top:50px'>\
                                <h1 style='color:green'>Login successful!</h1>\
                                <p>You can close this window and return to Mavi VPN.</p>\
                                <script>setTimeout(()=>window.close(),3000)</script></body></html>";
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n{}",
                                html
                            );
                            let _ = socket.write_all(resp.as_bytes()).await;
                            return Ok::<String, anyhow::Error>(code);
                        }

                        if let Some(err) = u
                            .query_pairs()
                            .find(|(k, _)| k == "error")
                            .map(|(_, v)| v.into_owned())
                        {
                            let html = format!(
                                "<html><body><h1 style='color:red'>Login failed</h1><p>{}</p></body></html>",
                                err
                            );
                            let resp = format!(
                                "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n{}",
                                html
                            );
                            let _ = socket.write_all(resp.as_bytes()).await;
                            return Err(anyhow::anyhow!("Keycloak error: {}", err));
                        }
                    }
                }
            }
        }
    })
    .await
    .context("Login timed out (5 minutes)")??;

    // 6. Exchange the authorization code for an access token
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
        ("code", auth_code.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("code_verifier", code_verifier.as_str()),
    ];
    let res = client
        .post(&token_endpoint)
        .form(&params)
        .send()
        .await
        .context("Could not reach Keycloak token endpoint")?;

    if !res.status().is_success() {
        let body = res.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Token exchange failed: {}", body));
    }

    let json: serde_json::Value = res.json().await?;
    let access_token = json["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No access_token in response"))?
        .to_string();
    
    let refresh_token = json["refresh_token"].as_str().map(|s| s.to_string());

    Ok(TokenPair {
        access_token,
        refresh_token,
    })
}

/// Open a URL in the default browser.
/// On Windows, running a VPN client requires Administrator privileges. Standard tools like `webbrowser::open`
/// or `cmd /c start` will fail to send IPC messages to an existing, non-elevated browser process.
/// Calling `explorer.exe <url>` bridges this gap by routing the request through the desktop shell.
fn open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    {
        // explorer requires URLs containing '&' to be quoted, but spawn() handles shell escaping.
        let _ = std::process::Command::new("explorer")
            .arg(url)
            .spawn();
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = webbrowser::open(url);
    }
}

/// Attempt to silently refresh the access token using a previously saved refresh token.
pub async fn refresh_oauth_token(
    kc_url: &str,
    realm: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<TokenPair> {
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
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ];

    let res = client
        .post(&token_endpoint)
        .form(&params)
        .send()
        .await
        .context("Could not reach Keycloak to refresh token")?;

    if !res.status().is_success() {
        let body = res.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Token refresh failed: {}", body));
    }

    let json: serde_json::Value = res.json().await?;
    let access_token = json["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No access_token in refresh response"))?
        .to_string();

    let new_refresh_token = json["refresh_token"].as_str().map(|s| s.to_string());

    Ok(TokenPair {
        access_token,
        refresh_token: new_refresh_token.or_else(|| Some(refresh_token.to_string())),
    })
}
