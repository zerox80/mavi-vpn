use anyhow::{Context, Result};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Fixed callback port so the redirect URI is predictable and can be registered
/// once in Keycloak: `http://127.0.0.1:18923/callback`
const OAUTH_CALLBACK_PORT: u16 = 18923;

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Run the Keycloak PKCE `OAuth2` flow in the user's browser session.
///
/// This must be called from the GUI process (not the service) because it needs
/// to open a browser window in the user's desktop session.
/// Returns the access **and** refresh tokens on success; the refresh token lets
/// the GUI renew the short-lived access token silently (no browser) later.
#[allow(clippy::too_many_lines)]
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

    let state_bytes: [u8; 32] = rand::random();
    let oauth_state = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(state_bytes);

    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let code_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());

    // 2. Bind the fixed callback port
    let listener = TcpListener::bind(format!("127.0.0.1:{OAUTH_CALLBACK_PORT}"))
        .await
        .context(format!(
            "Could not bind callback port {OAUTH_CALLBACK_PORT}. Is another instance running?"
        ))?;
    let redirect_uri = format!("http://127.0.0.1:{OAUTH_CALLBACK_PORT}/callback");

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
        .append_pair("scope", "openid")
        .append_pair("code_challenge", &code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", &oauth_state)
        // Force Keycloak to ignore an existing SSO cookie and always present the
        // login form. Without this, reconnecting while a previous browser session
        // is still alive makes Keycloak show its "You are already logged in" info
        // page instead of redirecting back to the loopback callback — so no fresh
        // authorization code ever reaches the listener and the reconnect hangs.
        // The Android client sets the same parameter for the same reason.
        .append_pair("prompt", "login");

    // 4. Open the browser (works on Windows and Linux/Wayland via xdg-open)
    let url_str = auth_url.as_str().to_string();
    open_browser(&url_str);

    // 5. Wait for the redirect callback (5 minute timeout)
    let auth_code = tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            let (mut socket, _) = listener.accept().await?;
            let Some((state, code, error)) = read_callback_params(&mut socket).await? else {
                continue;
            };

            match shared::kc_oauth::classify_oauth_callback(
                state.as_deref(),
                code.as_deref(),
                error.as_deref(),
                &oauth_state,
            ) {
                shared::kc_oauth::CallbackOutcome::Code(code) => {
                    let html = "<html><head><title>Login successful</title></head>\
                        <body style='font-family:sans-serif;text-align:center;padding-top:50px'>\
                        <h1 style='color:green'>Login successful!</h1>\
                        <p>You can close this window and return to Mavi VPN.</p>\
                        <script>setTimeout(()=>window.close(),3000)</script></body></html>";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n{html}"
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                    return Ok::<String, anyhow::Error>(code);
                }
                shared::kc_oauth::CallbackOutcome::Error(err) => {
                    let html = format!(
                        "<html><body><h1 style='color:red'>Login failed</h1><p>{}</p></body></html>",
                        html_escape(&err)
                    );
                    let resp = format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n{html}"
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                    return Err(anyhow::anyhow!("Keycloak error: {err}"));
                }
                shared::kc_oauth::CallbackOutcome::StateMismatch => {
                    let html = "<html><body><h1 style='color:red'>Login failed</h1><p>OAuth state invalid.</p></body></html>";
                    let resp = format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n{html}"
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                    return Err(anyhow::anyhow!("OAuth state mismatch"));
                }
                shared::kc_oauth::CallbackOutcome::Ignore => {
                    // Stray request (e.g. favicon) — answer politely, keep waiting.
                    let _ = socket
                        .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                        .await;
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
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
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
        return Err(anyhow::anyhow!("Token exchange failed: {body}"));
    }

    let body = res
        .text()
        .await
        .context("Failed to read Keycloak token response")?;
    shared::kc_oauth::parse_token_response(&body, None)
        .ok_or_else(|| anyhow::anyhow!("Token response missing access_token"))
}

/// Open a URL in the default browser (cross-platform via `webbrowser` crate).
fn open_browser(url: &str) {
    let _ = webbrowser::open(url);
}

/// Reads one loopback HTTP callback request and extracts its `(state, code,
/// error)` query parameters.
///
/// Reads the full request head — up to the blank-line terminator or
/// [`shared::kc_oauth::MAX_CALLBACK_REQUEST_BYTES`] — rather than a single
/// fixed-size read, so a callback split across TCP segments is not parsed
/// half-formed. Returns `Ok(None)` for an empty connection or a request that is
/// not a parseable `GET` callback (the caller should keep listening).
#[allow(clippy::type_complexity)]
async fn read_callback_params(
    socket: &mut tokio::net::TcpStream,
) -> Result<Option<(Option<String>, Option<String>, Option<String>)>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = socket.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if shared::kc_oauth::http_request_head_complete(&buf)
            || buf.len() >= shared::kc_oauth::MAX_CALLBACK_REQUEST_BYTES
        {
            break;
        }
    }
    if buf.is_empty() {
        return Ok(None);
    }

    let request = String::from_utf8_lossy(&buf);
    let Some(target) = shared::kc_oauth::callback_request_target(&request) else {
        return Ok(None);
    };
    let Ok(u) = url::Url::parse(&format!("http://localhost{target}")) else {
        return Ok(None);
    };

    let find = |key: &str| {
        u.query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    };
    Ok(Some((find("state"), find("code"), find("error"))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_empty() {
        assert_eq!(html_escape(""), "");
    }

    #[test]
    fn html_escape_no_special_chars() {
        assert_eq!(html_escape("hello world"), "hello world");
    }

    #[test]
    fn html_escape_angle_brackets() {
        assert_eq!(html_escape("a<b>c"), "a&lt;b&gt;c");
    }

    #[test]
    fn html_escape_ampersand() {
        assert_eq!(html_escape("a&b"), "a&amp;b");
    }

    #[test]
    fn html_escape_quotes() {
        assert_eq!(html_escape("say \"hello\""), "say &quot;hello&quot;");
    }

    #[test]
    fn html_escape_double_escapes_already_escaped_ampersand() {
        assert_eq!(
            html_escape("<script>alert(\"xss\")&amp;</script>"),
            "&lt;script&gt;alert(&quot;xss&quot;)&amp;amp;&lt;/script&gt;"
        );
    }
}
