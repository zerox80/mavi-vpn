use anyhow::{Context, Result};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Fixed callback port - register `http://127.0.0.1:18923/callback` in Keycloak.
const OAUTH_CALLBACK_PORT: u16 = 18923;

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[allow(clippy::too_many_lines)]
pub async fn start_oauth_flow(kc_url: &str, realm: &str, client_id: &str) -> Result<shared::kc_oauth::OAuthTokens> {
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

    // 2. Start local TCP listener on fixed port
    let listener = TcpListener::bind(format!("127.0.0.1:{OAUTH_CALLBACK_PORT}"))
        .await
        .context(format!(
            "Could not bind callback port {OAUTH_CALLBACK_PORT}. Is another instance running?"
        ))?;
    let redirect_uri = format!("http://127.0.0.1:{OAUTH_CALLBACK_PORT}/callback");

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
        // page instead of redirecting back to the loopback callback - so no fresh
        // authorization code ever reaches the listener and the reconnect hangs.
        .append_pair("prompt", "login");

    // 4. Open browser
    println!("\nOpening web browser for login...");
    if webbrowser::open(auth_url.as_str()).is_err() {
        println!(
            "Could not open browser automatically. Please manually click this link:\n{}",
            auth_url.as_str()
        );
    }
    println!("Waiting for successful login in browser (Timeout in 5 minutes)...");

    // 5. Wait for callback
    let auth_code = tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            let (mut socket, _) = listener.accept().await?;
            let mut buf = [0u8; 4096];
            let read_bytes = socket.read(&mut buf).await?;
            if read_bytes == 0 { continue; }

            let request = String::from_utf8_lossy(&buf[..read_bytes]);
            let first_line = request.lines().next().unwrap_or("");
            if !first_line.starts_with("GET ") { continue; }

            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() < 2 { continue; }
            let path_and_query = parts[1];

            let parsed_url = url::Url::parse(&format!("http://localhost{path_and_query}")).ok();
            if let Some(u) = parsed_url {
                let returned_state = u.query_pairs().find(|(k, _)| k == "state").map(|(_, v)| v.into_owned());
                if returned_state.as_deref() != Some(oauth_state.as_str()) {
                    let html = "<html><body><h1 style=\"color: red;\">Login failed!</h1><p>OAuth state invalid.</p></body></html>";
                    let response = format!("HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n{html}");
                    let _ = socket.write_all(response.as_bytes()).await;
                    return Err(anyhow::anyhow!("OAuth state mismatch"));
                }

                if let Some(code) = u.query_pairs().find(|(k, _)| k == "code").map(|(_, v)| v.into_owned()) {
                    let html = "<html><head><title>Login Successful</title></head><body style=\"font-family: sans-serif; text-align: center; padding-top: 50px;\"><h1 style=\"color: green;\">Login successful!</h1><p>You can now close this window and return to your terminal.</p><script>setTimeout(function(){window.close();}, 3000);</script></body></html>";
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n{html}");
                    let _ = socket.write_all(response.as_bytes()).await;
                    return Ok::<String, anyhow::Error>(code);
                }

                if let Some(err) = u.query_pairs().find(|(k, _)| k == "error").map(|(_, v)| v.into_owned()) {
                    let html = format!("<html><body><h1 style=\"color: red;\">Login failed!</h1><p>Error: {}</p></body></html>", html_escape(&err));
                    let response = format!("HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n{html}");
                    let _ = socket.write_all(response.as_bytes()).await;
                    return Err(anyhow::anyhow!("Keycloak error: {err}"));
                }
            }

            let html = "<html><body><h1>Error</h1><p>Invalid callback.</p></body></html>";
            let response = format!("HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n{html}");
            let _ = socket.write_all(response.as_bytes()).await;
        }
    }).await.context("Login Timeout (5 minutes)")??;

    println!("Login callback received! Retrieving Access Token...");

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
        .context("Connection to Keycloak failed")?;
    if !res.status().is_success() {
        let error_text = res.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Token exchange failed: {error_text}"));
    }

    let body = res.text().await?;
    shared::kc_oauth::parse_token_response(&body, None)
        .ok_or_else(|| anyhow::anyhow!("Token response missing access_token or refresh_token"))
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
    fn html_escape_double_escapes_already_escaped_ampersand() {
        assert_eq!(
            html_escape("<script>alert(\"xss\")&amp;</script>"),
            "&lt;script&gt;alert(&quot;xss&quot;)&amp;amp;&lt;/script&gt;"
        );
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
    fn html_escape_all_special_chars_combined() {
        assert_eq!(
            html_escape("<a href=\"x\" & b='y'>"),
            "&lt;a href=&quot;x&quot; &amp; b='y'&gt;"
        );
    }

    #[test]
    fn html_escape_preserves_whitespace() {
        assert_eq!(html_escape("  hello\nworld\t"), "  hello\nworld\t");
    }

    #[test]
    fn html_escape_unicode_passthrough() {
        assert_eq!(html_escape("Hello 世界 🌍"), "Hello 世界 🌍");
    }

    #[test]
    fn html_escape_single_quote_not_escaped() {
        assert_eq!(html_escape("it's fine"), "it's fine");
    }

    #[test]
    fn html_escape_consecutive_special_chars() {
        assert_eq!(html_escape("<<<>>>"), "&lt;&lt;&lt;&gt;&gt;&gt;");
    }

    #[test]
    fn html_escape_only_ampersands() {
        assert_eq!(html_escape("&&&"), "&amp;&amp;&amp;");
    }

    #[test]
    fn html_escape_only_angle_brackets() {
        assert_eq!(html_escape("<><>"), "&lt;&gt;&lt;&gt;");
    }

    #[test]
    fn html_escape_only_quotes() {
        assert_eq!(html_escape("\"\"\""), "&quot;&quot;&quot;");
    }

    #[test]
    fn html_escape_newlines_with_special_chars() {
        assert_eq!(
            html_escape("line1\n<line2>\n&line3"),
            "line1\n&lt;line2&gt;\n&amp;line3"
        );
    }

    #[test]
    fn html_escape_tabs_with_special_chars() {
        assert_eq!(
            html_escape("col1\t<col2>\t&col3"),
            "col1\t&lt;col2&gt;\t&amp;col3"
        );
    }

    #[test]
    fn html_escape_long_string() {
        let long_input = "a".repeat(10000);
        let result = html_escape(&long_input);
        assert_eq!(result.len(), 10000);
        assert_eq!(result, long_input);
    }

    #[test]
    fn html_escape_long_string_with_special_chars() {
        let long_input = "<a>".repeat(1000);
        let result = html_escape(&long_input);
        assert_eq!(result, "&lt;a&gt;".repeat(1000));
    }

    #[test]
    fn html_escape_mixed_whitespace_and_special() {
        assert_eq!(
            html_escape("  <tag>  &  \"value\"  "),
            "  &lt;tag&gt;  &amp;  &quot;value&quot;  "
        );
    }
}
