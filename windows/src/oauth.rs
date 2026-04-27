use anyhow::{Context, Result};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Fixed callback port — register `http://127.0.0.1:18923/callback` in Keycloak.
const OAUTH_CALLBACK_PORT: u16 = 18923;

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub async fn start_oauth_flow(kc_url: &str, realm: &str, client_id: &str) -> Result<String> {
    // 1. Generate PKCE verifier and challenge
    let verifier_bytes: [u8; 32] = rand::random();
    let code_verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifier_bytes);

    let state_bytes: [u8; 32] = rand::random();
    let oauth_state = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(state_bytes);

    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let code_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());

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
        .append_pair("state", &oauth_state);

    // 4. Open browser
    println!("\nÖffne Webbrowser für den Login...");
    if webbrowser::open(auth_url.as_str()).is_err() {
        println!(
            "Konnte Browser nicht automatisch öffnen. Bitte klicke manuell auf diesen Link:\n{}",
            auth_url.as_str()
        );
    }
    println!("Warte auf erfolgreichen Login im Browser (Timeout in 5 Minuten)...");

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

            let parsed_url = url::Url::parse(&format!("http://localhost{}", path_and_query)).ok();
            if let Some(u) = parsed_url {
                let returned_state = u.query_pairs().find(|(k, _)| k == "state").map(|(_, v)| v.into_owned());
                if returned_state.as_deref() != Some(oauth_state.as_str()) {
                    let html = "<html><body><h1 style=\"color: red;\">Login fehlgeschlagen!</h1><p>OAuth state ungültig.</p></body></html>";
                    let response = format!("HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n{}", html);
                    let _ = socket.write_all(response.as_bytes()).await;
                    return Err(anyhow::anyhow!("OAuth state mismatch"));
                }

                if let Some(code) = u.query_pairs().find(|(k, _)| k == "code").map(|(_, v)| v.into_owned()) {
                    let html = "<html><head><title>Login Erfolgreich</title></head><body style=\"font-family: sans-serif; text-align: center; padding-top: 50px;\"><h1 style=\"color: green;\">Login erfolgreich!</h1><p>Du kannst dieses Fenster jetzt schliessen und in dein Terminal zurueckkehren.</p><script>setTimeout(function(){window.close();}, 3000);</script></body></html>";
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n{}", html);
                    let _ = socket.write_all(response.as_bytes()).await;
                    return Ok::<String, anyhow::Error>(code);
                }

                if let Some(err) = u.query_pairs().find(|(k, _)| k == "error").map(|(_, v)| v.into_owned()) {
                    let html = format!("<html><body><h1 style=\"color: red;\">Login fehlgeschlagen!</h1><p>Fehler: {}</p></body></html>", html_escape(&err));
                    let response = format!("HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n{}", html);
                    let _ = socket.write_all(response.as_bytes()).await;
                    return Err(anyhow::anyhow!("Keycloak Fehler: {}", err));
                }
            }

            let html = "<html><body><h1>Fehler</h1><p>Ungueltiger Callback.</p></body></html>";
            let response = format!("HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n{}", html);
            let _ = socket.write_all(response.as_bytes()).await;
        }
    }).await.context("Login Timeout (5 Minuten)")??;

    println!("Login Callback empfangen! Hole Access Token...");

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
        .context("Verbindung zu Keycloak fehlgeschlagen")?;
    if !res.status().is_success() {
        let error_text = res.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "Token Exchange fehlgeschlagen: {}",
            error_text
        ));
    }

    let json: serde_json::Value = res.json().await?;
    let access_token = json["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Kein access_token gefunden"))?;

    Ok(access_token.to_string())
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
}
