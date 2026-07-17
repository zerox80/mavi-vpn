use anyhow::{Context, Result};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::net::TcpListener;

/// Fixed callback port - register `http://127.0.0.1:18923/callback` in Keycloak.
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

    // 5. Wait for the redirect callback. The shared listener serves connections
    //    concurrently, so a stray or stalled local probe cannot delay the real
    //    browser callback, and validates `state` in constant time.
    let auth_code = tokio::time::timeout(
        Duration::from_secs(300),
        shared::kc_oauth::recv_oauth_callback(&listener, &oauth_state),
    )
    .await
    .context("Login Timeout (5 minutes)")??;

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
    let status = res.status();
    if !status.is_success() {
        return Err(token_exchange_error(status));
    }

    let body = shared::kc_oauth::read_capped_text(res, shared::kc_oauth::MAX_TOKEN_RESPONSE_BYTES)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    shared::kc_oauth::parse_token_response(&body, None)
        .ok_or_else(|| anyhow::anyhow!("Token response missing access_token or refresh_token"))
}

fn token_exchange_error(status: reqwest::StatusCode) -> anyhow::Error {
    anyhow::anyhow!("Token exchange failed with HTTP status {status}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_exchange_error_only_reports_status() {
        let error = token_exchange_error(reqwest::StatusCode::UNAUTHORIZED).to_string();

        assert_eq!(
            error,
            "Token exchange failed with HTTP status 401 Unauthorized"
        );
    }
}
