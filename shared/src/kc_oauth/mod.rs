//! # Keycloak OAuth2 client helpers (desktop clients only)
//!
//! Shared, dependency-light logic for the Keycloak access/refresh token
//! lifecycle on the desktop clients (GUI + CLIs). Mirrors the Android
//! `OAuthHelper`/`KeycloakTokenManager` design so all platforms behave
//! identically:
//!
//! - parse the token endpoint response (with refresh-token fallback),
//! - read a JWT's `exp` and decide whether an access token is still usable,
//! - refresh a short-lived access token via `grant_type=refresh_token`,
//!   classifying the outcome into *usable again*, *temporary/network failure*
//!   (keep the session, retry) and *needs interactive login* (refresh rejected),
//! - the loopback PKCE callback (parsing in [`callback`], the concurrent
//!   listener in [`server`]).
//!
//! This module is gated behind the `oauth-client` cargo feature so the backend
//! (which only validates tokens) never pulls in a HTTP client.

use base64::Engine;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod callback;
mod server;

pub use callback::{
    callback_request_target, classify_oauth_callback, http_request_head_complete,
    read_callback_params, CallbackOutcome, CallbackParams, CALLBACK_READ_TIMEOUT,
    MAX_CALLBACK_REQUEST_BYTES,
};
pub use server::{recv_oauth_callback, CallbackError};

/// Tokens returned by the Keycloak token endpoint. `refresh_token` is optional
/// because not every realm/flow issues one; without it the session simply
/// cannot be renewed silently and the user must log in again on expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
}

/// Outcome of a refresh attempt, mirroring Android's `RefreshResult`.
///
/// The distinction matters for UX: a `NetworkError` is transient (stay
/// connected, keep retrying), while `NeedsLogin` is terminal (the refresh token
/// is dead — the user must re-authenticate in the browser).
#[derive(Debug, Clone)]
pub enum RefreshOutcome {
    Success(OAuthTokens),
    NetworkError(String),
    NeedsLogin(String),
}

fn json_i64(value: &serde_json::Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|v| i64::try_from(v).ok()))
}

/// Maximum size accepted for a Keycloak token-endpoint response body. Real
/// responses (access + refresh + optional id token, all JWTs) are a few KB;
/// this only guards against a compromised/MITMed Keycloak instance streaming
/// an unbounded body into memory. Every platform's token exchange/refresh
/// reads its response through [`read_capped_text`] rather than
/// `Response::text()`/`::json()` directly.
pub const MAX_TOKEN_RESPONSE_BYTES: usize = 256 * 1024;

/// Reads `resp`'s body up to `max_bytes`, one chunk at a time, instead of
/// buffering an unbounded response into memory.
///
/// # Errors
/// Returns `Err` if a read fails, the body is not valid UTF-8, or its total
/// size exceeds `max_bytes`.
pub async fn read_capped_text(mut resp: reqwest::Response, max_bytes: usize) -> Result<String, String> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("failed reading response body: {e}"))?
    {
        if buf.len().saturating_add(chunk.len()) > max_bytes {
            return Err(format!("response body exceeded {max_bytes}-byte limit"));
        }
        buf.extend_from_slice(&chunk);
    }
    String::from_utf8(buf).map_err(|_| "response body was not valid UTF-8".to_string())
}

/// Parses a Keycloak token endpoint JSON body into [`OAuthTokens`].
///
/// When the response omits a `refresh_token` (Keycloak does this on some
/// refresh responses), `fallback_refresh` is reused so a still-valid refresh
/// token is not lost. Returns `None` when there is no usable `access_token`.
#[must_use]
pub fn parse_token_response(body: &str, fallback_refresh: Option<&str>) -> Option<OAuthTokens> {
    let json: serde_json::Value = serde_json::from_str(body).ok()?;
    let access_token = json.get("access_token")?.as_str()?.trim().to_string();
    if access_token.is_empty() {
        return None;
    }

    let refresh_token = json
        .get("refresh_token")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| {
            fallback_refresh
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        });

    Some(OAuthTokens {
        access_token,
        refresh_token,
    })
}

/// Decodes a JWT's `exp` claim (Unix seconds) without verifying the signature.
///
/// The client only needs `exp` to decide when to refresh; signature
/// verification stays the server's job. Returns `None` for a malformed token or
/// a missing/non-positive `exp`.
#[must_use]
pub fn access_token_exp(jwt: &str) -> Option<i64> {
    // header.payload.signature — we only need the middle (base64url, unpadded).
    let payload_b64 = jwt.split('.').nth(1)?.trim_end_matches('=');
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let json: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    json.get("exp").and_then(json_i64).filter(|&exp| exp > 0)
}

/// Returns `true` when `jwt` is non-empty and still valid for at least
/// `skew_secs` more seconds. A larger skew refreshes earlier, leaving headroom
/// for the refresh round-trip and the reconnect.
#[must_use]
pub fn is_access_token_usable(jwt: &str, skew_secs: u64) -> bool {
    if jwt.is_empty() {
        return false;
    }
    match access_token_exp(jwt) {
        Some(exp) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let exp = u64::try_from(exp).unwrap_or(0);
            now.saturating_add(skew_secs) < exp
        }
        None => false,
    }
}

/// Exchanges a refresh token for a fresh access (and rotated refresh) token.
///
/// Classifies failures the same way Android does:
/// - 5xx / transport errors → [`RefreshOutcome::NetworkError`] (keep the session, retry later)
/// - 4xx / unparsable success → [`RefreshOutcome::NeedsLogin`] (refresh token is dead)
///
/// The Keycloak URL is re-validated so a misconfigured `http://` endpoint can
/// never leak the long-lived refresh token to a MITM.
pub async fn refresh_access_token(
    kc_url: &str,
    realm: &str,
    client_id: &str,
    refresh_token: &str,
) -> RefreshOutcome {
    if refresh_token.is_empty() {
        return RefreshOutcome::NeedsLogin("No refresh token available".to_string());
    }
    if let Err(e) = crate::validate_keycloak_url(kc_url) {
        return RefreshOutcome::NeedsLogin(e);
    }

    // reqwest is built with `rustls-no-provider`, so a process-wide crypto
    // provider must be installed first. Idempotent: ignore "already installed".
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let token_endpoint = format!(
        "{}/realms/{}/protocol/openid-connect/token",
        kc_url.trim_end_matches('/'),
        realm
    );

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => return RefreshOutcome::NetworkError(format!("HTTP client build failed: {e}")),
    };

    let params = [
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("refresh_token", refresh_token),
    ];

    match client.post(&token_endpoint).form(&params).send().await {
        Ok(resp) => {
            let status = resp.status();
            let body = read_capped_text(resp, MAX_TOKEN_RESPONSE_BYTES)
                .await
                .unwrap_or_default();
            if status.is_success() {
                parse_token_response(&body, Some(refresh_token)).map_or_else(
                    || {
                        RefreshOutcome::NeedsLogin(
                            "Refresh response missing access token".to_string(),
                        )
                    },
                    RefreshOutcome::Success,
                )
            } else if status.as_u16() >= 500 {
                // Server-side hiccup: do not invalidate the session.
                RefreshOutcome::NetworkError(format!("Keycloak server error (HTTP {status})"))
            } else {
                // 4xx: the refresh token is expired/revoked/invalid.
                RefreshOutcome::NeedsLogin(format!("Refresh rejected by Keycloak (HTTP {status})"))
            }
        }
        Err(e) => RefreshOutcome::NetworkError(format!("Refresh request failed: {e}")),
    }
}

/// Minimal HTML-escaping for text interpolated into a loopback callback response
/// page (e.g. a Keycloak `error` string). Escapes `& < > "` — the characters
/// that could otherwise break out of the surrounding element or attribute.
pub(crate) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    /// Spawns a one-shot HTTP server on loopback that replies with `body` and
    /// returns its address, mirroring the real Keycloak token endpoint shape
    /// closely enough to drive a real `reqwest::Response` through
    /// `read_capped_text`.
    async fn serve_once(body: &'static str) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(response.as_bytes()).await;
        });
        addr
    }

    #[tokio::test]
    async fn read_capped_text_accepts_body_within_limit() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let addr = serve_once("hello").await;
        let resp = reqwest::get(format!("http://{addr}/")).await.unwrap();

        assert_eq!(read_capped_text(resp, 1024).await.unwrap(), "hello");
    }

    #[tokio::test]
    async fn read_capped_text_rejects_oversized_body() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let addr = serve_once("this body is over the limit").await;
        let resp = reqwest::get(format!("http://{addr}/")).await.unwrap();

        assert!(read_capped_text(resp, 10).await.is_err());
    }

    /// Builds an unsigned JWT (`header.payload.`) whose payload carries `exp`.
    fn jwt_with_exp(exp: i64) -> String {
        let payload = format!("{{\"exp\":{exp}}}");
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
        format!("eyJhbGciOiJSUzI1NiJ9.{b64}.sig")
    }

    fn now() -> i64 {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
    }

    #[test]
    fn parse_token_response_extracts_both_tokens() {
        let body = r#"{"access_token":"acc","refresh_token":"ref","expires_in":300}"#;
        let tokens = parse_token_response(body, None).unwrap();
        assert_eq!(tokens.access_token, "acc");
        assert_eq!(tokens.refresh_token.as_deref(), Some("ref"));
    }

    #[test]
    fn parse_token_response_uses_fallback_refresh_when_missing() {
        let body = r#"{"access_token":"acc"}"#;
        let tokens = parse_token_response(body, Some("old-refresh")).unwrap();
        assert_eq!(tokens.access_token, "acc");
        assert_eq!(tokens.refresh_token.as_deref(), Some("old-refresh"));
    }

    #[test]
    fn parse_token_response_prefers_response_refresh_over_fallback() {
        let body = r#"{"access_token":"acc","refresh_token":"new-refresh"}"#;
        let tokens = parse_token_response(body, Some("old-refresh")).unwrap();
        assert_eq!(tokens.refresh_token.as_deref(), Some("new-refresh"));
    }

    #[test]
    fn parse_token_response_rejects_missing_access_token() {
        assert!(parse_token_response(r#"{"refresh_token":"ref"}"#, None).is_none());
        assert!(parse_token_response(r#"{"access_token":""}"#, None).is_none());
        assert!(parse_token_response("not json", None).is_none());
    }

    #[test]
    fn access_token_exp_reads_exp_claim() {
        assert_eq!(
            access_token_exp(&jwt_with_exp(1_700_000_000)),
            Some(1_700_000_000)
        );
    }

    #[test]
    fn access_token_exp_rejects_malformed() {
        assert!(access_token_exp("garbage").is_none());
        assert!(access_token_exp("only.two").is_none());
        assert!(access_token_exp("a.!!!notbase64!!!.c").is_none());
    }

    #[test]
    fn is_access_token_usable_respects_skew() {
        let token = jwt_with_exp(now() + 600);
        assert!(is_access_token_usable(&token, 300));
        // Within the skew window → treated as not usable (refresh needed).
        assert!(!is_access_token_usable(&token, 600));
    }

    #[test]
    fn is_access_token_usable_rejects_expired_and_empty() {
        assert!(!is_access_token_usable(&jwt_with_exp(now() - 60), 0));
        assert!(!is_access_token_usable("", 0));
    }

    #[test]
    fn html_escape_escapes_markup_characters() {
        assert_eq!(html_escape(""), "");
        assert_eq!(html_escape("hello world"), "hello world");
        assert_eq!(html_escape("a<b>c"), "a&lt;b&gt;c");
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape("say \"hi\""), "say &quot;hi&quot;");
        // Single quotes are intentionally left as-is (we never interpolate into
        // single-quoted attributes), and already-escaped text is escaped again.
        assert_eq!(html_escape("it's &amp;"), "it's &amp;amp;");
    }

    #[test]
    fn html_escape_handles_combined_and_unicode_input() {
        assert_eq!(
            html_escape("<script>alert(\"xss\")&</script>"),
            "&lt;script&gt;alert(&quot;xss&quot;)&amp;&lt;/script&gt;"
        );
        // Non-markup characters (whitespace, Unicode) pass through unchanged.
        assert_eq!(html_escape("Hello 世界 🌍\n\t"), "Hello 世界 🌍\n\t");
    }
}
