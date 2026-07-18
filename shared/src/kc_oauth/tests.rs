use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
        let mut request = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        while request.len() < MAX_CALLBACK_REQUEST_BYTES {
            let read = socket.read(&mut chunk).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if http_request_head_complete(&request) {
                break;
            }
        }
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
fn only_invalid_grant_proves_refresh_token_is_dead() {
    assert!(refresh_error_is_terminal(
        reqwest::StatusCode::BAD_REQUEST,
        r#"{"error":"invalid_grant","error_description":"expired"}"#
    ));
    assert!(!refresh_error_is_terminal(
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        r#"{"error":"invalid_grant"}"#
    ));
    assert!(!refresh_error_is_terminal(
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        r#"{"error":"temporarily_unavailable"}"#
    ));
    assert!(!refresh_error_is_terminal(
        reqwest::StatusCode::BAD_REQUEST,
        "not json"
    ));
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
