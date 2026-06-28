//! Loopback callback parsing for the desktop PKCE flow.
//!
//! Pure, allocation-light parsing of the single browser `GET /callback?…`
//! request the loopback listener receives, plus its constant-time `state`
//! validation. The concurrent listener that drives these lives in
//! [`super::server`].

use std::time::Duration;

/// Hard cap on how many bytes the loopback listener reads from a single OAuth
/// callback request before giving up.
///
/// The callback is one browser `GET /callback?…` request. 64 KiB dwarfs any
/// legitimate request line + headers, yet still bounds memory so a local
/// process that connects to the callback port and streams forever cannot push
/// the client into unbounded growth.
pub const MAX_CALLBACK_REQUEST_BYTES: usize = 64 * 1024;

/// Per-connection budget for reading one callback request head.
///
/// The legitimate browser callback arrives in a single round-trip; a connection
/// that opens but never finishes its request head (a stray probe, a browser
/// pre-connect that holds the socket, or a local process stalling on purpose)
/// is abandoned after this deadline. Combined with the concurrent listener in
/// [`super::server`], a stalled connection neither blocks the accept loop nor
/// wedges the login until the outer 5-minute timeout.
pub const CALLBACK_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// The `state`, `code` and `error` query parameters extracted from one loopback
/// OAuth callback request. Feed these into [`classify_oauth_callback`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallbackParams {
    pub state: Option<String>,
    pub code: Option<String>,
    pub error: Option<String>,
}

/// Classification of a parsed OAuth loopback callback request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallbackOutcome {
    /// A valid authorization `code` whose `state` matched the expected value.
    Code(String),
    /// Keycloak reported an `error` and `state` matched.
    Error(String),
    /// A `code`/`error` was present but `state` was missing or did not match — a
    /// likely forged/cross-site callback; the flow must abort.
    StateMismatch,
    /// Not a relevant callback (no `code`/`error`, e.g. a stray `/favicon.ico`
    /// request). The caller should answer politely and keep listening.
    Ignore,
}

/// Returns `true` once `buf` holds a complete HTTP request head, i.e. the
/// blank-line terminator after the headers has arrived. Both the spec
/// `\r\n\r\n` and a lenient `\n\n` are accepted.
///
/// Lets the loopback reader stop on the real end-of-headers instead of relying
/// on a single fixed-size `read`, which a segmented request can split mid-line.
#[must_use]
pub fn http_request_head_complete(buf: &[u8]) -> bool {
    buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.windows(2).any(|w| w == b"\n\n")
}

/// Extracts the request target (path + query) from an HTTP/1.x request head.
/// Returns `None` unless the first line is a well-formed `GET <target> HTTP/…`
/// request line.
#[must_use]
pub fn callback_request_target(request: &str) -> Option<&str> {
    let mut parts = request.lines().next()?.split_whitespace();
    if parts.next()? != "GET" {
        return None;
    }
    parts.next()
}

/// Classifies an OAuth loopback callback from its already-extracted query
/// parameters, validating `state` in **constant time** so the response timing
/// cannot reveal how many leading bytes of the anti-CSRF token a forged request
/// guessed.
///
/// `state` is only enforced when an actual `code` or `error` is present, so a
/// stray request (favicon, health probe) is reported as [`CallbackOutcome::Ignore`]
/// and the listener keeps waiting instead of failing the whole login.
#[must_use]
pub fn classify_oauth_callback(
    returned_state: Option<&str>,
    code: Option<&str>,
    error: Option<&str>,
    expected_state: &str,
) -> CallbackOutcome {
    let code = code.filter(|c| !c.is_empty());
    let error = error.filter(|e| !e.is_empty());
    if code.is_none() && error.is_none() {
        return CallbackOutcome::Ignore;
    }

    let state_ok = returned_state.is_some_and(|s| {
        constant_time_eq::constant_time_eq(s.as_bytes(), expected_state.as_bytes())
    });
    if !state_ok {
        return CallbackOutcome::StateMismatch;
    }

    match (code, error) {
        (Some(code), _) => CallbackOutcome::Code(code.to_string()),
        (None, Some(error)) => CallbackOutcome::Error(error.to_string()),
        // Unreachable: the early return above guarantees at least one is `Some`.
        (None, None) => CallbackOutcome::Ignore,
    }
}

/// Reads one loopback HTTP callback request from `reader` and extracts its
/// `state`/`code`/`error` query parameters.
///
/// The single shared implementation behind the GUI, Windows and Linux desktop
/// clients. It reads the **full request head** — up to the blank-line
/// terminator, capped at [`MAX_CALLBACK_REQUEST_BYTES`] and
/// [`CALLBACK_READ_TIMEOUT`] — rather than a single fixed-size read, so a
/// callback split across TCP segments is never parsed half-formed.
///
/// Returns `Ok(None)` when the caller should just keep listening: an empty
/// connection, a request that is not a parseable `GET` callback, or a
/// connection that stalled past [`CALLBACK_READ_TIMEOUT`]. Only an underlying
/// I/O error surfaces as `Err`.
pub async fn read_callback_params<R>(reader: &mut R) -> std::io::Result<Option<CallbackParams>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let read_head = async {
        let mut buf = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        loop {
            let n = reader.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if http_request_head_complete(&buf) || buf.len() >= MAX_CALLBACK_REQUEST_BYTES {
                break;
            }
        }
        std::io::Result::Ok(buf)
    };

    // A stalled connection yields `None` (skip it) instead of blocking the
    // accept loop until the outer login timeout.
    let buf = match tokio::time::timeout(CALLBACK_READ_TIMEOUT, read_head).await {
        Ok(result) => result?,
        Err(_elapsed) => return Ok(None),
    };
    if buf.is_empty() {
        return Ok(None);
    }

    let request = String::from_utf8_lossy(&buf);
    let Some(target) = callback_request_target(&request) else {
        return Ok(None);
    };
    let Ok(url) = url::Url::parse(&format!("http://localhost{target}")) else {
        return Ok(None);
    };

    let find = |key: &str| {
        url.query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    };
    Ok(Some(CallbackParams {
        state: find("state"),
        code: find("code"),
        error: find("error"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_request_head_complete_detects_terminator() {
        // No blank line yet — still reading.
        assert!(!http_request_head_complete(
            b"GET /callback?code=x HTTP/1.1\r\n"
        ));
        // Spec CRLF terminator.
        assert!(http_request_head_complete(
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        ));
        // Lenient LF-only terminator.
        assert!(http_request_head_complete(b"GET / HTTP/1.1\n\n"));
    }

    #[test]
    fn callback_request_target_extracts_path_and_query() {
        assert_eq!(
            callback_request_target(
                "GET /callback?code=abc&state=xyz HTTP/1.1\r\nHost: localhost\r\n\r\n"
            ),
            Some("/callback?code=abc&state=xyz")
        );
        // Wrong method, empty, and truncated request lines are rejected.
        assert_eq!(callback_request_target("POST /callback HTTP/1.1"), None);
        assert_eq!(callback_request_target(""), None);
        assert_eq!(callback_request_target("GET"), None);
    }

    #[test]
    fn classify_oauth_callback_accepts_matching_state_with_code() {
        assert_eq!(
            classify_oauth_callback(Some("st8"), Some("the-code"), None, "st8"),
            CallbackOutcome::Code("the-code".to_string())
        );
    }

    #[test]
    fn classify_oauth_callback_rejects_state_mismatch_or_absence() {
        assert_eq!(
            classify_oauth_callback(Some("wrong"), Some("the-code"), None, "st8"),
            CallbackOutcome::StateMismatch
        );
        assert_eq!(
            classify_oauth_callback(None, Some("the-code"), None, "st8"),
            CallbackOutcome::StateMismatch
        );
        // A Keycloak error is only surfaced once state is validated, so it cannot
        // be steered by an attacker who does not know the state.
        assert_eq!(
            classify_oauth_callback(Some("nope"), None, Some("access_denied"), "st8"),
            CallbackOutcome::StateMismatch
        );
    }

    #[test]
    fn classify_oauth_callback_reports_keycloak_error_after_state_check() {
        assert_eq!(
            classify_oauth_callback(Some("st8"), None, Some("access_denied"), "st8"),
            CallbackOutcome::Error("access_denied".to_string())
        );
    }

    #[test]
    fn classify_oauth_callback_ignores_stray_requests() {
        assert_eq!(
            classify_oauth_callback(None, None, None, "st8"),
            CallbackOutcome::Ignore
        );
        // Empty code/error params are treated as absent (stray request).
        assert_eq!(
            classify_oauth_callback(Some("st8"), Some(""), Some(""), "st8"),
            CallbackOutcome::Ignore
        );
    }

    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, ReadBuf};

    /// `AsyncRead` that hands out `data` in fixed-size pieces to exercise the
    /// reader's reassembly across TCP segments, then signals EOF.
    struct Segmented {
        data: Vec<u8>,
        pos: usize,
        step: usize,
    }

    impl AsyncRead for Segmented {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let remaining = &self.data[self.pos..];
            let take = remaining.len().min(self.step).min(buf.remaining());
            buf.put_slice(&remaining[..take]);
            self.pos += take;
            Poll::Ready(Ok(()))
        }
    }

    /// `AsyncRead` that never produces data — models a connection that opens and
    /// then stalls without ever finishing its request head.
    struct Stalled;

    impl AsyncRead for Stalled {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn read_callback_params_extracts_query() {
        let mut reader: &[u8] =
            b"GET /callback?state=st8&code=the-code HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let params = read_callback_params(&mut reader).await.unwrap().unwrap();
        assert_eq!(params.state.as_deref(), Some("st8"));
        assert_eq!(params.code.as_deref(), Some("the-code"));
        assert_eq!(params.error, None);
    }

    #[tokio::test]
    async fn read_callback_params_reassembles_segmented_request() {
        // One byte per read forces the head terminator to land across chunks;
        // the reader must still see the complete request.
        let mut reader = Segmented {
            data: b"GET /callback?state=st8&code=abc HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
            pos: 0,
            step: 1,
        };
        let params = read_callback_params(&mut reader).await.unwrap().unwrap();
        assert_eq!(params.state.as_deref(), Some("st8"));
        assert_eq!(params.code.as_deref(), Some("abc"));
    }

    #[tokio::test]
    async fn read_callback_params_skips_empty_and_non_get() {
        let mut empty: &[u8] = b"";
        assert_eq!(read_callback_params(&mut empty).await.unwrap(), None);

        let mut post: &[u8] = b"POST /callback HTTP/1.1\r\n\r\n";
        assert_eq!(read_callback_params(&mut post).await.unwrap(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn read_callback_params_abandons_stalled_connection() {
        // With time paused, the runtime auto-advances to the read timeout, so a
        // stalled connection resolves to `None` (skip it) without a real wait.
        let mut reader = Stalled;
        assert_eq!(read_callback_params(&mut reader).await.unwrap(), None);
    }
}
