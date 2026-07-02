//! Concurrent loopback callback listener for the desktop PKCE flow.
//!
//! The single accept loop behind the GUI, Windows and Linux desktop clients.
//! Each inbound connection is served in its own task, so a stray probe or a
//! connection that opens and then stalls (a local process holding the callback
//! port) can never delay the real browser callback. The previous per-client
//! loop accepted and read one connection at a time and could be wedged by a
//! deliberately slow local peer for the whole per-connection read budget.

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

use super::callback::{classify_oauth_callback, read_callback_params, CallbackOutcome};
use super::html_escape;

/// Page shown in the browser after a successful login. Generic wording so the
/// GUI and the CLIs can share it.
const SUCCESS_RESPONSE: &str = concat!(
    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n",
    "<html><head><title>Login successful</title></head>",
    "<body style=\"font-family:sans-serif;text-align:center;padding-top:50px\">",
    "<h1 style=\"color:green\">Login successful!</h1>",
    "<p>You can close this window and return to Mavi VPN.</p>",
    "<script>setTimeout(function(){window.close();},3000)</script>",
    "</body></html>",
);

/// Page shown when a callback's anti-CSRF `state` is missing or wrong.
const STATE_MISMATCH_RESPONSE: &str = concat!(
    "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n",
    "<html><body style=\"font-family:sans-serif;text-align:center;padding-top:50px\">",
    "<h1 style=\"color:red\">Login failed</h1><p>OAuth state invalid.</p></body></html>",
);

/// Reply to a stray request (e.g. `/favicon.ico`) that carries no `code`/`error`
/// — answered politely so the listener stays up for the real callback.
const IGNORE_RESPONSE: &str = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";

/// Builds the error page for a state-valid Keycloak `error`, HTML-escaping the
/// message so it cannot inject markup into the page.
fn error_response(message: &str) -> String {
    format!(
        "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n\
         <html><body style=\"font-family:sans-serif;text-align:center;padding-top:50px\">\
         <h1 style=\"color:red\">Login failed</h1><p>{}</p></body></html>",
        html_escape(message)
    )
}

/// Why [`recv_oauth_callback`] gave up on the login. Implements
/// [`std::error::Error`] so callers can fold it into their own error type.
#[derive(Debug)]
pub enum CallbackError {
    /// A callback carried a `code`/`error` whose anti-CSRF `state` was missing
    /// or did not match — a likely forged/cross-site callback.
    StateMismatch,
    /// Keycloak reported an `error` on an otherwise state-valid callback.
    Keycloak(String),
    /// The listener's `accept()` failed.
    Io(std::io::Error),
}

impl std::fmt::Display for CallbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StateMismatch => write!(f, "OAuth state mismatch"),
            Self::Keycloak(err) => write!(f, "Keycloak error: {err}"),
            Self::Io(err) => write!(f, "callback listener I/O error: {err}"),
        }
    }
}

impl std::error::Error for CallbackError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::StateMismatch | Self::Keycloak(_) => None,
        }
    }
}

/// Result of serving one connection: either it produced a terminal login
/// outcome, or it was a stray/stalled request and the listener should wait on.
enum ConnResult {
    KeepWaiting,
    Done(Result<String, CallbackError>),
}

/// Reads, classifies and replies to one callback connection.
///
/// A per-connection read error is treated as non-fatal ([`ConnResult::KeepWaiting`])
/// so a single misbehaving local peer cannot abort a login that the real
/// browser callback could still complete.
async fn handle_callback_connection(mut socket: TcpStream, expected_state: String) -> ConnResult {
    let params = match read_callback_params(&mut socket).await {
        Ok(Some(params)) => params,
        Ok(None) => return ConnResult::KeepWaiting,
        Err(_) => return ConnResult::KeepWaiting,
    };

    match classify_oauth_callback(
        params.state.as_deref(),
        params.code.as_deref(),
        params.error.as_deref(),
        &expected_state,
    ) {
        CallbackOutcome::Code(code) => {
            let _ = socket.write_all(SUCCESS_RESPONSE.as_bytes()).await;
            ConnResult::Done(Ok(code))
        }
        CallbackOutcome::Error(err) => {
            let _ = socket.write_all(error_response(&err).as_bytes()).await;
            ConnResult::Done(Err(CallbackError::Keycloak(err)))
        }
        CallbackOutcome::StateMismatch => {
            let _ = socket.write_all(STATE_MISMATCH_RESPONSE.as_bytes()).await;
            ConnResult::Done(Err(CallbackError::StateMismatch))
        }
        CallbackOutcome::Ignore => {
            let _ = socket.write_all(IGNORE_RESPONSE.as_bytes()).await;
            ConnResult::KeepWaiting
        }
    }
}

/// Serves loopback OAuth callbacks on `listener` until a valid one arrives,
/// validating each callback's `state` against `expected_state` in constant
/// time.
///
/// Connections are handled concurrently, so a stray or deliberately stalled
/// local connection can neither block the accept loop nor delay the real
/// browser callback. Returns the authorization `code` on success. A state-valid
/// Keycloak `error`, a forged/mismatched `state`, or an `accept()` failure end
/// the wait with the matching [`CallbackError`]; the caller is expected to wrap
/// this in its own overall login timeout.
pub async fn recv_oauth_callback(
    listener: &TcpListener,
    expected_state: &str,
) -> Result<String, CallbackError> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (socket, _peer) = accepted.map_err(CallbackError::Io)?;
                connections.spawn(handle_callback_connection(socket, expected_state.to_owned()));
            }
            Some(joined) = connections.join_next() => {
                match joined {
                    Ok(ConnResult::Done(result)) => return result,
                    // Stray/ignored request, a per-connection read error, or a
                    // handler task that was cancelled: keep waiting for the real
                    // callback.
                    Ok(ConnResult::KeepWaiting) | Err(_) => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn bound_listener() -> (TcpListener, std::net::SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, addr)
    }

    #[tokio::test]
    async fn recv_oauth_callback_is_not_blocked_by_a_stalled_connection() {
        let (listener, addr) = bound_listener().await;
        let server = tokio::spawn(async move { recv_oauth_callback(&listener, "st8").await });

        // A connection that opens and then stalls without ever sending a request
        // head. The old serial loop would block on it for the per-connection read
        // budget; the concurrent listener must not.
        let _stalled = TcpStream::connect(addr).await.unwrap();

        // The real browser callback arrives on a second connection and must be
        // served straight away despite the stalled one.
        let mut good = TcpStream::connect(addr).await.unwrap();
        good.write_all(
            b"GET /callback?state=st8&code=the-code HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await
        .unwrap();

        let code = server.await.unwrap().unwrap();
        assert_eq!(code, "the-code");
    }

    #[tokio::test]
    async fn recv_oauth_callback_ignores_stray_requests_and_keeps_waiting() {
        let (listener, addr) = bound_listener().await;
        let server = tokio::spawn(async move { recv_oauth_callback(&listener, "st8").await });

        // A stray request (no code/error) must not end the login.
        let mut stray = TcpStream::connect(addr).await.unwrap();
        stray
            .write_all(b"GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut good = TcpStream::connect(addr).await.unwrap();
        good.write_all(b"GET /callback?state=st8&code=ok HTTP/1.1\r\n\r\n")
            .await
            .unwrap();

        assert_eq!(server.await.unwrap().unwrap(), "ok");
    }

    #[tokio::test]
    async fn recv_oauth_callback_reports_state_mismatch() {
        let (listener, addr) = bound_listener().await;
        let server = tokio::spawn(async move { recv_oauth_callback(&listener, "expected").await });

        let mut forged = TcpStream::connect(addr).await.unwrap();
        forged
            .write_all(b"GET /callback?state=wrong&code=x HTTP/1.1\r\n\r\n")
            .await
            .unwrap();

        let err = server.await.unwrap().unwrap_err();
        assert!(matches!(err, CallbackError::StateMismatch));
    }
}
