use bytes::{Buf, Bytes};
use h3_quinn::Connection as H3QuinnConnection;
use shared::{
    looks_like_html_response,
    masque::{self, CAPSULE_MAVI_CONFIG},
    ControlMessage,
};
use std::time::{Duration, Instant};

/// Holds the h3 CONNECT-IP request state for the lifetime of the VPN session.
///
/// `h3::client::SendRequest::drop` decrements an internal sender count; when the last
/// handle goes away it calls `handle_connection_error_on_stream(H3_NO_ERROR,
/// "Connection closed by client")` and tears down the underlying quinn connection.
/// Keeping this guard alongside the `quinn::Connection` prevents that early shutdown
/// so the VPN datagram plane can keep using the same connection after the H3 auth
/// request completes.
///
/// The CONNECT-IP request stream itself must also remain open for the lifetime of
/// the session. Dropping it after reading `MAVI_CONFIG` can end the logical MASQUE
/// tunnel while QUIC datagrams are still being used.
pub struct H3SessionGuard {
    _send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    _stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    drive_handle: tokio::task::JoinHandle<()>,
}

impl Drop for H3SessionGuard {
    fn drop(&mut self) {
        self.drive_handle.abort();
    }
}

pub(super) async fn connect_and_handshake(
    connection: quinn::Connection,
    token: String,
) -> anyhow::Result<(ControlMessage, H3SessionGuard)> {
    let h3_conn = H3QuinnConnection::new(connection.clone());
    let mut builder = h3::client::builder();
    builder.enable_datagram(true);
    builder.enable_extended_connect(true);
    let (mut driver, mut send_request) = builder
        .build::<_, _, Bytes>(h3_conn)
        .await
        .map_err(|e| anyhow::anyhow!("H3 client init failed: {e}"))?;

    // Drive the H3 connection in the background for the lifetime of the session.
    let drive_handle = tokio::spawn(async move {
        let e = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        log::debug!("H3 driver finished: {e}");
    });

    // RFC 9484 connect-ip: Extended CONNECT with :protocol=connect-ip.
    // The target template /.well-known/masque/ip/*/* tunnels all addresses+protocols.
    let req = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("https://mavi-vpn/.well-known/masque/ip/*/*/")
        .extension(h3::ext::Protocol::CONNECT_IP)
        .header("authorization", format!("Bearer {token}"))
        .header("capsule-protocol", "?1")
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build H3 CONNECT request: {e}"))?;

    let mut stream = send_request
        .send_request(req)
        .await
        .map_err(|e| anyhow::anyhow!("H3 send_request failed: {e}"))?;

    // NOTE: do NOT call stream.finish(). connect-ip keeps the request stream
    // open bidirectionally for the whole session (for capsules + control).

    let resp = stream
        .recv_response()
        .await
        .map_err(|e| anyhow::anyhow!("H3 recv_response failed: {e}"))?;

    if resp.status() != http::StatusCode::OK {
        anyhow::bail!("AUTH_FAILED: Server returned HTTP {}", resp.status());
    }
    if resp
        .headers()
        .get("capsule-protocol")
        .is_none_or(|value| value != "?1")
    {
        anyhow::bail!("AUTH_FAILED: Server did not enable the capsule protocol");
    }
    if is_camouflage_h3_response(resp.headers()) {
        anyhow::bail!("AUTH_FAILED: Server returned camouflage HTML instead of MAVI_CONFIG");
    }

    // Parse capsule stream. The server sends ADDRESS_ASSIGN + ROUTE_ADVERTISEMENT
    // (standard connect-ip) followed by the vendor MAVI_CONFIG capsule carrying
    // our bincode ControlMessage::Config. Unknown capsule types are ignored per
    // RFC 9297 §3.2.
    //
    // Every wait on `recv_data` is bounded by the remaining handshake budget so
    // a silent or slow-drip server cannot block us indefinitely, and the buffer
    // itself is capped by `masque::MAX_CAPSULE_BUF`.
    let mut capsule_buf: Vec<u8> = Vec::new();
    let mut config: Option<ControlMessage> = None;
    let deadline = Instant::now() + Duration::from_secs(10);

    'read: while config.is_none() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("Timed out waiting for MAVI_CONFIG capsule");
        }

        while let Some((t, p, n)) = masque::read_capsule(&capsule_buf) {
            let (ctype, payload, consumed) = (t, p.to_vec(), n);
            capsule_buf.drain(..consumed);

            if ctype == CAPSULE_MAVI_CONFIG {
                let (cfg, _): (ControlMessage, _) =
                    bincode::serde::decode_from_slice(&payload, bincode::config::standard())
                        .map_err(|e| anyhow::anyhow!("Failed to decode MAVI_CONFIG: {e}"))?;
                config = Some(cfg);
                break 'read;
            }
            // Ignore ADDRESS_ASSIGN, ROUTE_ADVERTISEMENT, and any unknown type.
        }

        let chunk = match tokio::time::timeout(remaining, stream.recv_data()).await {
            Ok(Ok(Some(data))) => data,
            Ok(Ok(None)) => {
                anyhow::bail!("Server closed connect-ip stream before MAVI_CONFIG")
            }
            Ok(Err(e)) => anyhow::bail!("H3 recv_data failed: {e}"),
            Err(_) => anyhow::bail!("Timed out waiting for MAVI_CONFIG capsule"),
        };
        capsule_buf.extend_from_slice(chunk.chunk());
        if looks_like_html_response(&capsule_buf) {
            anyhow::bail!("AUTH_FAILED: Server returned HTML instead of MAVI_CONFIG");
        }
        if capsule_buf.len() > masque::MAX_CAPSULE_BUF {
            anyhow::bail!(
                "connect-ip capsule buffer exceeded {} bytes",
                masque::MAX_CAPSULE_BUF
            );
        }
    }

    let config = config.expect("loop invariant: broken out only when config set");

    if let ControlMessage::Error { message } = &config {
        return Err(anyhow::anyhow!("Server Error: {message}"));
    }

    Ok((
        config,
        H3SessionGuard {
            _send_request: send_request,
            _stream: stream,
            drive_handle,
        },
    ))
}

pub(super) fn is_camouflage_h3_response(headers: &http::HeaderMap) -> bool {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().contains("text/html"))
        || headers
            .get(http::header::SERVER)
            .and_then(|h| h.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("nginx"))
}
