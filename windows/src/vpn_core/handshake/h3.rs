use anyhow::{Context, Result};
use bytes::Buf;
use h3_quinn::Connection as H3QuinnConnection;
use shared::{looks_like_html_response, masque, masque::CAPSULE_MAVI_CONFIG, ControlMessage};
use std::time::Duration;

/// Holds the h3 `SendRequest` + driver task for the lifetime of the VPN session.
///
/// Dropping `::h3::client::SendRequest` decrements its internal `sender_count`; when the
/// last one goes, its `Drop` impl calls `handle_connection_error_on_stream(H3_NO_ERROR,
/// "Connection closed by client")` which tears down the underlying quinn connection.
/// We therefore keep the `SendRequest` alive for the whole session so the VPN datagram
/// plane can keep using the same `quinn::Connection`.
pub struct H3SessionGuard {
    _send_request: ::h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    drive_handle: tokio::task::JoinHandle<()>,
}

impl Drop for H3SessionGuard {
    fn drop(&mut self) {
        self.drive_handle.abort();
    }
}

/// MASQUE connect-ip (RFC 9484) handshake.
///
/// Sends `CONNECT` with `:protocol=connect-ip` over HTTP/3, then parses the
/// capsule stream on the request body to extract the vendor `MAVI_CONFIG`
/// capsule which carries the full `ControlMessage::Config`.
///
/// Returns the decoded `ControlMessage` plus an `H3SessionGuard` that owns the
/// `SendRequest` handle and the background driver task. The caller MUST hold
/// the guard for the entire VPN session — dropping it sends
/// `CONNECTION_CLOSE(H3_NO_ERROR)` and terminates the underlying quinn connection.
pub(super) async fn connect_and_handshake_h3(
    connection: quinn::Connection,
    token: String,
) -> Result<(ControlMessage, H3SessionGuard)> {
    let h3_conn = H3QuinnConnection::new(connection.clone());
    let mut builder = ::h3::client::builder();
    builder.enable_datagram(true);
    builder.enable_extended_connect(true);
    let (mut driver, mut send_request) = builder
        .build::<_, _, bytes::Bytes>(h3_conn)
        .await
        .map_err(|e| anyhow::anyhow!("H3 client init failed: {e}"))?;

    // Drive the H3 connection in the background. This task lives for the whole
    // VPN session (via H3SessionGuard) so h3's control/QPACK streams keep being
    // serviced. A clean close at session end is reported at debug level.
    let drive_handle = tokio::spawn(async move {
        let e = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        tracing::debug!("H3 driver finished: {}", e);
    });

    // Extended CONNECT with :protocol=connect-ip (RFC 9484 §3).
    // The `:authority` component is the MASQUE target URI template result;
    // per RFC 9484 we use the well-known path `/.well-known/masque/ip/*/*/`.
    let req = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("https://mavi-vpn/.well-known/masque/ip/*/*/")
        .extension(::h3::ext::Protocol::CONNECT_IP)
        .header("authorization", format!("Bearer {token}"))
        .header("capsule-protocol", "?1")
        .body(())
        .context("Failed to build H3 CONNECT request")?;

    let mut stream = send_request
        .send_request(req)
        .await
        .map_err(|e| anyhow::anyhow!("H3 send_request failed: {e}"))?;
    // NB: do NOT finish the stream — connect-ip keeps the request stream open
    // for bidirectional capsule traffic throughout the session.

    let resp = stream
        .recv_response()
        .await
        .map_err(|e| anyhow::anyhow!("H3 recv_response failed: {e}"))?;

    if resp.status() != http::StatusCode::OK {
        anyhow::bail!("AUTH_FAILED: Server returned HTTP {}", resp.status());
    }

    // Read capsules until we find MAVI_CONFIG. We collect into a rolling buffer
    // because capsule boundaries do not align with QUIC chunk boundaries.
    //
    // Every wait on `recv_data` is bounded by the remaining handshake budget so
    // a silent or slow-drip server cannot leave us blocked forever. The buffer
    // itself is capped at `masque::MAX_CAPSULE_BUF` as an extra defense against
    // an unbounded capsule stream.
    let mut capsule_buf: Vec<u8> = Vec::new();
    let mut config: Option<ControlMessage> = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    'read: while config.is_none() {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("Timed out waiting for MAVI_CONFIG capsule");
        }

        if let Some(cfg) = drain_mavi_config_capsule(&mut capsule_buf)? {
            config = Some(cfg);
            break 'read;
        }

        let chunk = match tokio::time::timeout(remaining, stream.recv_data()).await {
            Ok(Ok(Some(data))) => data,
            Ok(Ok(None)) => {
                anyhow::bail!("Server closed connect-ip stream before MAVI_CONFIG")
            }
            Ok(Err(e)) => anyhow::bail!("H3 recv_data failed: {e}"),
            Err(_) => anyhow::bail!("Timed out waiting for MAVI_CONFIG capsule"),
        };
        append_capsule_chunk(&mut capsule_buf, chunk.chunk())?;
        // In CR mode the server sends a fake nginx HTML page on auth failure.
        // Detect this early instead of waiting for the full 10s timeout.
        if looks_like_html_response(&capsule_buf) {
            anyhow::bail!(
                "AUTH_FAILED: Server returned HTML instead of MAVI_CONFIG capsule. \
                 Check token validity or Keycloak configuration."
            );
        }
    }

    let config =
        config.ok_or_else(|| anyhow::anyhow!("connect-ip response lacked MAVI_CONFIG capsule"))?;

    // Intentionally do NOT abort drive_handle or drop send_request here.
    // Both are moved into the guard and kept alive for the whole session.
    let guard = H3SessionGuard {
        _send_request: send_request,
        drive_handle,
    };
    Ok((config, guard))
}

fn drain_mavi_config_capsule(capsule_buf: &mut Vec<u8>) -> Result<Option<ControlMessage>> {
    while let Some(parts) = masque::read_capsule(capsule_buf) {
        let (ctype, payload, consumed) = (parts.0, parts.1.to_vec(), parts.2);
        capsule_buf.drain(..consumed);
        if ctype == CAPSULE_MAVI_CONFIG {
            return bincode::serde::decode_from_slice(&payload, bincode::config::standard())
                .map(|(v, _)| Some(v))
                .map_err(|e| anyhow::anyhow!("Failed to decode MAVI_CONFIG: {e}"));
        }
    }
    Ok(None)
}

fn append_capsule_chunk(capsule_buf: &mut Vec<u8>, chunk: &[u8]) -> Result<()> {
    capsule_buf.extend_from_slice(chunk);
    if capsule_buf.len() > masque::MAX_CAPSULE_BUF {
        anyhow::bail!(
            "connect-ip capsule buffer exceeded {} bytes",
            masque::MAX_CAPSULE_BUF
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn config_message() -> ControlMessage {
        ControlMessage::Config {
            assigned_ip: Ipv4Addr::new(10, 8, 0, 2),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::new(10, 8, 0, 1),
            dns_server: Ipv4Addr::new(1, 1, 1, 1),
            mtu: 1280,
            assigned_ipv6: None,
            netmask_v6: None,
            gateway_v6: None,
            dns_server_v6: None,
            whitelist_domains: None,
        }
    }

    #[test]
    fn capsule_parser_ignores_non_mavi_until_config_arrives() {
        let cfg = config_message();
        let payload = bincode::serde::encode_to_vec(&cfg, bincode::config::standard()).unwrap();
        let mut buf = Vec::new();
        masque::encode_capsule(masque::CAPSULE_ADDRESS_ASSIGN, &[0], &mut buf);
        masque::encode_capsule(CAPSULE_MAVI_CONFIG, &payload, &mut buf);

        let parsed = drain_mavi_config_capsule(&mut buf).unwrap().unwrap();

        assert!(matches!(parsed, ControlMessage::Config { mtu: 1280, .. }));
        assert!(buf.is_empty());
    }

    #[test]
    fn capsule_parser_waits_for_complete_capsule() {
        let mut buf = vec![CAPSULE_MAVI_CONFIG as u8];

        assert!(drain_mavi_config_capsule(&mut buf).unwrap().is_none());
        assert_eq!(buf, vec![CAPSULE_MAVI_CONFIG as u8]);
    }

    #[test]
    fn capsule_buffer_limit_is_enforced() {
        let mut buf = vec![0u8; masque::MAX_CAPSULE_BUF];
        assert!(append_capsule_chunk(&mut buf, &[0]).is_err());
    }

    #[test]
    fn capsule_parser_returns_none_for_empty_buffer() {
        let mut buf = Vec::new();
        assert!(drain_mavi_config_capsule(&mut buf).unwrap().is_none());
        assert!(buf.is_empty());
    }

    #[test]
    fn capsule_parser_skips_unknown_capsule_types() {
        let cfg = config_message();
        let payload = bincode::serde::encode_to_vec(&cfg, bincode::config::standard()).unwrap();
        let mut buf = Vec::new();
        masque::encode_capsule(0x42, &[1, 2, 3], &mut buf);
        masque::encode_capsule(0x99, &[4, 5], &mut buf);
        masque::encode_capsule(CAPSULE_MAVI_CONFIG, &payload, &mut buf);

        let parsed = drain_mavi_config_capsule(&mut buf).unwrap().unwrap();
        assert!(matches!(parsed, ControlMessage::Config { mtu: 1280, .. }));
        assert!(buf.is_empty());
    }

    #[test]
    fn append_capsule_chunk_succeeds_within_limit() {
        let mut buf = Vec::new();
        assert!(append_capsule_chunk(&mut buf, &[1, 2, 3]).is_ok());
        assert_eq!(buf, vec![1, 2, 3]);
        assert!(append_capsule_chunk(&mut buf, &[4, 5]).is_ok());
        assert_eq!(buf, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn append_capsule_chunk_allows_exact_limit() {
        let mut buf = vec![0u8; masque::MAX_CAPSULE_BUF - 1];
        assert!(append_capsule_chunk(&mut buf, &[0]).is_ok());
        assert_eq!(buf.len(), masque::MAX_CAPSULE_BUF);
    }

    #[test]
    fn capsule_parser_handles_error_message() {
        let error_msg = ControlMessage::Error {
            message: "access denied".to_string(),
        };
        let payload =
            bincode::serde::encode_to_vec(&error_msg, bincode::config::standard()).unwrap();
        let mut buf = Vec::new();
        masque::encode_capsule(CAPSULE_MAVI_CONFIG, &payload, &mut buf);

        let parsed = drain_mavi_config_capsule(&mut buf).unwrap().unwrap();
        assert!(matches!(parsed, ControlMessage::Error { message } if message == "access denied"));
    }

    #[test]
    fn capsule_parser_rejects_invalid_bincode_payload() {
        let mut buf = Vec::new();
        masque::encode_capsule(CAPSULE_MAVI_CONFIG, &[0xde, 0xad, 0xbe, 0xef], &mut buf);

        assert!(drain_mavi_config_capsule(&mut buf).is_err());
    }
}
