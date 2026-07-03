//! Client-side control-plane framing shared by the Linux, Windows and Android
//! VPN cores.
//!
//! Every control-plane exchange (handshake `Auth`/`Config`, in-band
//! `Reauth`/`ReauthResult`) uses the same wire format: a little-endian `u32`
//! length prefix followed by the bincode-serialised [`ControlMessage`]. The
//! helpers here are generic over `AsyncRead`/`AsyncWrite` (which quinn streams
//! implement) so this crate does not need a quinn dependency and the helpers
//! stay unit-testable over `tokio::io::duplex`.
//!
//! The server keeps its own framing (`backend/src/handlers/`) on purpose: its
//! read path enforces server-specific limits and anti-probing error semantics
//! that must not drift with client convenience changes.

use crate::ControlMessage;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Upper bound on a control frame accepted from the server. Config/reauth
/// replies are tiny; anything larger indicates a corrupt or hostile stream.
pub const MAX_CONTROL_FRAME_BYTES: usize = 65_536;

#[derive(Debug, thiserror::Error)]
pub enum ControlStreamError {
    #[error("control stream I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to encode control message: {0}")]
    Encode(bincode::error::EncodeError),
    #[error("failed to decode control message: {0}")]
    Decode(bincode::error::DecodeError),
    #[error("control frame of {len} bytes exceeds the {max}-byte limit")]
    FrameTooLarge { len: usize, max: usize },
    #[error("peer closed the control stream before sending the frame length")]
    ClosedBeforeLength,
    #[error("peer closed the control stream before sending the full frame body")]
    ClosedBeforeBody,
    #[error("unexpected control message in response")]
    UnexpectedMessage,
}

/// Serialises a [`ControlMessage`] with the bincode configuration every peer
/// uses (`bincode::config::standard()`), without the length prefix.
pub fn encode_control_message(msg: &ControlMessage) -> Result<Vec<u8>, ControlStreamError> {
    bincode::serde::encode_to_vec(msg, bincode::config::standard())
        .map_err(ControlStreamError::Encode)
}

/// Deserialises a length-checked frame body into a [`ControlMessage`].
///
/// Callers that must inspect the raw bytes first (e.g. the handshake's
/// camouflage-HTML detection via [`crate::looks_like_html_response`]) read the
/// frame with [`read_control_frame`] and decode afterwards.
pub fn decode_control_message(buf: &[u8]) -> Result<ControlMessage, ControlStreamError> {
    bincode::serde::decode_from_slice(buf, bincode::config::standard())
        .map(|(msg, _)| msg)
        .map_err(ControlStreamError::Decode)
}

/// Writes one length-prefixed control frame (`u32` LE length + bincode body).
pub async fn write_control_frame<W: AsyncWrite + Unpin>(
    send: &mut W,
    msg: &ControlMessage,
) -> Result<(), ControlStreamError> {
    let encoded = encode_control_message(msg)?;
    if encoded.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(ControlStreamError::FrameTooLarge {
            len: encoded.len(),
            max: MAX_CONTROL_FRAME_BYTES,
        });
    }
    // Infallible after the bound check above (MAX fits u32), but stated as a
    // conversion so no truncating cast can slip in if the bound ever changes.
    let len = u32::try_from(encoded.len()).map_err(|_| ControlStreamError::FrameTooLarge {
        len: encoded.len(),
        max: MAX_CONTROL_FRAME_BYTES,
    })?;
    send.write_u32_le(len).await?;
    send.write_all(&encoded).await?;
    Ok(())
}

/// Reads one length-prefixed control frame, rejecting frames larger than
/// `max_len` *before* allocating or reading the body. Returns the raw body so
/// callers can run content checks (camouflage HTML) ahead of decoding.
pub async fn read_control_frame<R: AsyncRead + Unpin>(
    recv: &mut R,
    max_len: usize,
) -> Result<Vec<u8>, ControlStreamError> {
    let len = recv.read_u32_le().await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            ControlStreamError::ClosedBeforeLength
        } else {
            ControlStreamError::Io(e)
        }
    })? as usize;
    if len > max_len {
        return Err(ControlStreamError::FrameTooLarge { len, max: max_len });
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            ControlStreamError::ClosedBeforeBody
        } else {
            ControlStreamError::Io(e)
        }
    })?;
    Ok(buf)
}

/// Client side of one in-band reauth exchange over a fresh bidirectional
/// stream: presents the refreshed token, half-closes the request side, and
/// returns whether the server accepted it.
///
/// `shutdown()` maps to `finish()` on a quinn `SendStream`, mirroring the
/// FIN-before-reply sequence the three clients used before this was shared.
/// Timeouts stay with the caller (each client wraps this in its own
/// `tokio::time::timeout`), matching the previous per-client behaviour.
pub async fn reauth_over_stream<S, R>(
    send: &mut S,
    recv: &mut R,
    token: &str,
) -> Result<bool, ControlStreamError>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    write_control_frame(
        send,
        &ControlMessage::Reauth {
            token: token.to_string(),
        },
    )
    .await?;
    let _ = send.shutdown().await;

    let buf = read_control_frame(recv, MAX_CONTROL_FRAME_BYTES).await?;
    match decode_control_message(&buf)? {
        ControlMessage::ReauthResult { accepted } => Ok(accepted),
        _ => Err(ControlStreamError::UnexpectedMessage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn frame_roundtrip_preserves_message() {
        let (mut client, mut server) = duplex(1024);
        let msg = ControlMessage::Auth {
            token: "secret-token".to_string(),
        };

        write_control_frame(&mut client, &msg).await.unwrap();
        let body = read_control_frame(&mut server, MAX_CONTROL_FRAME_BYTES)
            .await
            .unwrap();

        match decode_control_message(&body).unwrap() {
            ControlMessage::Auth { token } => assert_eq!(token, "secret-token"),
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[tokio::test]
    async fn frame_layout_is_u32_le_length_plus_bincode_body() {
        // Pins the wire layout the server expects: 4-byte LE length prefix
        // followed by exactly the bincode body.
        let (mut client, mut server) = duplex(1024);
        let msg = ControlMessage::Reauth {
            token: "t".to_string(),
        };
        let expected_body = encode_control_message(&msg).unwrap();

        write_control_frame(&mut client, &msg).await.unwrap();
        drop(client);

        let mut raw = Vec::new();
        server.read_to_end(&mut raw).await.unwrap();
        assert_eq!(&raw[..4], (expected_body.len() as u32).to_le_bytes());
        assert_eq!(&raw[4..], expected_body);
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_reading_the_body() {
        let (mut client, mut server) = duplex(64);
        // Announce a body far larger than the cap, then send nothing more. If
        // the length check ran after allocation/reading, this would hang on
        // the tiny duplex buffer instead of failing immediately.
        client.write_u32_le(u32::MAX).await.unwrap();

        let err = read_control_frame(&mut server, MAX_CONTROL_FRAME_BYTES)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ControlStreamError::FrameTooLarge { len, max }
                if len == u32::MAX as usize && max == MAX_CONTROL_FRAME_BYTES
        ));
    }

    #[tokio::test]
    async fn frame_length_bound_is_inclusive() {
        // Mirrors the former per-client validate_raw_response_len contract:
        // exactly MAX is accepted, one byte more is rejected.
        let (mut client, mut server) = duplex(2 * MAX_CONTROL_FRAME_BYTES);
        let body = vec![0u8; MAX_CONTROL_FRAME_BYTES];
        client
            .write_u32_le(MAX_CONTROL_FRAME_BYTES as u32)
            .await
            .unwrap();
        client.write_all(&body).await.unwrap();
        let read = read_control_frame(&mut server, MAX_CONTROL_FRAME_BYTES)
            .await
            .unwrap();
        assert_eq!(read.len(), MAX_CONTROL_FRAME_BYTES);

        let (mut client, mut server) = duplex(64);
        client
            .write_u32_le((MAX_CONTROL_FRAME_BYTES + 1) as u32)
            .await
            .unwrap();
        let err = read_control_frame(&mut server, MAX_CONTROL_FRAME_BYTES)
            .await
            .unwrap_err();
        assert!(matches!(err, ControlStreamError::FrameTooLarge { .. }));
    }

    #[tokio::test]
    async fn legacy_magic_length_0x1901_is_not_special_cased() {
        // Regression guard carried over from the Windows/Android clients:
        // older builds treated a 0x1901-byte response as the camouflage page
        // by length alone. Framing must accept that length like any other —
        // camouflage detection is content-based (looks_like_html_response).
        let (mut client, mut server) = duplex(2 * 0x1901);
        let body = vec![0xAAu8; 0x1901];
        client.write_u32_le(0x1901).await.unwrap();
        client.write_all(&body).await.unwrap();

        let read = read_control_frame(&mut server, MAX_CONTROL_FRAME_BYTES)
            .await
            .unwrap();
        assert_eq!(read, body);
    }

    #[tokio::test]
    async fn close_before_length_is_reported_distinctly() {
        let (client, mut server) = duplex(64);
        drop(client);

        let err = read_control_frame(&mut server, MAX_CONTROL_FRAME_BYTES)
            .await
            .unwrap_err();
        assert!(matches!(err, ControlStreamError::ClosedBeforeLength));
    }

    #[tokio::test]
    async fn close_mid_body_is_reported_distinctly() {
        let (mut client, mut server) = duplex(64);
        client.write_u32_le(10).await.unwrap();
        client.write_all(b"abc").await.unwrap();
        drop(client);

        let err = read_control_frame(&mut server, MAX_CONTROL_FRAME_BYTES)
            .await
            .unwrap_err();
        assert!(matches!(err, ControlStreamError::ClosedBeforeBody));
    }

    /// Serves one reauth exchange: reads the request frame, asserts it carries
    /// the expected token, and replies with `response`.
    async fn serve_one_reauth(
        recv: &mut (impl AsyncRead + Unpin),
        send: &mut (impl AsyncWrite + Unpin),
        expected_token: &str,
        response: ControlMessage,
    ) {
        let body = read_control_frame(recv, MAX_CONTROL_FRAME_BYTES)
            .await
            .unwrap();
        match decode_control_message(&body).unwrap() {
            ControlMessage::Reauth { token } => assert_eq!(token, expected_token),
            other => panic!("server expected Reauth, got {other:?}"),
        }
        write_control_frame(send, &response).await.unwrap();
    }

    #[tokio::test]
    async fn reauth_exchange_reports_accepted_and_rejected() {
        for accepted in [true, false] {
            let (mut client_send, mut server_recv) = duplex(1024);
            let (mut server_send, mut client_recv) = duplex(1024);

            let server = tokio::spawn(async move {
                serve_one_reauth(
                    &mut server_recv,
                    &mut server_send,
                    "fresh-token",
                    ControlMessage::ReauthResult { accepted },
                )
                .await;
            });

            let result = reauth_over_stream(&mut client_send, &mut client_recv, "fresh-token")
                .await
                .unwrap();
            assert_eq!(result, accepted);
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn reauth_rejects_unexpected_response_message() {
        let (mut client_send, mut server_recv) = duplex(1024);
        let (mut server_send, mut client_recv) = duplex(1024);

        let server = tokio::spawn(async move {
            serve_one_reauth(
                &mut server_recv,
                &mut server_send,
                "fresh-token",
                ControlMessage::Error {
                    message: "nope".to_string(),
                },
            )
            .await;
        });

        let err = reauth_over_stream(&mut client_send, &mut client_recv, "fresh-token")
            .await
            .unwrap_err();
        assert!(matches!(err, ControlStreamError::UnexpectedMessage));
        server.await.unwrap();
    }
}
