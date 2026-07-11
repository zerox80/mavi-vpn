use bytes::{Buf, Bytes};
use h3_quinn::Connection as H3QuinnConnection;
use log::info;
use shared::{
    compute_quic_mtu_config, control, looks_like_html_response,
    masque::{self, CAPSULE_MAVI_CONFIG},
    ControlMessage,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod h2;
mod validation;

/// How often the in-band reauth task checks whether `updateToken` has pushed a
/// fresher access token that needs presenting to the server.
const REAUTH_POLL_SECS: u64 = 15;

/// Background task: while the session is alive, present a GUI-refreshed access
/// token to the server over the active transport's in-band control path so the
/// live tunnel survives the original token's expiry without a reconnect. The token cell is
/// seeded with the handshake token and updated via `NativeLib.updateToken`.
pub async fn run_reauth_task(
    connection: TunnelConnection,
    token_cell: Arc<Mutex<String>>,
    stop_flag: Arc<AtomicBool>,
) {
    let mut last_token = token_cell.lock().map(|t| t.clone()).unwrap_or_default();
    loop {
        tokio::time::sleep(Duration::from_secs(REAUTH_POLL_SECS)).await;
        if stop_flag.load(Ordering::SeqCst) {
            break;
        }
        let current = token_cell.lock().map(|t| t.clone()).unwrap_or_default();
        if current.is_empty() || current == last_token {
            continue;
        }
        match connection.reauthenticate(&current).await {
            Ok(true) => {
                info!("In-band token reauth accepted; live session extended");
                last_token = current;
            }
            Ok(false) => log::warn!("In-band token reauth rejected by server"),
            Err(e) => log::warn!("In-band token reauth attempt failed: {e}"),
        }
    }
}

use crate::crypto::{decode_hex_pins, PinnedServerVerifier};
use validation::validate_server_mtu;

#[derive(Clone)]
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub enum TunnelConnection {
    Quic(quinn::Connection),
    Http2(h2::Http2Session),
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
impl TunnelConnection {
    pub async fn send_packet(&self, packet: Bytes) -> anyhow::Result<()> {
        match self {
            Self::Quic(connection) => connection
                .send_datagram(packet)
                .map_err(anyhow::Error::from),
            Self::Http2(connection) => connection.send_packet(packet).await,
        }
    }

    pub async fn recv_packet(&self) -> anyhow::Result<Bytes> {
        match self {
            Self::Quic(connection) => Ok(connection.read_datagram().await?),
            Self::Http2(connection) => connection.recv_packet().await,
        }
    }

    pub const fn quic(&self) -> Option<&quinn::Connection> {
        match self {
            Self::Quic(connection) => Some(connection),
            Self::Http2(_) => None,
        }
    }

    pub async fn reauthenticate(&self, token: &str) -> anyhow::Result<bool> {
        match self {
            Self::Quic(connection) => tokio::time::timeout(Duration::from_secs(10), async {
                let (mut send, mut recv) = connection.open_bi().await?;
                let accepted = control::reauth_over_stream(&mut send, &mut recv, token).await?;
                Ok::<bool, anyhow::Error>(accepted)
            })
            .await
            .map_err(|_| anyhow::anyhow!("Reauth timed out"))?,
            Self::Http2(session) => session.reauthenticate(token).await,
        }
    }
}

pub async fn connect_and_handshake_http2<F>(
    token: String,
    endpoint: String,
    cert_pin: String,
    vpn_mtu: Option<u16>,
    protect_socket: F,
) -> anyhow::Result<(TunnelConnection, ControlMessage)>
where
    F: FnMut(&tokio::net::TcpSocket) -> anyhow::Result<()>,
{
    let hashes = decode_hex_pins(&cert_pin)
        .ok_or_else(|| anyhow::anyhow!("Invalid Certificate PIN hex string"))?;
    let (connection, config) =
        h2::connect_and_handshake(&endpoint, token, hashes, protect_socket).await?;
    validate_server_mtu(&config, compute_quic_mtu_config(vpn_mtu).local_tun_mtu)?;
    Ok((TunnelConnection::Http2(connection), config))
}

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
    _send_request: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    _stream: h3::client::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>,
    drive_handle: tokio::task::JoinHandle<()>,
}

impl Drop for H3SessionGuard {
    fn drop(&mut self) {
        self.drive_handle.abort();
    }
}

pub const fn effective_http3_framing(censorship_resistant: bool, http3_framing: bool) -> bool {
    http3_framing || censorship_resistant
}

fn alpn_protocols(effective_http3_framing: bool) -> Vec<Vec<u8>> {
    if effective_http3_framing {
        vec![b"h3".to_vec()]
    } else {
        vec![b"mavivpn".to_vec()]
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub async fn connect_and_handshake(
    socket: std::net::UdpSocket,
    token: String,
    endpoint_str: String,
    cert_pin: String,
    censorship_resistant: bool,
    http3_framing: bool,
    ech_config_hex: Option<String>,
    vpn_mtu: Option<u16>,
) -> anyhow::Result<(TunnelConnection, ControlMessage, Option<H3SessionGuard>)> {
    info!("Connect and Handshake started. Pin: {cert_pin}");
    let effective_http3_framing = effective_http3_framing(censorship_resistant, http3_framing);

    // Verifier Setup
    let verifier = if let Some(hashes) = decode_hex_pins(&cert_pin) {
        info!("Pin(s) decoded successfully. Count: {}", hashes.len());
        Arc::new(PinnedServerVerifier::new(hashes))
    } else {
        return Err(anyhow::anyhow!("Invalid Certificate PIN hex string"));
    };

    let mut client_crypto = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| anyhow::anyhow!("failed to enable TLS 1.3 on client config: {e}"))?
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_no_client_auth();

    // Raw and HTTP/3 modes are different wire protocols. Advertise exactly the
    // protocol the client is going to speak so the server cannot select h3 while
    // the client sends raw bincode auth bytes.
    client_crypto.alpn_protocols = alpn_protocols(effective_http3_framing);
    if effective_http3_framing {
        info!("HTTP/3 transport enabled. ALPN: h3");
    } else {
        info!("Standard Mode enabled. ALPN: mavivpn");
    }

    // Connect & MTU Logic
    info!("Resolving host: {endpoint_str}");
    let addrs: Vec<_> = tokio::net::lookup_host(&endpoint_str).await?.collect();
    let _addr = *addrs
        .first()
        .ok_or_else(|| anyhow::anyhow!("Invalid address"))?;
    // If an ECHConfigList was provided, spoof the outer SNI to its `public_name`.
    // Android's `ring` provider lacks HPKE so we cannot offer ECH GREASE, but
    // SNI override alone already hides the real hostname from on-path censors
    // (the server uses cert pinning, not SNI, for auth).
    let server_name = match ech_config_hex.as_deref() {
        Some(hex) => {
            let sni = crate::ech_client::outer_sni_from_hex(hex)
                .ok_or_else(|| anyhow::anyhow!("Failed to parse provided ECH config hex"))?;
            info!("ECH config parsed, overriding outer SNI: {sni}");
            sni
        }
        None => endpoint_host(&endpoint_str),
    };
    if server_name.is_empty() {
        return Err(anyhow::anyhow!("Endpoint host missing"));
    }

    // Outer QUIC payload MTU is derived from the inner TUN MTU (configurable
    // via vpn_mtu, env VPN_MTU, or default 1280) + 80-byte QUIC/AEAD overhead.
    // Server and client MUST agree on the TUN MTU, otherwise the larger side
    // will send UDP payloads the smaller side considers out-of-spec.
    let mtu_cfg = compute_quic_mtu_config(vpn_mtu);
    info!(
        "Setting QUIC MTU: {} (TUN MTU budget: {}, source: {:?}, Target Wire: {} IPv4 / {} IPv6)",
        mtu_cfg.quic_mtu,
        mtu_cfg.transport_tun_mtu,
        mtu_cfg.mtu_source,
        mtu_cfg.wire_mtu_ipv4,
        mtu_cfg.wire_mtu_ipv6,
    );

    // Performance Optimizations
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(None); // Disable idle timeout for Doze Mode!
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(15))); // Less aggressive keep-alive

    // MTU Pinning
    transport_config.mtu_discovery_config(None);
    transport_config.initial_mtu(mtu_cfg.quic_mtu);
    transport_config.min_mtu(mtu_cfg.quic_mtu);
    transport_config
        .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));

    // Enable GSO (Segmentation Offload) for higher throughput.
    // With GSO, Quinn batches multiple QUIC packets into one sendmsg() call,
    // bypassing Android's poor timer resolution which otherwise limits pacing.
    transport_config.enable_segmentation_offload(true);

    // Datagram buffer tuning (matching v0.4 settings for GSO traffic)
    transport_config.datagram_receive_buffer_size(Some(2 * 1024 * 1024)); // 2MB
    transport_config.datagram_send_buffer_size(2 * 1024 * 1024); // 2MB

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));
    client_config.transport_config(Arc::new(transport_config));

    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(client_config);

    let mut last_error = None;
    let mut connection = None;
    for addr in addrs {
        info!("Connecting to {addr} (SNI: {server_name})");
        match endpoint.connect(addr, &server_name) {
            Ok(connecting) => match connecting.await {
                Ok(conn) => {
                    connection = Some(conn);
                    break;
                }
                Err(err) => {
                    info!("QUIC handshake to {addr} failed: {err}");
                    last_error = Some(anyhow::Error::from(err));
                }
            },
            Err(err) => {
                info!("endpoint.connect() failed for {addr}: {err}");
                last_error = Some(anyhow::Error::from(err));
            }
        }
    }
    let Some(connection) = connection else {
        return Err(last_error
            .unwrap_or_else(|| anyhow::anyhow!("No reachable address for {endpoint_str}")));
    };
    info!("Connection established");

    // Handshake
    //
    // `h3_guard` (when present) keeps the h3 SendRequest, CONNECT-IP request
    // stream and driver task alive for the whole VPN session. The caller must
    // hold it until the session ends; dropping it earlier can close the HTTP/3
    // control plane while QUIC datagrams are still being used.
    let (config, h3_guard) = if effective_http3_framing {
        let (cfg, guard) = connect_and_handshake_h3(connection.clone(), token).await?;
        (cfg, Some(guard))
    } else {
        let (mut send_stream, mut recv_stream) = connection.open_bi().await?;
        info!("Stream opened");

        let auth_msg = ControlMessage::Auth { token };
        control::write_control_frame(&mut send_stream, &auth_msg).await?;
        info!("Auth sent");

        // Read Config
        let buf =
            control::read_control_frame(&mut recv_stream, control::MAX_CONTROL_FRAME_BYTES).await?;

        // In censorship-resistant mode the server returns a fake nginx HTML
        // page on auth failure. Detect by content, not a magic length.
        if looks_like_html_response(&buf) {
            return Err(anyhow::anyhow!(
                "AUTH_FAILED: Server returned HTML (camouflage response). \
                 Check token validity or Keycloak configuration."
            ));
        }

        let cfg = decode_raw_server_config(&buf)?;
        (cfg, None)
    };

    validate_server_mtu(&config, mtu_cfg.local_tun_mtu)?;

    Ok((TunnelConnection::Quic(connection), config, h3_guard))
}

fn decode_raw_server_config(buf: &[u8]) -> anyhow::Result<ControlMessage> {
    let cfg = control::decode_control_message(buf)?;

    if let ControlMessage::Error { message } = &cfg {
        return Err(anyhow::anyhow!("Server Error: {message}"));
    }
    Ok(cfg)
}

async fn connect_and_handshake_h3(
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

fn is_camouflage_h3_response(headers: &http::HeaderMap) -> bool {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().contains("text/html"))
        || headers
            .get(http::header::SERVER)
            .and_then(|h| h.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("nginx"))
}

fn endpoint_host(endpoint: &str) -> String {
    shared::endpoint_host(endpoint).to_string()
}

#[cfg(test)]
mod tests;
