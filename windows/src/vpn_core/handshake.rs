use super::network::split_endpoint;
use anyhow::{Context, Result};
use bytes::Buf;
use h3_quinn::Connection as H3QuinnConnection;
use sha2::{Digest, Sha256};
use shared::{
    masque::{self, CAPSULE_MAVI_CONFIG},
    resolve_tun_mtu_with_source, ControlMessage, TunMtuSource, MAX_TUN_MTU, QUIC_OVERHEAD_BYTES,
};
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

/// Holds the h3 `SendRequest` + driver task for the lifetime of the VPN session.
///
/// Dropping `h3::client::SendRequest` decrements its internal `sender_count`; when the
/// last one goes, its `Drop` impl calls `handle_connection_error_on_stream(H3_NO_ERROR,
/// "Connection closed by client")` which tears down the underlying quinn connection.
/// We therefore keep the `SendRequest` alive for the whole session so the VPN datagram
/// plane can keep using the same `quinn::Connection`.
pub struct H3SessionGuard {
    _send_request: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    drive_handle: tokio::task::JoinHandle<()>,
}

impl Drop for H3SessionGuard {
    fn drop(&mut self) {
        self.drive_handle.abort();
    }
}

// --- Default timing parameters ---
const KEEPALIVE_SECS: u64 = 10;
const IDLE_TIMEOUT_SECS: u64 = 60;

/// QUIC connection setup with custom certificate pinning.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub async fn connect_and_handshake(
    socket: std::net::UdpSocket,
    token: String,
    endpoint_str: String,
    cert_pin: Vec<u8>,
    censorship_resistant: bool,
    http3_framing: bool,
    ech_config_list: Option<Vec<u8>>,
    vpn_mtu: Option<u16>,
) -> Result<(quinn::Connection, ControlMessage, Option<H3SessionGuard>)> {
    let effective_http3_framing = http3_framing || censorship_resistant;
    let verifier = Arc::new(PinnedServerVerifier::new(cert_pin));

    // Decide up-front whether we will offer ECH GREASE and which SNI to send on
    // the wire. The outer SNI spoof is safe because the server authenticates via
    // SHA-256 cert pinning and does not inspect the SNI.
    let ech_state = match ech_config_list.as_deref() {
        Some(bytes) => {
            let parsed = crate::ech_client::parse(bytes)
                .context("Failed to parse ECH config list")?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "ECH config list contained no HPKE suites supported by aws-lc-rs"
                    )
                })?;
            info!("ECH GREASE enabled, outer SNI: {}", parsed.outer_sni);
            Some(parsed)
        }
        None => None,
    };

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let builder = rustls::ClientConfig::builder_with_provider(provider.into());
    let versioned = if let Some(ech) = ech_state.as_ref() {
        // `with_ech` implicitly pins TLS 1.3 (required by ECH) and registers the
        // GREASE extension, mimicking the server's advertised HPKE suite.
        builder
            .with_ech(rustls::client::EchMode::Grease(ech.grease.clone()))
            .context("failed to enable ECH GREASE on client config")?
    } else {
        builder
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
    };

    let mut client_crypto = versioned
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    // HTTP/3 transport requires h3. Raw mode keeps mavivpn as the preferred ALPN.
    client_crypto.alpn_protocols = if effective_http3_framing {
        vec![b"h3".to_vec()]
    } else {
        vec![b"mavivpn".to_vec(), b"h3".to_vec()]
    };

    // Resolve endpoint and connect
    let resolve_started = Instant::now();
    let endpoint_clean = endpoint_str.trim();
    let mut addrs: Vec<_> = tokio::net::lookup_host(endpoint_clean)
        .await
        .map_err(|e| anyhow::anyhow!("DNS lookup failed for [{endpoint_clean:?}]: {e}"))?
        .collect();
    order_resolved_addrs(&mut addrs, endpoint_clean);
    let addr = *addrs.first().context("Failed to resolve endpoint")?;
    info!(
        "Resolved {} to {} address(es) in {} ms",
        endpoint_str,
        addrs.len(),
        resolve_started.elapsed().as_millis()
    );
    // When ECH is active we send the config's `public_name` as the outer SNI
    // instead of the real server hostname. Cert-pin auth is unaffected.
    let server_name: String = ech_state.as_ref().map_or_else(
        || {
            let (host, _) = split_endpoint(&endpoint_str);
            host.to_string()
        },
        |ech| ech.outer_sni.clone(),
    );
    if server_name.is_empty() {
        anyhow::bail!("Endpoint host missing");
    }

    // When the client has no operator-configured MTU, reserve enough QUIC
    // payload budget for any server-pushed MTU in the supported range. The
    // server config remains authoritative for the actual Windows adapter MTU.
    let (local_tun_mtu, mtu_source) = resolve_tun_mtu_with_source(vpn_mtu);
    let transport_tun_mtu = if matches!(mtu_source, TunMtuSource::Default) {
        MAX_TUN_MTU
    } else {
        local_tun_mtu
    };
    let quic_mtu = transport_tun_mtu + QUIC_OVERHEAD_BYTES;
    let (ip_overhead, udp_overhead) = (if addr.is_ipv4() { 20u16 } else { 40u16 }, 8u16);
    info!(
        "Address family: {}. Setting QUIC MTU: {} (TUN MTU budget: {}, source: {:?}, Target Wire: {})",
        if addr.is_ipv4() { "IPv4" } else { "IPv6" },
        quic_mtu,
        transport_tun_mtu,
        mtu_source,
        quic_mtu + ip_overhead + udp_overhead,
    );

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(
        Duration::from_secs(IDLE_TIMEOUT_SECS).try_into().unwrap(),
    ));
    transport_config.keep_alive_interval(Some(Duration::from_secs(KEEPALIVE_SECS)));

    // MTU PINNING
    transport_config.mtu_discovery_config(None);
    transport_config.initial_mtu(quic_mtu);
    transport_config.min_mtu(quic_mtu);

    // Rule 1: TUN MTU MUST be 1280.
    // Handled in NetworkConfig::apply. Peer datagram size is implicitly limited by path MTU discovery.

    transport_config.enable_segmentation_offload(true);
    transport_config
        .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));

    // Datagram queue tuning for high-speed GSO traffic (Avoiding 'dropping stale datagram' errors)
    transport_config.datagram_receive_buffer_size(Some(2 * 1024 * 1024)); // 2MB
    transport_config.datagram_send_buffer_size(2 * 1024 * 1024); // Increased from 256KB

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
        let handshake_started = Instant::now();
        info!(
            "Connecting to {} (resolved: {}, SNI: {})",
            endpoint_str, addr, server_name
        );
        match endpoint.connect(addr, &server_name) {
            Ok(connecting) => match connecting.await {
                Ok(conn) => {
                    info!(
                        "QUIC handshake to {} completed in {} ms",
                        addr,
                        handshake_started.elapsed().as_millis()
                    );
                    connection = Some(conn);
                    break;
                }
                Err(err) => {
                    warn!(
                        "QUIC handshake to {} failed after {} ms: {}",
                        addr,
                        handshake_started.elapsed().as_millis(),
                        err
                    );
                    last_error = Some(anyhow::Error::from(err));
                }
            },
            Err(err) => {
                warn!("endpoint.connect() failed for {}: {}", addr, err);
                last_error = Some(anyhow::Error::from(err));
            }
        }
    }
    let Some(connection) = connection else {
        return Err(last_error
            .unwrap_or_else(|| anyhow::anyhow!("No reachable address for {endpoint_str}")));
    };
    info!(
        "QUIC handshake OK, sending auth token ({} bytes)",
        token.len()
    );

    let config_started = Instant::now();
    let (config, h3_guard) = if effective_http3_framing {
        let (cfg, guard) = connect_and_handshake_h3(connection.clone(), token).await?;
        info!(
            "Received H3 server config in {} ms",
            config_started.elapsed().as_millis()
        );
        (cfg, Some(guard))
    } else {
        // Perform application-level handshake
        let (mut send, mut recv) = connection.open_bi().await?;
        let auth_msg = ControlMessage::Auth { token };
        let bytes = bincode::serde::encode_to_vec(&auth_msg, bincode::config::standard())?;
        #[allow(clippy::cast_possible_truncation)]
        send.write_u32_le(bytes.len() as u32).await?;
        send.write_all(&bytes).await?;
        let _ = send.finish(); // properly close the send side of the auth stream

        let len = recv.read_u32_le().await? as usize;
        if len > 65536 {
            anyhow::bail!("Server response too large: {len} bytes");
        }
        if len == 0x1901 {
            // This magic length happens when the server sends the HTTP/3 spoof payload
            // [0x01, 0x19, 0x00, 0x00] in censorship_resistant mode due to Auth Failure.
            anyhow::bail!("AUTH_FAILED: Server rejected authentication token");
        }
        let mut buf = vec![0u8; len];
        recv.read_exact(&mut buf).await?;
        let cfg: ControlMessage =
            bincode::serde::decode_from_slice(&buf, bincode::config::standard()).map(|(v, _)| v)?;
        info!(
            "Received raw server config in {} ms",
            config_started.elapsed().as_millis()
        );
        (cfg, None)
    };

    validate_server_mtu(&config, local_tun_mtu, mtu_source)?;

    Ok((connection, config, h3_guard))
}

pub fn endpoint_host_is_explicit_ipv6(endpoint: &str) -> bool {
    let (host, _) = split_endpoint(endpoint);
    host.parse::<Ipv6Addr>().is_ok()
}

pub fn order_resolved_addrs(addrs: &mut [SocketAddr], endpoint: &str) {
    if endpoint_host_is_explicit_ipv6(endpoint) {
        return;
    }

    addrs.sort_by_key(|addr| i32::from(!addr.is_ipv4()));
}

fn validate_server_mtu(
    config: &ControlMessage,
    local_tun_mtu: u16,
    mtu_source: TunMtuSource,
) -> Result<()> {
    if let ControlMessage::Config { mtu, .. } = config {
        if !(shared::MIN_TUN_MTU..=MAX_TUN_MTU).contains(mtu) {
            anyhow::bail!(
                "Server pushed unsupported VPN MTU {}. Supported range is {}-{}.",
                mtu,
                shared::MIN_TUN_MTU,
                MAX_TUN_MTU
            );
        }

        if mtu_source != TunMtuSource::Default && *mtu != local_tun_mtu {
            anyhow::bail!(
                "MTU mismatch: local/client VPN MTU is {local_tun_mtu}, but server pushed {mtu}. Configure both sides to the same VPN_MTU."
            );
        }

        if mtu_source == TunMtuSource::Default && *mtu != local_tun_mtu {
            info!(
                "Using server-pushed VPN MTU {} because client MTU is unset (default would be {})",
                mtu, local_tun_mtu
            );
        }
    }
    Ok(())
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
async fn connect_and_handshake_h3(
    connection: quinn::Connection,
    token: String,
) -> Result<(ControlMessage, H3SessionGuard)> {
    let h3_conn = H3QuinnConnection::new(connection.clone());
    let mut builder = h3::client::builder();
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
        .extension(h3::ext::Protocol::CONNECT_IP)
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

        // Try to decode any fully-received capsules in the buffer first.
        while let Some(parts) = masque::read_capsule(&capsule_buf) {
            let (ctype, payload, consumed) = (parts.0, parts.1.to_vec(), parts.2);
            capsule_buf.drain(..consumed);
            if ctype == CAPSULE_MAVI_CONFIG {
                config = Some(
                    bincode::serde::decode_from_slice(&payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| anyhow::anyhow!("Failed to decode MAVI_CONFIG: {e}"))?,
                );
                break 'read;
            }
            // Other capsule types (ADDRESS_ASSIGN, ROUTE_ADVERTISEMENT, …) are
            // acknowledged by being parsed; we rely on MAVI_CONFIG for the
            // authoritative Windows-side configuration.
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
        if capsule_buf.len() > masque::MAX_CAPSULE_BUF {
            anyhow::bail!(
                "connect-ip capsule buffer exceeded {} bytes",
                masque::MAX_CAPSULE_BUF
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
pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
/// Custom certificate verifier that trusts only a specific SHA-256 fingerprint.
#[derive(Debug)]
struct PinnedServerVerifier {
    expected_hash: Vec<u8>,
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PinnedServerVerifier {
    fn new(expected_hash: Vec<u8>) -> Self {
        Self {
            expected_hash,
            supported: rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms,
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let cert_hash = Sha256::digest(end_entity.as_ref());
        if cert_hash.as_slice() == self.expected_hash.as_slice() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("Certificate PIN mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn config_with_mtu(mtu: u16) -> ControlMessage {
        ControlMessage::Config {
            assigned_ip: Ipv4Addr::new(10, 8, 0, 2),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::new(10, 8, 0, 1),
            dns_server: Ipv4Addr::new(1, 1, 1, 1),
            mtu,
            assigned_ipv6: None,
            netmask_v6: None,
            gateway_v6: None,
            dns_server_v6: None,
            whitelist_domains: None,
        }
    }

    #[test]
    fn non_ipv6_endpoint_prefers_ipv4_addresses() {
        let mut addrs: Vec<SocketAddr> = vec![
            "[2001:db8::1]:443".parse().unwrap(),
            "203.0.113.10:443".parse().unwrap(),
            "[2001:db8::2]:443".parse().unwrap(),
            "203.0.113.11:443".parse().unwrap(),
        ];

        order_resolved_addrs(&mut addrs, "vpn.example.com:443");

        assert!(addrs[0].is_ipv4());
        assert!(addrs[1].is_ipv4());
        assert!(addrs[2].is_ipv6());
        assert!(addrs[3].is_ipv6());
    }

    #[test]
    fn explicit_ipv6_endpoint_keeps_resolution_order() {
        let original: Vec<SocketAddr> = vec![
            "[2001:db8::1]:443".parse().unwrap(),
            "203.0.113.10:443".parse().unwrap(),
        ];
        let mut addrs = original.clone();

        order_resolved_addrs(&mut addrs, "[2001:db8::1]:443");

        assert_eq!(addrs, original);
    }

    #[test]
    fn detects_explicit_ipv6_host() {
        assert!(endpoint_host_is_explicit_ipv6("[2001:db8::1]:443"));
        assert!(endpoint_host_is_explicit_ipv6("2001:db8::1"));
        assert!(!endpoint_host_is_explicit_ipv6("vpn.example.com:443"));
        assert!(!endpoint_host_is_explicit_ipv6("203.0.113.10:443"));
    }

    #[test]
    fn server_mtu_is_accepted_when_client_uses_default() {
        let cfg = config_with_mtu(1340);

        assert!(validate_server_mtu(&cfg, 1280, TunMtuSource::Default).is_ok());
    }

    #[test]
    fn explicit_client_mtu_must_match_server_mtu() {
        let cfg = config_with_mtu(1340);

        assert!(validate_server_mtu(&cfg, 1280, TunMtuSource::Config).is_err());
        assert!(validate_server_mtu(&cfg, 1280, TunMtuSource::Env).is_err());
        assert!(validate_server_mtu(&cfg, 1340, TunMtuSource::Config).is_ok());
    }

    #[test]
    fn server_mtu_must_be_supported() {
        let cfg = config_with_mtu(1500);

        assert!(validate_server_mtu(&cfg, 1280, TunMtuSource::Default).is_err());
    }
}
