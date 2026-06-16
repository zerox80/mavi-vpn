use anyhow::{Context, Result};
use shared::{
    compute_quic_mtu_config, endpoint_host_is_explicit_ipv6, looks_like_html_response,
    resolve_server_name, validate_control_message_mtu, ControlMessage,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

mod cert;
mod h3;
#[cfg(test)]
mod tests;

pub use self::cert::decode_hex;
use self::cert::PinnedServerVerifier;
pub use self::h3::H3SessionGuard;

// --- Default timing parameters ---
const KEEPALIVE_SECS: u64 = 10;
const IDLE_TIMEOUT_SECS: u64 = 60;

pub(super) struct HandshakeRequest {
    pub(super) socket: std::net::UdpSocket,
    pub(super) token: String,
    pub(super) endpoint_str: String,
    pub(super) cert_pin: Vec<u8>,
    pub(super) censorship_resistant: bool,
    pub(super) http3_framing: bool,
    pub(super) ech_config_list: Option<Vec<u8>>,
    pub(super) vpn_mtu: Option<u16>,
}

/// QUIC connection setup with custom certificate pinning.
#[allow(clippy::too_many_lines)]
pub(super) async fn connect_and_handshake(
    request: HandshakeRequest,
) -> Result<(quinn::Connection, ControlMessage, Option<H3SessionGuard>)> {
    let HandshakeRequest {
        socket,
        token,
        endpoint_str,
        cert_pin,
        censorship_resistant,
        http3_framing,
        ech_config_list,
        vpn_mtu,
    } = request;

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
            .context("failed to enable TLS 1.3 on client config")?
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
    let server_name = resolve_server_name(
        &endpoint_str,
        ech_state.as_ref().map(|e| e.outer_sni.as_str()),
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    // The client pins its QUIC payload budget to the local TUN MTU before the
    // handshake (MTU discovery is disabled), so the server-pushed MTU must
    // match it exactly - see `validate_server_mtu` / `shared::check_server_mtu`.
    let mtu_cfg = compute_quic_mtu_config(vpn_mtu);
    let wire_mtu = if addr.is_ipv4() {
        mtu_cfg.wire_mtu_ipv4
    } else {
        mtu_cfg.wire_mtu_ipv6
    };
    info!(
        "Address family: {}. Setting QUIC MTU: {} (TUN MTU budget: {}, source: {:?}, Target Wire: {})",
        if addr.is_ipv4() { "IPv4" } else { "IPv6" },
        mtu_cfg.quic_mtu,
        mtu_cfg.transport_tun_mtu,
        mtu_cfg.mtu_source,
        wire_mtu,
    );

    let mut transport_config = quinn::TransportConfig::default();
    let idle_timeout = Duration::from_secs(IDLE_TIMEOUT_SECS)
        .try_into()
        .context("invalid QUIC idle timeout")?;
    transport_config.max_idle_timeout(Some(idle_timeout));
    transport_config.keep_alive_interval(Some(Duration::from_secs(KEEPALIVE_SECS)));

    // MTU PINNING
    transport_config.mtu_discovery_config(None);
    transport_config.initial_mtu(mtu_cfg.quic_mtu);
    transport_config.min_mtu(mtu_cfg.quic_mtu);

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
        let (cfg, guard) = h3::connect_and_handshake_h3(connection.clone(), token).await?;
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
        validate_raw_response_len(len)?;
        let mut buf = vec![0u8; len];
        recv.read_exact(&mut buf).await?;

        // In censorship-resistant mode the server returns a fake nginx HTML
        // page on auth failure. Detect by content, not magic length.
        if looks_like_html_response(&buf) {
            anyhow::bail!(
                "AUTH_FAILED: Server returned HTML (camouflage response). \
                 Check token validity or Keycloak configuration."
            );
        }

        let cfg: ControlMessage =
            bincode::serde::decode_from_slice(&buf, bincode::config::standard()).map(|(v, _)| v)?;
        info!(
            "Received raw server config in {} ms",
            config_started.elapsed().as_millis()
        );
        (cfg, None)
    };

    validate_control_message_mtu(&config, mtu_cfg.local_tun_mtu).map_err(|e| anyhow::anyhow!(e))?;

    Ok((connection, config, h3_guard))
}

pub fn order_resolved_addrs(addrs: &mut [SocketAddr], endpoint: &str) {
    if endpoint_host_is_explicit_ipv6(endpoint) {
        return;
    }

    addrs.sort_by_key(|addr| i32::from(!addr.is_ipv4()));
}

#[cfg(test)]
fn validate_server_mtu(config: &ControlMessage, local_tun_mtu: u16) -> Result<()> {
    validate_control_message_mtu(config, local_tun_mtu).map_err(|e| anyhow::anyhow!(e))
}

#[cfg(test)]
fn wire_mtu_for_addr(config: shared::QuicMtuConfig, addr: &SocketAddr) -> u16 {
    if addr.is_ipv4() {
        config.wire_mtu_ipv4
    } else {
        config.wire_mtu_ipv6
    }
}

fn validate_raw_response_len(len: usize) -> Result<()> {
    if len > 65_536 {
        anyhow::bail!("Server response too large: {len} bytes");
    }
    Ok(())
}
