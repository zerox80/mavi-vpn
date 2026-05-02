use super::network::split_endpoint;
use anyhow::{Context, Result};
use shared::{
    resolve_tun_mtu_with_source, ControlMessage, TunMtuSource, MAX_TUN_MTU, QUIC_OVERHEAD_BYTES,
};
use std::net::{Ipv6Addr, SocketAddr};
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
