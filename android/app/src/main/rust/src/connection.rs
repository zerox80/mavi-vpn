use bytes::{Buf, Bytes};
use h3_quinn::Connection as H3QuinnConnection;
use log::info;
use shared::{
    masque::{self, CAPSULE_MAVI_CONFIG},
    resolve_tun_mtu, ControlMessage, QUIC_OVERHEAD_BYTES,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::crypto::{decode_hex, PinnedServerVerifier};

/// Holds the h3 CONNECT-IP request state for the lifetime of the VPN session.
///
/// `h3::client::SendRequest::drop` decrements an internal sender count; when the last
/// handle goes away it calls `handle_connection_error_on_stream(H3_NO_ERROR,
/// "Connection closed by client")` and tears down the underlying quinn connection.
/// Keeping this guard alongside the quinn::Connection prevents that early shutdown
/// so the VPN datagram plane can keep using the same connection after the H3 auth
/// request completes.
///
/// The CONNECT-IP request stream itself must also remain open for the lifetime of
/// the session. Dropping it after reading MAVI_CONFIG can end the logical MASQUE
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

#[allow(clippy::too_many_arguments)]
pub async fn connect_and_handshake(
    socket: std::net::UdpSocket,
    token: String,
    endpoint_str: String,
    cert_pin: String,
    censorship_resistant: bool,
    http3_framing: bool,
    ech_config_hex: Option<String>,
    vpn_mtu: Option<u16>,
) -> anyhow::Result<(quinn::Connection, ControlMessage, Option<H3SessionGuard>)> {
    info!("Connect and Handshake started. Pin: {}", cert_pin);

    // Verifier Setup
    let verifier = if let Some(bytes) = decode_hex(&cert_pin) {
        info!("Pin decoded successfully. Len: {}", bytes.len());
        Arc::new(PinnedServerVerifier::new(bytes))
    } else {
        return Err(anyhow::anyhow!("Invalid Certificate PIN hex string"));
    };

    let mut client_crypto = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_no_client_auth();

    // HTTP/3 transport requires h3. Raw mode keeps mavivpn as the preferred ALPN.
    if http3_framing || censorship_resistant {
        client_crypto.alpn_protocols = vec![b"h3".to_vec()];
        info!("HTTP/3 transport enabled. ALPN: h3");
    } else {
        client_crypto.alpn_protocols = vec![b"mavivpn".to_vec(), b"h3".to_vec()];
        info!("Standard Mode enabled. ALPN: mavivpn, h3");
    }

    // Connect & MTU Logic
    info!("Resolving host: {}", endpoint_str);
    let addrs: Vec<_> = tokio::net::lookup_host(&endpoint_str).await?.collect();
    let _addr = *addrs.first().ok_or(anyhow::anyhow!("Invalid address"))?;
    // If an ECHConfigList was provided, spoof the outer SNI to its `public_name`.
    // Android's `ring` provider lacks HPKE so we cannot offer ECH GREASE, but
    // SNI override alone already hides the real hostname from on-path censors
    // (the server uses cert pinning, not SNI, for auth).
    let server_name = match ech_config_hex.as_deref() {
        Some(hex) => {
            let sni = crate::ech_client::outer_sni_from_hex(hex)
                .ok_or_else(|| anyhow::anyhow!("Failed to parse provided ECH config hex"))?;
            info!("ECH config parsed, overriding outer SNI: {}", sni);
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
    let tun_mtu = resolve_tun_mtu(vpn_mtu);
    let quic_mtu = tun_mtu + QUIC_OVERHEAD_BYTES;
    info!(
        "Setting QUIC MTU: {} (TUN MTU: {}, Target Wire: {} IPv4 / {} IPv6)",
        quic_mtu,
        tun_mtu,
        quic_mtu + 20 + 8,
        quic_mtu + 40 + 8,
    );

    // Performance Optimizations
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(None); // Disable idle timeout for Doze Mode!
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(15))); // Less aggressive keep-alives

    // MTU Pinning
    transport_config.mtu_discovery_config(None);
    transport_config.initial_mtu(quic_mtu);
    transport_config.min_mtu(quic_mtu);
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
        info!("Connecting to {} (SNI: {})", addr, server_name);
        match endpoint.connect(addr, &server_name) {
            Ok(connecting) => match connecting.await {
                Ok(conn) => {
                    connection = Some(conn);
                    break;
                }
                Err(err) => {
                    info!("QUIC handshake to {} failed: {}", addr, err);
                    last_error = Some(anyhow::Error::from(err));
                }
            },
            Err(err) => {
                info!("endpoint.connect() failed for {}: {}", addr, err);
                last_error = Some(anyhow::Error::from(err));
            }
        }
    }
    let connection = match connection {
        Some(conn) => conn,
        None => {
            return Err(last_error
                .unwrap_or_else(|| anyhow::anyhow!("No reachable address for {}", endpoint_str)))
        }
    };
    info!("Connection established");

    // Handshake
    //
    // `h3_guard` (when present) keeps the h3 SendRequest, CONNECT-IP request
    // stream and driver task alive for the whole VPN session. The caller must
    // hold it until the session ends; dropping it earlier can close the HTTP/3
    // control plane while QUIC datagrams are still being used.
    let (config, h3_guard) = if http3_framing {
        let (cfg, guard) = connect_and_handshake_h3(connection.clone(), token).await?;
        (cfg, Some(guard))
    } else {
        let (mut send_stream, mut recv_stream) = connection.open_bi().await?;
        info!("Stream opened");

        let auth_msg = ControlMessage::Auth { token };
        let bytes = bincode::serde::encode_to_vec(&auth_msg, bincode::config::standard())
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        send_stream.write_u32_le(bytes.len() as u32).await?;
        send_stream.write_all(&bytes).await?;
        info!("Auth sent");

        // Read Config
        let len = recv_stream.read_u32_le().await? as usize;
        if len > 65536 {
            return Err(anyhow::anyhow!("Server response too large: {} bytes", len));
        }
        let mut buf = vec![0u8; len];
        if let Err(e) = recv_stream.read_exact(&mut buf).await {
            if len == 6401 && censorship_resistant {
                return Err(anyhow::anyhow!("Access Denied: Server rejected the token. Check Keycloak logs or token validity."));
            }
            return Err(anyhow::anyhow!("Handshake read error: {}", e));
        }

        let cfg: ControlMessage =
            bincode::serde::decode_from_slice(&buf, bincode::config::standard())
                .map(|(v, _)| v)
                .map_err(|e| anyhow::anyhow!("{}", e))?;

        if let ControlMessage::Error { message } = &cfg {
            return Err(anyhow::anyhow!("Server Error: {}", message));
        }
        (cfg, None)
    };

    validate_server_mtu(&config, tun_mtu)?;

    Ok((connection, config, h3_guard))
}

fn validate_server_mtu(config: &ControlMessage, local_tun_mtu: u16) -> anyhow::Result<()> {
    if let ControlMessage::Config { mtu, .. } = config {
        if *mtu != local_tun_mtu {
            anyhow::bail!(
                "MTU mismatch: local/client VPN MTU is {}, but server pushed {}. Configure both sides to the same VPN_MTU.",
                local_tun_mtu,
                mtu
            );
        }
    }
    Ok(())
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
        .map_err(|e| anyhow::anyhow!("H3 client init failed: {}", e))?;

    // Drive the H3 connection in the background for the lifetime of the session.
    let drive_handle = tokio::spawn(async move {
        let e = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        log::debug!("H3 driver finished: {}", e);
    });

    // RFC 9484 connect-ip: Extended CONNECT with :protocol=connect-ip.
    // The target template /.well-known/masque/ip/*/* tunnels all addresses+protocols.
    let req = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("https://mavi-vpn/.well-known/masque/ip/*/*/")
        .extension(h3::ext::Protocol::CONNECT_IP)
        .header("authorization", format!("Bearer {}", token))
        .header("capsule-protocol", "?1")
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build H3 CONNECT request: {}", e))?;

    let mut stream = send_request
        .send_request(req)
        .await
        .map_err(|e| anyhow::anyhow!("H3 send_request failed: {}", e))?;

    // NOTE: do NOT call stream.finish(). connect-ip keeps the request stream
    // open bidirectionally for the whole session (for capsules + control).

    let resp = stream
        .recv_response()
        .await
        .map_err(|e| anyhow::anyhow!("H3 recv_response failed: {}", e))?;

    if resp.status() != http::StatusCode::OK {
        anyhow::bail!("AUTH_FAILED: Server returned HTTP {}", resp.status());
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
                        .map_err(|e| anyhow::anyhow!("Failed to decode MAVI_CONFIG: {}", e))?;
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
            Ok(Err(e)) => anyhow::bail!("H3 recv_data failed: {}", e),
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

    let config = config.expect("loop invariant: broken out only when config set");

    if let ControlMessage::Error { message } = &config {
        return Err(anyhow::anyhow!("Server Error: {}", message));
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

fn endpoint_host(endpoint: &str) -> String {
    if let Some(rest) = endpoint.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].to_string();
        }
    }

    if endpoint.matches(':').count() == 1 {
        if let Some((host, _)) = endpoint.rsplit_once(':') {
            return host.to_string();
        }
    }

    endpoint.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_host_simple() {
        assert_eq!(endpoint_host("vpn.example.com:4433"), "vpn.example.com");
    }

    #[test]
    fn endpoint_host_ipv4() {
        assert_eq!(endpoint_host("192.168.1.1:4433"), "192.168.1.1");
    }

    #[test]
    fn endpoint_host_ipv6_bracketed() {
        assert_eq!(endpoint_host("[::1]:4433"), "::1");
    }

    #[test]
    fn endpoint_host_no_port() {
        assert_eq!(endpoint_host("vpn.example.com"), "vpn.example.com");
    }

    #[test]
    fn endpoint_host_ipv6_no_brackets() {
        assert_eq!(endpoint_host("::1"), "::1");
    }

    fn config_with_mtu(mtu: u16) -> ControlMessage {
        ControlMessage::Config {
            assigned_ip: "10.8.0.2".parse().unwrap(),
            netmask: "255.255.255.0".parse().unwrap(),
            gateway: "10.8.0.1".parse().unwrap(),
            dns_server: "1.1.1.1".parse().unwrap(),
            mtu,
            assigned_ipv6: None,
            netmask_v6: None,
            gateway_v6: None,
            dns_server_v6: None,
            whitelist_domains: None,
        }
    }

    #[test]
    fn validate_server_mtu_accepts_match() {
        assert!(validate_server_mtu(&config_with_mtu(1280), 1280).is_ok());
    }

    #[test]
    fn validate_server_mtu_rejects_mismatch() {
        let err = validate_server_mtu(&config_with_mtu(1360), 1280).unwrap_err();
        assert!(err.to_string().contains("MTU mismatch"));
    }
}
