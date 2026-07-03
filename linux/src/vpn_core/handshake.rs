use super::cert_pin::PinnedServerVerifier;
use super::h3::H3SessionGuard;
use anyhow::{Context, Result};
use shared::{
    compute_quic_mtu_config, control, looks_like_html_response, resolve_server_name,
    validate_control_message_mtu, ControlMessage,
};
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

const KEEPALIVE_SECS: u64 = 10;
const IDLE_TIMEOUT_SECS: u64 = 60;

/// QUIC connection setup with custom certificate pinning.
#[allow(clippy::too_many_arguments)]
pub(super) async fn connect_and_handshake(
    socket: std::net::UdpSocket,
    token: String,
    endpoint_str: String,
    cert_pin: Vec<Vec<u8>>,
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
    let addr = tokio::net::lookup_host(&endpoint_str)
        .await?
        .next()
        .context("Failed to resolve endpoint")?;

    // Outer QUIC payload MTU is derived from the operator-configured inner TUN
    // MTU (`VPN_MTU`, default 1280). The 80-byte overhead reserves room for
    // QUIC short-header framing + AEAD tag + connection-ID bytes. Server and
    // client MUST be configured with the same `VPN_MTU`, otherwise the larger
    // side will send UDP payloads the smaller side considers out-of-spec.
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
    // Handled in NetworkConfig::apply.

    transport_config.enable_segmentation_offload(true);
    transport_config
        .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));

    // Datagram queue tuning (match Windows/Android: 2MB each direction)
    transport_config.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
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

    // When ECH is active we send the config's `public_name` as the outer SNI
    // instead of the real server hostname. Cert-pin auth is unaffected.
    let server_name = resolve_server_name(
        &endpoint_str,
        ech_state.as_ref().map(|e| e.outer_sni.as_str()),
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    info!("Connecting to {} (SNI: {})", addr, server_name);
    let connection = endpoint
        .connect(addr, &server_name)?
        .await
        .context("QUIC handshake failed")?;

    // Application-level handshake
    let (config, h3_guard) = if effective_http3_framing {
        let (cfg, guard) = super::h3::connect_and_handshake_h3(connection.clone(), token).await?;
        (cfg, Some(guard))
    } else {
        let (mut send, mut recv) = connection.open_bi().await?;
        let auth_msg = ControlMessage::Auth { token };
        control::write_control_frame(&mut send, &auth_msg).await?;
        let _ = send.finish();

        let buf = control::read_control_frame(&mut recv, control::MAX_CONTROL_FRAME_BYTES).await?;
        let cfg = decode_raw_response_body(&buf)?;
        (cfg, None)
    };

    validate_control_message_mtu(&config, mtu_cfg.local_tun_mtu).map_err(|e| anyhow::anyhow!(e))?;

    Ok((connection, config, h3_guard))
}

#[cfg(test)]
fn endpoint_host(endpoint: &str) -> String {
    shared::endpoint_host(endpoint).to_string()
}

fn decode_raw_response_body(buf: &[u8]) -> Result<ControlMessage> {
    // In censorship-resistant mode the server returns a fake nginx HTML page
    // on auth failure instead of a bincode ControlMessage. Detect this
    // reliably by checking the content, not a magic length.
    if looks_like_html_response(buf) {
        anyhow::bail!(
            "AUTH_FAILED: Server returned HTML (camouflage response). \
             Check token validity or Keycloak configuration."
        );
    }
    Ok(control::decode_control_message(buf)?)
}

#[cfg(test)]
fn validate_server_mtu(config: &ControlMessage, local_tun_mtu: u16) -> Result<()> {
    validate_control_message_mtu(config, local_tun_mtu).map_err(|e| anyhow::anyhow!(e))
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

    fn encode(msg: &ControlMessage) -> Vec<u8> {
        bincode::serde::encode_to_vec(msg, bincode::config::standard()).unwrap()
    }

    #[test]
    fn endpoint_host_parses_hostname_ipv4_and_ipv6_forms() {
        assert_eq!(endpoint_host("vpn.example.com:443"), "vpn.example.com");
        assert_eq!(endpoint_host("203.0.113.10:443"), "203.0.113.10");
        assert_eq!(endpoint_host("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(endpoint_host("2001:db8::1"), "2001:db8::1");
        assert_eq!(endpoint_host("vpn.example.com"), "vpn.example.com");
    }

    #[test]
    fn raw_response_body_decodes_config_and_error() {
        let config = decode_raw_response_body(&encode(&config_with_mtu(1280))).unwrap();
        assert!(matches!(config, ControlMessage::Config { mtu: 1280, .. }));

        let error = decode_raw_response_body(&encode(&ControlMessage::Error {
            message: "denied".to_string(),
        }))
        .unwrap();
        assert!(matches!(error, ControlMessage::Error { message } if message == "denied"));
    }

    #[test]
    fn raw_response_body_rejects_malformed_bytes() {
        assert!(decode_raw_response_body(&[0xde, 0xad, 0xbe, 0xef]).is_err());
    }

    #[test]
    fn server_mtu_must_match_linux_client() {
        // Strict equality regardless of how the local MTU was sourced: a
        // server MTU that differs from the pinned local budget is rejected.
        assert!(validate_server_mtu(&config_with_mtu(1280), 1280).is_ok());
        assert!(validate_server_mtu(&config_with_mtu(1340), 1340).is_ok());
        assert!(validate_server_mtu(&config_with_mtu(1340), 1280).is_err());
        assert!(validate_server_mtu(&config_with_mtu(1280), 1340).is_err());
        assert!(validate_server_mtu(&config_with_mtu(1400), 1280).is_err());
    }

    #[test]
    fn raw_response_body_rejects_empty_buffer() {
        assert!(decode_raw_response_body(&[]).is_err());
    }

    #[test]
    fn server_mtu_ignores_non_config_messages() {
        let auth = ControlMessage::Auth {
            token: "tok".to_string(),
        };
        assert!(validate_server_mtu(&auth, 1280).is_ok());

        let err = ControlMessage::Error {
            message: "bad".to_string(),
        };
        assert!(validate_server_mtu(&err, 1280).is_ok());
    }

    #[test]
    fn server_mtu_boundary_values() {
        assert!(
            validate_server_mtu(&config_with_mtu(shared::MIN_TUN_MTU), shared::MIN_TUN_MTU).is_ok()
        );
        assert!(
            validate_server_mtu(&config_with_mtu(shared::MAX_TUN_MTU), shared::MAX_TUN_MTU).is_ok()
        );
        assert!(validate_server_mtu(&config_with_mtu(shared::MIN_TUN_MTU - 1), 1280).is_err());
        assert!(validate_server_mtu(&config_with_mtu(shared::MAX_TUN_MTU + 1), 1280).is_err());
    }

    #[test]
    fn endpoint_host_handles_empty_and_port_only() {
        assert_eq!(endpoint_host(""), "");
        assert_eq!(endpoint_host(":443"), "");
    }

    #[test]
    fn endpoint_host_bare_ipv6_without_brackets() {
        assert_eq!(endpoint_host("::1"), "::1");
        assert_eq!(endpoint_host("fe80::1"), "fe80::1");
    }
}
