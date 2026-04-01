use std::sync::Arc;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use log::info;
use shared::ControlMessage;
use crate::crypto::{decode_hex, PinnedServerVerifier};

pub async fn connect_and_handshake(
    socket: std::net::UdpSocket, 
    token: String, 
    endpoint_str: String, 
    cert_pin: String,
    censorship_resistant: bool,
) -> anyhow::Result<(quinn::Connection, ControlMessage)> {
    
    info!("Connect and Handshake started. Pin: {}", cert_pin);

    // Verifier Setup
    let verifier = if let Some(bytes) = decode_hex(&cert_pin) {
         info!("Pin decoded successfully. Len: {}", bytes.len());
         Arc::new(PinnedServerVerifier::new(bytes))
    } else {
         return Err(anyhow::anyhow!("Invalid Certificate PIN hex string"));
    };

    let mut client_crypto = rustls::ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    
    // STRICT MODE: If censorship_resistant is enabled, we ONLY send "h3".
    // We do NOT send "mavivpn" as a fallback, because the string "mavivpn" in the ClientHello 
    // is a cleartext fingerprint that censors can use to block us.
    if censorship_resistant {
        client_crypto.alpn_protocols = vec![b"h3".to_vec()];
        info!("Censorship Resistant Mode enabled. ALPN: h3 (Strict)");
    } else {
        client_crypto.alpn_protocols = vec![b"mavivpn".to_vec(), b"h3".to_vec()];
        info!("Standard Mode enabled. ALPN: mavivpn, h3");
    }

    // Connect & MTU Logic
    info!("Resolving host: {}", endpoint_str);
    let addrs: Vec<_> = tokio::net::lookup_host(&endpoint_str).await?.collect();
    let addr = *addrs.first().ok_or(anyhow::anyhow!("Invalid address"))?;
    let server_name = endpoint_host(&endpoint_str);
    if server_name.is_empty() {
        return Err(anyhow::anyhow!("Endpoint host missing"));
    }

    // Rule 2: Outgoing QUIC Payload (Initial MTU) MUST be 1360.
    // IPv4 Wire: 1360 + 20 (IP) + 8 (UDP) = 1388 bytes.
    // IPv6 Wire: 1360 + 40 (IP) + 8 (UDP) = 1408 bytes.
    let quic_mtu = 1360;
    info!("Hard-pinning QUIC MTU: {} (Target Wire: 1388-1408)", quic_mtu);

    // Performance Optimizations
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    
    // MTU Pinning
    transport_config.mtu_discovery_config(None);
    transport_config.initial_mtu(quic_mtu); 
    transport_config.min_mtu(quic_mtu);

    // Enable GSO (Segmentation Offload) for higher throughput.
    // With GSO, Quinn batches multiple QUIC packets into one sendmsg() call,
    // bypassing Android's poor timer resolution which otherwise limits pacing.
    transport_config.enable_segmentation_offload(true);

    // Datagram buffer tuning (matching v0.4 settings for GSO traffic)
    transport_config.datagram_receive_buffer_size(Some(2 * 1024 * 1024)); // 2MB
    transport_config.datagram_send_buffer_size(2 * 1024 * 1024); // 2MB

    let mut client_config = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?));
    client_config.transport_config(Arc::new(transport_config));



    let mut endpoint = quinn::Endpoint::new(
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
        None => return Err(last_error.unwrap_or_else(|| anyhow::anyhow!("No reachable address for {}", endpoint_str))),
    };
    info!("Connection established");

    // Handshake
    let (mut send_stream, mut recv_stream) = connection.open_bi().await?;
    info!("Stream opened");
    
    let auth_msg = ControlMessage::Auth { token };
    let bytes = bincode::serde::encode_to_vec(&auth_msg, bincode::config::standard()).map_err(|e| anyhow::anyhow!("{}", e))?;
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
    
    let config: ControlMessage = bincode::serde::decode_from_slice(&buf, bincode::config::standard())
        .map(|(v, _)| v)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    
    if let ControlMessage::Error { message } = &config {
        return Err(anyhow::anyhow!("Server Error: {}", message));
    }
    
    Ok((connection, config))
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
