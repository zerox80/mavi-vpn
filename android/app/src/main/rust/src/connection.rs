use bytes::Buf;
use h3_quinn::Connection as H3QuinnConnection;
use log::info;
use shared::ControlMessage;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::crypto::{decode_hex, PinnedServerVerifier};

pub async fn connect_and_handshake(
    socket: std::net::UdpSocket, 
    token: String, 
    endpoint_str: String, 
    cert_pin: String,
    censorship_resistant: bool,
    http3_framing: bool,
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
    transport_config.max_idle_timeout(None); // Disable idle timeout for Doze Mode!
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(15))); // Less aggressive keep-alives
    
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
    let config = if http3_framing {
        connect_and_handshake_h3(connection.clone(), token).await?
    } else {
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
        config
    };
    
    Ok((connection, config))
}

async fn connect_and_handshake_h3(
    connection: quinn::Connection,
    token: String,
) -> anyhow::Result<ControlMessage> {
    let h3_conn = H3QuinnConnection::new(connection.clone());
    let mut builder = h3::client::builder();
    builder.enable_datagram(true);
    let (mut driver, mut send_request) = builder.build::<_, _, bytes::Bytes>(h3_conn).await
        .map_err(|e| anyhow::anyhow!("H3 client init failed: {}", e))?;

    let drive_handle = tokio::spawn(async move {
        let e = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        log::warn!("H3 driver error: {}", e);
    });

    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/vpn")
        .header("authorization", format!("Bearer {}", token))
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build H3 request: {}", e))?;

    let mut stream = send_request.send_request(req).await
        .map_err(|e| anyhow::anyhow!("H3 send_request failed: {}", e))?;
    stream.finish().await
        .map_err(|e| anyhow::anyhow!("H3 finish failed: {}", e))?;

    let resp = stream.recv_response().await
        .map_err(|e| anyhow::anyhow!("H3 recv_response failed: {}", e))?;

    if resp.status() != http::StatusCode::OK {
        anyhow::bail!("AUTH_FAILED: Server returned HTTP {}", resp.status());
    }

    let mut body_buf = Vec::new();
    while let Some(chunk) = stream.recv_data().await
        .map_err(|e| anyhow::anyhow!("H3 recv_data failed: {}", e))? {
        body_buf.extend_from_slice(chunk.chunk());
    }

    let config: ControlMessage = bincode::serde::decode_from_slice(&body_buf, bincode::config::standard())
        .map(|(v, _)| v)
        .map_err(|e| anyhow::anyhow!("Failed to decode H3 config: {}", e))?;

    if let ControlMessage::Error { message } = &config {
        return Err(anyhow::anyhow!("Server Error: {}", message));
    }

    drive_handle.abort();
    Ok(config)
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
