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
        client_crypto.alpn_protocols = vec![b"mavivpn".to_vec()];
        info!("Standard Mode enabled. ALPN: mavivpn");
    }

    // Connect & MTU Logic
    info!("Resolving host: {}", endpoint_str);
    let addr = tokio::net::lookup_host(&endpoint_str).await?
        .next()
        .ok_or(anyhow::anyhow!("Invalid address"))?;

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

    // Enable Segmentation Offload (GSO) for higher throughput - Disabled for better stability on restricted networks
    transport_config.enable_segmentation_offload(false);

    // Congestion Control: Use BBR for higher bandwidth and resistance to loss/jitter
    transport_config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));

    // Datagram queue tuning for high-speed traffic
    // Reduced to 256KB to ensure clean TCP backpressure and avoid bufferbloat
    transport_config.datagram_receive_buffer_size(Some(4 * 1024 * 1024)); // 4MB
    transport_config.datagram_send_buffer_size(256 * 1024); // 256KB

    let mut client_config = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?));
    client_config.transport_config(Arc::new(transport_config));

    // --- ANTI-BUFFERBLOAT SCHUTZ ---
    // Wir wandeln den std::net Socket kurz in einen socket2 Socket um,
    // um die OS-Puffer-Größen auf Kernel-Ebene hart zu drosseln.
    let socket2_sock = socket2::Socket::from(socket);
    
    // Groß für 250+ Mbit/s Downloads
    let _ = socket2_sock.set_recv_buffer_size(4 * 1024 * 1024); 
    
    // EXTREM WICHTIG: Winzig (128 KB) für Uploads! 
    // Verhindert, dass BBR blind Pakete in den Android-RAM pumpt und das Modem crasht.
    let _ = socket2_sock.set_send_buffer_size(128 * 1024); 
    
    // Zurückwandeln für Quinn
    let socket = std::net::UdpSocket::from(socket2_sock);
    // --------------------------------

    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(client_config);

    info!("Connecting to {}", addr);
    let connection = endpoint.connect(addr, "localhost")?.await?;
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
    recv_stream.read_exact(&mut buf).await?;
    let config: ControlMessage = bincode::serde::decode_from_slice(&buf, bincode::config::standard())
        .map(|(v, _)| v)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    
    if let ControlMessage::Error { message } = &config {
        return Err(anyhow::anyhow!("Server Error: {}", message));
    }
    
    Ok((connection, config))
}
