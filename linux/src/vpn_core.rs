//! # Mavi VPN Linux Core
//!
//! Implements the core VPN logic for Linux, including:
//! - TUN device management via /dev/net/tun.
//! - QUIC transport via Quinn.
//! - Linux-specific routing and DNS leak prevention.
//! - Dual-stack (IPv4/IPv6) support.

use anyhow::{Context, Result};
use bytes::Buf;
use h3_quinn::Connection as H3QuinnConnection;
use sha2::{Digest, Sha256};
use shared::{
    icmp,
    ipc::Config,
    masque::{self, CAPSULE_MAVI_CONFIG},
    resolve_tun_mtu, ControlMessage, QUIC_OVERHEAD_BYTES,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

use crate::network::NetworkConfig;
use crate::tun::TunDevice;

// --- Default timing parameters ---
const KEEPALIVE_SECS: u64 = 10;
const IDLE_TIMEOUT_SECS: u64 = 60;
const RECONNECT_INITIAL_SECS: u64 = 1;
const RECONNECT_MAX_SECS: u64 = 30;

/// TUN device name used by the VPN.
const TUN_DEVICE_NAME: &str = "mavi0";

/// Entry point for the VPN runner. Manages the reconnection loop and TUN lifecycle.
pub async fn run_vpn(
    mut config: Config,
    running: Arc<AtomicBool>,
    connected: Arc<AtomicBool>,
    last_error: Arc<StdMutex<Option<String>>>,
    assigned_ip: Arc<StdMutex<Option<String>>>,
) -> Result<()> {
    config.normalize_transport();

    let cert_pin_bytes =
        decode_hex(&config.cert_pin).context("Invalid certificate PIN hex format")?;

    let mut backoff = Duration::from_secs(RECONNECT_INITIAL_SECS);

    while running.load(Ordering::Relaxed) {
        let outcome = run_session(
            &config,
            &cert_pin_bytes,
            &running,
            &connected,
            &last_error,
            &assigned_ip,
        )
        .await;

        if !running.load(Ordering::Relaxed) {
            break;
        }

        let (reconnect_delay, next_backoff) = match outcome {
            Ok(SessionEnd::UserStopped) => break,
            Ok(SessionEnd::ConnectionLost) => (
                Duration::from_secs(RECONNECT_INITIAL_SECS),
                Duration::from_secs(RECONNECT_INITIAL_SECS),
            ),
            Err(e) => {
                warn!("Session failed: {:#}. Reconnecting...", e);
                (
                    backoff,
                    (backoff * 2).min(Duration::from_secs(RECONNECT_MAX_SECS)),
                )
            }
        };

        tokio::time::sleep(reconnect_delay).await;
        backoff = next_backoff;
    }

    info!("VPN stopped.");
    Ok(())
}

enum SessionEnd {
    UserStopped,
    ConnectionLost,
}

/// Holds the h3 `SendRequest` + driver task for the lifetime of the VPN session.
///
/// Dropping `h3::client::SendRequest` decrements its internal `sender_count`; when the
/// last one goes, its `Drop` impl calls `handle_connection_error_on_stream(H3_NO_ERROR,
/// "Connection closed by client")` which tears down the underlying quinn connection.
/// We therefore keep the SendRequest alive for the whole session so the VPN datagram
/// plane can keep using the same quinn::Connection.
struct H3SessionGuard {
    _send_request: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    drive_handle: tokio::task::JoinHandle<()>,
}

impl Drop for H3SessionGuard {
    fn drop(&mut self) {
        self.drive_handle.abort();
    }
}

/// Creates a dual-stack UDP socket for QUIC transport.
fn create_udp_socket() -> Result<std::net::UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    socket.set_only_v6(false)?;
    socket.bind(&socket2::SockAddr::from(std::net::SocketAddrV6::new(
        std::net::Ipv6Addr::UNSPECIFIED,
        0,
        0,
        0,
    )))?;

    // Large socket buffers for high-throughput stability (try 4MB, fall back gracefully)
    for size in [4 * 1024 * 1024, 2 * 1024 * 1024, 1024 * 1024] {
        if socket.set_recv_buffer_size(size).is_ok() {
            let _ = socket.set_send_buffer_size(size); // Also set the send buffer
            break;
        }
    }

    // Disable PMTU discovery on the UDP socket to let QUIC handle it
    // (prevents the kernel from dropping packets that exceed path MTU)
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let fd = socket.as_raw_fd();
        let val: libc::c_int = libc::IP_PMTUDISC_DONT;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            );
        }
    }

    Ok(socket.into())
}

/// Manages a single active VPN session (handshake + packet pumping).
async fn run_session(
    config: &Config,
    cert_pin_bytes: &[u8],
    global_running: &Arc<AtomicBool>,
    connected_flag: &Arc<AtomicBool>,
    last_error_state: &Arc<StdMutex<Option<String>>>,
    assigned_ip_state: &Arc<StdMutex<Option<String>>>,
) -> Result<SessionEnd> {
    let socket = create_udp_socket()?;

    // 1. QUIC Handshake & Auth
    //    `_h3_guard` keeps the h3 SendRequest + driver task alive for the entire
    //    session; dropping it earlier would send CONNECTION_CLOSE(H3_NO_ERROR) and
    //    kill the VPN datagram plane. It lives to the end of `run_session` scope.
    // Optional ECH GREASE + SNI-spoofing config, derived from the admin's
    // out-of-band ECHConfigList (hex in config.json / $VPN_ECH_CONFIG). None →
    // legacy path.
    let ech_bytes = config
        .ech_config
        .as_deref()
        .and_then(crate::ech_client::decode_hex);

    let (connection, server_config, _h3_guard) = connect_and_handshake(
        socket,
        config.token.clone(),
        config.endpoint.clone(),
        cert_pin_bytes.to_vec(),
        config.censorship_resistant,
        config.effective_http3_framing(),
        ech_bytes,
        config.vpn_mtu,
    )
    .await?;

    // 2. Extract Network Configuration
    let (assigned_ip, netmask, gateway, dns, mtu, assigned_ipv6, netmask_v6, gateway_v6, dns_v6) =
        match server_config {
            ControlMessage::Config {
                assigned_ip,
                netmask,
                gateway,
                dns_server,
                mtu,
                assigned_ipv6,
                netmask_v6,
                gateway_v6,
                dns_server_v6,
                ..
            } => (
                assigned_ip,
                netmask,
                gateway,
                dns_server,
                mtu,
                assigned_ipv6,
                netmask_v6,
                gateway_v6,
                dns_server_v6,
            ),
            ControlMessage::Error { message } => {
                let msg = format!("Server rejected connection: {}", message);
                if let Ok(mut last) = last_error_state.lock() {
                    *last = Some(msg.clone());
                }
                return Err(anyhow::anyhow!(msg));
            }
            _ => return Err(anyhow::anyhow!("Unexpected server response")),
        };

    info!("Handshake successful. Internal IPv4: {}", assigned_ip);
    connected_flag.store(true, Ordering::SeqCst);
    if let Ok(mut ip) = assigned_ip_state.lock() {
        *ip = Some(assigned_ip.to_string());
    }

    // 3. Create TUN device
    let tun = TunDevice::create(TUN_DEVICE_NAME)?;
    let tun_name = tun.name().to_string();

    // 4. Configure Linux networking (IPs, routes, DNS)
    let remote_ip = connection.remote_address().ip();
    let endpoint_ip_str = match remote_ip {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(|v4| v4.to_string())
            .unwrap_or_else(|| v6.to_string()),
    };

    let net_config = NetworkConfig::apply(
        &tun_name,
        assigned_ip,
        netmask,
        gateway,
        dns,
        mtu,
        &endpoint_ip_str,
        assigned_ipv6,
        netmask_v6,
        gateway_v6,
        dns_v6,
    )?;

    // 5. Start async TUN I/O
    let async_tun = Arc::new(tun.into_async()?);
    let session_alive = Arc::new(AtomicBool::new(true));
    let connection = Arc::new(connection);

    // Task: MTU Monitor
    let conn_monitor = connection.clone();
    let alive_monitor = session_alive.clone();
    let running_monitor = global_running.clone();
    let mtu_monitor = tokio::spawn(async move {
        let mut last_mtu = 0;
        loop {
            if !running_monitor.load(Ordering::Relaxed) || !alive_monitor.load(Ordering::Relaxed) {
                break;
            }
            let current_mtu = conn_monitor.max_datagram_size().unwrap_or(0);
            if current_mtu != last_mtu && last_mtu != 0 {
                info!(
                    "[MTU] QUIC Path MTU changed: {} -> {} bytes",
                    last_mtu, current_mtu
                );
            }
            last_mtu = current_mtu;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    // Task: TUN -> QUIC (Read from TUN, send via QUIC)
    let tun_reader = async_tun.clone();
    let conn_sender = connection.clone();
    let alive_tun = session_alive.clone();
    let run_tun = global_running.clone();
    let is_h3_framing = config.effective_http3_framing();
    let tun_mtu_for_ptb = mtu;
    let gateway_v6_for_ptb = gateway_v6;
    let tun_to_quic = tokio::spawn(async move {
        let mut pool = bytes::BytesMut::with_capacity(4 * 1024 * 1024);
        let mut scratch = vec![0u8; 65536];
        loop {
            if !run_tun.load(Ordering::Relaxed) || !alive_tun.load(Ordering::Relaxed) {
                break;
            }
            if pool.capacity() < 65536 + masque::DATAGRAM_PREFIX.len() {
                pool.reserve(4 * 1024 * 1024);
            }
            match tun_reader.read(&mut scratch).await {
                Ok(n) if n > 0 => {
                    // In H3 mode, prepend [Quarter Stream ID] [Context ID]
                    // (connect-ip datagram framing, RFC 9484 §5 — 2 bytes).
                    let payload = if is_h3_framing {
                        pool.extend_from_slice(&masque::DATAGRAM_PREFIX);
                        pool.extend_from_slice(&scratch[..n]);
                        pool.split().freeze()
                    } else {
                        pool.extend_from_slice(&scratch[..n]);
                        pool.split().freeze()
                    };
                    if let Err(e) = conn_sender.send_datagram(payload) {
                        if matches!(e, quinn::SendDatagramError::TooLarge) {
                            let version = scratch[0] >> 4;
                            let source_ip = if version == 4 {
                                Some(std::net::IpAddr::V4(gateway))
                            } else if version == 6 {
                                gateway_v6_for_ptb.map(std::net::IpAddr::V6)
                            } else {
                                None
                            };
                            let reported_mtu = if version == 6 {
                                tun_mtu_for_ptb.max(1280)
                            } else {
                                tun_mtu_for_ptb
                            };
                            if let Some(icmp_packet) = icmp::generate_packet_too_big(
                                &scratch[..n],
                                reported_mtu,
                                source_ip,
                            ) {
                                let _ = tun_reader.write(&icmp_packet).await;
                            }
                        } else {
                            warn!("Datagram send error: {}", e);
                            alive_tun.store(false, Ordering::SeqCst);
                            break;
                        }
                    }
                }
                Ok(_) => {} // zero-length read, continue
                Err(e) => {
                    warn!("TUN read error: {}", e);
                    alive_tun.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }
    });

    // Task: QUIC -> TUN (Read from QUIC, write to TUN)
    let tun_writer = async_tun.clone();
    let alive_quic = session_alive.clone();
    let run_quic = global_running.clone();
    let is_h3_framing_dl = config.effective_http3_framing();
    let quic_to_tun = tokio::spawn(async move {
        loop {
            if !run_quic.load(Ordering::Relaxed) || !alive_quic.load(Ordering::Relaxed) {
                break;
            }
            match connection.read_datagram().await {
                Ok(mut data) => {
                    // Strip [Quarter Stream ID] [Context ID] for connect-ip.
                    if is_h3_framing_dl {
                        let inner_len = match masque::unwrap_datagram(&data) {
                            Some(slice) => slice.len(),
                            None => continue,
                        };
                        if inner_len == 0 {
                            continue;
                        }
                        let prefix = data.len() - inner_len;
                        data.advance(prefix);
                    }
                    if data.is_empty() {
                        continue;
                    }
                    if let Err(e) = tun_writer.write(&data).await {
                        warn!("TUN write error: {}", e);
                        alive_quic.store(false, Ordering::SeqCst);
                        break;
                    }
                }
                Err(_) => {
                    alive_quic.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }
    });

    // Wait for termination
    while global_running.load(Ordering::Relaxed) && session_alive.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    tun_to_quic.abort();
    quic_to_tun.abort();
    mtu_monitor.abort();

    // Cleanup networking
    net_config.cleanup();
    connected_flag.store(false, Ordering::SeqCst);
    if let Ok(mut ip) = assigned_ip_state.lock() {
        *ip = None;
    }

    if global_running.load(Ordering::Relaxed) {
        Ok(SessionEnd::ConnectionLost)
    } else {
        Ok(SessionEnd::UserStopped)
    }
}

/// QUIC connection setup with custom certificate pinning.
#[allow(clippy::too_many_arguments)]
async fn connect_and_handshake(
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
    let addr = tokio::net::lookup_host(&endpoint_str)
        .await?
        .next()
        .context("Failed to resolve endpoint")?;

    // Outer QUIC payload MTU is derived from the operator-configured inner TUN
    // MTU (`VPN_MTU`, default 1280). The 80-byte overhead reserves room for
    // QUIC short-header framing + AEAD tag + connection-ID bytes. Server and
    // client MUST be configured with the same `VPN_MTU`, otherwise the larger
    // side will send UDP payloads the smaller side considers out-of-spec.
    let tun_mtu = resolve_tun_mtu(vpn_mtu);
    let quic_mtu = tun_mtu + QUIC_OVERHEAD_BYTES;
    let (ip_overhead, udp_overhead) = (if addr.is_ipv4() { 20 } else { 40 }, 8);
    info!(
        "Address family: {}. Setting QUIC MTU: {} (TUN MTU: {}, Target Wire: {})",
        if addr.is_ipv4() { "IPv4" } else { "IPv6" },
        quic_mtu,
        tun_mtu,
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
    let server_name: String = match ech_state.as_ref() {
        Some(ech) => ech.outer_sni.clone(),
        None => {
            let raw = if endpoint_str.starts_with('[') {
                // IPv6 literal: [::1]:443 → ::1
                endpoint_str
                    .trim_start_matches('[')
                    .split(']')
                    .next()
                    .unwrap_or(&endpoint_str)
            } else {
                // hostname:port or IPv4:port
                endpoint_str.split(':').next().unwrap_or(&endpoint_str)
            };
            raw.to_string()
        }
    };
    info!("Connecting to {} (SNI: {})", addr, server_name);
    let connection = endpoint
        .connect(addr, &server_name)?
        .await
        .context("QUIC handshake failed")?;

    // Application-level handshake
    let (config, h3_guard) = if effective_http3_framing {
        let (cfg, guard) = connect_and_handshake_h3(connection.clone(), token).await?;
        (cfg, Some(guard))
    } else {
        let (mut send, mut recv) = connection.open_bi().await?;
        let auth_msg = ControlMessage::Auth { token };
        let encoded = bincode::serde::encode_to_vec(&auth_msg, bincode::config::standard())?;
        send.write_u32_le(encoded.len() as u32).await?;
        send.write_all(&encoded).await?;
        let _ = send.finish();

        let len = recv.read_u32_le().await? as usize;
        if len > 65536 {
            anyhow::bail!("Server response too large: {} bytes", len);
        }
        let mut buf = vec![0u8; len];
        recv.read_exact(&mut buf).await?;
        let cfg: ControlMessage =
            bincode::serde::decode_from_slice(&buf, bincode::config::standard()).map(|(v, _)| v)?;
        (cfg, None)
    };

    validate_server_mtu(&config, tun_mtu)?;

    Ok((connection, config, h3_guard))
}

fn validate_server_mtu(config: &ControlMessage, local_tun_mtu: u16) -> Result<()> {
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

/// MASQUE connect-ip (RFC 9484) handshake.
///
/// Sends `CONNECT` with `:protocol=connect-ip` over HTTP/3, then parses the
/// capsule stream on the request body to extract the vendor `MAVI_CONFIG`
/// capsule which carries the full `ControlMessage::Config`.
///
/// Returns the server config **and** an `H3SessionGuard` that MUST be held for the
/// entire VPN session. Dropping `send_request` here would tear the quinn connection
/// down (H3_NO_ERROR "Connection closed by client"), so we hand it to the caller.
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
        .map_err(|e| anyhow::anyhow!("H3 client init failed: {}", e))?;

    // Drive the H3 connection in the background for the lifetime of the session.
    let drive_handle = tokio::spawn(async move {
        let e = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        tracing::debug!("H3 driver finished: {}", e);
    });

    // Extended CONNECT with :protocol=connect-ip (RFC 9484 §3).
    let req = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("https://mavi-vpn/.well-known/masque/ip/*/*/")
        .extension(h3::ext::Protocol::CONNECT_IP)
        .header("authorization", format!("Bearer {}", token))
        .header("capsule-protocol", "?1")
        .body(())
        .context("Failed to build H3 CONNECT request")?;

    let mut stream = send_request
        .send_request(req)
        .await
        .map_err(|e| anyhow::anyhow!("H3 send_request failed: {}", e))?;
    // NB: do NOT finish the stream — connect-ip keeps the request stream open
    // for bidirectional capsule traffic throughout the session.

    let resp = stream
        .recv_response()
        .await
        .map_err(|e| anyhow::anyhow!("H3 recv_response failed: {}", e))?;

    if resp.status() != http::StatusCode::OK {
        anyhow::bail!("AUTH_FAILED: Server returned HTTP {}", resp.status());
    }

    // Accumulate capsules until we see MAVI_CONFIG. Every wait on `recv_data`
    // is bounded by the remaining handshake budget so a silent or slow-drip
    // server cannot leave us blocked forever; the buffer is also capped by
    // `masque::MAX_CAPSULE_BUF` to bound memory use.
    let mut capsule_buf: Vec<u8> = Vec::new();
    let mut config: Option<ControlMessage> = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    'read: while config.is_none() {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("Timed out waiting for MAVI_CONFIG capsule");
        }

        while let Some(parts) = masque::read_capsule(&capsule_buf) {
            let (ctype, payload, consumed) = (parts.0, parts.1.to_vec(), parts.2);
            capsule_buf.drain(..consumed);
            if ctype == CAPSULE_MAVI_CONFIG {
                config = Some(
                    bincode::serde::decode_from_slice(&payload, bincode::config::standard())
                        .map(|(v, _)| v)
                        .map_err(|e| anyhow::anyhow!("Failed to decode MAVI_CONFIG: {}", e))?,
                );
                break 'read;
            }
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

    let config =
        config.ok_or_else(|| anyhow::anyhow!("connect-ip response lacked MAVI_CONFIG capsule"))?;

    Ok((
        config,
        H3SessionGuard {
            _send_request: send_request,
            drive_handle,
        },
    ))
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
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
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    #[test]
    fn test_pinned_server_verifier_matches() {
        let dummy_cert_bytes = b"dummy certificate";
        let hash = Sha256::digest(dummy_cert_bytes).to_vec();

        let verifier = PinnedServerVerifier::new(hash);

        let end_entity = CertificateDer::from(dummy_cert_bytes.as_slice());
        let server_name = ServerName::try_from("example.com").unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(0));

        let result = verifier.verify_server_cert(&end_entity, &[], &server_name, &[], now);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pinned_server_verifier_mismatches() {
        let expected_hash = vec![0; 32];
        let verifier = PinnedServerVerifier::new(expected_hash);

        let dummy_cert_bytes = b"wrong certificate";
        let end_entity = CertificateDer::from(dummy_cert_bytes.as_slice());
        let server_name = ServerName::try_from("example.com").unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(0));

        let result = verifier.verify_server_cert(&end_entity, &[], &server_name, &[], now);
        assert!(result.is_err());
        if let Err(rustls::Error::General(msg)) = result {
            assert_eq!(msg, "Certificate PIN mismatch");
        } else {
            panic!("Expected General error, got {:?}", result);
        }
    }
}
