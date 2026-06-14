use anyhow::Result;
use bytes::Bytes;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tracing::{info, warn};

use shared::ControlMessage;

use crate::config::Config;
use crate::keycloak::KeycloakValidator;
use crate::state::AppState;

use crate::handlers::auth::authenticate_client;
use crate::handlers::h3::handle_h3_connection;
use crate::handlers::tunnel::run_tunnel;
use crate::handlers::utils::{emulate_http3, negotiated_alpn, negotiated_sni, IpGuard};

enum InitialStreams {
    Raw {
        send_stream: quinn::SendStream,
        recv_stream: quinn::RecvStream,
    },
    H3 {
        pre_bi: Option<(quinn::SendStream, quinn::RecvStream)>,
        pre_uni: quinn::RecvStream,
    },
}

const RAW_AUTH_MAX_BYTES: usize = 16_384;

/// Upper bound on how long a freshly accepted connection may take to open its
/// initial control stream (and, for H3, to send its request). Without it, a peer
/// that completes the handshake but never opens a stream would pin a bounded
/// connection-handler slot until the 60s idle timeout — cheap, unauthenticated
/// connection-slot exhaustion. Bounding the pre-auth phase releases stalled slots.
pub(crate) const PREAUTH_PHASE_TIMEOUT: Duration = Duration::from_secs(10);

fn validate_raw_auth_len(len: usize) -> Result<()> {
    if len > RAW_AUTH_MAX_BYTES {
        anyhow::bail!("Auth message too big");
    }
    Ok(())
}

fn decode_raw_auth_payload(buf: &[u8]) -> Result<String> {
    let msg: ControlMessage = bincode::serde::decode_from_slice(buf, bincode::config::standard())
        .map(|(v, _)| v)
        .map_err(|e| anyhow::anyhow!("Protocol error: {e}"))?;

    match msg {
        ControlMessage::Auth { token } => Ok(token),
        _ => anyhow::bail!("Protocol error: Expected Auth"),
    }
}

fn encode_control_message_frame(msg: &ControlMessage) -> Result<Vec<u8>> {
    let encoded = bincode::serde::encode_to_vec(msg, bincode::config::standard())?;
    let mut framed = Vec::with_capacity(4 + encoded.len());
    framed.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
    framed.extend_from_slice(&encoded);
    Ok(framed)
}

// The rejection reason stays in the server log only. Echoing it to the
// unauthenticated peer would let probers distinguish bad credentials from
// infrastructure state (Keycloak down, IP pool exhausted, ...).
fn unauthorized_control_message() -> ControlMessage {
    ControlMessage::Error {
        message: "Unauthorized".to_string(),
    }
}

/// Leeway applied on top of the token's `exp` before force-closing the
/// session, mirroring the validation leeway in `KeycloakValidator`.
const SESSION_EXPIRY_LEEWAY: Duration = Duration::from_secs(30);

/// Converts a token expiry (Unix seconds) into a tokio deadline. Returns
/// `None` when the session has no expiry (static token auth).
pub(super) fn session_deadline(expiry: Option<i64>) -> Option<tokio::time::Instant> {
    let exp = expiry?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let remaining = u64::try_from(exp).unwrap_or(0).saturating_sub(now);
    Some(tokio::time::Instant::now() + Duration::from_secs(remaining) + SESSION_EXPIRY_LEEWAY)
}

/// Runs the tunnel future, force-closing the QUIC connection when the
/// authenticating token expires so revoked/expired credentials cannot keep a
/// session alive indefinitely.
pub(super) async fn run_tunnel_until_session_expiry(
    connection: &quinn::Connection,
    expiry: Option<i64>,
    tunnel: impl Future<Output = Result<()>>,
) -> Result<()> {
    match session_deadline(expiry) {
        Some(deadline) => {
            tokio::pin!(tunnel);
            tokio::select! {
                res = &mut tunnel => res,
                () = tokio::time::sleep_until(deadline) => {
                    warn!(
                        "Closing connection from {}: session token expired",
                        connection.remote_address()
                    );
                    connection.close(0u32.into(), b"session token expired");
                    Ok(())
                }
            }
        }
        None => tunnel.await,
    }
}

/// Capacity of the per-client server→client packet queue. Mirrors the global
/// TUN channel capacity so backpressure behaves symmetrically on both legs.
const CLIENT_CHANNEL_CAPACITY: usize = 4096;

/// Shared post-authentication setup for both the raw and H3 paths: registers the
/// client's packet sink, starts the bidirectional tunnel, and tears it down when
/// the session token expires. The caller retains the [`IpGuard`] so the assigned
/// IP pair is released even if delivering the config/capsule response fails
/// before this runs.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_authenticated_tunnel(
    connection: Arc<quinn::Connection>,
    state: &AppState,
    tx_tun: tokio::sync::mpsc::Sender<Bytes>,
    assigned_ip: std::net::Ipv4Addr,
    assigned_ip6: std::net::Ipv6Addr,
    session_expiry: Option<i64>,
    mtu: u16,
    is_h3: bool,
) -> Result<()> {
    let (tx_client, rx_client) = tokio::sync::mpsc::channel::<Bytes>(CLIENT_CHANNEL_CAPACITY);
    state.register_client(assigned_ip, assigned_ip6, tx_client);

    let tunnel = run_tunnel(
        connection.clone(),
        rx_client,
        tx_tun,
        assigned_ip,
        assigned_ip6,
        state.gateway_ip(),
        state.gateway_ip_v6(),
        mtu,
        is_h3,
    );
    run_tunnel_until_session_expiry(&connection, session_expiry, tunnel).await
}

pub(super) fn build_config_message(
    state: &AppState,
    config: &Config,
    assigned_ip: std::net::Ipv4Addr,
    assigned_ip6: std::net::Ipv6Addr,
    ipv6_enabled: bool,
) -> ControlMessage {
    ControlMessage::Config {
        assigned_ip,
        netmask: state.network.mask(),
        gateway: state.gateway_ip(),
        dns_server: config.dns,
        mtu: config.mtu,
        assigned_ipv6: if ipv6_enabled {
            Some(assigned_ip6)
        } else {
            None
        },
        netmask_v6: if ipv6_enabled {
            Some(state.network_v6.prefix())
        } else {
            None
        },
        gateway_v6: if ipv6_enabled {
            Some(state.gateway_ip_v6())
        } else {
            None
        },
        dns_server_v6: if ipv6_enabled {
            Some(config.dns_v6.unwrap_or_else(|| {
                std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)
            }))
        } else {
            None
        },
        whitelist_domains: Some(config.whitelist_domains.clone()),
    }
}

async fn detect_initial_streams(connection: &quinn::Connection) -> Result<InitialStreams> {
    match negotiated_alpn(connection).as_deref() {
        // ALPN is the authoritative protocol signal. If the peer negotiated h3,
        // waiting for a unidirectional HTTP/3 control stream is correct; falling
        // back to raw mode after an arbitrary grace period races real H3 clients
        // on slow or jittery networks and makes their H3 bytes look like a raw
        // bincode auth message.
        Some(protocol) if protocol == b"h3" => {
            let pre_uni = connection.accept_uni().await?;
            Ok(InitialStreams::H3 {
                pre_bi: None,
                pre_uni,
            })
        }
        Some(protocol) if protocol == b"mavivpn" => {
            let (send_stream, recv_stream) = connection.accept_bi().await?;
            Ok(InitialStreams::Raw {
                send_stream,
                recv_stream,
            })
        }
        // Legacy fallback for peers without an ALPN value: accept the first bidi
        // stream as the raw control channel. Modern clients negotiate either
        // `mavivpn` or `h3`, so this avoids timing heuristics for supported paths.
        _ => {
            let (send_stream, recv_stream) = connection.accept_bi().await?;
            Ok(InitialStreams::Raw {
                send_stream,
                recv_stream,
            })
        }
    }
}

#[allow(clippy::too_many_lines)]
#[allow(clippy::cast_possible_truncation)]
pub async fn handle_connection(
    conn: quinn::Incoming,
    state: Arc<AppState>,
    config: Config,
    tx_tun: tokio::sync::mpsc::Sender<Bytes>,
    keycloak: Option<Arc<KeycloakValidator>>,
    ipv6_enabled: bool,
) -> Result<()> {
    let connection = conn.await?;
    let remote_addr = connection.remote_address();

    let sni = negotiated_sni(&connection);
    let alpn = negotiated_alpn(&connection).map_or_else(
        || "<none>".to_string(),
        |p| String::from_utf8_lossy(&p).into_owned(),
    );

    if config.censorship_resistant {
        let expected = &config.ech_public_name;
        match &sni {
            Some(s) if s == expected => info!(
                "New connection from {} | SNI: {:?} | ALPN: {} | ECH: cover SNI matches (ok)",
                remote_addr, s, alpn
            ),
            Some(s) => warn!(
                "New connection from {} | SNI: {:?} | ALPN: {} | ECH: expected cover SNI {:?}",
                remote_addr, s, alpn, expected
            ),
            None => info!(
                "New connection from {} | SNI: <none> | ALPN: {} | ECH: cover SNI expected {:?}",
                remote_addr, alpn, expected
            ),
        }
    } else {
        info!(
            "New connection from {} | SNI: {} | ALPN: {}",
            remote_addr,
            sni.as_deref().unwrap_or("<none>"),
            alpn
        );
    }

    let initial_streams = tokio::time::timeout(
        PREAUTH_PHASE_TIMEOUT,
        detect_initial_streams(&connection),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Pre-auth handshake timeout from {remote_addr}"))??;
    let (pre_bi, pre_uni) = match initial_streams {
        InitialStreams::Raw {
            send_stream,
            recv_stream,
        } => (Some((send_stream, recv_stream)), None),
        InitialStreams::H3 { pre_bi, pre_uni } => (pre_bi, Some(pre_uni)),
    };

    if let Some(pre_uni) = pre_uni {
        return handle_h3_connection(
            connection,
            pre_bi,
            pre_uni,
            state,
            config,
            tx_tun,
            keycloak,
            ipv6_enabled,
            sni,
        )
        .await;
    }

    let (mut send_stream, mut recv_stream) =
        pre_bi.expect("raw detection always includes a bidi stream");

    let auth_result = async {
        let buf = tokio::time::timeout(Duration::from_secs(5), async {
            let len = recv_stream.read_u32_le().await? as usize;
            validate_raw_auth_len(len)?;

            let mut buf = vec![0u8; len];
            recv_stream.read_exact(&mut buf).await?;
            Ok::<Vec<u8>, anyhow::Error>(buf)
        })
        .await
        .map_err(|_| anyhow::anyhow!("Handshake timeout"))??;

        let token = decode_raw_auth_payload(&buf)?;
        authenticate_client(
            &token,
            &state,
            &config,
            crate::handlers::auth::as_token_validator(keycloak.as_ref()),
        )
        .await
    }
    .await;

    let (assigned_ip, assigned_ip6, session_expiry) = match auth_result {
        Ok(ips) => ips,
        Err(e) => {
            if config.censorship_resistant {
                warn!(
                    "Unauthorized probe from {}. Emulating HTTP/3. Error: {}",
                    remote_addr, e
                );
                let _ = emulate_http3(&connection, &mut send_stream).await;
                return Err(anyhow::anyhow!("HTTP/3 probe response sent: {e}"));
            }
            warn!("Unauthorized connection from {}: {}", remote_addr, e);
            let err_payload = unauthorized_control_message();
            if let Ok(framed) = encode_control_message_frame(&err_payload) {
                let _ = send_stream.write_all(&framed).await;
                let _ = send_stream.finish();
            }
            return Err(anyhow::anyhow!("Unauthorized: {e}"));
        }
    };

    let _ip_guard = IpGuard {
        state: state.clone(),
        ip4: assigned_ip,
        ip6: assigned_ip6,
    };

    let success_msg =
        build_config_message(&state, &config, assigned_ip, assigned_ip6, ipv6_enabled);
    let bytes = encode_control_message_frame(&success_msg)?;
    send_stream.write_all(&bytes).await?;
    let _ = send_stream.finish();

    info!(
        "Authenticated {} | SNI: {} -> IPv4: {}, IPv6: {}",
        remote_addr,
        sni.as_deref().unwrap_or("<none>"),
        assigned_ip,
        assigned_ip6
    );

    let connection_arc = Arc::new(connection);
    let conn_stats = connection_arc.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let conn_metrics = conn_stats.stats();
            info!(
                "[SERVER QUIC STATS] Peer: {} | RTT: {}ms | CWND: {} bytes | Lost Packets: {} | Max Datagram: {}",
                remote_addr,
                conn_metrics.path.rtt.as_millis(),
                conn_metrics.path.cwnd,
                conn_metrics.path.lost_packets,
                conn_stats.max_datagram_size().unwrap_or(0)
            );
            if conn_stats.close_reason().is_some() {
                break;
            }
        }
    });

    run_authenticated_tunnel(
        connection_arc,
        &state,
        tx_tun,
        assigned_ip,
        assigned_ip6,
        session_expiry,
        config.mtu,
        false, // is_h3
    )
    .await
}

#[cfg(test)]
mod tests;
